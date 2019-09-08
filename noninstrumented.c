#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <syscall.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>

#define MARKER 0x12345678

uint64_t (*event_before_syscall_ptr)(uint32_t num, uint32_t *drop_syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8);

uint64_t __untag(uint64_t x)
{
	return x;
}

static __thread volatile int in_handler;
static void handle_sigsys(int num, siginfo_t *si, void *arg)
{
  ucontext_t *ctx = arg;
  greg_t *gregs = ctx->uc_mcontext.gregs;
  uint32_t drop = 0;
  uint64_t res;
  if (!in_handler) {
    in_handler = 1;
    res = event_before_syscall_ptr(gregs[REG_RAX], &drop, gregs[REG_RDI], gregs[REG_RSI], gregs[REG_RDX], gregs[REG_R10], gregs[REG_R8], gregs[REG_R9], 0, 0);
    in_handler = 0;
  }
  if (!drop) {
    res = syscall(gregs[REG_RAX], gregs[REG_RDI], gregs[REG_RSI], gregs[REG_RDX], gregs[REG_R10], gregs[REG_R8], MARKER);
  }
  gregs[REG_RAX] = res;
}

void finish_initialization(void)
{
  static int initialized = 0;
  if (initialized) {
    return;
  }
  event_before_syscall_ptr = dlsym(RTLD_NEXT, "event_before_syscall");
  initialized = 1;
  setvbuf(stdin,  NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
#define ALLOW(sys) \
    BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , sys, 0, 1), \
    BPF_STMT(BPF_RET           | BPF_K  , SECCOMP_RET_ALLOW),

  struct sock_filter filt[] = {
    BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, args[5]))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K  , MARKER, 0, 1),
    BPF_STMT(BPF_RET           | BPF_K  , SECCOMP_RET_ALLOW),
	ALLOW(SYS_mmap)
	ALLOW(SYS_clone)
	ALLOW(SYS_rt_sigreturn)
	ALLOW(SYS_rt_sigpending)
//	ALLOW(SYS_rt_sigprocmask)
	ALLOW(SYS_select)
    BPF_STMT(BPF_RET           | BPF_K  , SECCOMP_RET_TRAP),
  };

  struct sock_fprog prog = {
    sizeof(filt) / sizeof(filt[0]), filt
  };
  struct sigaction sig;
  memset(&sig, 0, sizeof(sig));
  sig.sa_sigaction = handle_sigsys;
  sig.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGSYS, &sig, NULL);
 
  if (event_before_syscall_ptr) {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  }
}

void __attribute__((constructor)) constr(void)
{
  finish_initialization();
}

