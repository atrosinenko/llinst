#include "BpfLoader.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <iostream>

// For old elf.h
#define RELOC_64_64 1
#define RELOC_64_32 10

#define str(x) #x
#define CHECK_THAT(x) if(!(x)) { throw bpf_loader_exception("Check failed: " str(x)); }

BpfLoader::BpfLoader(const char *fileName)
{
  int fd = open(fileName, O_RDONLY);
  if (fd < 0) {
    throw bpf_loader_exception("Cannot open eBPF object file");
  }
  length = lseek(fd, 0, SEEK_END);
  mappedFile = (unsigned char *)mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  if (mappedFile == MAP_FAILED) {
    throw bpf_loader_exception("Cannot map eBPF object file into memory");
  }
}

BpfLoader::BpfLoader(const std::map<std::string, uint64_t> &cbs, std::string fileName): BpfLoader(fileName.c_str())
{
  callbacks = cbs;
  parse();
}

BpfLoader::~BpfLoader()
{
  munmap(mappedFile, length);
}

void BpfLoader::parse()
{
  Elf64_Ehdr *header = (Elf64_Ehdr *)mappedFile;

  // Checking e_ident

  CHECK_THAT(header->e_ident[EI_MAG0] == 0x7F);
  CHECK_THAT(header->e_ident[EI_MAG1] == 'E');
  CHECK_THAT(header->e_ident[EI_MAG2] == 'L');
  CHECK_THAT(header->e_ident[EI_MAG3] == 'F');

  CHECK_THAT(header->e_ident[EI_CLASS] == ELFCLASS64);
#if defined(HOST_WORDS_BIGENDIAN)
  CHECK_THAT(header->e_ident[EI_DATA] == ELFDATA2MSB);
#else
  CHECK_THAT(header->e_ident[EI_DATA] == ELFDATA2LSB);
#endif

  // Checking other fields

  CHECK_THAT(header->e_type == ET_REL);
  CHECK_THAT(header->e_machine == EM_BPF);
  CHECK_THAT(header->e_version == EV_CURRENT);
  CHECK_THAT(header->e_shoff != 0);

  parseSections(header);
  std::map<void *, EBpfInstruction*> instructionMap;
  fetchFunctions();
  processRelocations();
}

void BpfLoader::parseSections(Elf64_Ehdr *header)
{
  int sectionCount = header->e_shnum;
  Elf64_Shdr *sectionHeaders = (Elf64_Shdr*)(mappedFile + header->e_shoff);
  for (int i = 0; i < sectionCount; ++i) {
    Elf64_Shdr *shdr = sectionHeaders + i;
    size_t size = shdr->sh_size;
    const char *name = (const char *)(mappedFile + sectionHeaders[header->e_shstrndx].sh_offset + shdr->sh_name);
    if (shdr->sh_type == SHT_NULL)
      sections.push_back(BpfSection(name, shdr));
    else if (shdr->sh_type == SHT_NOBITS)
      sections.push_back(BpfSection(name, size, shdr));
    else
      sections.push_back(BpfSection(name, mappedFile + shdr->sh_offset, size, shdr));

    if (shdr->sh_type == SHT_SYMTAB) {
      CHECK_THAT(symtab == NULL);
      symtab = (Elf64_Sym *)sections.back().start;
      CHECK_THAT(shdr->sh_entsize == 0 || shdr->sh_entsize == sizeof(Elf64_Sym));
      symtabEntryCount = shdr->sh_size / sizeof(Elf64_Sym);
    }
    if (shdr->sh_type == SHT_STRTAB) {
      CHECK_THAT(strtab == NULL);
      strtab = (const char *)sections.back().start;
    }
  }
}

void BpfLoader::processRelocations()
{
  for (auto sec = sections.begin(); sec != sections.end(); ++sec) {
    CHECK_THAT(sec->hdr->sh_type != SHT_RELA);
    if (sec->hdr->sh_type == SHT_REL) {
      int count = sec->length / sizeof(Elf64_Rel);
      Elf64_Rel *relSection = (Elf64_Rel *)sec->start;
      Elf64_Sym *linkedSymbolTable = (Elf64_Sym *)sections[sec->hdr->sh_link].start;
      BpfSection &patchedSection = sections[sec->hdr->sh_info];
      if ((patchedSection.hdr->sh_flags & SHF_EXECINSTR) == 0) {
        continue; // not a code section
      }
      for (int i = 0; i < count; ++i) {
        Elf64_Rel &rel = relSection[i];
        Elf64_Sym *sym = linkedSymbolTable + ELF64_R_SYM(rel.r_info);
        const char *name = strtab + sym->st_name;

        EBpfInstruction *insn = insnFrom(patchedSection.start + rel.r_offset);
        if (ELF64_R_TYPE(rel.r_info) == RELOC_64_64) {
          if (insn) {
            insn->rel = sym;
            symbols[sym] = name;
          } else {
            std::cerr << "Requested relocation of symbol " << name << " outside of any function\n";
          }
        } else if (ELF64_R_TYPE(rel.r_info) == RELOC_64_32) {
          if (callbacks.count(name)) {
            insn->imm = callbacks.at(name);
          } else {
            std::cerr << "[" << name << "] at " << std::hex << i << " from [" << sec->name << "]\n";
            throw bpf_loader_exception("Unknown callback");
          }
        } else {
          abort();
        }
      }
    }
  }
}

void BpfLoader::fetchFunctions()
{
  std::map<uintptr_t, std::string> functionByPtr;
  for (int i = 0; i < symtabEntryCount; ++i) {
    Elf64_Sym *sym = &symtab[i];
    const char *name = strtab + sym->st_name;
    // Clang 7 does not mark functions as such
    // It does not set sizes as well.
    if (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL && sym->st_shndx < sections.size() && (sections[sym->st_shndx].hdr->sh_flags & SHF_EXECINSTR) != 0) {
      uint64_t *funcBody = (uint64_t *)(sections[sym->st_shndx].start + sym->st_value);
      functionByPtr[uintptr_t(funcBody)] = name;
      functionByPtr[uintptr_t(sections[sym->st_shndx].start + sections[sym->st_shndx].length)] = "";
    }
  }
  uintptr_t previousEnd = 0;
  for (auto it = functionByPtr.rbegin(); it != functionByPtr.rend(); ++it) {
    if (it->second != "") {
      std::vector<EBpfInstruction> &func = functions[it->second];
      CHECK_THAT(func.empty());

      uint64_t *funcBody = (uint64_t *)(it->first);
      for (int j = 0; j < (previousEnd - it->first) / 8; ++j) {
        EBpfInstruction insn;
        insn.raw = funcBody[j];
        insn.source = funcBody + j;
        insn.rel = nullptr;
        func.push_back(insn);
      }
    }
    previousEnd = it->first;
  }
}

EBpfInstruction *BpfLoader::insnFrom(void *ptr)
{
  // highly inefficient but very simple and not on a hot path
  for (auto &F: functions) {
    for (auto &I: F.second) {
      if (I.source == ptr) {
        return &I;
      }
    }
  }
  return nullptr;
}
