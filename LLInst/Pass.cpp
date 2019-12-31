#ifdef NDEBUG
#undef NDEBUG
#endif

#include "llvm/Pass.h"
#include "llvm/IR/Verifier.h"

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <elf.h>
#include <stdlib.h>

#include <utility>
#include <iostream>
#include <set>
#include <unordered_map>

#include <bpfinst/bpf.h>

#include "BpfLoader.h"

using namespace llvm;

namespace {
  /**
   * @brief Size of stack available for eBPF programs via R10.
   */
  static const int NumStackBytes = 512;

  /**
   * @brief Maximum function argument count **expected**
   * for the program being instrumented.
   */
  static const int MaxArgNum = 32;

  /**
   * @brief Number of general purpose eBPF registers (R0 - R9).
   */
  static const int BPF_REAL_REG_COUNT = 10;

  /**
   * @brief Index of stack pointer eBPF register (R10).
   */
  static const int BPF_STACK_PTR_REG = 10;

  /**
   * @brief State of current branch of instrumenter program.
   */
  struct BpfState {
    /// General purpose eBPF registers (`nullptr` is "to be initialized with 0").
    std::vector<Value*> registers;
    /// Last set tag for **current** instrumenter branch.
    Value *returnedTag;

    BpfState(): registers(BPF_REAL_REG_COUNT, nullptr), returnedTag(nullptr) {}
  };

  /**
   * @brief The original instruction being instrumented now.
   */
  struct LlvmState {
    /**
     * @brief Instruction to set tag on
     */
    Instruction *taggedInsn;
    /**
     * @brief Instruction for callbacks to fetch info from.
     */
    Instruction *prototypeInsn;

    /**
     * @brief Operands of instrumenter program.
     *
     * Should not be fetched from the prototypeInsn directly, since
     * can be swapped in accordance with bpf.h, etc.
     */
    Value *opnds[2];

    uint64_t currentPseudoPc;
  };

  struct LLInst : ModulePass {
    /// Just for LLVM to be able to get its address...
    static char ID;

    LLInst();
    bool runOnModule(Module &M) override;
  private:

    /// Prototype of function registered for emitting named callback.
    typedef void (LLInst::*EmitCallbackFun)(BasicBlock *BB, unsigned currentProgIndex, uint64_t data);
    /// Registered named callbacks to be invoked from eBPF instrumenter code.
    static const std::vector<std::pair<std::string, std::pair<LLInst::EmitCallbackFun, uint64_t>>> callbacks;
    /// Utility function to create name-to-index callback mapping for BpfLoader.
    static std::map<std::string, uint64_t> callbackNames();

    /// Just an utility function for parseInstrumenters().
    static const BpfProg *instrumenterFor(const BpfLoader &loader, const std::string name);
    /// Fetch instrumenter functions by name from an eBPF object.
    static std::vector<const BpfProg *> parseInstrumenters(const BpfLoader &loader);

    /// \defgroup pass-const Variables that should not change during the whole pass.
    /// @{
    /// Requested ThreadLocal mode for auxiliary variables visible from the outside.
    const GlobalValue::ThreadLocalMode tlMode;
    /// eBPF ELF object file parser.
    const BpfLoader loader;
    /// Instrumenters fetched from eBPF object, indexed by LLVM IR opcode.
    const std::vector<const BpfProg *> instrumenters;
    std::map<Elf64_Sym*, Constant*> importBySymbol;
    Function *slowCallCallback;
    std::map<Twine, Function*> substitutes;
    /// @}

    /// \defgroup module-const Variables that should not change during processing of the particular module.
    /// @{
    Module *M;
    Type *Void;
    IntegerType *U8, *U16, *U32, *U64;
    PointerType *pU8, *pU16, *pU32, *pU64;
    /**
     * @brief Storage for stack accessible via R10 register.
     */
    GlobalVariable *bpfStack;
    /**
     * @brief Global storage for tags corresponding to arguments passed to function currently being called.
     */
    GlobalVariable *passedTags;
    /**
     * @brief Global storage for tag corresponding to the value being currently returned from function.
     */
    GlobalVariable *returnedTag;
    std::map<Elf64_Shdr *, GlobalVariable*> sections;
    /// @}

    /// \defgroup function-local Variables that should be reset for any new function to be processed.
    /// @{
    /// Tags associated with values from function currently being instrumented.
    std::unordered_map<Value*, Value*> tagByValue;
    /// Value to be returned for the R10 register
    Value *stackPointer;
    /// @}

    /// \defgroup orig-instruction-local Variables that should be reset for any of the **original** LLVM IR instruction.
    /// @{
    /// Current eBPF instrumenter program.
    const BpfProg *instrumenter;
    /// Current "host" LLVM instruction information.
    LlvmState nowInstrumented;
    /// State of the current **branch** of eBPF instrumenter program.
    BpfState bpfState;
    /// PHINode for collecting tags set by the current instrumenter program.
    PHINode *tagToSet;
    /// Set to true if at least one instrumenter branch invokes set_tag().
    bool maySetTag;
    /// BasicBlock to jump from the eBPF instrumenter program on exit.
    BasicBlock *exitPoint;
    /// @}

    Value *tagFor(Value *value)
    {
      if (tagByValue.count(value)) {
        return tagByValue[value];
      } else {
        return ConstantInt::get(U64, 0);
      }
    }

    void setTag(Value *tag)
    {
      if (tag != nullptr) {
        tagByValue[nowInstrumented.taggedInsn] = tag;
      } else {
        tagByValue.erase(nowInstrumented.taggedInsn);
      }
    }

    void setOperand(unsigned index, Value *opnd, Instruction *insertionPoint);

    Value *getReg(unsigned ind)
    {
      if (ind == BPF_STACK_PTR_REG) {
        return stackPointer;
      }
      assert(ind < BPF_REAL_REG_COUNT);
      if (bpfState.registers[ind] == nullptr) {
        bpfState.registers[ind] = ConstantInt::get(U64, 0);
      }
      return bpfState.registers[ind];
    }

    void setReg(unsigned ind, Value * v)
    {
      assert(ind < BPF_REAL_REG_COUNT);
      bpfState.registers[ind] = v;
    }


    void emitExit(BasicBlock *BB);

    /// \defgroup callbacks Emit code for eBPF callback functions.
    /// @{
    /// Invokes event_dispatch_slow_call() native function.
    void emitSlowCallCallback(BasicBlock *BB, unsigned, uint64_t);
    /// Emits condition() callback for the current ICmpInst.
    void emitGetCondCallback(BasicBlock *, unsigned, uint64_t);
    /// Emits condition_result() callback (effectively copies current ICmpInst).
    void emitGetCondResCallback(BasicBlock *BB, unsigned currentProgIndex, uint64_t);
    /// Returns (to eBPF code) some identifier of currently instrumented "host" instruction.
    void emitGetPcCallback(BasicBlock *, unsigned currentProgIndex, uint64_t);
    /**
     * @brief Returns (to eBPF code) tag for the specific eBPF instrumenter operand.
     *
     * Index is statically known at compile time and starts from 1.
     */
    void emitGetTagCallback(BasicBlock *, unsigned, uint64_t tag_ind);
    /**
     * @brief Returns (to eBPF code) bit width of the specific eBPF instrumenter operand.
     *
     * Index is statically known at compile time (0 means current instruction itself).
     */
    void emitGetBitWidthCallback(BasicBlock *, unsigned, uint64_t index);
    /// Emit stop_if_no_tags() callback.
    void emitStopIfNoTagsCallback(BasicBlock *BB, unsigned, uint64_t);
    /// Emits set_tag() callback.
    void emitSetTag(BasicBlock *, unsigned, uint64_t);
    /// @}

    /// Emit ALU eBPF opcode.
    void emitAlu(BasicBlock *BB, unsigned currentInstInsnIdx);
    /// Emit load/store eBPF opcode.
    void emitLdSt(BasicBlock *BB, unsigned currentInstInsnIdx);
    /// Emit branch/exit/call eBPF opcode.
    void emitBr(BasicBlock *BB, unsigned currentInstInsnIdx);

    /// Utility function for createImports().
    GlobalVariable *createIntegerArray(IntegerType *elementTy, unsigned count, GlobalValue::LinkageTypes linkage, const Twine &name);
    void createImports();
    /// Utility function for createSubstitutes().
    void createSubstitution(StringRef fromName, Twine toName, FunctionType *fty);
    void createSubstitutes();

    void instrumentFunctionEntry(Function *F, Instruction *insertionPoint);
    void performInstrumentation(Instruction *proto, Instruction *taggedInsn, Instruction *insertionPoint);
    void instrumentPHI(PHINode *I);
    void instrumentCall(CallInst *I);
    void instrumentRet(ReturnInst *I);
    void instrumentSelect(SelectInst *I);
    void instrumentSwitch(SwitchInst *I);
    void instrumentOneInstruction(BasicBlock *BB, unsigned currentInstInsnIdx);
  };
}

char LLInst::ID = 0;

const std::vector<std::pair<std::string, std::pair<LLInst::EmitCallbackFun, uint64_t>>> LLInst::callbacks = {
  std::make_pair("slow_call",        std::make_pair(&LLInst::emitSlowCallCallback, 0)),
  std::make_pair("pseudo_pc",        std::make_pair(&LLInst::emitGetPcCallback, 0)),
  std::make_pair("condition",        std::make_pair(&LLInst::emitGetCondCallback, 0)),
  std::make_pair("condition_result", std::make_pair(&LLInst::emitGetCondResCallback, 0)),
  std::make_pair("stop_if_no_tags",  std::make_pair(&LLInst::emitStopIfNoTagsCallback, 0)),
  std::make_pair("set_tag",          std::make_pair(&LLInst::emitSetTag, 0)),
  std::make_pair("bit_width_res",    std::make_pair(&LLInst::emitGetBitWidthCallback, 0)),
  std::make_pair("bit_width1",       std::make_pair(&LLInst::emitGetBitWidthCallback, 1)),
  std::make_pair("bit_width2",       std::make_pair(&LLInst::emitGetBitWidthCallback, 2)),
  std::make_pair("tag1",             std::make_pair(&LLInst::emitGetTagCallback, 1)),
  std::make_pair("tag2",             std::make_pair(&LLInst::emitGetTagCallback, 2)),
};

const BpfProg *LLInst::instrumenterFor(const BpfLoader &loader, const std::string name)
{
  if (loader.exportedFunctions().count(name)) {
    return &loader.exportedFunctions().at(name);
  }
  return nullptr;
}

std::vector<const BpfProg *> LLInst::parseInstrumenters(const BpfLoader &loader)
{
  std::vector<const BpfProg *> result(67 /* LLVM IR opcode count */);
  result[Instruction::Br]         = instrumenterFor(loader, "inst_br");
  result[Instruction::IndirectBr] = instrumenterFor(loader, "inst_indirectbr");
  result[Instruction::Add]   = instrumenterFor(loader, "inst_add");
  result[Instruction::Sub]   = instrumenterFor(loader, "inst_sub");
  result[Instruction::Mul]   = instrumenterFor(loader, "inst_mul");
  result[Instruction::UDiv]  = instrumenterFor(loader, "inst_udiv");
  result[Instruction::SDiv]  = instrumenterFor(loader, "inst_sdiv");
  result[Instruction::URem]  = instrumenterFor(loader, "inst_urem");
  result[Instruction::SRem]  = instrumenterFor(loader, "inst_srem_1starg");
  result[Instruction::Shl]   = instrumenterFor(loader, "inst_shl");
  result[Instruction::AShr]  = instrumenterFor(loader, "inst_ashr");
  result[Instruction::LShr]  = instrumenterFor(loader, "inst_lshr");
  result[Instruction::And]   = instrumenterFor(loader, "inst_and");
  result[Instruction::Or]    = instrumenterFor(loader, "inst_or");
  result[Instruction::Xor]   = instrumenterFor(loader, "inst_xor");
  result[Instruction::Load]  = instrumenterFor(loader, "inst_load");
  result[Instruction::Store] = instrumenterFor(loader, "inst_store");
  result[Instruction::Trunc] = instrumenterFor(loader, "inst_trunc");
  result[Instruction::ZExt]  = instrumenterFor(loader, "inst_zext");
  result[Instruction::SExt]  = instrumenterFor(loader, "inst_sext");
  result[Instruction::ICmp]  = instrumenterFor(loader, "inst_cmp");
  return result;
}

std::map<std::string, uint64_t> LLInst::callbackNames()
{
  std::map<std::string, uint64_t> result;
  for (unsigned i = 0; i < callbacks.size(); ++i) {
    result[callbacks[i].first] = i;
  }
  return result;
}

LLInst::LLInst() :
  ModulePass(ID),
  tlMode(getenv("NOTLS") ? GlobalValue::ThreadLocalMode::NotThreadLocal : GlobalValue::ThreadLocalMode::GeneralDynamicTLSModel),
  loader(callbackNames(), std::string(getenv("BPF_INST"))),
  instrumenters(parseInstrumenters(loader))
{
}

void LLInst::setOperand(unsigned index, Value *opnd, Instruction *insertionPoint)
{
  IRBuilder<> irb(insertionPoint);
  nowInstrumented.opnds[index] = opnd; // should be original insn!

  if (isa<PointerType>(opnd->getType()))
    opnd = irb.CreatePtrToInt(opnd, U64);
  else if (!isa<IntegerType>(opnd->getType()))
    opnd = ConstantInt::get(U64, 0);

  unsigned width = cast<IntegerType>(opnd->getType())->getBitWidth();
  if (width < 64) {
    setReg(1 + index, irb.CreateZExt(opnd, U64));
  } else if (width > 64) {
    setReg(1 + index, irb.CreateTrunc(opnd, U64));
  } else {
    setReg(1 + index, opnd);
  }
}

void LLInst::performInstrumentation(Instruction *proto, Instruction *taggedInsn, Instruction *insertionPoint)
{
  instrumenter = instrumenters[proto->getOpcode()];
  if (instrumenter) {
    bpfState = BpfState();

    nowInstrumented.taggedInsn = taggedInsn;
    nowInstrumented.prototypeInsn = proto;
    memset(&nowInstrumented.opnds, 0, sizeof(nowInstrumented.opnds));

    // populate operands
    if (isa<StoreInst>(proto)) {
      setOperand(0, cast<StoreInst>(proto)->getPointerOperand(), insertionPoint);
      setOperand(1, cast<StoreInst>(proto)->getValueOperand(), insertionPoint);
    } else if (isa<BranchInst>(proto)) {
      BranchInst *br = cast<BranchInst>(proto);
      if (br->isConditional())
        setOperand(0, br->getCondition(), insertionPoint);
      else
        setOperand(0, ConstantInt::get(U64, 1), insertionPoint);
    } else if (isa<IndirectBrInst>(proto)) {
      // no operands
    } else {
      for (unsigned ind = 0; ind < proto->getNumOperands() && ind <= 2; ++ind) {
        setOperand(ind, proto->getOperand(ind), insertionPoint);
      }
    }

    exitPoint = insertionPoint->getParent()->splitBasicBlock(insertionPoint);
    BranchInst *entryPoint = cast<BranchInst>(exitPoint->getPrevNode()->getTerminator());
    tagToSet = PHINode::Create(U64, 0, "", exitPoint->getFirstNonPHI());

    // do not pass nullptr incoming Value* to PHINode, handle all-NULL manually
    bpfState.returnedTag = ConstantInt::get(U64, 0);
    maySetTag = false;

    BasicBlock *instrumenterContainer = BasicBlock::Create(M->getContext(), "", insertionPoint->getFunction(), exitPoint);
    entryPoint->setSuccessor(0, instrumenterContainer);

    // perform actual instrumentation
    instrumentOneInstruction(instrumenterContainer, 0);

    // set tag
    setTag(maySetTag ? tagToSet : nullptr);
  }
}

void LLInst::instrumentPHI(PHINode *phi)
{
  if (phi) {
    PHINode *phiTag = PHINode::Create(U64, phi->getNumIncomingValues(), "", phi);
    for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
      phiTag->addIncoming(tagFor(phi->getIncomingBlock(i)), phi->getIncomingBlock(i));
    }
    tagByValue[phi] = phiTag;
  }
}

void LLInst::instrumentFunctionEntry(Function *F, Instruction *insertionPoint)
{
  // load passed argument tags
  IRBuilder<> irb(insertionPoint);
  unsigned argIndex = 0;
  for (auto arg = F->arg_begin(); arg != F->arg_end(); ++arg, ++argIndex) {
    assert(argIndex < MaxArgNum);
    if (isa<IntegerType>(arg->getType()) || isa<PointerType>(arg->getType())) {
      std::vector<Value *> indices;
      indices.push_back(ConstantInt::get(U32, 0));
      indices.push_back(ConstantInt::get(U32, argIndex));
      Value *TagCell = irb.CreateGEP(passedTags, indices);
      tagByValue[&*arg] = irb.CreateLoad(TagCell, U64);
    }
  }
}

void LLInst::instrumentCall(CallInst *I)
{
  if (I) {
    IRBuilder<> beforeInserter(I);
    // unset returned tag
    beforeInserter.CreateStore(ConstantInt::get(U64, 0), returnedTag);

    // before call: propagate arguments' tags
    for (unsigned i = 0; i < I->getNumArgOperands(); ++i) {
      std::vector<Value *> indices;
      indices.push_back(ConstantInt::get(U32, 0));
      indices.push_back(ConstantInt::get(U32, i));
      Value *TagCell = beforeInserter.CreateGEP(passedTags, indices);
      Value *Tag = tagFor(I->getArgOperand(i));
      beforeInserter.CreateStore(Tag, TagCell);
    }

    // after call: get returned tag
    if (I->isMustTailCall()) {
      // do nothing, first non-tail call will pick up this tag
    } else {
      tagByValue[I] = new LoadInst(returnedTag, "", I->getNextNode());
    }
  }
}

void LLInst::instrumentRet(ReturnInst *I)
{
  if (I) {
    new StoreInst(tagFor(I->getReturnValue()), returnedTag, I);
  }
}

void LLInst::instrumentSelect(SelectInst *I)
{
  if (I) {
    // if cond:
    //   res = opt1 # no instrumentation required
    // else:
    //   res = opt2 # no instrumentation required

    BasicBlock *dummy1 = BasicBlock::Create(M->getContext());
    BasicBlock *dummy2 = BasicBlock::Create(M->getContext());
    Instruction *proto = BranchInst::Create(dummy1, dummy2, I->getCondition());
    performInstrumentation(proto, I, I);
    proto->deleteValue();
    dummy1->deleteValue();
    dummy2->deleteValue();
  }
}

void LLInst::instrumentSwitch(SwitchInst *I)
{
  if (I) {
    // if selector == value1:
    //   br label1
    // if selector == value2:
    //   br label2
    // ...
    // br label_default

    for (auto c: I->cases()) {
      ICmpInst *condProto = new ICmpInst(ICmpInst::Predicate::ICMP_EQ, I->getCondition(), c.getCaseValue());
      BasicBlock *dummy1 = BasicBlock::Create(M->getContext());
      BasicBlock *dummy2 = BasicBlock::Create(M->getContext());
      Instruction *brProto = BranchInst::Create(dummy1, dummy2, condProto);
      performInstrumentation(condProto, condProto, I);
      performInstrumentation(brProto, brProto, I);
      brProto->deleteValue();
      dummy1->deleteValue();
      dummy2->deleteValue();
      condProto->deleteValue();
    }

    BasicBlock *dummy1 = BasicBlock::Create(M->getContext());
    BasicBlock *dummy2 = BasicBlock::Create(M->getContext());
    Instruction *brProto = BranchInst::Create(dummy1, dummy2, ConstantInt::getTrue(M->getContext()));
    performInstrumentation(brProto, brProto, I);
    brProto->deleteValue();
    dummy1->deleteValue();
    dummy2->deleteValue();
  }
}

bool LLInst::runOnModule(Module &_M) {
  M = &_M;
  Void = Type::getVoidTy(M->getContext());
  U8  = IntegerType::getInt8Ty(M->getContext());
  U16 = IntegerType::getInt16Ty(M->getContext());
  U32 = IntegerType::getInt32Ty(M->getContext());
  U64 = IntegerType::getInt64Ty(M->getContext());
  pU8  = PointerType::get(U8,  0);
  pU16 = PointerType::get(U16, 0);
  pU32 = PointerType::get(U32, 0);
  pU64 = PointerType::get(U64, 0);

  createImports();
  createSubstitutes();

  for (auto &F: *M) {
    tagByValue.clear();

    if (F.getName().equals("res_fill_buffer") || F.getName().equals("res_rand"))
      continue;

    std::vector<Instruction*> insnsCopy;
    for (inst_iterator I = inst_begin(F); I != inst_end(F); ++I)
      insnsCopy.push_back(&*I);

    if (insnsCopy.empty()) {
      continue;
    }

    IRBuilder<> irb(*insnsCopy.begin());
    stackPointer = irb.CreateAdd(irb.CreatePtrToInt(bpfStack, U64), ConstantInt::get(U64, NumStackBytes));

    instrumentFunctionEntry(&F, *insnsCopy.begin());
    for (Instruction *I: insnsCopy) {
      instrumentPHI(dyn_cast<PHINode>(I));
      instrumentCall(dyn_cast<CallInst>(I));
      instrumentRet(dyn_cast<ReturnInst>(I));
      instrumentSelect(dyn_cast<SelectInst>(I));

      performInstrumentation(I, I, I); // try generic case
    }
  }

  if (getenv("VERIFY")) {
    if (verifyModule(*M, &errs())) {
      fprintf(stderr, "Verification failed\n");
      abort();
    }
  }

  return true;
}

void LLInst::emitExit(BasicBlock *BB) {
  IRBuilder<> irb(BB);
  tagToSet->addIncoming(bpfState.returnedTag, BB);
  irb.CreateBr(exitPoint);
}

GlobalVariable *LLInst::createIntegerArray(IntegerType *elementTy, unsigned size, GlobalValue::LinkageTypes linkage, const Twine &name)
{
  ArrayType *arrayTy = ArrayType::get(elementTy, size);
  std::vector<Constant *> initializerData(size);
  std::fill(initializerData.begin(), initializerData.end(), ConstantInt::get(elementTy, 0));
  Constant *arrayInitializer = ConstantArray::get(arrayTy, ArrayRef<Constant*>(initializerData.data(), size));
  return new GlobalVariable(*M, arrayTy, false, linkage, arrayInitializer, name, nullptr, tlMode);
}

void LLInst::createImports() {
  importBySymbol.clear();
  sections.clear();

  // Create own symbols

  bpfStack = createIntegerArray(U8, NumStackBytes, GlobalValue::LinkageTypes::CommonLinkage, "__llinst_bpf_stack");
  passedTags = createIntegerArray(U64, MaxArgNum, GlobalValue::LinkageTypes::CommonLinkage, "__llinst_passed_tags");

  returnedTag = new GlobalVariable(*M, U64, false, GlobalValue::LinkageTypes::CommonLinkage,
                                   ConstantInt::get(U64, 0), "__llinst_returned_tag", nullptr, tlMode);

  FunctionType *slowCallTy = FunctionType::get(U64, ArrayRef<Type*>(U64), false);
  slowCallCallback = Function::Create(slowCallTy, GlobalValue::LinkageTypes::ExternalLinkage, "event_dispatch_slow_call", M);

  // Create sections (with proper initialization)

  for (auto section: loader.getSections()) {
    if (section.isBss() || section.isData()) {
      ArrayType *arrayTy = ArrayType::get(U8, section.length);
      std::vector<Constant*> initializerData;
      for (unsigned i = 0; i < section.length; ++i) {
        initializerData.push_back(ConstantInt::get(U8, section.start[i]));
      }
      Constant *initializer = ConstantArray::get(arrayTy, ArrayRef<Constant*>(initializerData.data(), initializerData.size()));
      GlobalVariable *sectionGlobal = new GlobalVariable(*M, arrayTy, false, GlobalValue::LinkageTypes::InternalLinkage,
                                                initializer, section.name + "_data");
      sections[section.hdr] = sectionGlobal;
    }
  }

  // Create imported symbols

  for (const std::pair<Elf64_Sym *, std::string> sym: loader.referencedSymbols()) {
    const std::string &symbolName = sym.second;
    if (ELF64_ST_TYPE(sym.first->st_info) == STT_FUNC) {
      // cannot call nor eBPF, nor native functions directly
      abort();
    }
    if (ELF64_ST_TYPE(sym.first->st_info) == STT_COMMON) {
      Type *ty = IntegerType::get(M->getContext(), sym.first->st_size * 8);
      importBySymbol[sym.first] = new GlobalVariable(*M, ty, false, GlobalValue::LinkageTypes::CommonLinkage,
                                                     ConstantInt::get(ty, 0), symbolName);
    }
    if (ELF64_ST_BIND(sym.first->st_info) == STB_GLOBAL) {
      Type *arrayTy = ArrayType::get(U64, 128); // TODO
      importBySymbol[sym.first] = new GlobalVariable(*M, arrayTy, false, GlobalValue::LinkageTypes::ExternalLinkage,
                                                     nullptr, symbolName, nullptr, GlobalVariable::ThreadLocalMode::NotThreadLocal, 0, true);
    }
  }
}

void LLInst::createSubstitution(StringRef fromName, Twine toName, FunctionType *funcTy)
{
  Value *oldFunc = M->getValueSymbolTable().lookup(fromName);
  if (oldFunc) {
    Function *newFunc = Function::Create(funcTy, GlobalVariable::LinkageTypes::ExternalLinkage, toName, M);
    oldFunc->replaceAllUsesWith(newFunc);
  }
}

void LLInst::createSubstitutes()
{
  if (!getenv("USE_SUBST"))
    return;
  Type *strncmp_args[] = {pU8, pU8, U64, IntegerType::getInt1Ty(M->getContext())};

  createSubstitution("llvm.memcpy.p0i8.p0i8.i64", "my_memcpy",
                     FunctionType::get(Void, ArrayRef<Type*>(strncmp_args, 4), false));
  createSubstitution("llvm.memmove.p0i8.p0i8.i64", "my_memmove",
                     FunctionType::get(Void, ArrayRef<Type*>(strncmp_args, 4), false));
//  createSubstitution("memcpy", "my_memcpy_nb",
//                     FunctionType::get(U32, ArrayRef<Type*>(strncmp_args, 3), false));
//  createSubstitution("memmove", "my_memmove_nb",
//                     FunctionType::get(U32, ArrayRef<Type*>(strncmp_args, 3), false));
  createSubstitution("strcmp", "my_strcmp",
                     FunctionType::get(U32, ArrayRef<Type*>(strncmp_args, 2), false));
  createSubstitution("strncmp", "my_strncmp",
                     FunctionType::get(U32, ArrayRef<Type*>(strncmp_args, 3), false));
}

void LLInst::emitAlu(BasicBlock *BB, unsigned currentInstInsnIdx)
{
  const EBpfInstruction &currentInsn = (*instrumenter)[currentInstInsnIdx];
  IRBuilder<> irb(BB);

  int opc = currentInsn.opcode;
  bool is32bit = (opc & 0x03) == 0;
  Value *src = getReg(currentInsn.src);
  Value *dst = getReg(currentInsn.dst);
  Value *imm = nullptr, *res = nullptr;
  if (is32bit) {
    src = irb.CreateTrunc(src, U32);
    dst = irb.CreateTrunc(dst, U32);
    imm = ConstantInt::get(U32, int64_t(currentInsn.imm));
    opc += 3;
  } else {
    imm = ConstantInt::get(U64, int64_t(currentInsn.imm));
  }
  switch (opc) {
  case 0x07: res = irb.CreateAdd(dst, imm); break;
  case 0x0f: res = irb.CreateAdd(dst, src); break;
  case 0x17: res = irb.CreateSub(dst, imm); break;
  case 0x1f: res = irb.CreateSub(dst, src); break;
  case 0x27: res = irb.CreateMul(dst, imm); break;
  case 0x2f: res = irb.CreateMul(dst, src); break;
  case 0x37: res = irb.CreateUDiv(dst, imm); break;
  case 0x3f: res = irb.CreateUDiv(dst, src); break;
  case 0x47: res = irb.CreateOr(dst, imm); break;
  case 0x4f: res = irb.CreateOr(dst, src); break;
  case 0x57: res = irb.CreateAnd(dst, imm); break;
  case 0x5f: res = irb.CreateAnd(dst, src); break;
  case 0x67: res = irb.CreateShl(dst, imm); break;
  case 0x6f: res = irb.CreateShl(dst, src); break;
  case 0x77: res = irb.CreateLShr(dst, imm); break;
  case 0x7f: res = irb.CreateLShr(dst, src); break;
  case 0x87: res = irb.CreateNeg(dst); break;
  case 0x8f: abort();
  case 0x97: res = irb.CreateURem(dst, imm); break;
  case 0x9f: res = irb.CreateURem(dst, src); break;
  case 0xa7: res = irb.CreateXor(dst, imm); break;
  case 0xaf: res = irb.CreateXor(dst, src); break;
  case 0xb7: res = imm; break;
  case 0xbf: res = src; break;
  case 0xc7: res = irb.CreateAShr(dst, imm); break;
  case 0xcf: res = irb.CreateAShr(dst, src); break;
  default: abort();
  }
  if (is32bit) {
    res = irb.CreateZExt(res, U64);
  }
  setReg(currentInsn.dst, res);
  instrumentOneInstruction(BB, currentInstInsnIdx + 1);
}

void LLInst::emitSlowCallCallback(BasicBlock *BB, unsigned, uint64_t)
{
  IRBuilder<> irb(BB);
  setReg(0, irb.CreateCall(slowCallCallback, ArrayRef<Value*>(getReg(1))));
}

void LLInst::emitGetCondCallback(BasicBlock *, unsigned, uint64_t)
{
  unsigned result;
  ICmpInst::Predicate predicate = cast<ICmpInst>(nowInstrumented.prototypeInsn)->getPredicate();
  switch(predicate) {
  case ICmpInst::ICMP_EQ:
    result = COND_EQ;
    break;
  case ICmpInst::ICMP_SLT:
  case ICmpInst::ICMP_ULT:
    result = COND_EQ;
    break;
  case ICmpInst::ICMP_SLE:
  case ICmpInst::ICMP_ULE:
    result = COND_EQ;
    break;
  case ICmpInst::ICMP_SGT:
  case ICmpInst::ICMP_UGT:
    result = COND_EQ;
    break;
  case ICmpInst::ICMP_SGE:
  case ICmpInst::ICMP_UGE:
    result = COND_EQ;
    break;
  case ICmpInst::ICMP_NE:
    result = COND_EQ;
    break;
  default:
    std::cerr << "Unknown comparison predicate: " << predicate << "\n";
    abort();
  }
  setReg(0, ConstantInt::get(U64, result));
}

void LLInst::emitGetCondResCallback(BasicBlock *BB, unsigned currentProgIndex, uint64_t)
{
  IRBuilder<> irb(BB);
  Instruction *copy = nowInstrumented.prototypeInsn->clone();
  irb.Insert(copy);
  setReg(0, irb.CreateZExt(copy, U64));
}

void LLInst::emitGetPcCallback(BasicBlock *, unsigned, uint64_t)
{
  setReg(0, ConstantInt::get(U64, nowInstrumented.currentPseudoPc));
}

void LLInst::emitGetTagCallback(BasicBlock *, unsigned, uint64_t tag_ind)
{
  Value *taggedOpnd = nowInstrumented.opnds[tag_ind - 1];
  setReg(0, tagFor(taggedOpnd));
}

void LLInst::emitGetBitWidthCallback(BasicBlock *, unsigned, uint64_t index)
{
  Value *value;
  if (index == 0) {
    value = nowInstrumented.prototypeInsn;
  } else {
    value = nowInstrumented.opnds[index - 1];
  }

  IntegerType *ity = nullptr;
  if (isa<IntegerType>(value->getType()))
    ity = cast<IntegerType>(value->getType());
  else if (isa<PointerType>(value->getType()))
    ity = U64;

  unsigned bits = 0;

  if (ity) {
    bits = ity->getBitWidth();
  } else {
    std::cerr << ity << "\n";
    std::cerr << "Warning: strange type of " << (isa<Instruction>(value) ? cast<Instruction>(value)->getOpcodeName() : "---") << ".\n";
  }

  setReg(0, ConstantInt::get(U64, bits));
}

void LLInst::emitStopIfNoTagsCallback(BasicBlock *BB, unsigned, uint64_t)
{
  // nothing for now
}

void LLInst::emitSetTag(BasicBlock *, unsigned, uint64_t)
{
  bpfState.returnedTag = bpfState.registers[1];
  maySetTag = true;
}

void LLInst::emitBr(BasicBlock *BB, unsigned currentInstInsnIdx)
{
  IRBuilder<> irb(BB);
  const EBpfInstruction &currentInsn = (*instrumenter)[currentInstInsnIdx];
  if (currentInsn.opcode == 0x85) { // call
    unsigned callbackIndex = currentInsn.imm;
    EmitCallbackFun cb = callbacks[callbackIndex].second.first;
    uint64_t cbArg     = callbacks[callbackIndex].second.second;
    (this->*cb)(BB, currentInstInsnIdx, cbArg);
    instrumentOneInstruction(BB, currentInstInsnIdx + 1);
    return;
  }
  if (currentInsn.opcode == 0x95) { // exit
    emitExit(BB);
    return;
  }

  Value *src = getReg(currentInsn.src);
  Value *dst = getReg(currentInsn.dst);
  Value *imm = ConstantInt::get(U64, (int64_t)currentInsn.imm);
  Value *condition = nullptr;

  switch(currentInsn.opcode) {
  case 0x05: condition = ConstantInt::getTrue(M->getContext()); break;
  case 0x15: condition = irb.CreateICmpEQ(dst, imm); break;
  case 0x1d: condition = irb.CreateICmpEQ(dst, src); break;
  case 0x25: condition = irb.CreateICmpUGT(dst, imm); break;
  case 0x2d: condition = irb.CreateICmpUGT(dst, src); break;
  case 0x35: condition = irb.CreateICmpUGE(dst, imm); break;
  case 0x3d: condition = irb.CreateICmpUGE(dst, src); break;
  case 0xa5: condition = irb.CreateICmpULT(dst, imm); break;
  case 0xad: condition = irb.CreateICmpULT(dst, src); break;
  case 0xb5: condition = irb.CreateICmpULE(dst, imm); break;
  case 0xbd: condition = irb.CreateICmpULE(dst, src); break;
  case 0x45: condition = irb.CreateAnd(dst, imm); break;
  case 0x4d: condition = irb.CreateAnd(dst, src); break;
  case 0x55: condition = irb.CreateICmpNE(dst, imm); break;
  case 0x5d: condition = irb.CreateICmpNE(dst, src); break;
  case 0x65: condition = irb.CreateICmpSGT(dst, imm); break;
  case 0x6d: condition = irb.CreateICmpSGT(dst, src); break;
  case 0x75: condition = irb.CreateICmpSGE(dst, imm); break;
  case 0x7d: condition = irb.CreateICmpSGE(dst, src); break;
  case 0xc5: condition = irb.CreateICmpSLT(dst, imm); break;
  case 0xcd: condition = irb.CreateICmpSLT(dst, src); break;
  case 0xd5: condition = irb.CreateICmpSLE(dst, imm); break;
  case 0xdd: condition = irb.CreateICmpSLE(dst, src); break;
  default: abort();
  }
  assert(currentInsn.offset > 0);
  BasicBlock *ifTrue = BasicBlock::Create(BB->getContext(), "", BB->getParent(), exitPoint);
  BasicBlock *ifFalse = BasicBlock::Create(BB->getContext(), "", BB->getParent(), exitPoint);
  irb.CreateCondBr(condition, ifTrue, ifFalse);

  BpfState oldState = bpfState;
  instrumentOneInstruction(ifFalse, currentInstInsnIdx + 1);
  bpfState = oldState;
  instrumentOneInstruction(ifTrue, currentInstInsnIdx + currentInsn.offset + 1);
}

void LLInst::emitLdSt(BasicBlock *BB, unsigned currentInstInsnIdx)
{
  const EBpfInstruction &currentInsn = (*instrumenter)[currentInstInsnIdx];
  IRBuilder<> irb(BB);

  Value *imm32 = ConstantInt::get(U64, (int64_t)currentInsn.imm);
  Value *off = ConstantInt::get(U64, (int64_t)currentInsn.offset);

  Value *src = getReg(currentInsn.src);
  Value *dst = getReg(currentInsn.dst);
  Value *srcAddr, *dstAddr;
  if (currentInsn.offset) {
    srcAddr = irb.CreateAdd(src, off);
    dstAddr = irb.CreateAdd(dst, off);
  } else {
    srcAddr = src;
    dstAddr = dst;
  }

  switch (currentInsn.opcode) {
  case 0x61: setReg(currentInsn.dst, irb.CreateZExt(irb.CreateLoad(U32, irb.CreateIntToPtr(srcAddr, pU32)), U64)); break;
  case 0x69: setReg(currentInsn.dst, irb.CreateZExt(irb.CreateLoad(U16, irb.CreateIntToPtr(srcAddr, pU16)), U64)); break;
  case 0x71: setReg(currentInsn.dst, irb.CreateZExt(irb.CreateLoad(U8 , irb.CreateIntToPtr(srcAddr, pU8 )), U64)); break;
  case 0x79: setReg(currentInsn.dst, irb.CreateLoad(U64, irb.CreateIntToPtr(srcAddr, pU64))); break;

  case 0x62: irb.CreateStore(irb.CreateTrunc(imm32, U32), irb.CreateIntToPtr(dstAddr, pU32)); break;
  case 0x6a: irb.CreateStore(irb.CreateTrunc(imm32, U16), irb.CreateIntToPtr(dstAddr, pU16)); break;
  case 0x72: irb.CreateStore(irb.CreateTrunc(imm32, U8 ), irb.CreateIntToPtr(dstAddr, pU8 )); break;
  case 0x7a: irb.CreateStore(                imm32      , irb.CreateIntToPtr(dstAddr, pU64)); break;

  case 0x63: irb.CreateStore(irb.CreateTrunc(src, U32), irb.CreateIntToPtr(dstAddr, pU32)); break;
  case 0x6b: irb.CreateStore(irb.CreateTrunc(src, U16), irb.CreateIntToPtr(dstAddr, pU16)); break;
  case 0x73: irb.CreateStore(irb.CreateTrunc(src, U8 ), irb.CreateIntToPtr(dstAddr, pU8 )); break;
  case 0x7b: irb.CreateStore(                src      , irb.CreateIntToPtr(dstAddr, pU64)); break;
  default: abort();
  }
  instrumentOneInstruction(BB, currentInstInsnIdx + 1);
}

void LLInst::instrumentOneInstruction(BasicBlock *BB, unsigned currentInstInsnIdx)
{
  if (currentInstInsnIdx < instrumenter->size()) {
    const EBpfInstruction &currentInsn = (*instrumenter)[currentInstInsnIdx];
    nowInstrumented.currentPseudoPc = uintptr_t(BB) ^ uintptr_t(currentInstInsnIdx);
    switch (currentInsn.opcode & 0x07) {
    case 0x0:
      if (currentInsn.rel) {
        IRBuilder<> irb(BB);
        if (importBySymbol.count(currentInsn.rel)) {
          setReg(currentInsn.dst, irb.CreateAdd(
                   irb.CreatePtrToInt(importBySymbol[currentInsn.rel], U64),
                   ConstantInt::get(U64, currentInsn.imm + currentInsn.rel->st_value)
                 ));
        } else {
          Value * addr = irb.CreateAdd(irb.CreatePtrToInt(sections[loader.getSections()[currentInsn.rel->st_shndx].hdr], U64),
                                       ConstantInt::get(U64, currentInsn.imm + currentInsn.rel->st_value));
          setReg(currentInsn.dst, addr);
        }
      } else {
        uint64_t imm_lo = uint32_t(currentInsn.imm);
        uint64_t imm_hi = uint32_t((*instrumenter)[currentInstInsnIdx + 1].imm);
        setReg(currentInsn.dst, ConstantInt::get(U64, imm_lo | (imm_hi<< 32)));
      }
      instrumentOneInstruction(BB, currentInstInsnIdx + 2);
      break;
    case 0x1:
    case 0x2:
    case 0x3:
      emitLdSt(BB, currentInstInsnIdx);
      break;
    case 0x4:
    case 0x7:
      emitAlu(BB, currentInstInsnIdx);
      break;
    case 0x5:
      emitBr(BB, currentInstInsnIdx);
      break;
    default:
      std::cerr << "Unknown eBPF opcode " << std::hex << int(currentInsn.opcode)
                << " while instrumenting " << nowInstrumented.prototypeInsn->getOpcodeName() << "\n";
      abort();
    }
  } else {
    std::cerr << "Jump out of eBPF prog (at insn #" << currentInstInsnIdx << ")"
              << " while instrumenting " << nowInstrumented.prototypeInsn->getOpcodeName() << "\n";
    abort();
  }
}

static RegisterPass<LLInst> X("llinst", "LLInst Pass");

static void registerLLInstPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new LLInst());
}

// Like in AFL llvm-mode...
static RegisterStandardPasses RegisterLLInstPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerLLInstPass);

static RegisterStandardPasses RegisterLLInstPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerLLInstPass);
