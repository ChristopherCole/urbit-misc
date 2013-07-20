/*
 * Copyright 2013 Christopher Cole
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>

#if NOCK_LLVM
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/PassManager.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Scalar.h"
// REVISIT: cache result of "getGlobalContext()"?
#if UINTPTR_MAX == UINT64_MAX
#define llvm_tagged_noun_type() Type::getInt64Ty(getGlobalContext())
#define LLVM_NOUN(noun) ConstantInt::get(getGlobalContext(), APInt(64, noun))
#else
#define llvm_tagged_noun_type() Type::getInt32Ty(getGlobalContext())
#define LLVM_NOUN(noun) ConstantInt::get(getGlobalContext(), APInt(32, noun))
#endif

using namespace llvm;
#endif /* NOCK_LLVM */

#include "arkham.h"

#define ENV_FAIL(pstr, msg) env->fail(pstr, msg, __FILE__, __FUNCTION__, __LINE__);
#define ENV_CHECK_VOID(p, msg) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(pstr, msg); return; } } while(false)
#define ENV_CHECK(p, msg, val) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(pstr, msg) return val; } } while(false)

__thread machine_t *machine;

#if NOCK_LLVM
typedef struct llvm_s {
  Module *module;
  ExecutionEngine *engine;
  FunctionPassManager *pass_manager;
} llvm_t;
#endif

#if NOCK_LLVM
void llvm_init_global() {
  char *msg;

  if (InitializeNativeTarget() == 1) {
    ERROR0("Could not initialize LLVM native target\n");
    exit(1);
  }
}
#endif

#if NOCK_LLVM
class TestJITEventListener : public JITEventListener {
public:
  virtual void NotifyFunctionEmitted(const Function &function,
				     void *data, size_t size,
				     const EmittedFunctionDetails &details) {
    INFO("%s %p %lu\n", __FUNCTION__, data, size);
  }
};

#define ALLOC(t) ((t *)calloc(1, sizeof(t))) //XXX

llvm_t *llvm_new(const char *module_name) {
  llvm_t *llvm = ALLOC(llvm_t);//XXX
  LLVMContext &Context = getGlobalContext();

  llvm->module = new Module(module_name, Context);
    
  // Create execution engine.
  std::string ErrStr;
  EngineBuilder builder = EngineBuilder(llvm->module).setErrorStr(&ErrStr);
  if (false) {
    TargetMachine *target = builder.selectTarget();
    target->Options.PrintMachineCode = true;
    llvm->engine = builder.create(target);
  } else {
    llvm->engine = builder.create();
  }
  if (!llvm->engine) {
    ERROR("Could not create ExecutionEngine: %s\n", ErrStr.c_str());
    exit(1);
  }
    
  llvm->engine->RegisterJITEventListener(new TestJITEventListener());

  std::vector<Type*> parameter_types;
  parameter_types.push_back(llvm_tagged_noun_type());
  FunctionType *function1_type = FunctionType::get(llvm_tagged_noun_type(), parameter_types, /* is_vararg */ false);
  parameter_types.push_back(llvm_tagged_noun_type());
  FunctionType *function2_type = FunctionType::get(llvm_tagged_noun_type(), parameter_types, /* is_vararg */ false);

  Function* atom_increment_fn = Function::Create(function1_type, Function::ExternalLinkage, "atom_increment", llvm->module);
  llvm->engine->addGlobalMapping(atom_increment_fn, (void *)atom_increment);
  Function* atom_equals_fn = Function::Create(function2_type, Function::ExternalLinkage, "atom_equals", llvm->module);
  llvm->engine->addGlobalMapping(atom_equals_fn, (void *)atom_equals);
  Function* atom_add_fn = Function::Create(function2_type, Function::ExternalLinkage, "atom_add", llvm->module);
  llvm->engine->addGlobalMapping(atom_add_fn, (void *)atom_add);

  // Setup optimizations.
  llvm->pass_manager = new FunctionPassManager(llvm->module);

  // Set up the optimizer pipeline.  Start with registering info about how the
  // target lays out data structures.
  llvm->pass_manager->add(new DataLayout(*llvm->engine->getDataLayout()));
  // Provide basic AliasAnalysis support for GVN.
  llvm->pass_manager->add(createBasicAliasAnalysisPass());
  // Promote allocas to registers.
  llvm->pass_manager->add(createPromoteMemoryToRegisterPass());
  // Do simple "peephole" optimizations and bit-twiddling optzns.
  llvm->pass_manager->add(createInstructionCombiningPass());
  // Reassociate expressions.
  llvm->pass_manager->add(createReassociatePass());
  // Eliminate Common SubExpressions.
  llvm->pass_manager->add(createGVNPass());
  // Simplify the control flow graph (deleting unreachable blocks, etc).
  llvm->pass_manager->add(createCFGSimplificationPass());

  llvm->pass_manager->doInitialization();

  return llvm;
}
#endif

#if NOCK_LLVM
void llvm_delete(llvm_t *llvm) {
  delete llvm->pass_manager;
  delete llvm->module;
}
#endif

machine_t *machine_get() {
  return machine;
}

void machine_set(machine_t *m) {
  machine = m;
}

// static inline tagged_noun_t
// add(tagged_noun_t n1, tagged_noun_t n2) {
//   ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
//   ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

//   // For JIT, use: http://llvm.org/docs/LangRef.html#llvm-uadd-with-overflow-intrinsics

//   if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2)) {
//     satom_t sn1 = noun_as_satom(n1);
//     satom_t sn2 = noun_as_satom(n2);
//     satom_t sum = sn1 + sn2;
// #if FAT_NOUNS
//     if (sum >= sn1 && sum >= sn2)
//       return satom_as_noun(sum);
// #else
//     if (sum & SATOM_OVERLOW_BIT)
//       return satom_as_noun(sum);
// #endif
//   }

//   return atom_add(n1, n2);
// }

// static inline tagged_noun_t
// inc(tagged_noun_t n) {
//   ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

//   if (NOUN_IS_SATOM(n)) {
//     satom_t satom = noun_as_satom(n);
//     if (satom < SATOM_MAX)
//       return satom_as_noun(satom + 1);
//   }

//   return atom_increment(n);
// }

// static inline tagged_noun_t
// eq(tagged_noun_t n1, tagged_noun_t n2) {
//   ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
//   ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

//   if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2))
//     return noun_as_satom(n1) == noun_as_satom(n2);
//   else
//     return atom_equals(n1, n2);
// }

extern tagged_noun_t
fib(tagged_noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

  tagged_noun_t f0 = _0;
  tagged_noun_t f1 = _1;
  tagged_noun_t counter = _0;
  while (true) {
    if (NOUN_EQUALS(atom_equals(n, counter), _YES))
      return f0;
    else {
      counter = atom_increment(counter);
      tagged_noun_t sum = atom_add(f0, f1);
      f0 = f1;
      f1 = sum;
    }
  }
}

#if ALLOC_DEBUG
#define SHARE(noun, o) noun_share(noun, machine->heap, o)
#define UNSHARE(noun, o) noun_unshare(noun, machine->heap, true, o)
#else
#define SHARE(noun, o) noun_share(noun, machine->heap)
#define UNSHARE(noun, o) noun_unshare(noun, machine->heap, true)
#endif
#define ASSIGN(l, r, o) do { tagged_noun_t old = l; l = SHARE(r, o) ; UNSHARE(old, o); } while (false)

// Addresses a node in a tree: an argument to the slash operator.
typedef uint32_t jit_address_t;
#define JIT_ADDRESS_FMT PRIu32
#define JIT_ADDRESS_MAX UINT32_MAX

// An index into the local variable list.
typedef uint32_t jit_index_t;
#define JIT_INDEX_FMT PRIu32
#define JIT_INDEX_MAX UINT32_MAX

// Shouldn't be too big (uint16 is way overkill).
#define JIT_STACK_MAX UINT16_MAX

typedef tagged_noun_t (*compiled_fn_t)(tagged_noun_t noun);//ZZZ

class local_t {
public:
  tagged_noun_t value;
#if NOCK_LLVM
  char *name;
  Value *llvm_value;
  tagged_noun_t initial_value;
#endif

  ~local_t() {
    free(name);
  }
};

class env_t {
/* protected */ public:
  //XXX: use vectors
  vec_t locals;
  vec_t next_locals;
  vec_t stack;
  tagged_noun_t args_root;
  tagged_noun_t local_variable_index_map;
  tagged_noun_t args_placeholder;
  tagged_noun_t loop_body_placeholder;
#if NOCK_LLVM
  void *fp;
#endif
  // Failure information:
  const char *predicate;
  const char *failure_message;
  const char *file_name;
  const char *function_name;
  int line_number;

public:
  bool failed;
  IRBuilder<> *builder;
  Function *function;
  jit_index_t next_local_variable_index;
  jit_index_t current_stack_index;
  jit_index_t max_stack_index;

  env_t() {
    // Use an "impossible" value as the placeholder:
    args_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 1UL);
    SHARE(args_placeholder, ENV_OWNER);
    loop_body_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 2UL);
    SHARE(loop_body_placeholder, ENV_OWNER);
    local_variable_index_map = args_placeholder;
    SHARE(local_variable_index_map, ENV_OWNER);
    
    current_stack_index = -1;
    args_root = _UNDEFINED;
    
    vec_init(&locals, sizeof(local_t));
    vec_init(&next_locals, sizeof(local_t));
    vec_init(&stack, sizeof(local_t));
  }

  ~env_t() {
    {
      // REVISIT: pass a elem_destroy_fn to vec_destroy
      local_t *l_it = (local_t *)vec_get(&locals, 0);
      local_t *l_end = l_it + vec_size(&locals);
      for(; l_it != l_end; ++l_it) {
	if (NOUN_IS_UNDEFINED(l_it->value))
	  WARN0("Undefined local variable\n");
	else
	  UNSHARE(l_it->value, LOCALS_OWNER);
#if NOCK_LLVM
	free(l_it->name);
#endif
      }
    }
    {
      // REVISIT: pass a elem_destroy_fn to vec_destroy
      local_t *nl_it = (local_t *)vec_get(&next_locals, 0);
      local_t *nl_end = nl_it + vec_size(&next_locals);
      for(; nl_it != nl_end; ++nl_it) {
	if (NOUN_IS_DEFINED(nl_it->value))
	  WARN0("Leaked local variable\n");
#if NOCK_LLVM
	free(nl_it->name);
#endif
      }
    }
    UNSHARE(args_placeholder, ENV_OWNER);
    UNSHARE(loop_body_placeholder, ENV_OWNER);
    UNSHARE(local_variable_index_map, ENV_OWNER);
    if (NOUN_IS_DEFINED(args_root))
      UNSHARE(args_root, ENV_OWNER);
#if NOCK_LLVM
    // REVISIT: Deleting the function while it is referred to by the
    // module causes problems.  Figure out what (if anything) we need to
    // do after compilation to free resources.
    // if (function != NULL)
    //   delete function;
    if (builder != NULL)
      delete builder;
#endif

    vec_destroy(&locals);
    vec_destroy(&next_locals);
    vec_destroy(&stack);
  }

  void fail(const char *predicate, const char *failure_message, const char *file_name, const char *function_name, int line_number) {
    this->failed = true;
    this->predicate = predicate;
    this->failure_message = failure_message;
    this->file_name = file_name;
    this->function_name = function_name;
    this->line_number = line_number;

    nock_log(ERROR_PREFIX " Failure to compile: predicate = '%s', message = '%s', file = '%s', function = '%s', line = %d\n", predicate, failure_message, file_name, function_name, line_number);
  }

#if NOCK_LLVM
  char *make_var_name(const char *prefix, satom_t satom) {
    const int n = snprintf(NULL, 0, "%s%" SATOM_FMT, prefix, satom);
    ASSERT0(n > 0);
    char buf[n+1];
    int c = snprintf(buf, n+1, "%s%" SATOM_FMT, prefix, satom);
    ASSERT0(buf[n] == '\0');
    ASSERT0(c == n);
    return strdup(buf);
  }
#endif /* NOCK_LLVM */

#if NOCK_LLVM
  Value *compile_alloca(const char *var_name) {
    IRBuilder<> builder(&function->getEntryBlock(), function->getEntryBlock().begin());
    return builder.CreateAlloca(llvm_tagged_noun_type(), 0, var_name);
  }
#endif /* NOCK_LLVM */

  void init_local(local_t *local, const char *prefix, jit_index_t index, tagged_noun_t initial_value) {
    local->value = _UNDEFINED;
#if NOCK_LLVM
    local->name = make_var_name(prefix, index);
    local->initial_value = initial_value;
    local->llvm_value = compile_alloca(env, local->name);
#endif
  }

  jit_index_t allocate_local(tagged_noun_t initial_value) {
    if (failed) return 0;

    CHECK(next_local_variable_index < JIT_INDEX_MAX, "Too many local variable declarations", 0);
    jit_index_t index = next_local_variable_index++;

    {
      local_t local;
      init_local(env, &local, "local", index, initial_value);
      vec_resize(&locals, index + 1, &local);
    }
    {
      local_t local;
      init_local(env, &local, "next_local", index, _UNDEFINED);
      vec_resize(&next_locals, index + 1, &local);
    }

    return index;
  }

  // An address can be an argument or a declared variable.
  void allocate_address(jit_address_t address) {
    ENV_CHECK_VOID(address >= 1, "Invalid address");

    tagged_noun_t noun = local_variable_index_map;
    int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);
    tagged_noun_t ancestors[depth];
    bool choice[depth];

    // Run through the bits from left to right:
    satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
    for (int i = 0; i < depth; ++i) {
      ENV_CHECK_VOID(!NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body");

      if (NOUN_EQUALS(noun, args_placeholder)) {
	noun = cell_new(machine->heap, args_placeholder, args_placeholder);

	if (NOUN_IS_UNDEFINED(args_root)) {
	  args_root = noun;
	  SHARE(args_root, ENV_OWNER);
	}
      }
    
      ancestors[i] = noun;
      choice[i] = (mask & address);

      noun = choice[i] ? noun_get_right(noun) : noun_get_left(noun);
      mask = (mask >> 1);
    }
  
    ENV_CHECK_VOID(!NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body");

    if (NOUN_EQUALS(noun, args_placeholder)) {
      // This is an undeclared reference, so it must be an argument.
      // We are fetching an undeclared local variable value: i.e. an argument.
      // Allocate an index and initialize the local variable.

      // Allocate a local variable slot for an argument:
      noun = satom_as_noun(allocate_local(env, _UNDEFINED));

      if (NOUN_IS_UNDEFINED(args_root)) {
	args_root = noun;
	SHARE(args_root, ENV_OWNER);
      }

      tagged_noun_t n = noun;
      int i;
      for (i = depth - 1; i >= 0; --i) {
	if (choice[i])
	  n = cell_set_right(ancestors[i], n, machine->heap);
	else
	  n = cell_set_left(ancestors[i], n, machine->heap);

	if (NOUN_EQUALS(n, ancestors[i]))
	  break;
      }

      if (i == -1)
	ASSIGN(local_variable_index_map, n, ENV_OWNER);
    }

    ENV_CHECK_VOID(noun_get_type(noun) == satom_type, "Type mismatch");
    ENV_CHECK_VOID(noun_as_satom(noun) <= JIT_INDEX_MAX, "Invalid index");
  }

  jit_index_t get_index_of_address(jit_address_t address) {
    ENV_CHECK(address >= 1, "Invalid address", 0);

    tagged_noun_t noun = local_variable_index_map;
    ENV_CHECK(!NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body", 0);
    ENV_CHECK(!NOUN_EQUALS(noun, args_placeholder), "Undefined value", 0);
    int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);

    // Run through the bits from left to right:
    satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
    for (int i = 0; i < depth; ++i) {    
      noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
      ENV_CHECK(!NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body", 0);
      ENV_CHECK(!NOUN_EQUALS(noun, args_placeholder), "Undefined value", 0);
      mask = (mask >> 1);
    }

    ENV_CHECK(noun_get_type(noun) == satom_type, "Type mismatch", 0);
    satom_t index_satom = noun_as_satom(noun);
    ENV_CHECK(index_satom <= JIT_INDEX_MAX, "Invalid address", 0);
    return (jit_index_t)index_satom;
  }

  /* Callers must unshare the value. */
  tagged_noun_t get_stack(jit_index_t index) {
    if (failed) return _UNDEFINED;

    ENV_CHECK(index <= max_stack_index, "Invalid index", _UNDEFINED);

    tagged_noun_t value = ((local_t *)vec_get(&stack, index))->value;
    ENV_CHECK(NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

    return value;
  }

  void set_stack(jit_index_t index, tagged_noun_t value) {
    if (failed) return;

    ENV_CHECK_VOID(index <= max_stack_index, "Invalid index");
    ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

    SHARE(value, STACK_OWNER);
    ((local_t *)vec_get(&stack, index))->value = value;
  }

  tagged_noun_t get_local(jit_index_t index) {
    if (failed) return _UNDEFINED;

    ENV_CHECK(index < vec_size(&locals), "Invalid index", _UNDEFINED);

    tagged_noun_t value = ((local_t *)vec_get(&locals, index))->value;
    ENV_CHECK(NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

    return value;
  }

  void set_local(jit_index_t index, tagged_noun_t value) {
    if (failed) return;

    ENV_CHECK_VOID(index < vec_size(&next_locals), "Invalid index");
    ENV_CHECK_VOID(NOUN_IS_UNDEFINED(*(tagged_noun_t *)vec_get(&next_locals, index)), "Overwritten value");
    ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

    SHARE(value, LOCALS_OWNER);
    ((local_t *)vec_get(&next_locals, index))->value = value;
  }

  void initialize_local(jit_index_t index, tagged_noun_t value) {
    if (failed) return;

    ENV_CHECK_VOID(index < vec_size(&locals), "Invalid index");
    ENV_CHECK_VOID(NOUN_IS_UNDEFINED(((local_t *)vec_get(&locals, index))->value), "Overwritten value");
    ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

    SHARE(value, LOCALS_OWNER);
    ((local_t *)vec_get(&locals, index))->value = value;
  }

  void declare_loop() {
    ASSIGN(local_variable_index_map, cell_new(machine->heap, loop_body_placeholder, local_variable_index_map), ENV_OWNER);
  }

  //XXX
void env_initialize_args(env_t *env, tagged_noun_t args, tagged_noun_t args_root) {
  if (noun_get_type(args) == cell_type) {
    ENV_CHECK_VOID(noun_get_type(args_root) == cell_type, "Argument type mismatch");
    env_initialize_args(env, noun_get_left(args), noun_get_left(args_root));
    env_initialize_args(env, noun_get_right(args), noun_get_right(args_root));
  } else {
    ENV_CHECK_VOID(noun_get_type(args_root) == satom_type, "Type mismatch");
    satom_t index_satom = noun_as_satom(args_root);
    ENV_CHECK_VOID(index_satom <= JIT_INDEX_MAX, "Invalid index");
    env_initialize_local(env, (jit_index_t)index_satom, args);
  }
}

tagged_noun_t env_eval(env_t *env, jit_oper_t *oper, tagged_noun_t args) {
  ENV_CHECK(NOUN_IS_UNDEFINED(args) == NOUN_IS_UNDEFINED(env->args_root), "Arguments mismatch", _UNDEFINED);

  env_initialize_args(env, args, env->args_root);

#if NOCK_LLVM
  compiled_fn_t fn = (compiled_fn_t)env->fp; //ZZZ
  tagged_noun_t result = (fn)(args);
  printf(">>> "); noun_print(stdout, result, true); printf("\n");
#endif

  EVAL(oper);

  return env->failed ? _UNDEFINED : env_get_stack(env, 0);
}

#if NOCK_LLVM
typedef struct {
  Function::arg_iterator iter;  
} iter_t;

void env_compile_copy_args_to_locals(env_t *env, tagged_noun_t args, iter_t *iter) {
  if (noun_get_type(args) == cell_type) {
    env_compile_copy_args_to_locals(env, noun_get_left(args), iter);
    env_compile_copy_args_to_locals(env, noun_get_right(args), iter);
  } else {
    jit_index_t index = (jit_index_t)noun_as_satom(args);
    local_t *local = (local_t *)vec_get(&env->locals, index);
    env->builder->CreateStore(iter->iter++, local->llvm_value);
  }
}
#endif /* NOCK_LLVM */

#if NOCK_LLVM
void env_compile(env_t *env, jit_oper_t *oper) {
  llvm_t *llvm = machine->llvm;

  iter_t iter = (iter_t){ .iter = env->function->arg_begin() };
  env_compile_copy_args_to_locals(env, env->args_root, &iter);
  // Set initial values for locals:
  local_t *l_it = (local_t *)vec_get(&env->locals, 0);
  local_t *l_end = l_it + vec_size(&env->locals);
  for(; l_it != l_end; ++l_it)
    if (NOUN_IS_DEFINED(l_it->initial_value))
      env->builder->CreateStore(LLVM_NOUN(l_it->initial_value), l_it->llvm_value);

  Value *body = COMPILE(oper);
  if (env->failed) return;

  // Finish off the function.
  env->builder->CreateRet(body);

  // Print the function.
  env->function->dump();

  // Validate the generated code, checking for consistency.
  ENV_CHECK_VOID(!verifyFunction(*(env->function), /*ZZZ*/ AbortProcessAction), "Invalid function");

  // Print the function.
  env->function->dump();

  // Optimize the function.
  llvm->pass_manager->run(*(env->function));

  // Print the function.
  env->function->dump();

  env->fp = llvm->engine->getPointerToFunction(env->function);
}
#endif /* NOCK_LLVM */

void env_prep(env_t *env, jit_oper_t *oper) {
#if NOCK_LLVM
  llvm_t *llvm = machine->llvm;
  env->builder = new IRBuilder<> (getGlobalContext());

  // REVISIT: calling convention fastcc? (Function::setCallingConv())

  // Create argument list.
  std::vector<Type*> params(1 /*ZZZ*/, llvm_tagged_noun_type());
  
  // Create function type.
  FunctionType *functionType = FunctionType::get(llvm_tagged_noun_type(), params, false);
  
  // Create function.
  env->function = Function::Create(functionType, Function::PrivateLinkage, /* anonymous */ std::string(""), llvm->module);

  // Create basic block.
  BasicBlock *block = BasicBlock::Create(getGlobalContext(), "entry", env->function);
  env->builder->SetInsertPoint(block);
#endif /* NOCK_LLVM */

  PREP(oper);

  for (int i = 0; i <= env->max_stack_index; ++i) {
    local_t local;
    env_init_local(env, &local, "stack", i, _UNDEFINED);
    vec_resize(&env->stack, i + 1, &local);
  }
}
}; // class env_t

class jit_oper_t {
/* protected */ public:
  jit_oper_t *outer; // REVISIT: used?

public:
  void prep(env_t *env) = 0;
  void dump(env_t *env) = 0;
  void eval(env_t *env) = 0;
#if NOCK_LLVM
  Value *compile(env_t *env) = 0;
#endif

  // REVISIT: source information: file, line, column
};

class jit_expr_t : public jit_oper_t {
/* protected */ public:
  jit_index_t stack_index;
};

class jit_decl_t : public jit_oper_t {
/* protected */ public:
  jit_oper_t *inner;
  tagged_noun_t local_variable_initial_values;
  tagged_noun_t local_variable_index_map;

public:
  jit_decl_t(tagged_noun_t local_variable_initial_values) {
    SHARE(local_variable_initial_values, AST_OWNER);
    this->local_variable_initial_values = local_variable_initial_values;
    this->local_variable_index_map = _UNDEFINED;
  }

  ~jit_decl_t() { // XXX: should be declared virtual in jit_oper_t
    if (NOUN_IS_DEFINED(local_variable_index_map))
      UNSHARE(local_variable_index_map, AST_OWNER);
    UNSHARE(local_variable_initial_values, AST_OWNER);
    delete inner;
  }

  tagged_noun_t prep_impl(env_t *env, tagged_noun_t local_variable_initial_values) {
    if (noun_get_type(local_variable_initial_values) == cell_type) {
      tagged_noun_t left = decl_prep_impl(env, noun_get_left(local_variable_initial_values));
      tagged_noun_t right = decl_prep_impl(env, noun_get_right(local_variable_initial_values));
      return cell_new(machine->heap, left, right);
    } else {
      // Allocate a local variable slot for a declared variable:
      return satom_as_noun(env_allocate_local(env, local_variable_initial_values));
    }
  }

  void dump(env_t *env) {
    if (env->failed) return;
    printf("decl(\n");
    inner->dump(env);
  }

  void prep(env_t *env) {
    if (env->failed) return;

    local_variable_index_map = prep_impl(env, local_variable_initial_values);
    SHARE(local_variable_index_map, AST_OWNER);

    tagged_noun_t new_local_variable_index_map = cell_new(machine->heap, local_variable_index_map, env->local_variable_index_map);
    ASSIGN(env->local_variable_index_map, new_local_variable_index_map, ENV_OWNER);

    inner->prep(env);
  }

#if NOCK_LLVM
  Value *compile(env_t *env) {
    if (env->failed) return NULL;
    return inner->compile(env);
  }
#endif /* NOCK_LLVM */

  void eval_impl(env_t *env, tagged_noun_t local_variable_initial_values, tagged_noun_t local_variable_index_map) {
    if (noun_get_type(local_variable_initial_values) == cell_type) {
      eval_impl(env, noun_get_left(local_variable_initial_values), noun_get_left(local_variable_index_map));
      eval_impl(env, noun_get_right(local_variable_initial_values), noun_get_right(local_variable_index_map));
    } else {
      satom_t index = noun_as_satom(local_variable_index_map);
      ENV_CHECK_VOID(index <= JIT_INDEX_MAX, "Invalid index");
      env_initialize_local(env, (jit_index_t)index, local_variable_initial_values);
    }
  }

  void eval(env_t *env) {
    if (env->failed) return;
    eval_impl(env, local_variable_initial_values, local_variable_index_map);
    inner->eval(env);
  }

  void set_inner(jit_oper_t *inner) {
    ASSERT(inner == NULL, "inner == NULL");
    this->inner = inner;
    inner->outer = this;
  }
}; // class jit_decl_t

enum binop_type {
  binop_eq_type,
  binop_add_type
};

class jit_binop_t : public jit_expr_t {
/* protected */ public:
  enum binop_type type;
  jit_expr_t *left;
  jit_expr_t *right;

public:
  jit_binop_t(enum binop_type type) {
    this->type = type;
  }

  ~jit_binop_t() {
    delete left;
    delete right;
  }

  void dump(env_t *env) {
    if (env->failed) return;
    
    switch (type) {
    case binop_eq_type: 
      printf("eq(");
    case binop_add_type:
      printf("add(");
    }
    left->dump(env);
    printf(",");
    right->dump(env);
    printf(")");
  }

  void prep(env_t *env) {
    if (env->failed) return;

    left->prep(env);
    right->prep(env);

    stack_index = --env->current_stack_index;
  }

#if NOCK_LLVM
  typedef Value * (*if_atoms_fn_t)(env_t *env, Value *left, Value *right);
#endif

#if NOCK_LLVM
  Value *if_then_else(env_t *env, Type *type, Value *left, Value *right, Value *test, if_atoms_fn_t if_atoms_fn, if_atoms_fn_t if_not_atoms_fn) {

    BasicBlock *then_block = BasicBlock::Create(getGlobalContext(), "if_then", env->function);
    BasicBlock *else_block = BasicBlock::Create(getGlobalContext(), "if_else");
    BasicBlock *merge_block = BasicBlock::Create(getGlobalContext(), "if_merge");

    env->builder->CreateCondBr(test, then_block, else_block);

    // Emit 'then' value.
    env->builder->SetInsertPoint(then_block);
    Value *then_value = if_atoms_fn(env, left, right);
    env->builder->CreateBr(merge_block);
    // Codegen of 'then' can change the current block, update then_block for the PHI.
    then_block = env->builder->GetInsertBlock();

    // Emit 'else' block.
    env->function->getBasicBlockList().push_back(else_block);
    env->builder->SetInsertPoint(else_block);
    Value *else_value = if_not_atoms_fn(env, left, right);
    env->builder->CreateBr(merge_block);
    // Codegen of 'else' can change the current block, update else_block for the PHI.
    else_block = env->builder->GetInsertBlock();

    // Emit 'merge' block.
    env->function->getBasicBlockList().push_back(merge_block);
    env->builder->SetInsertPoint(merge_block);
    PHINode *phi = env->builder->CreatePHI(type, 2);

    phi->addIncoming(then_value, then_block);
    phi->addIncoming(else_value, else_block);

    return phi;
  }

  Value *if_atoms(env_t *env, Type *type, Value *left, Value *right, if_atoms_fn_t if_atoms_fn, if_atoms_fn_t if_not_atoms_fn) {
    Value *both = env->builder->CreateOr(left, right);
    Value *low_bit = env->builder->CreateAnd(both, LLVM_NOUN(1));
    Value *test = env->builder->CreateICmpEQ(low_bit, LLVM_NOUN(0));

    return if_then_else(env, type, left, right, test, if_atoms_fn, if_not_atoms_fn);
  }
#endif

#if NOCK_LLVM
  Value *eq_if_atoms(env_t *env, Value *left, Value *right) {
    return env->builder->CreateICmpEQ(left, right);
  }

  Value *eq_if_not_atoms(env_t *env, Value *left, Value *right) {
    return env->builder->CreateICmpEQ(env->builder->CreateCall2(machine->llvm->module->getFunction("atom_equals"), left, right), LLVM_NOUN(_YES));
  }

  Value *add_if_atoms(env_t *env, Value *left, Value *right) {
    return env->builder->CreateAdd(left, right);
  }

  Value *add_if_not_atoms(env_t *env, Value *left, Value *right) {
    return env->builder->CreateCall2(machine->llvm->module->getFunction("atom_add"), left, right);
  }

  Value *compile(env_t *env) {
    if (env->failed) return NULL;
    
    Value *left = left->compile(env);
    Value *right = right->compile(env);
    
    switch (type) {
    case binop_eq_type: 
      return if_atoms(env, Type::getInt1Ty(getGlobalContext()), left, right, eq_if_atoms, eq_if_not_atoms);
    case binop_add_type:
      return if_atoms(env, llvm_tagged_noun_type(), left, right, add_if_atoms, add_if_not_atoms);
    }
    
    return NULL;
  }
#endif /* NOCK_LLVM */

  void eval(env_t *env) {
    if (env->failed) return;

    left->eval(env);
    right->eval(env);
    
    tagged_noun_t n1 = env->get_stack(stack_index);
    tagged_noun_t n2 = env->get_stack(stack_index + 1);
    
    if (!env->failed) {
      switch (type) {
      case binop_eq_type:
	env->set_stack(stack_index, (atom_equals(n1, n2) ? _YES : _NO));
	break;
      case binop_add_type:
	env->set_stack(stack_index, atom_add(n1, n2));
	break;
      }
    }
    
    UNSHARE(n1, STACK_OWNER);
    UNSHARE(n2, STACK_OWNER);
  }

  void set_left(jit_expr_t *left) {
    ASSERT(binop->left == NULL, "binop->left == NULL\n");
    this->left = left;
    left->outer = this;
  }

  void set_right(jit_expr_t *right) {
    ASSERT(binop->right == NULL, "binop->right == NULL\n");
    this->right = right;
    right->outer = this;
  }
}; // jit_binop_t

class jit_inc_t : public jit_expr_t {
/* protected */ public:
  jit_expr_t *subexpr;

public:
  ~jit_inc_t() {
    delete subexpr;
  }

  void eval(env_t *env) {
    if (env->failed) return;

    subexpr->eval(env);
    
    tagged_noun_t popped;
    env->set_stack(stack_index, atom_increment(popped = env->get_stack(stack_index)));
    UNSHARE(popped, STACK_OWNER);
  }

  void dump(env_t *env) {
    if (env->failed) return;

    printf("inc(");
    subexpr->dump(env);
    printf(")");
  }

  void prep(env_t *env) {
    if (env->failed) return;
    
    subexpr->prep(env);
    stack_index = env->current_stack_index;
  }

#if NOCK_LLVM
  Value *if_atoms(env_t *env, Value *subexpr, Value *unused) {
    return env->builder->CreateAdd(subexpr, LLVM_NOUN(_1));
  }
  
  Value *if_not_atoms(env_t *env, Value *subexpr, Value *unused) {
    return env->builder->CreateCall(machine->llvm->module->getFunction("atom_increment"), subexpr);
  }

  Value *compile(env_t *env) {
    Value *subexpr_value = subexpr->compile(env);
    Value *test = env->builder->CreateICmpULT(subexpr_value, LLVM_NOUN(satom_as_noun(SATOM_MAX)));
    
    return if_then_else(env, llvm_tagged_noun_type(), subexpr_value, NULL, test, inc_if_atoms, inc_if_not_atoms);
  }
#endif /* NOCK_LLVM */

  void set_subexpr(jit_expr_t *subexpr) {
    ASSERT(this->subexpr == NULL, "this->subexpr == NULL\n");
    this->subexpr = subexpr;
    subexpr->outer = this;
  }
}; // class jit_inc_t

class jit_load_t : public jit_expr_t {
/* protected */ public:
  jit_address_t address;

public:
  jit_load_t(jit_address_t address) {
    this->address = address;
  }

  void dump(env_t *env) {
    if (env->failed) return;
    
    printf("load(%" JIT_ADDRESS_FMT ")", address);
  }

  void prep(env_t *env) {
    if (env->failed) return;
    
    subexpr->prep(env);

    env_allocate_address(env, address);

    stack_index = ++env->current_stack_index; 
    if (env->current_stack_index > env->max_stack_index)
      env->max_stack_index = env->current_stack_index;
  }

  void eval(env_t *env) {
    if (env->failed) return;

    env->set_stack(stack_index, env->get_local(env->get_index_of_addressd(address)));
  }

#if NOCK_LLVM
  Value *compile(env_t *env) {
    local_t *local = (local_t *)vec_get(&env->locals, env->get_index_of_address(address));
    return env->builder->CreateLoad(local->llvm_value);
  }
#endif /* NOCK_LLVM */
}; // class jit_load_t

class jit_store_t : public jit_expr_t {
/* protected */ public:
  jit_address_t address;
  jit_expr_t *subexpr;

public:
  jit_store_t(jit_address_t address) {
    this->address = address;
  }

  ~jit_store_t() {
    if (subexpr != NULL)
      delete subexpr;
  }

  void dump(env_t *env) {
    if (env->failed) return;
    
    printf("store(");
    subexpr->dump(env);
    printf(", %" JIT_ADDRESS_FMT ")", oper_as_store(oper)->address);
  }

  void prep(env_t *env) {
    if (env->failed) return;

    subexpr->prep(env);

    env->allocate_address(address);
    
    stack_index = env->current_stack_index--;
  }

  void eval(env_t *env) {
    if (env->failed) return;

    subexpr->eval(env);

    tagged_noun_t popped;
    env->set_local(env->get_index_of_address(address), popped = env->get_stack(stack_index));
    UNSHARE(popped, STACK_OWNER);
  }

#if NOCK_LLVM
  Value *compile(env_t *env) {
    local_t *next_local = (local_t *)vec_get(&env->next_locals, env->get_index_of_address(address));
    return env->builder->CreateStore(subexpr->compile(env), next_local->llvm_value);
  }
#endif /* NOCK_LLVM */

#if NOCK_LLVM
  Value *compile_copy(env_t *env) {
    local_t *local = (local_t *)vec_get(&env->locals, env->get_index_of_address(address));
    local_t *next_local = (local_t *)vec_get(&env->next_locals, env->get_index_of_address(address));
    return env->builder->CreateStore(env->builder->CreateLoad(next_local->llvm_value), local->llvm_value);
  }
#endif /* NOCK_LLVM */

  void set_subexpr(jit_store_t *store, jit_expr_t *subexpr) {
    ASSERT(this->subexpr == NULL, "this->subexpr == NULL\n");
    this->subexpr = subexpr;
    subexpr->outer = store;
  }
}; // class jit_store_t

//XXX: use a vector
class jit_store_list_t {
  jit_store_t *store;
  jit_store_list_t *next;
};

class jit_loop_t : public jit_expr_t {
/* protected */ public:
  jit_expr_t *test;
  jit_expr_t *result;
  jit_store_list_t *first_store;
  jit_store_list_t *last_store;

public:
  ~jit_loop_t() {
    if (test != NULL)
      delete test;
    if (result != NULL)
      delete result;
  
    jit_store_list_t *store_list = first_store;
    while (store_list != NULL) {
      delete store_list->store;
      jit_store_list_t *next = store_list->next;
      delete store_list;
      store_list = next;
    }
  }

  void dump(env_t *env) {
    if (env->failed) return;

    printf("while(\n");
    test->dump(env);
    printf(")\n");
    printf("do(\n");
    jit_store_list_t *store_list = first_store;
    while (store_list != NULL) {
      store_list->store->dump(env);
      store_list = store_list->next;
    }
    printf(")\n");
    printf("done(\n");
    result->dump(env);
    printf(")\n");
  }

  void prep(env_t *env) {
    if (env->failed) return;

    env->declare_loop();

    test->prep(env);

    stack_index = env->current_stack_index--;

    result->prep(env);

    --env->current_stack_index;

    jit_store_list_t *store_list = first_store;
    while (store_list != NULL) {
      store_list->store->prep(env);
      store_list = store_list->next;
    }
  }

  void eval(env_t *env) {
    if (env->failed) return;

    while (true) {
      test->eval(env);

      if (env->failed) return;
      tagged_noun_t popped;
      bool is_eq = atom_equals(popped = env->get_stack(stack_index), _YES);
      UNSHARE(popped, STACK_OWNER);

      if (is_eq) {
	result->eval(env);
	return;
      } else {
	jit_store_list_t *store_list = first_store;
	while (store_list != NULL) {
	  store_list->store->eval(env);
	  store_list = store_list->next;
	}
	// Copy the locals for the next iteration:
	// REVISIT: pass a elem_copy_fn to vec_copy
	local_t *l_it = (local_t *)vec_get(&env->locals, 0);
	local_t *l_end = l_it + vec_size(&env->locals);
	local_t *nl_it = (local_t *)vec_get(&env->next_locals, 0);
	for (; l_it != l_end; ++l_it, ++nl_it) {
	  UNSHARE(l_it->value, LOCALS_OWNER);
	  l_it->value = nl_it->value;
	  nl_it->value = _UNDEFINED;
	}
      }
    }
  }

#if NOCK_LLVM
  /*
   *            |
   *            V
   *        +--TEST<-+
   *        |   |    |
   *        |   V    |
   *        |  NEXT--+
   *        |   
   *        |   
   *        +->DONE
   */
  Value *compile(env_t *env) {
    BasicBlock *incoming_block = env->builder->GetInsertBlock();

    BasicBlock *test_block = BasicBlock::Create(getGlobalContext(), "loop_test", env->function);
    BasicBlock *next_block = BasicBlock::Create(getGlobalContext(), "loop_next");
    BasicBlock *done_block = BasicBlock::Create(getGlobalContext(), "loop_done");

    // Insert an explicit fall through from the current block to the loop.
    env->builder->CreateBr(test_block);

    // Test block.
    env->builder->SetInsertPoint(test_block);
    Type *loop_type = llvm_tagged_noun_type();
    PHINode *test_phi = env->builder->CreatePHI(loop_type, 2);
    test_phi->addIncoming(LLVM_NOUN(_0), incoming_block);
    Value *test_value = test->compile(env);
    test_value = env->builder->CreateICmpEQ(test_value, ConstantInt::get(getGlobalContext(), APInt(1, 0)));
    env->builder->CreateCondBr(test_value, next_block, done_block);

    // Next block.
    env->function->getBasicBlockList().push_back(next_block);
    env->builder->SetInsertPoint(next_block);
    {
      jit_store_list_t *store_list = first_store;
      while (store_list != NULL) {
	store_list->store->compile(env);
	store_list = store_list->next;
      }
    }
    {
      jit_store_list_t *store_list = first_store;
      while (store_list != NULL) {
	store_list->store->compile_copy(env);
	store_list = store_list->next;
      }
    }
    env->builder->CreateBr(test_block);
    next_block = env->builder->GetInsertBlock();
    test_phi->addIncoming(LLVM_NOUN(_0), next_block);

    // Done block.
    env->function->getBasicBlockList().push_back(done_block);
    env->builder->SetInsertPoint(done_block);
    return COMPILE(expr_as_oper(result));
  }
#endif /* NOCK_LLVM */

  void set_test(jit_loop_t *loop, jit_expr_t *test) {
    ASSERT(this->test == NULL, "this->test == NULL\n");
    this->test = test;
    test->outer = this;
  }

  void set_result(jit_loop_t *loop, jit_expr_t *result) {
    ASSERT(this->result == NULL, "this->result == NULL\n");
    this->result = result;
    result->outer = this;
  }

  void add_store(jit_loop_t *loop, jit_store_t *store) {
    jit_store_list_t *store_list = new jit_store_list_t();
    store_list->store = store;
  
    if (first_store == NULL) {
      first_store = last_store = store_list;
    } else {
      last_store->next = store_list;
      last_store = store_list;
    }
  }
}; // class jit_loop_t

jit_oper_t *dec_ast(env_t *env) {
  struct heap *heap = machine->heap;

  jit_decl_t *decl_counter = new jit_decl_t(_0); {
    jit_loop_t *loop = new jit_loop_t();
    /**/ decl_counter->set_inner(loop); {
      jit_binop_t *eq = new jit_binop_t(binop_eq_type);
      /**/ loop->set_test(eq); {
	jit_load_t *eq_left = new jit_load_t(7);
	/**/ eq->set_left(eq_left);
      } {
	jit_inc_t *eq_right = new jit_inc_t();
	/**/ eq->set_right(eq_right); {
	  jit_load_t *load_6 = new jit_load_t(6);
	  /**/ eq_right->set_subexpr(load_6);
	}
      }
    } {
      jit_load_t *result = new jit_load_t(6);
      /**/ loop->set_result(result);
    } {
      jit_store_t *store_6 = new jit_store_t(6);
      /**/ loop->add_store(store_6); {
	jit_inc_t *inc_6 = new jit_inc_t();
	/**/ store_6->set_subexpr(inc_6); {
	  jit_load_t *load_6 = new jit_load_t(6);
	  /**/ inc_6->set_subexpr(load_6);
	}
      }
    } {
      jit_store_t *store_7 = new jit_store_t(7);
      /**/ loop->add_store(store_7); {
	jit_load_t *load_7 = new jit_load_t(7);
	/**/ store_7->set_subexpr(load_7);
      }
    }
  }

  return decl_counter;
}

jit_oper_t *fib_ast(env_t *env) {
  struct heap *heap = machine->heap;

  jit_decl_t *decl_f0_f1 = new jit_decl_t(CELL(_0, _1)); {
    jit_decl_t *decl_counter = new jit_decl_t(_0);
    /**/ decl_f0_f1->set_inner(decl_counter); {
      jit_loop_t *loop = new jit_loop_t();
      /**/ decl_counter->set_inner(loop); {
	jit_binop_t *eq = new jit_binop_t(binop_eq_type);
	/**/ loop->set_test(eq); {
	  jit_load_t *eq_left = new jit_load_t(15);
	  /**/ eq->set_left(eq_left);
	} {
	  jit_load_t *eq_right = new jit_load_t(6);
	  /**/ eq->set_right(eq_right);
	} 
      } {
	jit_load_t *result = new jit_load_t(28);
	/**/ loop->set_result(result);
      } {
	jit_store_t *store_6 = new jit_store_t(6);
	/**/ loop->add_store(store_6);
	jit_inc_t *inc_6 = new jit_inc_t();
	/**/ store_6->set_subexpr(inc_6);
	jit_load_t *load_6 = new jit_load_t(6);
	/**/ inc_6->set_subexpr(load_6);
      } {
	jit_store_t *store_28 = new jit_store_t(28);
	/**/ loop->add_store(store_28);
	jit_load_t *load_29 = new jit_load_t(29);
	/**/ store_28->set_subexpr(load_29);
      } {
	jit_store_t *store_29 = new jit_store_t(29);
	/**/ loop->add_store(store_29);
	jit_binop_t *add = new jit_binop_t(binop_add_type);
	/**/ store_29->set_subexpr(add);
	jit_load_t *add_left = new jit_load_t(28);
	/**/ add->set_left(add_left);
	jit_load_t *add_right = new jit_load_t(29);
	/**/ add->set_right(add_right);
      } {
	jit_store_t *store_15 = new jit_store_t(15);
	/**/ loop->add_store(store_15);
	jit_load_t *load_15 = new jit_load_t(15);
	/**/ store_15->set_subexpr(load_15);
      }
    }
  }

  return decl_f0_f1;
}

void test_jit(tagged_noun_t args) { //ZZZ
  // For testing, generate the AST that the pattern matcher *would*
  // generate when parsing "fib" in Nock:

  env_t *env = new env_t();
  bool do_fib = true;
  jit_oper_t *root = (do_fib ? fib_ast(env) : dec_ast(env));
  
  // ZZZ
  // DUMP(root);

  env->prep(root);
#if NOCK_LLVM
  env->compile(root);
#endif
  tagged_noun_t result = env->eval(root, args);

  // ZZZ
  if (env->failed) 
    ERROR0("Evaluation failed\n");
  else {
    printf("%s(", (do_fib ? "fib" : "dec")); noun_print(stdout, args, true); printf(")="); noun_print(stdout, result, true); printf("\n");
    UNSHARE(result, STACK_OWNER);
  }

  delete root;
  delete env;
}
