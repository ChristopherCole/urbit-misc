/*
 * Copyright 2013 Christopher Cole
 */

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>

#include <vector>

#if ARKHAM_LLVM
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Intrinsics.h"
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
#endif /* ARKHAM_LLVM */

#include "arkham.h"

#define ENV_FAIL(env, pstr, msg) env->fail(pstr, msg, __FILE__, __FUNCTION__, __LINE__);
#define ENV_CHECK_VOID(env, p, msg) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(env, pstr, msg); return; } } while(false)
#define ENV_CHECK(env, p, msg, val) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(env, pstr, msg) return val; } } while(false)

__thread machine_t *machine;

#if ARKHAM_LLVM
typedef struct llvm_s {
  Module *module;
  ExecutionEngine *engine;
  FunctionPassManager *pass_manager;
  Function *uadd_with_overflow;
} llvm_t;
#endif

#if ARKHAM_LLVM
void llvm_init_global() {
  char *msg;

  if (InitializeNativeTarget() == 1) {
    ERROR0("Could not initialize LLVM native target\n");
    exit(1);
  }
}
#endif

#if ARKHAM_LLVM
class TestJITEventListener : public JITEventListener {
public:
  virtual void NotifyFunctionEmitted(const Function &function,
				     void *data, size_t size,
				     const EmittedFunctionDetails &details) {
    INFO("%s %p %lu\n", __FUNCTION__, data, size);
  }
};

llvm_t *llvm_new(const char *module_name) {
  llvm_t *llvm = (llvm_t *)calloc(1, sizeof(llvm_t));
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
  llvm->uadd_with_overflow = Intrinsic::getDeclaration(llvm->module, Intrinsic::uadd_with_overflow, parameter_types);
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

#if ARKHAM_LLVM
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

namespace jit {
  namespace ast {
    class LocalVariable {
    public:
      char *name;
      base_t *owner;
      tagged_noun_t value;
#if ARKHAM_LLVM
      Value *llvm_value;
      tagged_noun_t initial_value;
#endif

      LocalVariable(char *name, tagged_noun_t initial_value, base_t *owner) {
	this->name = name;
	this->owner = owner;
	this->value = _UNDEFINED;
#if ARKHAM_LLVM
	this->llvm_value = NULL;
	this->initial_value = initial_value;
#endif
      }

      LocalVariable(const LocalVariable& local) {
	this->name = strdup(local.name);
	this->owner = local.owner;
	this->value = local.value;
	if (NOUN_IS_DEFINED(this->value))
	  SHARE(this->value, this->owner);
#if ARKHAM_LLVM
	this->llvm_value = local.llvm_value;
	this->initial_value = local.initial_value;
#endif
      }

#if ARKHAM_LLVM
      void set_llvm_value(Value *llvm_value) {
	this->llvm_value = llvm_value;
      }
#endif

      void set_value(tagged_noun_t value) {
	if (NOUN_IS_DEFINED(this->value))
	  UNSHARE(this->value, this->owner);
	if (NOUN_IS_DEFINED(value))
	  SHARE(value, this->owner);
	this->value = value;
      }

      ~LocalVariable() {
#if ARKHAM_LLVM
	if (name != NULL)
	  free(name);
	if (NOUN_IS_DEFINED(value))
	  UNSHARE(value, owner);
#endif
      }
    };

    class Environment;

    class Node {
      /* protected */ public:
      Node *outer; // REVISIT: used?

    public:
      virtual ~Node() { }
      virtual void prep(Environment *env) = 0;
      virtual void dump(Environment *env, FILE *fp, int indent) = 0;
      virtual void eval(Environment *env) = 0;
#if ARKHAM_LLVM
      virtual Value *compile(Environment *env) = 0;
#endif

      // REVISIT: source information: file, line, column
    };

    class Environment {
      /* protected */ public:
      std::vector<LocalVariable> locals;
      std::vector<LocalVariable> next_locals;
      std::vector<LocalVariable> stack;
      tagged_noun_t args_root;
      tagged_noun_t local_variable_index_map;
      tagged_noun_t args_placeholder;
      tagged_noun_t loop_body_placeholder;
#if ARKHAM_LLVM
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
#if ARKHAM_LLVM
      IRBuilder<> *builder;
      Function *function;
#endif
      jit_index_t next_local_variable_index;
      jit_index_t current_stack_index;
      jit_index_t max_stack_index;

      Environment() {
	// Use an "impossible" value as the placeholder:
	args_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 1UL);
	SHARE(args_placeholder, ENV_OWNER);
	loop_body_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 2UL);
	SHARE(loop_body_placeholder, ENV_OWNER);
	local_variable_index_map = args_placeholder;
	SHARE(local_variable_index_map, ENV_OWNER);
    
	current_stack_index = -1;
	args_root = _UNDEFINED;
      }

      ~Environment() {
	UNSHARE(args_placeholder, ENV_OWNER);
	UNSHARE(loop_body_placeholder, ENV_OWNER);
	UNSHARE(local_variable_index_map, ENV_OWNER);
	if (NOUN_IS_DEFINED(args_root))
	  UNSHARE(args_root, ENV_OWNER);
#if ARKHAM_LLVM
	// REVISIT: Deleting the function while it is referred to by the
	// module causes problems.  Figure out what (if anything) we need to
	// do after compilation to free resources.
	// if (function != NULL)
	//   delete function;
	if (builder != NULL)
	  delete builder;
#endif
      }

      void fail(const char *predicate, const char *failure_message, const char *file_name, const char *function_name, int line_number) {
	this->failed = true;
	this->predicate = predicate;
	this->failure_message = failure_message;
	this->file_name = file_name;
	this->function_name = function_name;
	this->line_number = line_number;

	arkham_log(ERROR_PREFIX " Failure to compile: predicate = '%s', message = '%s', file = '%s', function = '%s', line = %d\n", predicate, failure_message, file_name, function_name, line_number);
      }

      char *make_var_name(const char *prefix, satom_t satom) {
	const int n = snprintf(NULL, 0, "%s%" SATOM_FMT, prefix, satom);
	ASSERT0(n > 0);
	char buf[n+1];
	int c = snprintf(buf, n+1, "%s%" SATOM_FMT, prefix, satom);
	ASSERT0(buf[n] == '\0');
	ASSERT0(c == n);
	return strdup(buf);
      }

#if ARKHAM_LLVM
      Value *compile_alloca(const char *var_name) {
	IRBuilder<> builder(&function->getEntryBlock(), function->getEntryBlock().begin());
	return builder.CreateAlloca(llvm_tagged_noun_type(), 0, var_name);
      }
#endif /* ARKHAM_LLVM */

      jit_index_t allocate_local(tagged_noun_t initial_value) {
	if (failed) return 0;

	ENV_CHECK(this, next_local_variable_index < JIT_INDEX_MAX, "Too many local variable declarations", 0);
	jit_index_t index = next_local_variable_index++;
	locals.resize(index + 1, LocalVariable(make_var_name("local", index), initial_value, LOCALS_OWNER));
#if ARKHAM_LLVM
	LocalVariable &local = locals.at(index);
	local.llvm_value = compile_alloca(local.name);
#endif /* ARKHAM_LLVM */
	next_locals.resize(index + 1, LocalVariable(make_var_name("next_local", index), initial_value, LOCALS_OWNER));
#if ARKHAM_LLVM
	LocalVariable &next_local = next_locals.at(index);
	next_local.llvm_value = compile_alloca(next_local.name);
#endif /* ARKHAM_LLVM */

	return index;
      }

      // An address can be an argument or a declared variable.
      void allocate_address(jit_address_t address) {
	ENV_CHECK_VOID(this, address >= 1, "Invalid address");

	tagged_noun_t noun = local_variable_index_map;
	int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);
	tagged_noun_t ancestors[depth];
	bool choice[depth];

	// Run through the bits from left to right:
	satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
	for (int i = 0; i < depth; ++i) {
	  ENV_CHECK_VOID(this, !NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body");

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
  
	ENV_CHECK_VOID(this, !NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body");

	if (NOUN_EQUALS(noun, args_placeholder)) {
	  // This is an undeclared reference, so it must be an argument.
	  // We are fetching an undeclared local variable value: i.e. an argument.
	  // Allocate an index and initialize the local variable.

	  // Allocate a local variable slot for an argument:
	  noun = satom_as_noun(allocate_local(_UNDEFINED));

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

	ENV_CHECK_VOID(this, noun_get_type(noun) == satom_type, "Type mismatch");
	ENV_CHECK_VOID(this, noun_as_satom(noun) <= JIT_INDEX_MAX, "Invalid index");
      }

      jit_index_t get_index_of_address(jit_address_t address) {
	ENV_CHECK(this, address >= 1, "Invalid address", 0);

	tagged_noun_t noun = local_variable_index_map;
	ENV_CHECK(this, !NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body", 0);
	ENV_CHECK(this, !NOUN_EQUALS(noun, args_placeholder), "Undefined value", 0);
	int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);

	// Run through the bits from left to right:
	satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
	for (int i = 0; i < depth; ++i) {    
	  noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
	  ENV_CHECK(this, !NOUN_EQUALS(noun, loop_body_placeholder), "Cannot refer to the loop body", 0);
	  ENV_CHECK(this, !NOUN_EQUALS(noun, args_placeholder), "Undefined value", 0);
	  mask = (mask >> 1);
	}

	ENV_CHECK(this, noun_get_type(noun) == satom_type, "Type mismatch", 0);
	satom_t index_satom = noun_as_satom(noun);
	ENV_CHECK(this, index_satom <= JIT_INDEX_MAX, "Invalid address", 0);
	return (jit_index_t)index_satom;
      }

      /* Callers must unshare the value. */
      tagged_noun_t get_stack(jit_index_t index) {
	if (failed) return _UNDEFINED;

	ENV_CHECK(this, index <= max_stack_index, "Invalid index", _UNDEFINED);

	tagged_noun_t value = stack.at(index).value;
	ENV_CHECK(this, NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

	return value;
      }

      void set_stack(jit_index_t index, tagged_noun_t value) {
	if (failed) return;

	ENV_CHECK_VOID(this, index <= max_stack_index, "Invalid index");

	stack.at(index).set_value(value);
      }

      tagged_noun_t get_local(jit_index_t index) {
	if (failed) return _UNDEFINED;

	ENV_CHECK(this, index < locals.size(), "Invalid index", _UNDEFINED);

	tagged_noun_t value = locals.at(index).value;
	ENV_CHECK(this, NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

	return value;
      }

      void set_local(jit_index_t index, tagged_noun_t value) {
	if (failed) return;

	ENV_CHECK_VOID(this, index < next_locals.size(), "Invalid index");
	ENV_CHECK_VOID(this, NOUN_IS_UNDEFINED(next_locals.at(index).value), "Overwritten value");
	ENV_CHECK_VOID(this, NOUN_IS_DEFINED(value), "Undefined value");

	next_locals.at(index).set_value(value);
      }

      void initialize_local(jit_index_t index, tagged_noun_t value) {
	if (failed) return;

	ENV_CHECK_VOID(this, index < locals.size(), "Invalid index");
	ENV_CHECK_VOID(this, NOUN_IS_UNDEFINED(locals.at(index).value), "Overwritten value");
	ENV_CHECK_VOID(this, NOUN_IS_DEFINED(value), "Undefined value");

	locals.at(index).set_value(value);
      }

      void declare_loop() {
	ASSIGN(local_variable_index_map, cell_new(machine->heap, loop_body_placeholder, local_variable_index_map), ENV_OWNER);
      }

      void initialize_args(tagged_noun_t args, tagged_noun_t args_root) {
	if (noun_get_type(args) == cell_type) {
	  ENV_CHECK_VOID(this, noun_get_type(args_root) == cell_type, "Argument type mismatch");
	  initialize_args(noun_get_left(args), noun_get_left(args_root));
	  initialize_args(noun_get_right(args), noun_get_right(args_root));
	} else {
	  ENV_CHECK_VOID(this, noun_get_type(args_root) == satom_type, "Type mismatch");
	  satom_t index_satom = noun_as_satom(args_root);
	  ENV_CHECK_VOID(this, index_satom <= JIT_INDEX_MAX, "Invalid index");
	  initialize_local((jit_index_t)index_satom, args);
	}
      }

      tagged_noun_t eval(Node *oper, tagged_noun_t args) {
	ENV_CHECK(this, NOUN_IS_UNDEFINED(args) == NOUN_IS_UNDEFINED(args_root), "Arguments mismatch", _UNDEFINED);

	initialize_args(args, args_root);

#if ARKHAM_LLVM
	compiled_fn_t fn = (compiled_fn_t)fp; //ZZZ
	tagged_noun_t compiled_result = (fn)(args); // ZZZ: unshare?
	printf(">>> "); noun_print(stdout, compiled_result, true); printf("\n");
#endif
    
	oper->eval(this);
    
	tagged_noun_t result = failed ? _UNDEFINED : get_stack(0);
	SHARE(result, ENV_OWNER);
	set_stack(0, _UNDEFINED);
	return result;
      }

#if ARKHAM_LLVM
      typedef struct {
	Function::arg_iterator iter;  
      } iter_t;
  
      void compile_copy_args_to_locals(tagged_noun_t args, iter_t *iter) {
	if (noun_get_type(args) == cell_type) {
	  compile_copy_args_to_locals(noun_get_left(args), iter);
	  compile_copy_args_to_locals(noun_get_right(args), iter);
	} else {
	  jit_index_t index = (jit_index_t)noun_as_satom(args);
	  builder->CreateStore(iter->iter++, locals.at(index).llvm_value);
	}
      }
#endif /* ARKHAM_LLVM */

#if ARKHAM_LLVM
      void compile(Node *oper) {
	llvm_t *llvm = machine->llvm;

	iter_t iter = (iter_t){ .iter = function->arg_begin() };
	compile_copy_args_to_locals(args_root, &iter);
	// Set initial values for locals:
	for(std::vector<LocalVariable>::iterator it = locals.begin(); it != locals.end(); ++it)
	  if (NOUN_IS_DEFINED(it->initial_value))
	    builder->CreateStore(LLVM_NOUN(it->initial_value), it->llvm_value);
    
	Value *body = oper->compile(this);
	if (failed) return;
    
	// Finish off the function.
	builder->CreateRet(body);
    
	// Print the function.
	function->dump();
    
	// Validate the generated code, checking for consistency.
	ENV_CHECK_VOID(this, !verifyFunction(*(function), /*ZZZ*/ AbortProcessAction), "Invalid function");
    
	// Print the function.
	function->dump();
    
	// Optimize the function.
	llvm->pass_manager->run(*(function));
    
	// Print the function.
	function->dump();
    
	fp = llvm->engine->getPointerToFunction(function);
      }
#endif /* ARKHAM_LLVM */

      void prep(Node *oper) {
#if ARKHAM_LLVM
	llvm_t *llvm = machine->llvm;
	builder = new IRBuilder<> (getGlobalContext());
    
	// REVISIT: calling convention fastcc? (Function::setCallingConv())
    
	// Create argument list.
	std::vector<Type*> params(1 /*ZZZ*/, llvm_tagged_noun_type());
    
	// Create function type.
	FunctionType *functionType = FunctionType::get(llvm_tagged_noun_type(), params, false);
    
	// Create function.
	function = Function::Create(functionType, Function::PrivateLinkage, /* anonymous */ std::string(""), llvm->module);
    
	// Create basic block.
	BasicBlock *block = BasicBlock::Create(getGlobalContext(), "entry", function);
	builder->SetInsertPoint(block);
#endif /* ARKHAM_LLVM */
    
	oper->prep(this);
    
	for (int i = 0; i <= max_stack_index; ++i)
	  stack.resize(i + 1, LocalVariable(make_var_name("stack", i), _UNDEFINED, STACK_OWNER));
      }

      void copy_locals() {
	std::vector<LocalVariable>::iterator it = locals.begin();
	std::vector<LocalVariable>::iterator nit = next_locals.begin();
	for(; it != locals.end(); ++it, ++nit) {
	  it->set_value(nit->value);
	  nit->set_value(_UNDEFINED);
	}
      }

      void indent(FILE *fp, int indent) {
	for (int i = 0; i < indent; ++i)
	  fprintf(fp, "..");
      }
    }; // class Environment

#if ARKHAM_LLVM
    typedef struct {
      Value *value;
      BasicBlock *block;
    } incoming_t;
#endif /* ARKHAM_LLVM */

#if ARKHAM_LLVM
    class IfThenElseBlocks {
    public:
      IfThenElseBlocks *parent;
      BasicBlock *if_block;
      BasicBlock *else_block;
      BasicBlock *merge_block;
      std::vector<incoming_t> incoming_to_else;
      std::vector<incoming_t> incoming_to_merge;

      IfThenElseBlocks(IfThenElseBlocks *parent) {
	this->parent = parent;
      }

      void add_incoming_to_else(Value *value, BasicBlock *block) {
	incoming_to_else.push_back((incoming_t){ .value = value, .block = block });
      }

      PHINode *begin(Environment *env, Type *type, std::vector<incoming_t> &incoming) {
	size_t size = incoming.size();
	if (size > 0) {
	  PHINode *phi = env->builder->CreatePHI(type, size);
	  int i = 0;
	  for(std::vector<incoming_t>::iterator it = incoming.begin(); it != incoming.end(); ++it) {
	    printf("phi->addIncoming: i=%d\n", i);
	    it->value->dump();
	    phi->addIncoming(it->value, it->block);
	    ++i;
	  }
	  return phi;
	} else 
	  return NULL;
      }

      PHINode *begin_else(Environment *env, Type *type) {
	return begin(env, type, incoming_to_else);
      }

      void add_incoming_to_merge(Value *value, BasicBlock *block) {
	incoming_to_merge.push_back((incoming_t){ .value = value, .block = block });
      }

      PHINode *begin_merge(Environment *env, Type *type) {
	return begin(env, type, incoming_to_merge);
      }
    };
#endif /* ARKHAM_LLVM */

    class Expression : public Node {
      /* protected */ public:
      jit_index_t stack_index;

#if ARKHAM_LLVM
      typedef Value * (*if_atoms_fn_t)(Environment *env, Value *left, Value *right, IfThenElseBlocks *blocks, bool *add_default_branch);
#endif

#if ARKHAM_LLVM
      static Value *if_else(Environment *env, const char *prefix, Type *type, Value *left, Value *right, Value *test, if_atoms_fn_t if_atoms_fn, if_atoms_fn_t if_not_atoms_fn, IfThenElseBlocks *parent_blocks) {
	IfThenElseBlocks blocks(parent_blocks);
	bool add_default_branch;
	char buffer[strlen(prefix) + 7];

	snprintf(buffer, sizeof(buffer), "%s.if", prefix);
	blocks.if_block = BasicBlock::Create(getGlobalContext(), buffer, env->function);
	snprintf(buffer, sizeof(buffer), "%s.else", prefix);
	blocks.else_block = BasicBlock::Create(getGlobalContext(), buffer);
	snprintf(buffer, sizeof(buffer), "%s.merge", prefix);
	blocks.merge_block = BasicBlock::Create(getGlobalContext(), buffer);

	blocks.add_incoming_to_else(UndefValue::get(llvm_tagged_noun_type()), env->builder->GetInsertBlock());
	env->builder->CreateCondBr(test, blocks.if_block, blocks.else_block);

	// Emit 'then' value.
	env->builder->SetInsertPoint(blocks.if_block);
	add_default_branch = true;
	Value *if_value = if_atoms_fn(env, left, right, &blocks, &add_default_branch);
	// Codegen of 'then' can change the current block, update if_block for the PHI.
	blocks.if_block = env->builder->GetInsertBlock();
	if (add_default_branch) {
	  blocks.add_incoming_to_merge(if_value, blocks.if_block);
	  env->builder->CreateBr(blocks.merge_block);
	}

	// Emit 'else' block.
	env->function->getBasicBlockList().push_back(blocks.else_block);
	env->builder->SetInsertPoint(blocks.else_block);
	blocks.begin_else(env, llvm_tagged_noun_type());
	add_default_branch = true;
	Value *else_value = if_not_atoms_fn(env, left, right, &blocks, &add_default_branch);
	// Codegen of 'else' can change the current block, update else_block for the PHI.
	blocks.else_block = env->builder->GetInsertBlock();
	if (add_default_branch) {
	  blocks.add_incoming_to_merge(else_value, blocks.else_block);
	  env->builder->CreateBr(blocks.merge_block);
	}

	// Emit 'merge' block.
	env->function->getBasicBlockList().push_back(blocks.merge_block);
	env->builder->SetInsertPoint(blocks.merge_block);
	return blocks.begin_merge(env, type);
      }

      static Value *if_atoms(Environment *env, const char *prefix, Type *type, Value *left, Value *right, if_atoms_fn_t if_atoms_fn, if_atoms_fn_t if_not_atoms_fn) {
	Value *both = env->builder->CreateOr(left, right);
	Value *low_bit = env->builder->CreateAnd(both, LLVM_NOUN(1));
	Value *test = env->builder->CreateICmpEQ(low_bit, LLVM_NOUN(0));

	return if_else(env, prefix, type, left, right, test, if_atoms_fn, if_not_atoms_fn, /* parent_blocks */ NULL);
      }
#endif
    };

    class Declaration : public Node {
      /* protected */ public:
      Node *inner;
      tagged_noun_t local_variable_initial_values;
      tagged_noun_t local_variable_index_map;

    public:
      Declaration(tagged_noun_t local_variable_initial_values) {
	SHARE(local_variable_initial_values, AST_OWNER);
	this->local_variable_initial_values = local_variable_initial_values;
	this->local_variable_index_map = _UNDEFINED;
      }

      ~Declaration() {
	if (NOUN_IS_DEFINED(local_variable_index_map))
	  UNSHARE(local_variable_index_map, AST_OWNER);
	UNSHARE(local_variable_initial_values, AST_OWNER);
	delete inner;
      }

      tagged_noun_t prep_impl(Environment *env, tagged_noun_t local_variable_initial_values) {
	if (noun_get_type(local_variable_initial_values) == cell_type) {
	  tagged_noun_t left = prep_impl(env, noun_get_left(local_variable_initial_values));
	  tagged_noun_t right = prep_impl(env, noun_get_right(local_variable_initial_values));
	  return cell_new(machine->heap, left, right);
	} else {
	  // Allocate a local variable slot for a declared variable:
	  return satom_as_noun(env->allocate_local(local_variable_initial_values));
	}
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;
	env->indent(fp, indent); fprintf(fp, "decl(\n");
	inner->dump(env, fp, indent + 1);
	env->indent(fp, indent); fprintf(fp, ")\n");
      }

      void prep(Environment *env) {
	if (env->failed) return;

	local_variable_index_map = prep_impl(env, local_variable_initial_values);
	SHARE(local_variable_index_map, AST_OWNER);

	tagged_noun_t new_local_variable_index_map = cell_new(machine->heap, local_variable_index_map, env->local_variable_index_map);
	ASSIGN(env->local_variable_index_map, new_local_variable_index_map, ENV_OWNER);

	inner->prep(env);
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
	if (env->failed) return NULL;
	return inner->compile(env);
      }
#endif /* ARKHAM_LLVM */

      void eval_impl(Environment *env, tagged_noun_t local_variable_initial_values, tagged_noun_t local_variable_index_map) {
	if (noun_get_type(local_variable_initial_values) == cell_type) {
	  eval_impl(env, noun_get_left(local_variable_initial_values), noun_get_left(local_variable_index_map));
	  eval_impl(env, noun_get_right(local_variable_initial_values), noun_get_right(local_variable_index_map));
	} else {
	  satom_t index = noun_as_satom(local_variable_index_map);
	  ENV_CHECK_VOID(env, index <= JIT_INDEX_MAX, "Invalid index");
	  env->initialize_local((jit_index_t)index, local_variable_initial_values);
	}
      }

      void eval(Environment *env) {
	if (env->failed) return;
	eval_impl(env, local_variable_initial_values, local_variable_index_map);
	inner->eval(env);
      }

      void set_inner(Node *inner) {
	ASSERT(this->inner == NULL, "this->inner == NULL");
	this->inner = inner;
	inner->outer = this;
      }
    }; // class Declaration

    enum binop_type {
      binop_eq_type,
      binop_add_type
    };

    class BinaryExpression : public Expression {
      /* protected */ public:
      enum binop_type type;
      Expression *left;
      Expression *right;

    public:
      BinaryExpression(enum binop_type type) {
	this->type = type;
      }

      ~BinaryExpression() {
	delete left;
	delete right;
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;
    
	env->indent(fp, indent); 

	switch (type) {
	case binop_eq_type: 
	  fprintf(fp, "eq(");
	  break;
	case binop_add_type:
	  fprintf(fp, "add(");
	  break;
	}
	left->dump(env, fp, -1);
	fprintf(fp, ", ");
	right->dump(env, fp, -1);
	// switch (type) {
	// case binop_eq_type: 
	//   fprintf(fp, "]");
	// case binop_add_type:
	//   fprintf(fp, ">");
	// }
	fprintf(fp, ")");
      }

      void prep(Environment *env) {
	if (env->failed) return;

	left->prep(env);
	right->prep(env);

	stack_index = --env->current_stack_index;
      }

#if ARKHAM_LLVM
      static Value *eq_if_atoms(Environment *env, Value *left, Value *right, IfThenElseBlocks *blocks, bool *add_default_branch) {
	return env->builder->CreateICmpEQ(left, right);
      }

      static Value *eq_if_not_atoms(Environment *env, Value *left, Value *right, IfThenElseBlocks *blocks, bool *add_default_branch) {
	return env->builder->CreateICmpEQ(env->builder->CreateCall2(machine->llvm->module->getFunction("atom_equals"), left, right), LLVM_NOUN(_YES));
      }

      static Value *if_overflow(Environment *env, Value *sum, Value *unused, IfThenElseBlocks *blocks, bool *add_default_branch) {
	blocks->parent->add_incoming_to_else(UndefValue::get(llvm_tagged_noun_type()), blocks->if_block);
	env->builder->CreateBr(blocks->parent->else_block);
	*add_default_branch = false;
	return sum;
      }

      static Value *if_not_overflow(Environment *env, Value *sum, Value *unused, IfThenElseBlocks *blocks, bool *add_default_branch) {
      	return sum;
      }

      static Value *add_if_atoms(Environment *env, Value *left, Value *right, IfThenElseBlocks *blocks, bool *add_default_branch) {
	Value *result = env->builder->CreateCall2(machine->llvm->uadd_with_overflow, left, right);
	Value *sum = env->builder->CreateExtractValue(result, 0);
	Value *overflow = env->builder->CreateExtractValue(result, 1);
	return if_else(env, "add.check.overflow", llvm_tagged_noun_type(), sum, NULL, overflow, if_overflow, if_not_overflow, /* parent_blocks */ blocks);
      }

      static Value *add_if_not_atoms(Environment *env, Value *left, Value *right, IfThenElseBlocks *blocks, bool *add_default_branch) {
	return env->builder->CreateCall2(machine->llvm->module->getFunction("atom_add"), left, right);
      }

      Value *compile(Environment *env) {
	if (env->failed) return NULL;
    
	Value *left = this->left->compile(env);
	Value *right = this->right->compile(env);
    
	switch (type) {
	case binop_eq_type: 
	  return if_atoms(env, "eq", Type::getInt1Ty(getGlobalContext()), left, right, eq_if_atoms, eq_if_not_atoms);
	case binop_add_type:
	  return if_atoms(env, "add", llvm_tagged_noun_type(), left, right, add_if_atoms, add_if_not_atoms);
	}
    
	return NULL;
      }
#endif /* ARKHAM_LLVM */

      void eval(Environment *env) {
	if (env->failed) return;

	left->eval(env);
	right->eval(env);
    
	tagged_noun_t n1 = env->get_stack(stack_index);
	tagged_noun_t n2 = env->get_stack(stack_index + 1);
    
	if (!env->failed) {
	  switch (type) {
	  case binop_eq_type:
	    env->set_stack(stack_index, (atom_equals(n1, n2) ? _YES : _NO));
	    env->set_stack(stack_index + 1, _UNDEFINED);
	    break;
	  case binop_add_type:
	    env->set_stack(stack_index, atom_add(n1, n2));
	    env->set_stack(stack_index + 1, _UNDEFINED);
	    break;
	  }
	}
      }

      void set_left(Expression *left) {
	ASSERT(this->left == NULL, "this->left == NULL\n");
	this->left = left;
	left->outer = this;
      }

      void set_right(Expression *right) {
	ASSERT(this->right == NULL, "this->right == NULL\n");
	this->right = right;
	right->outer = this;
      }
    }; // BinaryExpression

    class IncrementExpression : public Expression {
      /* protected */ public:
      Expression *subexpr;

    public:
      ~IncrementExpression() {
	delete subexpr;
      }

      void eval(Environment *env) {
	if (env->failed) return;

	subexpr->eval(env);
    
	env->set_stack(stack_index, atom_increment(env->get_stack(stack_index)));
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;

	env->indent(fp, indent); fprintf(fp, "inc(");
	subexpr->dump(env, fp, -1);
	fprintf(fp, ")");
      }

      void prep(Environment *env) {
	if (env->failed) return;
    
	subexpr->prep(env);
	stack_index = env->current_stack_index;
      }

#if ARKHAM_LLVM
      static Value *inc_if_atoms(Environment *env, Value *subexpr, Value *unused, IfThenElseBlocks *blocks, bool *add_default_branch) {
	return env->builder->CreateAdd(subexpr, LLVM_NOUN(_1));
      }
  
      static Value *inc_if_not_atoms(Environment *env, Value *subexpr, Value *unused, IfThenElseBlocks *blocks, bool *add_default_branch) {
	return env->builder->CreateCall(machine->llvm->module->getFunction("atom_increment"), subexpr);
      }

      Value *compile(Environment *env) {
	Value *subexpr_value = subexpr->compile(env);
	Value *test = env->builder->CreateICmpULT(subexpr_value, LLVM_NOUN(satom_as_noun(SATOM_MAX)));
    
	return if_else(env, "inc", llvm_tagged_noun_type(), subexpr_value, NULL, test, inc_if_atoms, inc_if_not_atoms, /* parent_blocks */ NULL);
      }
#endif /* ARKHAM_LLVM */

      void set_subexpr(Expression *subexpr) {
	ASSERT(this->subexpr == NULL, "this->subexpr == NULL\n");
	this->subexpr = subexpr;
	subexpr->outer = this;
      }
    }; // class IncrementExpression

    class Load : public Expression {
      /* protected */ public:
      jit_address_t address;

    public:
      Load(jit_address_t address) {
	this->address = address;
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;
    
	env->indent(fp, indent); fprintf(fp, "load(%" JIT_ADDRESS_FMT ")", address);
      }

      void prep(Environment *env) {
	if (env->failed) return;
    
	env->allocate_address(address);

	stack_index = ++env->current_stack_index; 
	if (env->current_stack_index > env->max_stack_index)
	  env->max_stack_index = env->current_stack_index;
      }

      void eval(Environment *env) {
	if (env->failed) return;

	env->set_stack(stack_index, env->get_local(env->get_index_of_address(address)));
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
	return env->builder->CreateLoad(env->locals.at(env->get_index_of_address(address)).llvm_value);
      }
#endif /* ARKHAM_LLVM */
    }; // class Load

    class Store : public Expression {
      /* protected */ public:
      jit_address_t address;
      Expression *subexpr;

    public:
      Store(jit_address_t address) {
	this->address = address;
      }

      ~Store() {
	if (subexpr != NULL)
	  delete subexpr;
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;
    
	env->indent(fp, indent); fprintf(fp, "store(");
	subexpr->dump(env, fp, -1);
	fprintf(fp, ", %" JIT_ADDRESS_FMT ")", address);
      }

      void prep(Environment *env) {
	if (env->failed) return;

	subexpr->prep(env);

	env->allocate_address(address);
    
	stack_index = env->current_stack_index--;
      }

      void eval(Environment *env) {
	if (env->failed) return;

	subexpr->eval(env);

	env->set_local(env->get_index_of_address(address), env->get_stack(stack_index));
	env->set_stack(stack_index, _UNDEFINED);
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
	return env->builder->CreateStore(subexpr->compile(env), env->next_locals.at(env->get_index_of_address(address)).llvm_value);
      }
#endif /* ARKHAM_LLVM */

#if ARKHAM_LLVM
      Value *compile_copy(Environment *env) {
	const LocalVariable &local = env->locals.at(env->get_index_of_address(address));
	const LocalVariable &next_local = env->next_locals.at(env->get_index_of_address(address));
	return env->builder->CreateStore(env->builder->CreateLoad(next_local.llvm_value), local.llvm_value);
      }
#endif /* ARKHAM_LLVM */

      void set_subexpr(Expression *subexpr) {
	ASSERT(this->subexpr == NULL, "this->subexpr == NULL\n");
	this->subexpr = subexpr;
	subexpr->outer = this;
      }
    }; // class Store

    class Loop : public Expression {
      /* protected */ public:
      Expression *test;
      Expression *result;
      std::vector<Store *> stores;

    public:
      ~Loop() {
	if (test != NULL)
	  delete test;
	if (result != NULL)
	  delete result;
  
	for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it)
	  delete *it;
      }

      void dump(Environment *env, FILE *fp, int indent) {
	if (env->failed) return;

	env->indent(fp, indent); fprintf(fp, "while(\n");
	env->indent(fp, indent+ 1); test->dump(env, fp, -1);
	fprintf(fp, "\n"); env->indent(fp, indent); fprintf(fp, ")\n");
	env->indent(fp, indent); fprintf(fp, "do(\n");
	env->indent(fp, indent + 1); 

	for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it) {
	  if (it != stores.begin())
	    fprintf(fp, ", ");
	  (*it)->dump(env, fp, -1);
	}

	fprintf(fp, "\n"); env->indent(fp, indent); fprintf(fp, ")\n");
	env->indent(fp, indent); fprintf(fp, "done(\n");
	env->indent(fp, indent + 1); result->dump(env, fp, -1);
	fprintf(fp, "\n"); env->indent(fp, indent); fprintf(fp, ")\n");
      }

      void prep(Environment *env) {
	if (env->failed) return;

	env->declare_loop();

	test->prep(env);

	stack_index = env->current_stack_index--;

	result->prep(env);

	--env->current_stack_index;

	for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it)
	  (*it)->prep(env);
      }

      void eval(Environment *env) {
	if (env->failed) return;

	while (true) {
	  test->eval(env);

	  if (env->failed) return;
	  bool is_eq = atom_equals(env->get_stack(stack_index), _YES);
	  env->set_stack(stack_index, _UNDEFINED);

	  if (is_eq) {
	    result->eval(env);
	    return;
	  } else {
	    for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it)
	      (*it)->eval(env);
	    // Copy the locals for the next iteration:
	    env->copy_locals();
	  }
	}
      }

#if ARKHAM_LLVM
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
      Value *compile(Environment *env) {
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
	  for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it)
	    (*it)->compile(env);
	}
	{
	  for(std::vector<Store *>::iterator it = stores.begin(); it != stores.end(); ++it)
	    (*it)->compile_copy(env);
	}
	env->builder->CreateBr(test_block);
	next_block = env->builder->GetInsertBlock();
	test_phi->addIncoming(LLVM_NOUN(_0), next_block);

	// Done block.
	env->function->getBasicBlockList().push_back(done_block);
	env->builder->SetInsertPoint(done_block);

	return result->compile(env);
      }
#endif /* ARKHAM_LLVM */

      void set_test(Expression *test) {
	ASSERT(this->test == NULL, "this->test == NULL\n");
	this->test = test;
	test->outer = this;
      }

      void set_result(Expression *result) {
	ASSERT(this->result == NULL, "this->result == NULL\n");
	this->result = result;
	result->outer = this;
      }

      void add_store(Store *store) {
	stores.push_back(store);
      }
    }; // class Loop
  } // namespace ast
} // namespace jit

using namespace jit::ast;

Node *dec_ast(Environment *env) {
  struct heap *heap = machine->heap;

  Declaration *decl_counter = new Declaration(_0); {
    Loop *loop = new Loop();
    /**/ decl_counter->set_inner(loop); {
      BinaryExpression *eq = new BinaryExpression(binop_eq_type);
      /**/ loop->set_test(eq); {
	Load *eq_left = new Load(7);
	/**/ eq->set_left(eq_left);
      } {
	IncrementExpression *eq_right = new IncrementExpression();
	/**/ eq->set_right(eq_right); {
	  Load *load_6 = new Load(6);
	  /**/ eq_right->set_subexpr(load_6);
	}
      }
    } {
      Load *result = new Load(6);
      /**/ loop->set_result(result);
    } {
      Store *store_6 = new Store(6);
      /**/ loop->add_store(store_6); {
	IncrementExpression *inc_6 = new IncrementExpression();
	/**/ store_6->set_subexpr(inc_6); {
	  Load *load_6 = new Load(6);
	  /**/ inc_6->set_subexpr(load_6);
	}
      }
    } {
      Store *store_7 = new Store(7);
      /**/ loop->add_store(store_7); {
	Load *load_7 = new Load(7);
	/**/ store_7->set_subexpr(load_7);
      }
    }
  }

  return decl_counter;
}

Node *fib_ast(Environment *env) {
  struct heap *heap = machine->heap;

  Declaration *decl_f0_f1 = new Declaration(CELL(_0, _1)); {
    Declaration *decl_counter = new Declaration(_0);
    /**/ decl_f0_f1->set_inner(decl_counter); {
      Loop *loop = new Loop();
      /**/ decl_counter->set_inner(loop); {
	BinaryExpression *eq = new BinaryExpression(binop_eq_type);
	/**/ loop->set_test(eq); {
	  Load *eq_left = new Load(15);
	  /**/ eq->set_left(eq_left);
	} {
	  Load *eq_right = new Load(6);
	  /**/ eq->set_right(eq_right);
	} 
      } {
	Load *result = new Load(28);
	/**/ loop->set_result(result);
      } {
	Store *store_6 = new Store(6);
	/**/ loop->add_store(store_6);
	IncrementExpression *inc_6 = new IncrementExpression();
	/**/ store_6->set_subexpr(inc_6);
	Load *load_6 = new Load(6);
	/**/ inc_6->set_subexpr(load_6);
      } {
	Store *store_28 = new Store(28);
	/**/ loop->add_store(store_28);
	Load *load_29 = new Load(29);
	/**/ store_28->set_subexpr(load_29);
      } {
	Store *store_29 = new Store(29);
	/**/ loop->add_store(store_29);
	BinaryExpression *add = new BinaryExpression(binop_add_type);
	/**/ store_29->set_subexpr(add);
	Load *add_left = new Load(28);
	/**/ add->set_left(add_left);
	Load *add_right = new Load(29);
	/**/ add->set_right(add_right);
      } {
	Store *store_15 = new Store(15);
	/**/ loop->add_store(store_15);
	Load *load_15 = new Load(15);
	/**/ store_15->set_subexpr(load_15);
      }
    }
  }

  return decl_f0_f1;
}

void test_jit(tagged_noun_t args) { //ZZZ
  // For testing, generate the AST that the pattern matcher *would*
  // generate when parsing "fib" in Nock:

  Environment *env = new Environment();
  bool do_fib = true;
  Node *root = (do_fib ? fib_ast(env) : dec_ast(env));
  
  root->dump(env, machine->file, 0);

  env->prep(root);
#if ARKHAM_LLVM
  env->compile(root);
#endif
  tagged_noun_t result = env->eval(root, args);

  // ZZZ
  if (env->failed) 
    ERROR0("Evaluation failed\n");
  else {
    printf("%s(", (do_fib ? "fib" : "dec")); noun_print(stdout, args, true); printf(")="); noun_print(stdout, result, true); printf("\n");
    UNSHARE(result, ENV_OWNER);
  }

  delete root;
  delete env;
}
