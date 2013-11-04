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

#include <sstream>
#include <string>
#include <vector>

#if ARKHAM_LLVM
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/ExecutionEngine/JITEventListener.h"
#include "llvm/GVMaterializer.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/PassManager.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/system_error.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Scalar.h"
// REVISIT: cache result of "getGlobalContext()"?
#if UINTPTR_MAX == UINT64_MAX
#define llvm_noun_type() Type::getInt64Ty(getGlobalContext())
#define LLVM_NOUN(noun) ConstantInt::get(getGlobalContext(), \
  APInt(64, (noun).value))
#else
#define llvm_noun_type() Type::getInt32Ty(getGlobalContext())
#define LLVM_NOUN(noun) ConstantInt::get(getGlobalContext(), \
  APInt(32, (noun).value))
#endif

using namespace llvm;
#endif /* ARKHAM_LLVM */

#include "arkham.h"
#include "mkpath.h"

#define ARKHAM_TRACE_DISASSEMBLY false
#define ARKHAM_TRACE_TRANSFORM false
#define ARKHAM_TRACE_LLVM_FUNCTIONS false
#define ARKHAM_TRACE_RLYEH false

#define FUNCTION_NAME "singleton"

#define L(noun) noun_get_left(noun)
#define R(noun) noun_get_right(noun)
#define T(noun) noun_get_type(noun)

#define ENV_FAIL(env, pstr, msg) env->fail(pstr, msg, __FILE__, __FUNCTION__, \
  __LINE__);
#define ENV_CHECK_VOID(env, p, msg) do { \
  const char *pstr = #p; \
  if (!(p)) { \
    ENV_FAIL(env, pstr, msg); return; \
  } \
} while(false)
#define ENV_CHECK(env, p, msg, val) do { \
  const char *pstr = #p; \
  if (!(p)) { \
    ENV_FAIL(env, pstr, msg) return val; \
  } \
} while(false)

__thread machine_t *machine;

#if ARKHAM_LLVM
typedef noun_t (*compiled_formula_fn_t)(noun_t noun);

typedef struct llvm_s {
  Module *module;
  ExecutionEngine *engine;
  FunctionPassManager *pass_manager;
  Function *uadd_with_overflow;
  compiled_formula_fn_t fn;
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
#if ARKHAM_TRACE_DISASSEMBLY
class TestJITEventListener : public JITEventListener {
public:
  virtual void NotifyFunctionEmitted(const Function &function,
                                     void *data, size_t size,
                                     const EmittedFunctionDetails &details) {
    // llvm-mc -disassemble -triple=x86_64-pc-linux-gnu < /tmp/disasm
    static char hex[] = "0123456789abcdef";
    INFO("%s %p %lu\n", __FUNCTION__, data, size);
    char *instructions = static_cast<char *>(data);
    FILE *file = machine->trace_file;
    for (int i = 0; i < size; ++i) {
      if (i > 0)
        fprintf(file, " ");
      char instruction = instructions[i];
      fprintf(file, "0x%c%c", hex[(instruction >> 4) & 0xf],
              hex[instruction & 0xf]);
    }
    fprintf(file, "\n");
  }
};
#endif /* ARKHAM_TRACE_DISASSEMBLY */

void llvm_store_function(llvm_t *llvm, Function *function) {
  llvm->fn = (compiled_formula_fn_t)llvm->engine->
    getPointerToFunction(function);
}

void llvm_lookup_and_store_function(llvm_t *llvm) {
  // XXX: don't crash on missing name
  llvm_store_function(llvm, llvm->engine->FindFunctionNamed(FUNCTION_NAME));
}

llvm_t *llvm_new_module(Module *module) {
  llvm_t *llvm = (llvm_t *)calloc(1, sizeof(llvm_t));

  llvm->module = module;
    
  // Create execution engine.
  std::string error;
  EngineBuilder builder = EngineBuilder(llvm->module).setErrorStr(&error);
  // XXX: check error
  if (false) {
    // XXX: do something here?
    TargetMachine *target = builder.selectTarget();
    target->Options.PrintMachineCode = true;
    llvm->engine = builder.create(target);
  } else {
    llvm->engine = builder.create();
  }
  if (!llvm->engine) {
    ERROR("Could not create ExecutionEngine: %s\n", error.c_str());
    exit(1); //XXX: do something
  }
    
#if ARKHAM_TRACE_DISASSEMBLY
  // XXX: (and be sure to free)
  llvm->engine->RegisterJITEventListener(new TestJITEventListener());
#endif

  std::vector<Type*> parameter_types;
  parameter_types.push_back(llvm_noun_type());
  FunctionType *function1_type = FunctionType::get(llvm_noun_type(),
                                                   parameter_types,
                                                   /* is_vararg */ false);
  llvm->uadd_with_overflow = Intrinsic::getDeclaration(llvm->module,
    Intrinsic::uadd_with_overflow, parameter_types);
  parameter_types.push_back(llvm_noun_type());
  FunctionType *function2_type = FunctionType::get(llvm_noun_type(),
                                                   parameter_types,
                                                   /* is_vararg */ false);

  Function *atom_increment_fn = llvm->engine->
    FindFunctionNamed("atom_increment");
  if (atom_increment_fn == NULL) {
    atom_increment_fn = Function::Create(function1_type,
                                         Function::ExternalLinkage,
                                         "atom_increment",
                                         llvm->module);
  }
  llvm->engine->addGlobalMapping(atom_increment_fn, (void *)atom_increment);

  Function *atom_equals_fn = llvm->engine->FindFunctionNamed("atom_equals");
  if (atom_equals_fn == NULL) {
    atom_equals_fn = Function::Create(function2_type,
                                      Function::ExternalLinkage,
                                      "atom_equals", llvm->module);
  }
  llvm->engine->addGlobalMapping(atom_equals_fn, (void *)atom_equals);

  Function *atom_add_fn = llvm->engine->FindFunctionNamed("atom_add");
  if (atom_add_fn == NULL) {
    atom_add_fn = Function::Create(function2_type,
                                   Function::ExternalLinkage,
                                   "atom_add", llvm->module);
  }
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

llvm_t *llvm_new(const char *module_name) {
  return llvm_new_module(new Module(module_name, getGlobalContext()));
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

std::string machine_path(machine_t *machine) {
  std::ostringstream filename;
  filename << machine->home_directory << "/." << machine->executable_name;
  return filename.str();
}

std::string machine_jet_file(machine_t *machine, satom_t index) {
  std::ostringstream filename;
  filename << "jet-" << index << ".bc";
  return filename.str();
}

std::string machine_jet_dir(machine_t *machine, satom_t index) {
  std::ostringstream filename;
  filename << machine_path(machine);
  return filename.str();
}

std::string machine_jet_path(machine_t *machine, satom_t index) {
  std::ostringstream filename;
  filename << machine_jet_dir(machine, index) << 
    "/" << machine_jet_file(machine, index);
  return filename.str();
}

static inline noun_t
noun_nop(noun_t noun) {
  return noun;
}

#if ARKHAM_USE_NURSERY
#define SHARE(n, o) noun_nop(n)
#define UNSHARE(n, o)
#elif ALLOC_DEBUG
#define SHARE(n, o) noun_share(n, machine->heap, o)
#define UNSHARE(n, o) noun_unshare(n, machine->heap, true, o)
#else /* #if !ARKHAM_USE_NURSERY && !ALLOC_DEBUG */
#define SHARE(n, o) noun_share(n, machine->heap)
#define UNSHARE(n, o) noun_unshare(n, machine->heap, true)
#endif /* #if ARKHAM_USE_NURSERY */

#define ASSIGN(l, r, o) do { \
  noun_t old = l; l = SHARE(r, o) ; UNSHARE(old, o); \
} while (false)

// Addresses a node in a tree: an argument to the slash operator.
typedef uint32_t jit_address_t;
#define JIT_ADDRESS_FMT PRIu32
#define JIT_ADDRESS_MAX (UINT32_MAX-1)
#define JIT_ADDRESS_UNDEFINED UINT32_MAX

// An index into the local variable list.
typedef uint32_t jit_index_t;
#define JIT_INDEX_FMT PRIu32
#define JIT_INDEX_MAX (UINT32_MAX-1)
#define JIT_INDEX_UNDEFINED UINT32_MAX

// Shouldn't be too big (uint16 is overkill).
#define JIT_STACK_MAX UINT16_MAX

namespace jit {
  namespace rlyeh {
    class LocalVariable {
    public:
      char *name;
      noun_metainfo_t *owner;
      noun_t value;
#if ARKHAM_LLVM
      Value *llvm_value;
      noun_t initial_value;
#endif

      LocalVariable(char *name, noun_t initial_value, noun_metainfo_t *owner) {
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

      void set_value(noun_t value) {
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
      virtual void eval_rlyeh(Environment *env) = 0;
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
      root_t *args_root;
      root_t *local_variable_index_map;
      root_t *args_placeholder;
      root_t *loop_body_placeholder;
#if ARKHAM_LLVM
      llvm_t *m_llvm;
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

      Environment(std::string module_name) {
        heap_t *heap = machine->heap;

        // Use an "impossible" value as the placeholder:
        BATOMS(2);
        args_placeholder = root_new(heap, 
                                    BATOM_ULONG(JIT_INDEX_MAX + 1UL));
        SHARE(args_placeholder->noun, ENV_OWNER);
        loop_body_placeholder = root_new(heap,
                                         BATOM_ULONG(JIT_INDEX_MAX + 2UL));
        END_BATOMS();
        SHARE(loop_body_placeholder->noun, ENV_OWNER);
        local_variable_index_map = root_new(heap, args_placeholder->noun);
        SHARE(local_variable_index_map->noun, ENV_OWNER);
    
        current_stack_index = -1;
        args_root = root_new(heap, _UNDEFINED);

#if ARKHAM_LLVM
        m_llvm = llvm_new(module_name.c_str());
#endif
      }

      ~Environment() {
        heap_t *heap = machine->heap;

        UNSHARE(args_placeholder->noun, ENV_OWNER);
        root_delete(heap, args_placeholder);
        UNSHARE(loop_body_placeholder->noun, ENV_OWNER);
        root_delete(heap, loop_body_placeholder);
        UNSHARE(local_variable_index_map->noun, ENV_OWNER);
        root_delete(heap, local_variable_index_map);
        if (NOUN_IS_DEFINED(args_root->noun))
          UNSHARE(args_root, ENV_OWNER);
        root_delete(heap, args_root);
#if ARKHAM_LLVM
        // REVISIT: Deleting the function while it is referred to by the
        // module causes problems.  Figure out what (if anything) we need to
        // do after compilation to free resources.
        // if (function != NULL)
        //   delete function;
        if (builder != NULL)
          delete builder;
        if (m_llvm != NULL && failed)
          llvm_delete(m_llvm);
#endif
      }

#if ARKHAM_LLVM
      llvm_t *llvm() { return m_llvm; }
#endif

      void fail(const char *predicate, const char *failure_message,
                const char *file_name, const char *function_name,
                int line_number) {
        this->failed = true;
        this->predicate = predicate;
        this->failure_message = failure_message;
        this->file_name = file_name;
        this->function_name = function_name;
        this->line_number = line_number;

        arkham_log(ERROR_PREFIX " Failure to compile: predicate = '%s', "
                   "message = '%s', file = '%s', function = '%s', line = %d\n",
                   predicate, failure_message, file_name, function_name,
                   line_number);
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
        IRBuilder<> builder(&function->getEntryBlock(),
                            function->getEntryBlock().begin());
        return builder.CreateAlloca(llvm_noun_type(), 0, var_name);
      }
#endif /* ARKHAM_LLVM */

      jit_index_t allocate_local(noun_t initial_value) {
        if (failed) return 0;

        ENV_CHECK(this, next_local_variable_index < JIT_INDEX_MAX,
                  "Too many local variable declarations", 0);
        jit_index_t index = next_local_variable_index++;
        locals.resize(index + 1, LocalVariable(make_var_name("local", index),
                                               initial_value, LOCALS_OWNER));
#if ARKHAM_LLVM
        LocalVariable &local = locals.at(index);
        local.llvm_value = compile_alloca(local.name);
#endif /* ARKHAM_LLVM */
        next_locals.resize(index + 1, LocalVariable(make_var_name(
          "next_local", index), initial_value, LOCALS_OWNER));
#if ARKHAM_LLVM
        LocalVariable &next_local = next_locals.at(index);
        next_local.llvm_value = compile_alloca(next_local.name);
#endif /* ARKHAM_LLVM */

        return index;
      }

      // Allocate a slot on the stack for an address.
      // 'address' can represent an argument or a declared variable.
      // 'address' is a Nock (slash) tree traversal descriptor.
      void allocate_address(jit_address_t address) {
        heap_t *heap = machine->heap;
        ENV_CHECK_VOID(this, address >= 1, "Invalid address");

        // 'depth' is an aid to tree traversal.
        // It is the length of the traversal (the depth of the tree
        // along the traversal).
        const int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);
        // 'choice' describes the path of the traversal: it remembers
        // the 'left' versus 'right' decision at each level of the
        // traversal.
        bool choice[depth];
        // 'ancestors' are all of the nouns encountered during the traversal.
        vec_t ancestors;
        vec_init(&ancestors, sizeof(noun_t));
        noun_t undef = _UNDEFINED;
        vec_resize(&ancestors, depth, &undef);

#if ARKHAM_USE_NURSERY
        void *roots_hook_handle = roots_hook_add(vec_do_roots, &ancestors);
#endif

        // 'local_variable_index_map' is a tree of cells and atoms.
        // Each leaf addressed by 'address' is an index.
        // Each index represents a slot on the stack.

        // 'noun' starts as the root of the index map.
        // 'noun' ends as leaf whose values is an stack slot index.
        noun_t noun = local_variable_index_map->noun;
        // 'mask' is an aid to tree traversal.
        // It is used to guide the walk of the tree based on 'address'.
        // 'mask' and 'address' are used to together to determine
        // whether to 'descend left' or 'descend right'.
        satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
        // Run through the bits from left to right (and therefore the
        // tree from root to leaf):
        for (int i = 0; i < depth; ++i) {
          ENV_CHECK_VOID(this, !NOUN_EQUALS(noun, loop_body_placeholder->noun),
                         "Cannot refer to the loop body");

          // Determine if we've allocated this address already. If we
          // find a placeholder along the path then that means we have
          // not. It further means that we are looking up an argument
          // and not a local variable since local variables already
          // (at this point) all have entries in 'local_variable_index_map'.
          if (NOUN_EQUALS(noun, args_placeholder->noun)) {
            // We have not allocated this address already.
            CELLS(1);
            noun = CELL(args_placeholder->noun, args_placeholder->noun);
            END_CELLS();

            if (NOUN_IS_UNDEFINED(args_root->noun)) {
              // This is the first allocation for any argument.
              // All subsequent arguments will be rooted at
              // 'args_root'.
              args_root->noun = noun;
              SHARE(args_root->noun, ENV_OWNER);
            }
          }
    
          // Remember the ancestor for this level:
          vec_set(&ancestors, i, &noun);
          // Remember the choice for this level:
          choice[i] = (mask & address);
          // Update the current noun:
          noun = choice[i] ? noun_get_right(noun) : noun_get_left(noun);
          // Prepare the mask for the next iteration:
          mask = (mask >> 1);
        }
  
        ENV_CHECK_VOID(this, !NOUN_EQUALS(noun, loop_body_placeholder->noun),
                       "Cannot refer to the loop body");

        // Determine if we've allocated this address already. If we
        // find a placeholder along the path then that means we have
        // not. It further means that we are looking up an argument
        // and not a local variable since local variables already
        // (at this point) all have entries in 'local_variable_index_map'.
        if (NOUN_EQUALS(noun, args_placeholder->noun)) {
          // This is an undeclared reference, so it must be an
          // argument.  We are fetching an undeclared local variable
          // value: i.e. an argument.
          // Allocate an index and initialize the local variable.
          // Allocate a local variable slot for an argument:
          noun = satom_as_noun(allocate_local(_UNDEFINED));

          if (NOUN_IS_UNDEFINED(args_root->noun)) {
            // This is the first allocation for any address (either
            // argument or local variable).  All subsequent arguments
            // will be rooted at 'args_root'.
            args_root->noun = noun;
            SHARE(args_root->noun, ENV_OWNER);
          }

          // Build a new tree with the placeholder replaced by the 
          // newly allocated stack slot index.
          root_t *n = root_new(heap, noun);
          int i;
          for (i = depth - 1; i >= 0; --i) {
            CELLS(1);
            noun_t ancestor = *(noun_t *)vec_get(&ancestors, i);
            if (choice[i])
              n->noun = CELL(L(ancestor), n->noun);
            else
              n->noun = CELL(n->noun, R(ancestor));
            vec_set(&ancestors, i, &(n->noun));
            END_CELLS();
          }

          // If we got to the root of the index map then update 
          // variable which refers to it.
          ASSIGN(local_variable_index_map->noun, n->noun, ENV_OWNER);
          root_delete(heap, n);
        }

#if ARKHAM_USE_NURSERY
        roots_hook_remove(roots_hook_handle);
#endif

        vec_destroy(&ancestors);

        ENV_CHECK_VOID(this, noun_get_type(noun) == satom_type,
                       "Type mismatch");
        ENV_CHECK_VOID(this, noun_as_satom(noun) <= JIT_INDEX_MAX,
                       "Invalid index");
      }

      /* no-gc */
      jit_index_t get_index_of_address(jit_address_t address) {
        ENV_CHECK(this, address >= 1, "Invalid address", 0);

        noun_t noun = local_variable_index_map->noun;
        ENV_CHECK(this, !NOUN_EQUALS(noun, loop_body_placeholder->noun),
                  "Cannot refer to the loop body", 0);
        ENV_CHECK(this, !NOUN_EQUALS(noun, args_placeholder->noun),
                  "Undefined value", 0);
        int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);

        // Run through the bits from left to right:
        satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
        for (int i = 0; i < depth; ++i) {    
          noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
          ENV_CHECK(this, !NOUN_EQUALS(noun, loop_body_placeholder->noun),
                    "Cannot refer to the loop body", 0);
          ENV_CHECK(this, !NOUN_EQUALS(noun, args_placeholder->noun),
                    "Undefined value", 0);
          mask = (mask >> 1);
        }

        ENV_CHECK(this, noun_get_type(noun) == satom_type, "Type mismatch", 0);
        satom_t index_satom = noun_as_satom(noun);
        ENV_CHECK(this, index_satom <= JIT_INDEX_MAX, "Invalid address", 0);
        return (jit_index_t)index_satom;
      }

      /* Callers must unshare the value. */
      noun_t get_stack(jit_index_t index) {
        if (failed) return _UNDEFINED;

        ENV_CHECK(this, index <= max_stack_index, "Invalid index", _UNDEFINED);

        noun_t value = stack.at(index).value;
        ENV_CHECK(this, NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

        return value;
      }

      void set_stack(jit_index_t index, noun_t value) {
        if (failed) return;

        ENV_CHECK_VOID(this, index <= max_stack_index, "Invalid index");

        stack.at(index).set_value(value);
      }

      noun_t get_local(jit_index_t index) {
        if (failed) return _UNDEFINED;

        ENV_CHECK(this, index < locals.size(), "Invalid index", _UNDEFINED);

        noun_t value = locals.at(index).value;
        ENV_CHECK(this, NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

        return value;
      }

      void set_local(jit_index_t index, noun_t value) {
        if (failed) return;

        ENV_CHECK_VOID(this, index < next_locals.size(), "Invalid index");
        ENV_CHECK_VOID(this, NOUN_IS_UNDEFINED(next_locals.at(index).value),
                       "Overwritten value");
        ENV_CHECK_VOID(this, NOUN_IS_DEFINED(value), "Undefined value");

        next_locals.at(index).set_value(value);
      }

      /* no-gc */
      void initialize_local(jit_index_t index, noun_t value) {
        if (failed) return;

        ENV_CHECK_VOID(this, index < locals.size(), "Invalid index");
        ENV_CHECK_VOID(this, NOUN_IS_UNDEFINED(locals.at(index).value),
                       "Overwritten value");
        ENV_CHECK_VOID(this, NOUN_IS_DEFINED(value), "Undefined value");

        locals.at(index).set_value(value);
      }

      void declare_loop() {
        heap_t *heap = machine->heap;
        CELLS(1);
        ASSIGN(local_variable_index_map->noun, CELL(
          loop_body_placeholder->noun, local_variable_index_map->noun),
          ENV_OWNER);
      }

      /* no-gc */
      void initialize_args(noun_t args, noun_t args_root) {
        if (noun_get_type(args) == cell_type) {
          ENV_CHECK_VOID(this, noun_get_type(args_root) == cell_type,
                         "Argument type mismatch");
          initialize_args(noun_get_left(args), noun_get_left(args_root));
          initialize_args(noun_get_right(args), noun_get_right(args_root));
        } else {
          ENV_CHECK_VOID(this, noun_get_type(args_root) == satom_type,
                         "Type mismatch");
          satom_t index_satom = noun_as_satom(args_root);
          ENV_CHECK_VOID(this, index_satom <= JIT_INDEX_MAX, "Invalid index");
          initialize_local((jit_index_t)index_satom, args);
        }
      }

      noun_t eval_rlyeh(Node *oper, noun_t args) {
        ENV_CHECK(this, NOUN_IS_UNDEFINED(args) == 
                  NOUN_IS_UNDEFINED(args_root->noun), "Arguments mismatch",
                  _UNDEFINED);

        initialize_args(args, args_root->noun);

        oper->eval_rlyeh(this);
    
        noun_t result = failed ? _UNDEFINED : get_stack(0);
        SHARE(result, ENV_OWNER);
        set_stack(0, _UNDEFINED);
        return result;
      }

#if ARKHAM_LLVM
      typedef struct {
        Function::arg_iterator iter;  
      } iter_t;
  
      /* no-gc */
      void compile_copy_args_to_locals(noun_t args, iter_t *iter) {
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
      llvm_t *compile(Node *oper, satom_t index) {
        iter_t iter = (iter_t){ .iter = function->arg_begin() };
        compile_copy_args_to_locals(args_root->noun, &iter);
        // Set initial values for locals:
        for(std::vector<LocalVariable>::iterator it = locals.begin();
            it != locals.end(); ++it)
          if (NOUN_IS_DEFINED(it->initial_value))
            builder->CreateStore(LLVM_NOUN(it->initial_value), it->llvm_value);
    
        Value *body = oper->compile(this);
        if (failed) return NULL;
    
        // Finish off the function.
        builder->CreateRet(body);
    
        // Print the function (before verification and optimization).
        if (ARKHAM_TRACE_LLVM_FUNCTIONS)
          function->dump();
    
        // Verify the generated code, checking for consistency.
        ENV_CHECK(this, !verifyFunction(*(function),
          /*XXX*/ AbortProcessAction), "Invalid function", NULL);
    
        // Print the function (after verification).
        if (ARKHAM_TRACE_LLVM_FUNCTIONS)
          function->dump();
    
        // Optimize the function.
        llvm()->pass_manager->run(*(function));
    
        // Print the function (after optimization).
        if (ARKHAM_TRACE_LLVM_FUNCTIONS)
          function->dump();
    
        mkpath(machine_jet_dir(machine, index).c_str(),
               S_IRUSR | S_IWUSR | S_IXUSR);

        std::string filename = machine_jet_path(machine, index);
        std::string error;
        raw_fd_ostream stream(filename.c_str(), error);
        if (!error.empty()) {
          INFO("Could not open bitcode file for writing '%s': '%s'\n",
               filename.c_str(), error.c_str());
        } else {
          // TODO: Output Rlyeh when saving bitcode
          INFO("Wrote bitcode to file '%s'\n", filename.c_str());
          WriteBitcodeToFile(llvm()->module, stream);
        }

        llvm_store_function(llvm(), function);

        return llvm();
      }
#endif /* ARKHAM_LLVM */

      void prep(Node *oper) {
#if ARKHAM_LLVM
        builder = new IRBuilder<> (getGlobalContext());
    
        // REVISIT: calling convention fastcc? (Function::setCallingConv())
    
        // Create argument list.
        std::vector<Type*> params(1 /*XXX*/, llvm_noun_type());
    
        // Create function type.
        FunctionType *functionType = FunctionType::get(llvm_noun_type(),
                                                       params, false);
    
        // Create function.
        function = Function::Create(functionType, Function::PrivateLinkage,
          std::string(FUNCTION_NAME), llvm()->module);
    
        // Create basic block.
        BasicBlock *block = BasicBlock::Create(getGlobalContext(), "entry",
                                               function);
        builder->SetInsertPoint(block);
#endif /* ARKHAM_LLVM */
    
        oper->prep(this);
    
        for (int i = 0; i <= max_stack_index; ++i)
          stack.resize(i + 1, LocalVariable(make_var_name("stack", i),
            _UNDEFINED, STACK_OWNER));
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
        incoming_to_else.push_back((incoming_t){
          .value = value,
          .block = block 
        });
      }

      PHINode *begin(Environment *env, Type *type,
                     std::vector<incoming_t> &incoming) {
        size_t size = incoming.size();
        if (size > 0) {
          PHINode *phi = env->builder->CreatePHI(type, size);
          int i = 0;
          for(std::vector<incoming_t>::iterator it = incoming.begin();
              it != incoming.end(); ++it) {
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
        incoming_to_merge.push_back((incoming_t){
          .value = value,
          .block = block
        });
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
      typedef Value * (*if_atoms_fn_t)(Environment *env, Value *left,
        Value *right, IfThenElseBlocks *blocks, bool *add_default_branch);
#endif

#if ARKHAM_LLVM
      static Value *if_else(Environment *env, const char *prefix, Type *type,
                            Value *left, Value *right, Value *test,
                            if_atoms_fn_t if_atoms_fn,
                            if_atoms_fn_t if_not_atoms_fn,
                            IfThenElseBlocks *parent_blocks) {
        IfThenElseBlocks blocks(parent_blocks);
        bool add_default_branch;
        char buffer[strlen(prefix) + 7];

        snprintf(buffer, sizeof(buffer), "%s.if", prefix);
        blocks.if_block = BasicBlock::Create(getGlobalContext(), buffer,
                                             env->function);
        snprintf(buffer, sizeof(buffer), "%s.else", prefix);
        blocks.else_block = BasicBlock::Create(getGlobalContext(), buffer);
        snprintf(buffer, sizeof(buffer), "%s.merge", prefix);
        blocks.merge_block = BasicBlock::Create(getGlobalContext(), buffer);

        blocks.add_incoming_to_else(UndefValue::get(llvm_noun_type()),
                                    env->builder->GetInsertBlock());
        env->builder->CreateCondBr(test, blocks.if_block, blocks.else_block);

        // Emit 'then' value.
        env->builder->SetInsertPoint(blocks.if_block);
        add_default_branch = true;
        Value *if_value = if_atoms_fn(env, left, right, &blocks,
                                      &add_default_branch);
        // Codegen of 'then' can change the current block, update
        // if_block for the PHI.
        blocks.if_block = env->builder->GetInsertBlock();
        if (add_default_branch) {
          blocks.add_incoming_to_merge(if_value, blocks.if_block);
          env->builder->CreateBr(blocks.merge_block);
        }

        // Emit 'else' block.
        env->function->getBasicBlockList().push_back(blocks.else_block);
        env->builder->SetInsertPoint(blocks.else_block);
        blocks.begin_else(env, llvm_noun_type());
        add_default_branch = true;
        Value *else_value = if_not_atoms_fn(env, left, right, &blocks,
                                            &add_default_branch);
        // Codegen of 'else' can change the current block, update
        // else_block for the PHI.
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

      static Value *if_atoms(Environment *env, const char *prefix, Type *type,
                             Value *left, Value *right,
                             if_atoms_fn_t if_atoms_fn,
                             if_atoms_fn_t if_not_atoms_fn) {
        Value *both = env->builder->CreateOr(left, right);
        Value *low_bit = env->builder->CreateAnd(both,
          LLVM_NOUN(RAW_VALUE_AS_NOUN(NOUN_NOT_SATOM_FLAG)));
        Value *test = env->builder->CreateICmpEQ(low_bit,
          LLVM_NOUN(RAW_VALUE_AS_NOUN(0)));

        return if_else(env, prefix, type, left, right, test, if_atoms_fn,
          if_not_atoms_fn, /* parent_blocks */ NULL);
      }
#endif
    };

    class Declaration : public Node {
      /* protected */ public:
      Node *inner;
      root_t *local_variable_initial_values;
      root_t *local_variable_index_map;

    private:
      jit_address_t get_root_address(noun_t env_local_variable_index_map,
                                     jit_address_t address) {
        if (NOUN_EQUALS(local_variable_index_map->noun,
                        env_local_variable_index_map)) {
          return address;
        } else if (noun_get_type(env_local_variable_index_map) == cell_type) {
          jit_address_t left_address = get_root_address(noun_get_left(
            env_local_variable_index_map), address * 2);
          if (left_address != JIT_ADDRESS_UNDEFINED)
            return left_address;
          else
            return get_root_address(noun_get_right(
              env_local_variable_index_map), address * 2 + 1);
        } else
          return JIT_ADDRESS_UNDEFINED;
      }

      /* no-gc */
      void dump_impl(Environment *env, FILE *fp, int indent,
                     noun_t local_variable_initial_values,
                     jit_address_t address) {
        if (noun_get_type(local_variable_initial_values) == cell_type) {
          dump_impl(env, fp, indent, noun_get_left(
            local_variable_initial_values), address * 2);
          dump_impl(env, fp, indent, noun_get_right(
            local_variable_initial_values), address * 2 + 1);
        } else {
          // Allocate a local variable slot for a declared variable:
          env->indent(fp, indent + 1);
          fprintf(fp, "store(@%" JIT_ADDRESS_FMT ", %" SATOM_FMT ")\n",
                  address, noun_as_satom(local_variable_initial_values));
        }
      }

      /* no-gc */
      int pre_prep_impl(Environment *env,
                        noun_t local_variable_initial_values) {
        if (noun_get_type(local_variable_initial_values) == cell_type) {
          return 
            pre_prep_impl(env, noun_get_left(local_variable_initial_values)) +
            pre_prep_impl(env, noun_get_right(local_variable_initial_values)) +
            1;
        } else {
          return 0;
        }
      }

      /* no-gc */
      noun_t prep_impl(Environment *env,
                       noun_t local_variable_initial_values,
                       CELLS_DECL) {
        if (noun_get_type(local_variable_initial_values) == cell_type) {
          noun_t left = prep_impl(env, noun_get_left(
            local_variable_initial_values), CELLS_ARG);
          noun_t right = prep_impl(env, noun_get_right(
            local_variable_initial_values), CELLS_ARG);
          heap_t *heap = machine->heap;
          return CELL(left, right);
        } else {
          // Allocate a local variable slot for a declared variable:
          return satom_as_noun(env->allocate_local(
            local_variable_initial_values));
        }
      }

      /* no-gc */
      void eval_impl(Environment *env, noun_t local_variable_initial_values,
                     noun_t local_variable_index_map) {
        if (noun_get_type(local_variable_initial_values) == cell_type) {
          eval_impl(env, noun_get_left(local_variable_initial_values),
            noun_get_left(local_variable_index_map));
          eval_impl(env, noun_get_right(local_variable_initial_values),
            noun_get_right(local_variable_index_map));
        } else {
          satom_t index = noun_as_satom(local_variable_index_map);
          ENV_CHECK_VOID(env, index <= JIT_INDEX_MAX, "Invalid index");
          env->initialize_local((jit_index_t)index,
                                local_variable_initial_values);
        }
      }

    public:
      Declaration(noun_t local_variable_initial_values): inner(NULL) {
        SHARE(local_variable_initial_values, RLYEH_OWNER);
        this->local_variable_initial_values = 
          root_new(machine->heap, local_variable_initial_values);
        this->local_variable_index_map = root_new(machine->heap, _UNDEFINED);
      }

      ~Declaration() {
        if (NOUN_IS_DEFINED(local_variable_index_map->noun))
          UNSHARE(local_variable_index_map->noun, RLYEH_OWNER);
        UNSHARE(local_variable_initial_values->noun, RLYEH_OWNER);
        root_delete(machine->heap, local_variable_initial_values);
        root_delete(machine->heap, local_variable_index_map);
        if (inner != NULL)
          delete inner;
      }

      void dump(Environment *env, FILE *fp, int indent) {
        if (env->failed) return;
        env->indent(fp, indent); 
        fprintf(fp, "declare(\n"); 
        dump_impl(env, fp, indent, local_variable_initial_values->noun,
                  get_root_address(env->local_variable_index_map->noun, 1));
        inner->dump(env, fp, indent + 1);
        env->indent(fp, indent); fprintf(fp, ")\n");
      }

      void prep(Environment *env) {
        if (env->failed) return;

        heap_t *heap = machine->heap;

        {
          CELLS(pre_prep_impl(env, local_variable_index_map->noun));
          local_variable_index_map->noun = prep_impl(env,
            local_variable_initial_values->noun, CELLS_ARG);
          SHARE(local_variable_index_map->noun, RLYEH_OWNER);
        }

        {
          CELLS(1);
          noun_t new_local_variable_index_map = CELL(
            local_variable_index_map->noun,
            env->local_variable_index_map->noun);
          ASSIGN(env->local_variable_index_map->noun,
            new_local_variable_index_map, ENV_OWNER);
        }

        inner->prep(env);
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
        if (env->failed) return NULL;
        return inner->compile(env);
      }
#endif /* ARKHAM_LLVM */

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;
        eval_impl(env, local_variable_initial_values->noun,
                  local_variable_index_map->noun);
        inner->eval_rlyeh(env);
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
      BinaryExpression(enum binop_type type): 
        type(type), left(NULL), right(NULL) {  }

      ~BinaryExpression() {
        if (left != NULL)
          delete left;
        if (right != NULL)
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
      static Value *eq_if_atoms(Environment *env, Value *left, Value *right,
                                IfThenElseBlocks *blocks,
                                bool *add_default_branch) {
        return env->builder->CreateICmpEQ(left, right);
      }

      static Value *eq_if_not_atoms(Environment *env, Value *left,
                                    Value *right, IfThenElseBlocks *blocks,
                                    bool *add_default_branch) {
        return env->builder->CreateICmpEQ(env->builder->CreateCall2(
          env->llvm()->module->getFunction("atom_equals"), left, right),
          LLVM_NOUN(_YES));
      }

      static Value *if_overflow(Environment *env, Value *sum, Value *unused,
                                IfThenElseBlocks *blocks,
                                bool *add_default_branch) {
        blocks->parent->add_incoming_to_else(UndefValue::get(llvm_noun_type()),
                                             blocks->if_block);
        env->builder->CreateBr(blocks->parent->else_block);
        *add_default_branch = false;
        return sum;
      }

      static Value *if_not_overflow(Environment *env, Value *sum,
                                    Value *unused, IfThenElseBlocks *blocks,
                                    bool *add_default_branch) {
        return sum;
      }

      static Value *add_if_atoms(Environment *env, Value *left, Value *right,
                                 IfThenElseBlocks *blocks,
                                 bool *add_default_branch) {
        Value *result = env->builder->CreateCall2(
          env->llvm()->uadd_with_overflow, left, right);
        Value *sum = env->builder->CreateExtractValue(result, 0);
        Value *overflow = env->builder->CreateExtractValue(result, 1);
        return if_else(env, "add.check.overflow", llvm_noun_type(), sum, NULL,
                       overflow, if_overflow, if_not_overflow,
                       /* parent_blocks */ blocks);
      }

      static Value *add_if_not_atoms(Environment *env, Value *left,
                                     Value *right, IfThenElseBlocks *blocks,
                                     bool *add_default_branch) {
        return env->builder->CreateCall2(env->llvm()->module->getFunction(
          "atom_add"), left, right);
      }

      Value *compile(Environment *env) {
        if (env->failed) return NULL;
    
        Value *left = this->left->compile(env);
        Value *right = this->right->compile(env);
    
        switch (type) {
        case binop_eq_type: {
          return if_atoms(env, "eq", Type::getInt1Ty(getGlobalContext()), left,
                          right, eq_if_atoms, eq_if_not_atoms);
        }
        case binop_add_type: {
          return if_atoms(env, "add", llvm_noun_type(), left, right,
                          add_if_atoms, add_if_not_atoms);
        }
        }
    
        return NULL;
      }
#endif /* ARKHAM_LLVM */

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        left->eval_rlyeh(env);
        right->eval_rlyeh(env);
    
        noun_t n1 = env->get_stack(stack_index);
        noun_t n2 = env->get_stack(stack_index + 1);
    
        if (!env->failed) {
          switch (type) {
          case binop_eq_type:
            env->set_stack(stack_index, atom_equals(n1, n2));
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
      IncrementExpression(): subexpr(NULL) { }

      ~IncrementExpression() {
        if (subexpr != NULL)
          delete subexpr;
      }

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        subexpr->eval_rlyeh(env);
    
        env->set_stack(stack_index, atom_increment(
          env->get_stack(stack_index)));
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
      static Value *inc_if_atoms(Environment *env, Value *subexpr,
                                 Value *unused, IfThenElseBlocks *blocks,
                                 bool *add_default_branch) {
        return env->builder->CreateAdd(subexpr, LLVM_NOUN(_1));
      }
  
      static Value *inc_if_not_atoms(Environment *env, Value *subexpr,
                                     Value *unused, IfThenElseBlocks *blocks,
                                     bool *add_default_branch) {
        return env->builder->CreateCall(env->llvm()->module->getFunction(
          "atom_increment"), subexpr);
      }

      Value *compile(Environment *env) {
        Value *subexpr_value = subexpr->compile(env);
        Value *test = env->builder->CreateICmpULT(subexpr_value,
          LLVM_NOUN(satom_as_noun(SATOM_MAX)));
    
        return if_else(env, "inc", llvm_noun_type(), subexpr_value, NULL, test,
          inc_if_atoms, inc_if_not_atoms, /* parent_blocks */ NULL);
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
    
        env->indent(fp, indent); fprintf(fp, "load(@%" JIT_ADDRESS_FMT ")",
          address);
      }

      void prep(Environment *env) {
        if (env->failed) return;
    
        env->allocate_address(address);

        stack_index = ++env->current_stack_index; 
        if (env->current_stack_index > env->max_stack_index)
          env->max_stack_index = env->current_stack_index;
      }

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        env->set_stack(stack_index, env->get_local(env->get_index_of_address(
          address)));
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
        return env->builder->CreateLoad(env->locals.at(
          env->get_index_of_address(address)).llvm_value);
      }
#endif /* ARKHAM_LLVM */
    }; // class Load

    class Store : public Expression {
      /* protected */ public:
      jit_address_t address;
      Expression *subexpr;

    public:
      Store(jit_address_t address): subexpr(NULL) {
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
        fprintf(fp, ", @%" JIT_ADDRESS_FMT ")", address);
      }

      void prep(Environment *env) {
        if (env->failed) return;

        subexpr->prep(env);

        env->allocate_address(address);
    
        stack_index = env->current_stack_index--;
      }

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        subexpr->eval_rlyeh(env);

        env->set_local(env->get_index_of_address(address), env->get_stack(
          stack_index));
        env->set_stack(stack_index, _UNDEFINED);
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
        return env->builder->CreateStore(subexpr->compile(env),
          env->next_locals.at(env->get_index_of_address(address)).llvm_value);
      }
#endif /* ARKHAM_LLVM */

#if ARKHAM_LLVM
      Value *compile_copy(Environment *env) {
        const LocalVariable &local = env->locals.at(
          env->get_index_of_address(address));
        const LocalVariable &next_local = env->next_locals.at(
          env->get_index_of_address(address));
        return env->builder->CreateStore(env->builder->CreateLoad(
          next_local.llvm_value), local.llvm_value);
      }
#endif /* ARKHAM_LLVM */

      void set_subexpr(Expression *subexpr) {
        ASSERT(this->subexpr == NULL, "this->subexpr == NULL\n");
        this->subexpr = subexpr;
        subexpr->outer = this;
      }
    }; // class Store

    class Iteration : public Expression {
      /* protected */ public:
      std::vector<Store *> stores;

    public:
      ~Iteration() {
        for(std::vector<Store *>::iterator it = stores.begin();
            it != stores.end(); ++it)
          delete *it;
      }

      void dump(Environment *env, FILE *fp, int indent) {
        if (env->failed) return;

        for(std::vector<Store *>::iterator it = stores.begin();
            it != stores.end(); ++it) {
          if (it != stores.begin())
            fprintf(fp, ", ");
          (*it)->dump(env, fp, -1);
        }
      }

      void prep(Environment *env) {
        if (env->failed) return;

        for(std::vector<Store *>::iterator it = stores.begin();
            it != stores.end(); ++it)
          (*it)->prep(env);
      }

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        for(std::vector<Store *>::iterator it = stores.begin();
            it != stores.end(); ++it)
          (*it)->eval_rlyeh(env);
        // Copy the locals for the next iteration:
        env->copy_locals();
      }

#if ARKHAM_LLVM
      Value *compile(Environment *env) {
        {
          for(std::vector<Store *>::iterator it = stores.begin();
              it != stores.end(); ++it)
            (*it)->compile(env);
        }
        {
          for(std::vector<Store *>::iterator it = stores.begin();
              it != stores.end(); ++it)
            (*it)->compile_copy(env);
        }
        return NULL;
      }
#endif /* ARKHAM_LLVM */

      void add_store(Store *store) {
        stores.push_back(store);
      }
    }; // class Iteration

    class Loop : public Expression {
      /* protected */ public:
      Expression *test;
      Expression *result;
      Iteration *iteration;

    public:
      Loop(): test(NULL), result(NULL), iteration(NULL) { }

      ~Loop() {
        if (test != NULL)
          delete test;
        if (result != NULL)
          delete result;
        if (iteration != NULL)
          delete iteration;
      }

      void dump(Environment *env, FILE *fp, int indent) {
        if (env->failed) return;

        env->indent(fp, indent); fprintf(fp, "loop(\n");
        env->indent(fp, indent + 1); fprintf(fp, "while(\n");
        env->indent(fp, indent + 2); test->dump(env, fp, -1);
        fprintf(fp, "\n"); env->indent(fp, indent + 1); fprintf(fp, ")\n");
        env->indent(fp, indent + 1); fprintf(fp, "do(\n");
        env->indent(fp, indent + 2); 

        iteration->dump(env, fp, indent);

        fprintf(fp, "\n"); env->indent(fp, indent + 1); fprintf(fp, ")\n");
        env->indent(fp, indent + 1); fprintf(fp, "done(\n");
        env->indent(fp, indent + 2); result->dump(env, fp, -1); 
        fprintf(fp, "\n");
        env->indent(fp, indent + 1); fprintf(fp, ")\n");
        env->indent(fp, indent); fprintf(fp, ")\n");
      }

      void prep(Environment *env) {
        if (env->failed) return;

        env->declare_loop();

        test->prep(env);

        stack_index = env->current_stack_index--;

        result->prep(env);

        --env->current_stack_index;

        iteration->prep(env);
      }

      void eval_rlyeh(Environment *env) {
        if (env->failed) return;

        while (true) {
          test->eval_rlyeh(env);

          if (env->failed) return;
          bool is_eq = NOUN_EQUALS(env->get_stack(stack_index), _YES);
          env->set_stack(stack_index, _UNDEFINED);

          if (is_eq)
            result->eval_rlyeh(env);
          else
            iteration->eval_rlyeh(env);
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

        BasicBlock *test_block = BasicBlock::Create(getGlobalContext(),
                                                    "loop.test",
                                                    env->function);
        BasicBlock *next_block = BasicBlock::Create(getGlobalContext(),
                                                    "loop.next");
        BasicBlock *done_block = BasicBlock::Create(getGlobalContext(),
                                                    "loop.done");

        // Insert an explicit fall through from the current block to the loop.
        env->builder->CreateBr(test_block);

        // Test block.
        env->builder->SetInsertPoint(test_block);
        Type *loop_type = llvm_noun_type();
        PHINode *test_phi = env->builder->CreatePHI(loop_type, 2);
        test_phi->addIncoming(LLVM_NOUN(_0), incoming_block);
        Value *test_value = test->compile(env);
        test_value = env->builder->CreateICmpEQ(test_value,
          ConstantInt::get(getGlobalContext(), APInt(1, 0)));
        env->builder->CreateCondBr(test_value, next_block, done_block);

        // Next block.
        env->function->getBasicBlockList().push_back(next_block);
        env->builder->SetInsertPoint(next_block);

        iteration->compile(env);

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

      void set_iteration(Iteration *iteration) {
        ASSERT(this->iteration == NULL, "this->iteration == NULL\n");
        this->iteration = iteration;
        iteration->outer = this;
      }
    }; // class Loop
  } // namespace rlyeh
} // namespace jit

using namespace jit::rlyeh;

Node *transform(noun_t rt);

#define T_ENTER(n) if (ARKHAM_TRACE_TRANSFORM) do { \
  fprintf(machine->trace_file, "enter %s: ", __FUNCTION__); \
  noun_print(machine->trace_file, rt, true, false); \
  fprintf(machine->trace_file, "\n"); \
} while (false)

#define T_LEAVE(n) if (ARKHAM_TRACE_TRANSFORM) do { \
  fprintf(machine->trace_file, "leave %s: ", __FUNCTION__); \
  noun_print(machine->trace_file, rt, true, false); \
  fprintf(machine->trace_file, "\n"); \
} while (false)

Declaration *transform_decl(noun_t rt) {
  T_ENTER(rt);

  Node *inner = transform(R(rt));

  if (inner != NULL) {
    Declaration *decl = new Declaration(R(L(rt)));
    decl->set_inner(inner);
    T_LEAVE(rt);
    return decl;
  }

  return NULL;
}

Loop *transform_simple_loop(noun_t rt) {
  T_ENTER(rt);

  if (!NOUN_IS_CELL(rt))
    return NULL;

  noun_t l = L(rt);
  noun_t r = R(rt);

  if (!NOUN_IS_CELL(r))
    return NULL;

  noun_t rl = L(r);

  Node *test = transform(rl);
  Node *yes = NULL;
  Node *no = NULL;

  Expression *test_expr = dynamic_cast<Expression *>(test);
  if (test_expr != NULL) {
      noun_t rr = R(r);
      yes = transform(L(rr));

      Expression *yes_expr = dynamic_cast<Expression *>(yes);
      if (yes != NULL) {
        no = transform(R(rr));

        Iteration *no_iter = dynamic_cast<Iteration *>(no);
        if (no != NULL) {
          Loop *loop = new Loop();

          // Assume that yes is "return" and that no is "continue".

          // REVISIT: Reverse the sense of the test is yes is "continue"
          // and no is "return".

          loop->set_test(test_expr);
          loop->set_result(yes_expr);
          loop->set_iteration(no_iter);

          T_LEAVE(rt);

          return loop;
        }
      }
  }

 error:

  if (test != NULL) delete test;
  if (yes != NULL) delete yes;
  if (no != NULL) delete no;

  return NULL;
}

Load *transform_load(noun_t rt) {
  T_ENTER(rt);

  if (NOUN_IS_SATOM(rt)) {
    T_LEAVE(rt);
    return new Load(NOUN_AS_SATOM(rt));
  }
  else
    return NULL;
}

IncrementExpression *transform_inc(noun_t rt) {
  T_ENTER(rt);

  Node *sub = transform(rt);

  Expression *sub_expr = dynamic_cast<Expression *>(sub);
  if (sub_expr != NULL) {
    IncrementExpression *inc = new IncrementExpression();
    inc->set_subexpr(sub_expr);
    T_LEAVE(rt);
    return inc;
  }

  return NULL;
}

BinaryExpression *transform_binop(noun_t rt, enum binop_type type) {
  T_ENTER(rt);

  Node *left = transform(L(rt));
  Node *right = NULL;

  Expression *left_expr = dynamic_cast<Expression *>(left);
  if (left != NULL) {
    Node *right = transform(R(rt));

    Expression *right_expr = dynamic_cast<Expression *>(right);
    if (right != NULL) {
      BinaryExpression *binop = new BinaryExpression(type);

      binop->set_left(left_expr);
      binop->set_right(right_expr);

      T_LEAVE(rt);

      return binop;
    }
  }

 error:

  if (left != NULL) delete left;
  if (right != NULL) delete right;

  return NULL;
}

Store *transform_store(noun_t rt, jit_address_t address) {
  T_ENTER(rt);

  Node *sub = transform(rt);

  Expression *sub_expr = dynamic_cast<Expression *>(sub);
  if (sub_expr != NULL) {
    Store *store = new Store(address);
    store->set_subexpr(sub_expr);
    T_LEAVE(rt);
    return store;
  }

  return NULL;
}

bool transform_iter_impl(noun_t rt, jit_address_t address,
                         Iteration *iteration) {
  T_ENTER(rt);

  if (address > JIT_ADDRESS_MAX)
    return false;
  else if (!NOUN_IS_CELL(rt))
    return false;

  noun_t l = L(rt);
  bool result;

  if (NOUN_IS_CELL(l)) {
    result = transform_iter_impl(l, address * 2, iteration) && 
      transform_iter_impl(R(rt), address * 2 + 1, iteration);
  } else {
    Store *store = transform_store(rt, address);

    if (store != NULL) 
      iteration->add_store(store);

    result = (store != NULL);
  }    

  T_LEAVE(rt);

  return result;
}

Iteration *transform_iter(noun_t rt) {
  T_ENTER(rt);

  if (NOUN_EQUALS(L(rt), _2)) {
    noun_t r = R(rt);
    noun_t rl = L(r);

    if (NOUN_IS_CELL(rl) && NOUN_EQUALS(L(rl), _0) && NOUN_EQUALS(R(rl), _2)) {
      Iteration *iteration = new Iteration();

      if (!transform_iter_impl(R(r), 3, iteration)) {
        delete iteration;
        return NULL;
      } else {
        T_LEAVE(rt);
        return iteration;
      }
    }
  }

  return NULL;
}

Node *transform(noun_t rt) {
  T_ENTER(rt);

  heap_t *heap = machine->heap;
  
  if (NOUN_IS_CELL(rt)) {
    noun_t l = L(rt);
    if (NOUN_IS_SATOM(l)) {
      noun_t r = R(rt);
      switch (NOUN_AS_SATOM(l)) {
      case 0:
        return transform_load(r);
      case 4:
        return transform_inc(r);
      case 5:
        return transform_binop(r, binop_eq_type);
      case 8:
        if (NOUN_IS_CELL(r)) {
          noun_t rl = L(r);
          
          if (NOUN_IS_CELL(rl)) {
            if (NOUN_EQUALS(L(rl), _1)) {
              noun_t rr = R(r), rrr, rrrr;

              if (!NOUN_IS_CELL(rr) || !NOUN_EQUALS(L(rr), _9))
                goto is_decl;
              rrr = R(rr);
              if (!NOUN_IS_CELL(rrr) || !NOUN_EQUALS(L(rrr), _2))
                goto is_decl;
              rrrr = R(rrr);
              if (!NOUN_IS_CELL(rrrr) || !NOUN_EQUALS(L(rrrr), _0) 
                  || !NOUN_EQUALS(R(rrrr), _1))
                goto is_decl;

              return transform_simple_loop(R(rl));

            is_decl:
              return transform_decl(r);
            }
          }
        }
      case 9:
        return transform_iter(r);
      }
    }
  }

  return NULL;
}

#if ARKHAM_LLVM
// TODO: More jet slots
static llvm_t *compiled_formulas[16];
static llvm_t undefined_compiled_formula;
#endif

noun_t accelerate(noun_t subject, noun_t formula, noun_t hint) {
  satom_t index;

  if (!NOUN_IS_SATOM(hint))
    return _UNDEFINED;

  index = NOUN_AS_SATOM(hint);
  
#if ARKHAM_LLVM
  if (index > (sizeof(compiled_formulas) / sizeof(compiled_formulas[0])))
    return _UNDEFINED; //XXX: log
#endif

  Node *rlyeh = NULL;
  noun_t result = _UNDEFINED;
  Environment *env = NULL;

#if ARKHAM_LLVM
  llvm_t *compiled_formula = compiled_formulas[index];

  if (compiled_formula != NULL) {
    if (compiled_formula != &undefined_compiled_formula)
      return (compiled_formula->fn)(subject);
    else
      return _UNDEFINED;
  }

  {
    std::string filename = machine_jet_path(machine, index);
    OwningPtr<MemoryBuffer> file;
    error_code read_error = MemoryBuffer::getFile(filename.c_str(), file);

    if (read_error) {
      ERROR("Could not open bitcode file for reading '%s': '%s'\n",
            filename.c_str(), read_error.message().c_str());
    } else {
      INFO("Read bitcode from file '%s'\n", filename.c_str());

      std::string parse_error;
      Module *module = ParseBitcodeFile(file.take(), getGlobalContext(),
                                        &parse_error);

      if (module != NULL) {
        compiled_formula = llvm_new_module(module);
        llvm_lookup_and_store_function(compiled_formula);

        goto compiled;
      } else {
        ERROR("Could not read bitcode file '%s': '%s'\n",
              filename.c_str(), parse_error.c_str());
      }
    }
  }
#endif

  rlyeh = transform(formula);

  if (rlyeh == NULL) {
#if ARKHAM_LLVM
    compiled_formulas[index] = &undefined_compiled_formula;
#endif
    goto done;
  }
  
  env = new Environment(machine_jet_file(machine, index));

  env->prep(rlyeh);

  if (env->failed) {
    INFO("Preparation failed: %" SATOM_FMT "\n", NOUN_AS_SATOM(hint));
    goto done;
  }

  if (ARKHAM_TRACE_RLYEH)
    rlyeh->dump(env, machine->trace_file, 0);

#if ARKHAM_LLVM
  compiled_formula = env->compile(rlyeh, index);

  if (env->failed) {
    INFO("Compilation failed: %" SATOM_FMT "\n", NOUN_AS_SATOM(hint));
    goto done;
  }

 compiled:

  compiled_formulas[index] = compiled_formula;

  result = (compiled_formula->fn)(subject); // XXX: unshare?
#else
  result = env->eval_rlyeh(rlyeh, subject);

  if (env->failed)
    INFO("Evaluation failed: %" SATOM_FMT "\n", NOUN_AS_SATOM(hint));
#endif

 done:

#if ARKHAM_LLVM
  if (NOUN_IS_UNDEFINED(result))
    compiled_formulas[index] = &undefined_compiled_formula;
#endif

  if (rlyeh != NULL)
    delete rlyeh;
  if (env != NULL)
    delete env;

  return result;
}

// QQQ: remove
// Node *fib_rlyeh(Environment *env) {
//   heap_t *heap = machine->heap;
//   CELLS(1);

//   Declaration *decl_f0_f1 = new Declaration(CELL(_0, _1)); {
//     Declaration *decl_counter = new Declaration(_0);
//     /**/ decl_f0_f1->set_inner(decl_counter); {
//       Loop *loop = new Loop();
//       /**/ decl_counter->set_inner(loop); {
//         BinaryExpression *eq = new BinaryExpression(binop_eq_type);
//         /**/ loop->set_test(eq); {
//           Load *eq_left = new Load(15);
//           /**/ eq->set_left(eq_left);
//         } {
//           Load *eq_right = new Load(6);
//           /**/ eq->set_right(eq_right);
//         } 
//       } {
//         Load *result = new Load(28);
//         /**/ loop->set_result(result);
//       } {
//         Iteration *iteration = new Iteration();
//         /**/ loop->set_iteration(iteration); {
//           Store *store_6 = new Store(6);
//           /**/ iteration->add_store(store_6);
//           IncrementExpression *inc_6 = new IncrementExpression();
//           /**/ store_6->set_subexpr(inc_6);
//           Load *load_6 = new Load(6);
//           /**/ inc_6->set_subexpr(load_6);
//         } {
//           Store *store_28 = new Store(28);
//           /**/ iteration->add_store(store_28);
//           Load *load_29 = new Load(29);
//           /**/ store_28->set_subexpr(load_29);
//         } {
//           Store *store_29 = new Store(29);
//           /**/ iteration->add_store(store_29);
//           BinaryExpression *add = new BinaryExpression(binop_add_type);
//           /**/ store_29->set_subexpr(add);
//           Load *add_left = new Load(28);
//           /**/ add->set_left(add_left);
//           Load *add_right = new Load(29);
//           /**/ add->set_right(add_right);
//         } {
//           Store *store_15 = new Store(15);
//           /**/ iteration->add_store(store_15);
//           Load *load_15 = new Load(15);
//           /**/ store_15->set_subexpr(load_15);
//         }
//       }
//     }
//   }

//   return decl_f0_f1;
// }
