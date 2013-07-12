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
/* REVISIT: these *must* come before the inclusion of nock5k.h: figure
 * out why. */
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>
#include <llvm-c/Transforms/Scalar.h>
#include <llvm-c/Core.h>
#include <llvm-c/Analysis.h>
#endif

#include "nock5k.h"

#define ENV_FAIL(pstr, msg) env_fail(env, pstr, msg, __FILE__, __FUNCTION__, __LINE__);
#define ENV_CHECK_VOID(p, msg) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(pstr, msg); return; } } while(false)
#define ENV_CHECK(p, msg, val) do { const char *pstr = #p; if (!(p)) { ENV_FAIL(pstr, msg) return val; } } while(false)
#define ALLOC(t) ((t *)calloc(1, sizeof(t)))

__thread machine_t *machine;

#if NOCK_LLVM
typedef struct llvm_s {
  LLVMModuleRef module;
  LLVMExecutionEngineRef engine;
  LLVMPassManagerRef pass_manager;
} llvm_t;
#endif

#if NOCK_LLVM
void llvm_init_global() {
  char *msg;

  if (LLVMInitializeNativeTarget() == 1) {
    ERROR0("Could not initialize LLVM native target\n");
    exit(5);
  }
}
#endif

#if NOCK_LLVM
llvm_t *llvm_new(const char *module_name) {
  llvm_t *llvm = ALLOC(llvm_t);
  char *msg;

  llvm->module = LLVMModuleCreateWithName(module_name);
    
  // Create execution engine.
  if (LLVMCreateExecutionEngineForModule(&(llvm->engine), llvm->module, &msg) == 1) {
    fprintf(stderr, "%s\n", msg);//ZZZ
    LLVMDisposeMessage(msg);
    exit(5);
  }
    
  // Setup optimizations.
  llvm->pass_manager =  LLVMCreateFunctionPassManagerForModule(llvm->module);

  LLVMAddTargetData(LLVMGetExecutionEngineTargetData(llvm->engine), llvm->pass_manager); /* ok */
  LLVMAddPromoteMemoryToRegisterPass(llvm->pass_manager); /* ok */
  LLVMAddInstructionCombiningPass(llvm->pass_manager); /* ok */
  LLVMAddReassociatePass(llvm->pass_manager); /* ok */
  LLVMAddGVNPass(llvm->pass_manager); /* ok */
  LLVMAddCFGSimplificationPass(llvm->pass_manager); /* ok */
  LLVMInitializeFunctionPassManager(llvm->pass_manager); /* check this */

  // TODO: check against the above:
  // // Provide basic AliasAnalysis support for GVN.
  // OurFPM.add(createBasicAliasAnalysisPass()); /* check this */

  return llvm;
}
#endif

#if NOCK_LLVM
void llvm_delete(llvm_t *llvm) {
  LLVMDumpModule(llvm->module);
  LLVMDisposePassManager(llvm->pass_manager);
  LLVMDisposeModule(llvm->module);
}
#endif

void machine_set(machine_t *m) {
  machine = m;
}

static inline tagged_noun_t
add(tagged_noun_t n1, tagged_noun_t n2) {
  ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
  ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

  // For JIT, use: http://llvm.org/docs/LangRef.html#llvm-uadd-with-overflow-intrinsics

  if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2)) {
    satom_t sn1 = noun_as_satom(n1);
    satom_t sn2 = noun_as_satom(n2);
    satom_t sum = sn1 + sn2;
#if FAT_NOUNS
    if (sum >= sn1 && sum >= sn2)
      return satom_as_noun(sum);
#else
    if (sum & SATOM_OVERLOW_BIT)
      return satom_as_noun(sum);
#endif
  }

  return atom_add(n1, n2, machine->heap);
}

static inline tagged_noun_t
inc(tagged_noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

  if (NOUN_IS_SATOM(n)) {
    satom_t satom = noun_as_satom(n);
    if (satom < SATOM_MAX)
      return satom_as_noun(satom + 1);
  }

  return atom_increment(n, machine->heap);
}

static inline bool
eq(tagged_noun_t n1, tagged_noun_t n2) {
  ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
  ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

  if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2))
    return noun_as_satom(n1) == noun_as_satom(n2);
  else
    return atom_equals(n1, n2);
}

extern tagged_noun_t
fib(tagged_noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

  tagged_noun_t f0 = _0;
  tagged_noun_t f1 = _1;
  tagged_noun_t counter = _0;
  while (true) {
    if (eq(n, counter))
      return f0;
    else {
      counter = inc(counter);
      tagged_noun_t sum = add(f0, f1);
      f0 = f1;
      f1 = sum;
    }
  }
}

#define _YES _0
#define _NO _1
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

typedef struct {
  vec_t locals;
  vec_t next_locals;
  vec_t stack;
  // Needed at function entry:
  tagged_noun_t args_root;
  // Only needed during prep (except for asserts):
  tagged_noun_t local_variable_index_map;
  tagged_noun_t args_placeholder;
  tagged_noun_t loop_body_placeholder;
  jit_index_t next_local_variable_index;
  jit_index_t current_stack_index;
  jit_index_t max_stack_index;
  // Needed during compilation:
#if NOCK_LLVM
  vec_t locals_names;
  vec_t next_locals_names;
  LLVMBuilderRef builder;
  LLVMValueRef function;
  void *fp;
#endif
  // Failure information:
  bool failed;
  const char *predicate;
  const char *failure_message;
  const char *file_name;
  const char *function_name;
  int line_number;
} env_t;

static void
env_fail(env_t *env, const char *predicate, const char *failure_message, const char *file_name, const char *function_name, int line_number) {
  env->failed = true;
  env->predicate = predicate;
  env->failure_message = failure_message;
  env->file_name = file_name;
  env->function_name = function_name;
  env->line_number = line_number;

  nock_log(ERROR_PREFIX " Failure to compile: predicate = '%s', message = '%s', file = '%s', function = '%s', line = %d\n", predicate, failure_message, file_name, function_name, line_number);
}

static jit_index_t env_allocate_local(env_t *env) {
  if (env->failed) return 0;

  ENV_CHECK(env->next_local_variable_index < JIT_INDEX_MAX, "Too many local variable declarations", 0);
  int index = env->next_local_variable_index++;

  tagged_noun_t undef = _UNDEFINED;
  vec_resize(&env->locals, index + 1, &undef);
  vec_resize(&env->next_locals, index + 1, &undef);

  return index;
}

static void env_allocate_address(env_t *env, jit_address_t address) {
  ENV_CHECK_VOID(address >= 1, "Invalid address");

  tagged_noun_t noun = env->local_variable_index_map;
  int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);
  tagged_noun_t ancestors[depth];
  bool choice[depth];

  // Run through the bits from left to right:
  satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
  for (int i = 0; i < depth; ++i) {
    ENV_CHECK_VOID(!NOUN_EQUALS(noun, env->loop_body_placeholder), "Cannot refer to the loop body");

    if (NOUN_EQUALS(noun, env->args_placeholder)) {
      noun = cell_new(machine->heap, env->args_placeholder, env->args_placeholder);

      if (NOUN_IS_UNDEFINED(env->args_root)) {
	env->args_root = noun;
	SHARE(env->args_root, ENV_OWNER);
      }
    }
    
    ancestors[i] = noun;
    choice[i] = (mask & address);

    noun = choice[i] ? noun_get_right(noun) : noun_get_left(noun);
    mask = (mask >> 1);
  }
  
  ENV_CHECK_VOID(!NOUN_EQUALS(noun, env->loop_body_placeholder), "Cannot refer to the loop body");

  if (NOUN_EQUALS(noun, env->args_placeholder)) {
    // This is an undeclared reference, so it must be an argument.
    // We are fetching an undeclared local variable value: i.e. an argument.
    // Allocate an index and initialize the local variable.

    // Allocate a local variable slot for an argument:
    noun = satom_as_noun(env_allocate_local(env));

    if (NOUN_IS_UNDEFINED(env->args_root)) {
      env->args_root = noun;
      SHARE(env->args_root, ENV_OWNER);
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
      ASSIGN(env->local_variable_index_map, n, ENV_OWNER);
  }

  ENV_CHECK_VOID(noun_get_type(noun) == satom_type, "Type mismatch");
  ENV_CHECK_VOID(noun_as_satom(noun) <= JIT_INDEX_MAX, "Invalid index");
}

static jit_index_t
env_get_index_of_address(env_t *env, jit_address_t address) {
  ENV_CHECK(address >= 1, "Invalid address", 0);

  tagged_noun_t noun = env->local_variable_index_map;
  ENV_CHECK(!NOUN_EQUALS(noun, env->loop_body_placeholder), "Cannot refer to the loop body", 0);
  ENV_CHECK(!NOUN_EQUALS(noun, env->args_placeholder), "Undefined value", 0);
  int depth = (sizeof(address) * 8 - __builtin_clz(address) - 1);

  // Run through the bits from left to right:
  satom_t mask = (depth >= 1 ? (1 << (depth - 1)) : 0);
    
  for (int i = 0; i < depth; ++i) {    
    noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
    ENV_CHECK(!NOUN_EQUALS(noun, env->loop_body_placeholder), "Cannot refer to the loop body", 0);
    ENV_CHECK(!NOUN_EQUALS(noun, env->args_placeholder), "Undefined value", 0);
    mask = (mask >> 1);
  }

  ENV_CHECK(noun_get_type(noun) == satom_type, "Type mismatch", 0);
  satom_t index_satom = noun_as_satom(noun);
  ENV_CHECK(index_satom <= JIT_INDEX_MAX, "Invalid address", 0);
  return (jit_index_t)index_satom;
}

/* Callers must unshare the value. */
tagged_noun_t env_get_stack(env_t *env, jit_index_t index) {
  if (env->failed) return _UNDEFINED;

  ENV_CHECK(index <= env->max_stack_index, "Invalid index", _UNDEFINED);

  tagged_noun_t value = *(tagged_noun_t *)vec_get(&env->stack, index);
  ENV_CHECK(NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

  return value;
}

void env_set_stack(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index <= env->max_stack_index, "Invalid index");
  ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

  SHARE(value, STACK_OWNER);
  vec_set(&env->stack, index, &value);
}

static tagged_noun_t env_get_local(env_t *env, jit_index_t index) {
  if (env->failed) return _UNDEFINED;

  ENV_CHECK(index < vec_size(&env->locals), "Invalid index", _UNDEFINED);

  tagged_noun_t value = *(tagged_noun_t *)vec_get(&env->locals, index);
  ENV_CHECK(NOUN_IS_DEFINED(value), "Undefined value", _UNDEFINED);

  return value;
}

static void env_set_local(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index < vec_size(&env->next_locals), "Invalid index");
  ENV_CHECK_VOID(NOUN_IS_UNDEFINED(*(tagged_noun_t *)vec_get(&env->next_locals, index)), "Overwritten value");
  ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

  SHARE(value, LOCALS_OWNER);
  vec_set(&env->next_locals, index, &value);
}

static void env_initialize_local(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index < vec_size(&env->locals), "Invalid index");
  ENV_CHECK_VOID(NOUN_IS_UNDEFINED(*(tagged_noun_t *)vec_get(&env->locals, index)), "Overwritten value");
  ENV_CHECK_VOID(NOUN_IS_DEFINED(value), "Undefined value");

  SHARE(value, LOCALS_OWNER);
  vec_set(&env->locals, index, &value);
}

static void env_declare_loop(env_t *env) {
  ASSIGN(env->local_variable_index_map, cell_new(machine->heap, env->loop_body_placeholder, env->local_variable_index_map), ENV_OWNER);
}

static LLVMValueRef compile_alloca(env_t *env, const char *var_name) {
  LLVMPositionBuilderBefore(env->builder, LLVMGetEntryBasicBlock(env->function));
  return LLVMBuildAlloca(env->builder, llvm_tagged_noun_type(), var_name);
}

struct jit_oper;

typedef void (*prep_fn_t)(struct jit_oper *oper, env_t *env);
#define PREP(oper) ((oper)->prep_fn)(oper, env)
typedef void (*eval_fn_t)(struct jit_oper *oper, env_t *env);
#define EVAL(oper) ((oper)->eval_fn)(oper, env)
#if NOCK_LLVM
typedef LLVMValueRef (*compile_fn_t)(struct jit_oper *oper, env_t *env);
#define COMPILE(oper) ((oper)->compile_fn)(oper, env)
#endif
typedef void (*delete_fn_t)(struct jit_oper *oper);
#define DELETE(oper) ((oper)->delete_fn)(oper)

typedef struct jit_oper {
  struct jit_oper *outer;
  prep_fn_t prep_fn;
  eval_fn_t eval_fn;
  compile_fn_t compile_fn;
  delete_fn_t delete_fn;
  // TODO: source information: file, line, column
} jit_oper_t;

typedef struct jit_expr_t {
  jit_oper_t base;
  jit_index_t stack_index;
} jit_expr_t;

#define expr_as_oper(expr) (&(expr)->base)

typedef struct jit_decl {
  jit_oper_t base;
  jit_oper_t *inner;
  tagged_noun_t local_variable_initial_values;
  tagged_noun_t local_variable_index_map;
} jit_decl_t;

#define decl_as_oper(decl) (&(decl)->base)
#define oper_as_decl(oper) ((jit_decl_t *)(oper))

static tagged_noun_t decl_prep_impl(env_t *env, tagged_noun_t local_variable_initial_values) {
  if (noun_get_type(local_variable_initial_values) == cell_type) {
    tagged_noun_t left = decl_prep_impl(env, noun_get_left(local_variable_initial_values));
    tagged_noun_t right = decl_prep_impl(env, noun_get_right(local_variable_initial_values));
    return cell_new(machine->heap, left, right);
  } else {
    // Allocate a local variable slot for a declared variable:
    return satom_as_noun(env_allocate_local(env));
  }
}

void decl_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_decl_t *decl = oper_as_decl(oper);

  decl->local_variable_index_map = decl_prep_impl(env, decl->local_variable_initial_values);
  SHARE(decl->local_variable_index_map, AST_OWNER);

  tagged_noun_t new_local_variable_index_map = cell_new(machine->heap, decl->local_variable_index_map, env->local_variable_index_map);
  ASSIGN(env->local_variable_index_map, new_local_variable_index_map, ENV_OWNER);

  PREP(decl->inner);
}

static char *make_var_name(const char *prefix, satom_t satom) {
  const int n = snprintf(NULL, 0, "%s%" SATOM_FMT, prefix, satom);
  ASSERT0(n > 0);
  char buf[n+1];
  int c = snprintf(buf, n+1, "%s%" SATOM_FMT, prefix, satom);
  ASSERT0(buf[n] == '\0');
  ASSERT0(c == n);
  return strdup(buf);
}

#if NOCK_LLVM
static void decl_compile_impl(env_t *env, tagged_noun_t local_variable_initial_values, tagged_noun_t local_variable_index_map) {
  if (noun_get_type(local_variable_initial_values) == cell_type) {
    decl_compile_impl(env, noun_get_left(local_variable_initial_values), noun_get_left(local_variable_index_map));
    decl_compile_impl(env, noun_get_right(local_variable_initial_values), noun_get_right(local_variable_index_map));
  } else {
    satom_t index = noun_as_satom(local_variable_index_map);
    ENV_CHECK_VOID(index <= JIT_INDEX_MAX, "Invalid index");

    {
      char *var_name = make_var_name("l", index);
      vec_resize(&env->locals_names, index + 1, NULL);
      vec_set(&env->locals_names, index, var_name);
      LLVMValueRef value = LLVMConstInt(llvm_tagged_noun_type(), local_variable_initial_values, 0);
      LLVMBuildStore(env->builder, value, compile_alloca(env, var_name));
    }
    {
      char *var_name = make_var_name("l", index);
      vec_resize(&env->next_locals_names, index + 1, NULL);
      vec_set(&env->next_locals_names, index, var_name);
      compile_alloca(env, var_name);
    }
  }
}
#endif /* NOCK_LLVM */

#if NOCK_LLVM
LLVMValueRef decl_compile(jit_oper_t *oper, env_t *env) {
  if (env->failed) return NULL;

  jit_decl_t *decl = oper_as_decl(oper);

  decl_compile_impl(env, decl->local_variable_initial_values, decl->local_variable_index_map);

  return COMPILE(decl->inner);
}
#endif /* NOCK_LLVM */

static void decl_eval_impl(env_t *env, tagged_noun_t local_variable_initial_values, tagged_noun_t local_variable_index_map) {
  if (noun_get_type(local_variable_initial_values) == cell_type) {
    decl_eval_impl(env, noun_get_left(local_variable_initial_values), noun_get_left(local_variable_index_map));
    decl_eval_impl(env, noun_get_right(local_variable_initial_values), noun_get_right(local_variable_index_map));
  } else {
    satom_t index = noun_as_satom(local_variable_index_map);
    ENV_CHECK_VOID(index <= JIT_INDEX_MAX, "Invalid index");
    env_initialize_local(env, (jit_index_t)index, local_variable_initial_values);
  }
}

void decl_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_decl_t *decl = oper_as_decl(oper);

  decl_eval_impl(env, decl->local_variable_initial_values, decl->local_variable_index_map);

  EVAL(decl->inner);
}

void decl_delete(jit_oper_t *oper) {
  jit_decl_t *decl = oper_as_decl(oper);
  if (NOUN_IS_DEFINED(decl->local_variable_index_map))
    UNSHARE(decl->local_variable_index_map, AST_OWNER);
  UNSHARE(decl->local_variable_initial_values, AST_OWNER);
  DELETE(decl->inner);
  free(decl);
}

jit_decl_t *decl_new(tagged_noun_t local_variable_initial_values) {
  jit_decl_t *decl = ALLOC(jit_decl_t);

  SHARE(local_variable_initial_values, AST_OWNER);
  decl->local_variable_initial_values = local_variable_initial_values;
  decl->local_variable_index_map = _UNDEFINED;
  decl_as_oper(decl)->prep_fn = decl_prep;
  decl_as_oper(decl)->eval_fn = decl_eval;
  decl_as_oper(decl)->compile_fn = decl_compile;
  decl_as_oper(decl)->delete_fn = decl_delete;

  return decl;
}

void decl_set_inner(jit_decl_t *decl, jit_oper_t *inner) {
  ASSERT(decl->inner == NULL, "decl->inner == NULL");
  decl->inner = inner;
  inner->outer = decl_as_oper(decl);
}

enum binop_type {
  binop_eq_type,
  binop_add_type
};

typedef struct jit_binop {
  jit_expr_t expr;
  enum binop_type type;
  jit_expr_t *left;
  jit_expr_t *right;
} jit_binop_t;

#define binop_as_expr(binop) (&(binop)->expr)
#define binop_as_oper(binop) expr_as_oper(binop_as_expr(binop))
#define oper_as_binop(oper) ((jit_binop_t *)(oper))

void binop_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_binop_t *binop = oper_as_binop(oper);

  PREP(expr_as_oper(binop->left));
  PREP(expr_as_oper(binop->right));

  binop_as_expr(binop)->stack_index = --env->current_stack_index;
}

void binop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_binop_t *binop = oper_as_binop(oper);
  jit_expr_t *expr = binop_as_expr(binop);

  EVAL(expr_as_oper(binop->left));
  EVAL(expr_as_oper(binop->right));

  tagged_noun_t n1 = env_get_stack(env, expr->stack_index);
  tagged_noun_t n2 = env_get_stack(env, expr->stack_index + 1);

  if (!env->failed) {
    switch (binop->type) {
    case binop_eq_type:
      env_set_stack(env, expr->stack_index, (eq(n1, n2) ? _YES : _NO));
      break;
    case binop_add_type:
      env_set_stack(env, expr->stack_index, add(n1, n2));
      break;
    }
  }

  UNSHARE(n1, STACK_OWNER);
  UNSHARE(n2, STACK_OWNER);
}

void binop_delete(jit_oper_t *oper) {
  jit_binop_t *binop = oper_as_binop(oper);

  DELETE(expr_as_oper(binop->left));
  DELETE(expr_as_oper(binop->right));

  free(binop);
}

#if NOCK_LLVM
LLVMValueRef binop_compile(jit_oper_t *oper, env_t *env) {
  //ZZZ
  return NULL;
}
#endif /* NOCK_LLVM */

jit_binop_t *binop_new(enum binop_type type) {
  jit_binop_t *binop = ALLOC(jit_binop_t);

  binop->type = type;
  binop_as_oper(binop)->prep_fn = binop_prep;
  binop_as_oper(binop)->eval_fn = binop_eval;
  binop_as_oper(binop)->compile_fn = binop_compile;
  binop_as_oper(binop)->delete_fn = binop_delete;

  return binop;
}

void binop_set_left(jit_binop_t *binop, jit_expr_t *left) {
  ASSERT(binop->left == NULL, "binop->left == NULL\n");
  binop->left = left;
  expr_as_oper(left)->outer = binop_as_oper(binop);
}

void binop_set_right(jit_binop_t *binop, jit_expr_t *right) {
  ASSERT(binop->right == NULL, "binop->right == NULL\n");
  binop->right = right;
  expr_as_oper(right)->outer = binop_as_oper(binop);
}

typedef struct jit_inc {
  jit_expr_t expr;
  jit_expr_t *subexpr;
} jit_inc_t;

#define inc_as_expr(inc) (&(inc)->expr)
#define inc_as_oper(inc) expr_as_oper(inc_as_expr(inc))
#define oper_as_inc(oper) ((jit_inc_t *)(oper))

void inc_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_inc_t *_inc = oper_as_inc(oper);
  jit_expr_t *expr = inc_as_expr(_inc);

  EVAL(expr_as_oper(_inc->subexpr));
  
  tagged_noun_t popped;
  env_set_stack(env, expr->stack_index, inc(popped = env_get_stack(env, expr->stack_index)));
  UNSHARE(popped, STACK_OWNER);
}

void inc_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_inc_t *inc = oper_as_inc(oper);

  PREP(expr_as_oper(inc->subexpr));

  inc_as_expr(inc)->stack_index = env->current_stack_index;
}

void inc_delete(jit_oper_t *oper) {
  jit_inc_t *inc = oper_as_inc(oper);
  
  DELETE(expr_as_oper(inc->subexpr));

  free(inc);
}

#if NOCK_LLVM
LLVMValueRef inc_compile(jit_oper_t *oper, env_t *env) {
  //ZZZ
  return NULL;
}
#endif /* NOCK_LLVM */

jit_inc_t *inc_new() {
  jit_inc_t *inc = ALLOC(jit_inc_t);

  inc_as_oper(inc)->prep_fn = inc_prep;
  inc_as_oper(inc)->eval_fn = inc_eval;
  inc_as_oper(inc)->compile_fn = inc_compile;
  inc_as_oper(inc)->delete_fn = inc_delete;

  return inc;
}

void inc_set_subexpr(jit_inc_t *inc, jit_expr_t *expr) {
  ASSERT(inc->subexpr == NULL, "inc->subexpr == NULL\n");
  inc->subexpr = expr;
  expr_as_oper(expr)->outer = inc_as_oper(inc);
}

typedef struct jit_load {
  jit_expr_t expr;
  jit_address_t address;
} jit_load_t;

#define load_as_expr(load) (&(load)->expr)
#define load_as_oper(load) expr_as_oper(load_as_expr(load))
#define oper_as_load(oper) ((jit_load_t *)(oper))

void load_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_load_t *load = oper_as_load(oper);

  env_allocate_address(env, load->address);

  load_as_expr(load)->stack_index = ++env->current_stack_index;
  if (env->current_stack_index > env->max_stack_index)
    env->max_stack_index = env->current_stack_index;
}

void load_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_load_t *load = oper_as_load(oper);
  jit_expr_t *expr = load_as_expr(load);

  env_set_stack(env, expr->stack_index, env_get_local(env, env_get_index_of_address(env, load->address)));
}

void load_delete(jit_oper_t *oper) {
  jit_load_t *load = (jit_load_t *)oper;

  free(load);
}

#if NOCK_LLVM
LLVMValueRef load_compile(jit_oper_t *oper, env_t *env) {
  //ZZZ
  return NULL;
}
#endif /* NOCK_LLVM */

jit_load_t *load_new(jit_address_t address) {
  jit_load_t *load = ALLOC(jit_load_t);

  load->address = address;
  load_as_oper(load)->prep_fn = load_prep;
  load_as_oper(load)->eval_fn = load_eval;
  load_as_oper(load)->compile_fn = load_compile;
  load_as_oper(load)->delete_fn = load_delete;

  return load;
}

typedef struct jit_store {
  jit_expr_t expr;
  jit_address_t address;
  jit_expr_t *subexpr;
} jit_store_t;

#define store_as_expr(store) (&(store)->expr)
#define store_as_oper(store) expr_as_oper(store_as_expr(store))
#define oper_as_store(oper) ((jit_store_t *)(oper))

void store_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_store_t *store = (jit_store_t *)oper;
  PREP(expr_as_oper(store->subexpr));

  env_allocate_address(env, oper_as_load(oper)->address);

  store_as_expr(store)->stack_index = env->current_stack_index--;
}

void store_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_store_t *store = oper_as_store(oper);
  jit_expr_t *expr = store_as_expr(store);

  EVAL(expr_as_oper(store->subexpr));

  tagged_noun_t popped;
  env_set_local(env, env_get_index_of_address(env, oper_as_load(oper)->address), popped = env_get_stack(env, expr->stack_index));
  UNSHARE(popped, STACK_OWNER);
}

void store_delete(jit_oper_t *oper) {
  jit_store_t *store = oper_as_store(oper);

  free(store);
}

#if NOCK_LLVM
LLVMValueRef store_compile(jit_oper_t *oper, env_t *env) {
  //ZZZ
  return NULL;
}
#endif /* NOCK_LLVM */

jit_store_t *store_new(jit_address_t address) {
  jit_store_t *store = ALLOC(jit_store_t);

  store->address = address;
  store_as_oper(store)->prep_fn = store_prep;
  store_as_oper(store)->eval_fn = store_eval;
  store_as_oper(store)->compile_fn = store_compile;
  store_as_oper(store)->delete_fn = store_delete;

  return store;
}

void store_set_subexpr(jit_store_t *store, jit_expr_t *expr) {
  ASSERT(store->subexpr == NULL, "store->subexpr == NULL\n");
  store->subexpr = expr;
  expr_as_oper(expr)->outer = store_as_oper(store);
}

typedef struct jit_store_list {
  jit_store_t *store;
  struct jit_store_list *next;
} jit_store_list_t;

typedef struct jit_loop {
  jit_expr_t expr;
  jit_expr_t *test;
  jit_expr_t *result;
  jit_store_list_t *first_store;
  jit_store_list_t *last_store;
} jit_loop_t;

#define loop_as_expr(loop) (&(loop)->expr)
#define loop_as_oper(loop) expr_as_oper(loop_as_expr(loop))
#define oper_as_loop(oper) ((jit_loop_t *)(oper))

void loop_prep(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  env_declare_loop(env);

  jit_loop_t *loop = oper_as_loop(oper);

  PREP(expr_as_oper(loop->test));

  loop_as_expr(loop)->stack_index = env->current_stack_index--;

  PREP(expr_as_oper(loop->result));

  --env->current_stack_index;

  jit_store_list_t *store_list = loop->first_store;
  while (store_list != NULL) {
    PREP(store_as_oper(store_list->store));
    store_list = store_list->next;
  }
}

void loop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_loop_t *loop = oper_as_loop(oper);
  jit_expr_t *expr = loop_as_expr(loop);

  while (true) {
    jit_oper_t *test = expr_as_oper(loop->test);
    EVAL(test);

    if (env->failed) return;
    tagged_noun_t popped;
    bool is_eq = eq(popped = env_get_stack(env, expr->stack_index), _YES);
    UNSHARE(popped, STACK_OWNER);

    if (is_eq) {
      jit_oper_t *result = expr_as_oper(loop->result);
      EVAL(result);
      return;
    } else {
      jit_store_list_t *store_list = loop->first_store;
      while (store_list != NULL) {
	jit_oper_t *store = store_as_oper(store_list->store);
	EVAL(store);
	store_list = store_list->next;
      }
      // Copy the locals for the next iteration:
      tagged_noun_t *l_it = vec_get(&env->locals, 0);
      tagged_noun_t *l_end = l_it + vec_size(&env->locals);
      tagged_noun_t *nl_it = vec_get(&env->next_locals, 0);
      for (; l_it != l_end; ++l_it, ++nl_it) {
	UNSHARE(*l_it, LOCALS_OWNER);
	*l_it = *nl_it;
	*nl_it = _UNDEFINED;
      }
    }
  }
}

void loop_delete(jit_oper_t *oper) {
  jit_loop_t *loop = oper_as_loop(oper);
  jit_oper_t *test = expr_as_oper(loop->test);
  jit_oper_t *result = expr_as_oper(loop->result);
  
  DELETE(test);
  DELETE(result);

  jit_store_list_t *store_list = loop->first_store;
  while (store_list != NULL) {
    jit_oper_t *store = store_as_oper(store_list->store);
    DELETE(store);
    jit_store_list_t *next = store_list->next;
    free(store_list);
    store_list = next;
  }

  free(loop);
}

#if NOCK_LLVM
LLVMValueRef loop_compile(jit_oper_t *oper, env_t *env) {
  //ZZZ
  return NULL;
}
#endif /* NOCK_LLVM */

jit_loop_t *loop_new() {
  jit_loop_t *loop = ALLOC(jit_loop_t);

  loop_as_oper(loop)->prep_fn = loop_prep;
  loop_as_oper(loop)->eval_fn = loop_eval;
  loop_as_oper(loop)->compile_fn = loop_compile;
  loop_as_oper(loop)->delete_fn = loop_delete;

  return loop;
}

void loop_set_test(jit_loop_t *loop, jit_expr_t *test) {
  ASSERT(loop->test == NULL, "loop->test == NULL\n");
  loop->test = test;
  expr_as_oper(test)->outer = loop_as_oper(loop);
}

void loop_set_result(jit_loop_t *loop, jit_expr_t *result) {
  ASSERT(loop->result == NULL, "loop->result == NULL\n");
  loop->result = result;
  expr_as_oper(result)->outer = loop_as_oper(loop);
}

void loop_add_store(jit_loop_t *loop, jit_store_t *store) {
  jit_store_list_t *store_list = ALLOC(jit_store_list_t);
  store_list->store = store;
  
  store_as_oper(store)->outer = loop_as_oper(loop);

  if (loop->first_store == NULL) {
    loop->first_store = loop->last_store = store_list;
  } else {
    loop->last_store->next = store_list;
    loop->last_store = store_list;
  }
}

static void env_initialize_args(env_t *env, tagged_noun_t args, tagged_noun_t args_root) {
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

typedef tagged_noun_t (*binop_fn_t)(tagged_noun_t a, tagged_noun_t b);//ZZZ

env_t *env_new() {
  env_t *env = ALLOC(env_t);

  // Use an "impossible" value as the placeholder:
  env->args_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 1UL);
  SHARE(env->args_placeholder, ENV_OWNER);
  env->loop_body_placeholder = batom_new_ui(machine->heap, JIT_INDEX_MAX + 2UL);
  SHARE(env->loop_body_placeholder, ENV_OWNER);
  env->local_variable_index_map = env->args_placeholder;
  SHARE(env->local_variable_index_map, ENV_OWNER);

  env->current_stack_index = -1;
  env->args_root = _UNDEFINED;

  vec_init(&env->locals, sizeof(tagged_noun_t));
  vec_init(&env->next_locals, sizeof(tagged_noun_t));
  vec_init(&env->stack, sizeof(tagged_noun_t));

#if NOCK_LLVM
  vec_init(&env->locals_names, sizeof(char *));
  vec_init(&env->next_locals_names, sizeof(char *));
#endif /* NOCK_LLVM */

  return env;
}

void env_delete(env_t *env, jit_oper_t *root) {
  DELETE(root);

  {
    tagged_noun_t *l_it = vec_get(&env->locals, 0);
    tagged_noun_t *l_end = l_it + vec_size(&env->locals);
    for(; l_it != l_end; ++l_it) {
      if (NOUN_IS_UNDEFINED(*l_it))
	WARN0("Undefined local variable\n");
      else
	UNSHARE(*l_it, LOCALS_OWNER);
    }
  }
  {
    tagged_noun_t *nl_it = vec_get(&env->next_locals, 0);
    tagged_noun_t *nl_end = nl_it + vec_size(&env->next_locals);
    for(; nl_it != nl_end; ++nl_it) {
      if (NOUN_IS_DEFINED(*nl_it))
	WARN0("Leaked local variable\n");
    }
  }
  UNSHARE(env->args_placeholder, ENV_OWNER);
  UNSHARE(env->loop_body_placeholder, ENV_OWNER);
  UNSHARE(env->local_variable_index_map, ENV_OWNER);
  if (NOUN_IS_DEFINED(env->args_root))
    UNSHARE(env->args_root, ENV_OWNER);
#if NOCK_LLVM
  if (env->function != NULL)
    LLVMDeleteFunction(env->function);
  if (env->builder != NULL)
    LLVMDisposeBuilder(env->builder);
#endif

  vec_destroy(&env->locals);
  vec_destroy(&env->next_locals);
  vec_destroy(&env->stack);

#if NOCK_LLVM
  {
    char **ln_it = vec_get(&env->locals_names, 0);
    char **ln_end = ln_it + vec_size(&env->locals_names);
    for(; ln_it != ln_end; ++ln_it) {
      if (*ln_it != NULL)
	free(*ln_it);
    }
  }
  vec_destroy(&env->locals_names);
  {
    char **nln_it = vec_get(&env->next_locals_names, 0);
    char **nln_end = nln_it + vec_size(&env->next_locals_names);
    for(; nln_it != nln_end; ++nln_it) {
      if (*nln_it != NULL)
	free(*nln_it);
    }
  }
  vec_destroy(&env->next_locals_names);
#endif /* NOCK_LLVM */

  free(env);
}

tagged_noun_t env_eval(env_t *env, jit_oper_t *oper, tagged_noun_t args) {
  ENV_CHECK(NOUN_IS_UNDEFINED(args) == NOUN_IS_UNDEFINED(env->args_root), "Arguments mismatch", _UNDEFINED);

  env_initialize_args(env, args, env->args_root);

#if NOCK_LLVM
  binop_fn_t binop_fn = (binop_fn_t)env->fp; //ZZZ
  printf(">>> "); noun_print(stdout, (binop_fn)(satom_as_noun(1), satom_as_noun(2)), true); printf("\n");
#endif

  EVAL(oper);

  return env->failed ? _UNDEFINED : env_get_stack(env, 0);
}

#if NOCK_LLVM
void env_compile(env_t *env, jit_oper_t *oper) {
  llvm_t *llvm = machine->llvm;
  env->builder = LLVMCreateBuilder();

  // Create argument list.
  int arg_count = 2; //ZZZ
  LLVMTypeRef *params = (LLVMTypeRef *)calloc(arg_count, sizeof(LLVMTypeRef));
  for (int i = 0; i < arg_count; ++i)
    params[i] = llvm_tagged_noun_type();
  
  // REVISIT: calling convention fastcc?
  
  // Create function type.
  LLVMTypeRef functionType = LLVMFunctionType(llvm_tagged_noun_type(), params, arg_count, 0);
  
  // Create function.
  env->function = LLVMAddFunction(llvm->module, /* anonymous */ "", functionType);
  LLVMSetLinkage(env->function, LLVMPrivateLinkage);

  // Create basic block.
  LLVMBasicBlockRef block = LLVMAppendBasicBlock(env->function, "entry");
  LLVMPositionBuilderAtEnd(env->builder, block);
  
  LLVMValueRef body;
  if (false) { //QQQ
    body = COMPILE(oper);

    if (env->failed) return;
  } else {
    //ZZZ
    body = LLVMBuildAdd(env->builder, LLVMGetParam(env->function, 0), LLVMGetParam(env->function, 1), "addtmp");
  }

  // Insert body as return value.
  LLVMBuildRet(env->builder, body);
    
  // Verify function.
  ENV_CHECK_VOID(!LLVMVerifyFunction(env->function, LLVMPrintMessageAction), "Invalid function");

  LLVMDumpValue(env->function); //QQQ

  LLVMRunFunctionPassManager(llvm->pass_manager, env->function);

  env->fp = LLVMGetPointerToGlobal(llvm->engine, env->function);
}
#endif /* NOCK_LLVM */

void env_prep(env_t *env, jit_oper_t *oper) {
  PREP(oper);

  tagged_noun_t undef = _UNDEFINED;
  vec_resize(&env->stack, env->max_stack_index + 1, &undef);
}

static jit_oper_t *dec_ast(env_t *env) {
  struct heap *heap = machine->heap;

  jit_decl_t *decl_counter = decl_new(_0); {
    jit_loop_t *loop = loop_new();
    /**/ decl_set_inner(decl_counter, loop_as_oper(loop)); {
      jit_binop_t *eq = binop_new(binop_eq_type);
      /**/ loop_set_test(loop, binop_as_expr(eq)); {
	jit_load_t *eq_left = load_new(7);
	/**/ binop_set_left(eq, load_as_expr(eq_left));
      } {
	jit_inc_t *eq_right = inc_new();
	/**/ binop_set_right(eq, inc_as_expr(eq_right)); {
	  jit_load_t *load_6 = load_new(6);
	  /**/ inc_set_subexpr(eq_right, load_as_expr(load_6));
	}
      }
    } {
      jit_load_t *result = load_new(6);
      /**/ loop_set_result(loop, load_as_expr(result));
    } {
      jit_store_t *store_6 = store_new(6);
      /**/ loop_add_store(loop, store_6); {
	jit_inc_t *inc_6 = inc_new();
	/**/ store_set_subexpr(store_6, inc_as_expr(inc_6)); {
	  jit_load_t *load_6 = load_new(6);
	  /**/ inc_set_subexpr(inc_6, load_as_expr(load_6));
	}
      }
    } {
      jit_store_t *store_7 = store_new(7);
      /**/ loop_add_store(loop, store_7); {
	jit_load_t *load_7 = load_new(7);
	/**/ store_set_subexpr(store_7, load_as_expr(load_7));
      }
    }
  }

  return decl_as_oper(decl_counter);
}

static jit_oper_t *fib_ast(env_t *env) {
  struct heap *heap = machine->heap;

  jit_decl_t *decl_f0_f1 = decl_new(CELL(_0, _1)); {
    jit_decl_t *decl_counter = decl_new(_0);
    /**/ decl_set_inner(decl_f0_f1, decl_as_oper(decl_counter)); {
      jit_loop_t *loop = loop_new();
      /**/ decl_set_inner(decl_counter, loop_as_oper(loop)); {
	jit_binop_t *eq = binop_new(binop_eq_type);
	/**/ loop_set_test(loop, binop_as_expr(eq)); {
	  jit_load_t *eq_left = load_new(15);
	  /**/ binop_set_left(eq, load_as_expr(eq_left));
	} {
	  jit_load_t *eq_right = load_new(6);
	  /**/ binop_set_right(eq, load_as_expr(eq_right));
	} 
      } {
	jit_load_t *result = load_new(28);
	/**/ loop_set_result(loop, load_as_expr(result));
      } {
	jit_store_t *store_6 = store_new(6);
	/**/ loop_add_store(loop, store_6);
	jit_inc_t *inc_6 = inc_new();
	/**/ store_set_subexpr(store_6, inc_as_expr(inc_6));
	jit_load_t *load_6 = load_new(6);
	/**/ inc_set_subexpr(inc_6, load_as_expr(load_6));
      } {
	jit_store_t *store_28 = store_new(28);
	/**/ loop_add_store(loop, store_28);
	jit_load_t *load_29 = load_new(29);
	/**/ store_set_subexpr(store_28, load_as_expr(load_29));
      } {
	jit_store_t *store_29 = store_new(29);
	/**/ loop_add_store(loop, store_29);
	jit_binop_t *add = binop_new(binop_add_type);
	/**/ store_set_subexpr(store_29, load_as_expr(add));
	jit_load_t *add_left = load_new(28);
	/**/ binop_set_left(add, load_as_expr(add_left));
	jit_load_t *add_right = load_new(29);
	/**/ binop_set_right(add, load_as_expr(add_right));
      } {
	jit_store_t *store_15 = store_new(15);
	/**/ loop_add_store(loop, store_15);
	jit_load_t *load_15 = load_new(15);
	/**/ store_set_subexpr(store_15, load_as_expr(load_15));
      }
    }
  }

  return decl_as_oper(decl_f0_f1);
}

void jit(tagged_noun_t args) {
  // For testing, generate the AST that the pattern matcher *would*
  // generate when parsing "fib" in Nock:

  env_t *env = env_new();
  bool do_fib = false;
  jit_oper_t *root = (do_fib ? fib_ast(env) : dec_ast(env));

  env_prep(env, root);
#if NOCK_LLVM
  env_compile(env, root);
#endif
  tagged_noun_t result = env_eval(env, root, args);

  // QQQ
  if (env->failed) 
    ERROR0("Evaluation failed\n");
  else {
    printf("%s(", (do_fib ? "fib" : "dec")); noun_print(stdout, args, true); printf(")="); noun_print(stdout, result, true); printf("\n");
    UNSHARE(result, STACK_OWNER);
  }

  env_delete(env, root);
}
