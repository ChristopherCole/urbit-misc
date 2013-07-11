/*
 * Copyright 2013 Christopher Cole
 */

#include <stdlib.h>
#include <gmp.h>

#include "nock5k.h"

#include <vector>

#define ENV_CHECK_VOID(p, msg) do { const char *pstr = #p; if (!(p)) { env_fail(env, pstr, msg, __FILE__, __FUNCTION__, __LINE__); return; } } while(false)
#define ENV_CHECK(p, msg, val) do { const char *pstr = #p; if (!(p)) { env_fail(env, pstr, msg, __FILE__, __FUNCTION__, __LINE__); return val; } } while(false)

__thread machine_t *machine;

void machine_set(machine_t *m) {
  machine = m;
}

static inline tagged_noun_t
add(tagged_noun_t n1, tagged_noun_t n2) {
  ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
  ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

  if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2)) {
    satom_t sn1 = noun_as_satom(n1);
    satom_t sn2 = noun_as_satom(n2);
    satom_t sum = sn1 + sn2;
    if (sum >= sn1 && sum >= sn2)
      return satom_as_noun(sum);
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

#define ALLOC(t) ((t *)calloc(1, sizeof(t)))
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
  // REVISIT: replace STL uses with small C classes?
  std::vector<tagged_noun_t> locals;
  std::vector<tagged_noun_t> next_locals;
  std::vector<tagged_noun_t> stack;
  // Needed at function entry:
  tagged_noun_t args_root;
  // Only needed during prep (except for asserts):
  tagged_noun_t local_variable_index_map;
  tagged_noun_t args_placeholder;
  tagged_noun_t loop_body_placeholder;
  jit_index_t next_local_variable_index;
  jit_index_t current_stack_index;
  jit_index_t max_stack_index;
  // Failure information:
  bool failed;
  const char *predicate;
  const char *failure_message;
  const char *file;
  const char *function;
  int line_number;
} env_t;

static void
env_fail(env_t *env, const char *predicate, const char *failure_message, const char *file, const char *function, int line_number) {
  env->failed = true;
  env->predicate = predicate;
  env->failure_message = failure_message;
  env->file = file;
  env->function = function;
  env->line_number = line_number;

  nock_log(ERROR_PREFIX " Failure to compile: predicate = '%s', message = '%s', file = '%s', function = '%s', line = %d\n", predicate, failure_message, file, function, line_number);
}

static jit_index_t env_allocate_local(env_t *env) {
  if (env->failed) return 0;

  ENV_CHECK(env->next_local_variable_index < JIT_INDEX_MAX, "Too many local variable declarations", 0);
  int index = env->next_local_variable_index++;

  env->locals.resize(index + 1, _UNDEFINED);
  env->next_locals.resize(index + 1, _UNDEFINED);

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

  return env;
}

void env_delete(env_t *env) {
  for(std::vector<tagged_noun_t>::iterator it = env->locals.begin(); it != env->locals.end(); ++it) {
    if (NOUN_IS_UNDEFINED(*it))
      ENV_CHECK_VOID(!NOUN_IS_UNDEFINED(*it), "Undefined local variable");
    else
      UNSHARE(*it, LOCALS_OWNER);
  }
  env->locals.~vector();
  for(std::vector<tagged_noun_t>::iterator it = env->next_locals.begin(); it != env->next_locals.end(); ++it) {
    ENV_CHECK_VOID(NOUN_IS_UNDEFINED(*it), "Leaked local variable");
  }
  env->next_locals.~vector();
  env->stack.~vector();
  UNSHARE(env->args_placeholder, ENV_OWNER);
  UNSHARE(env->loop_body_placeholder, ENV_OWNER);
  UNSHARE(env->local_variable_index_map, ENV_OWNER);
  if (!NOUN_IS_UNDEFINED(env->args_root))
    UNSHARE(env->args_root, ENV_OWNER);
  free(env);
}

/* Callers must unshare the value. */
tagged_noun_t env_get_stack(env_t *env, jit_index_t index) {
  if (env->failed) return _UNDEFINED;

  ENV_CHECK(index <= env->max_stack_index, "Invalid index", _UNDEFINED);

  tagged_noun_t value = env->stack[index];
  ENV_CHECK(!NOUN_IS_UNDEFINED(value), "Undefined value", _UNDEFINED);

  return value;
}

void env_set_stack(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index <= env->max_stack_index, "Invalid index");
  ENV_CHECK_VOID(!NOUN_IS_UNDEFINED(value), "Undefined value");

  SHARE(value, STACK_OWNER);
  env->stack[index] = value;
}

static tagged_noun_t env_get_local(env_t *env, jit_index_t index) {
  if (env->failed) return _UNDEFINED;

  ENV_CHECK(index < env->next_locals.size(), "Invalid index", _UNDEFINED);

  tagged_noun_t value = env->locals[index];
  ENV_CHECK(!NOUN_IS_UNDEFINED(value), "Undefined value", _UNDEFINED);

  return value;
}

static void env_set_local(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index < env->next_locals.size(), "Invalid index");
  ENV_CHECK_VOID(NOUN_IS_UNDEFINED(env->next_locals[index]), "Overwritten value");
  ENV_CHECK_VOID(!NOUN_IS_UNDEFINED(value), "Undefined value");

  SHARE(value, LOCALS_OWNER);
  env->next_locals[index] = value;
}

static void env_initialize_local(env_t *env, jit_index_t index, tagged_noun_t value) {
  if (env->failed) return;

  ENV_CHECK_VOID(index < env->locals.size(), "Invalid index");
  ENV_CHECK_VOID(NOUN_IS_UNDEFINED(env->locals[index]), "Overwritten value");
  ENV_CHECK_VOID(!NOUN_IS_UNDEFINED(value), "Undefined value");

  SHARE(value, LOCALS_OWNER);
  env->locals[index] = value;
}

static void env_declare_loop(env_t *env) {
  ASSIGN(env->local_variable_index_map, cell_new(machine->heap, env->loop_body_placeholder, env->local_variable_index_map), ENV_OWNER);
}

typedef void (*prep_fn_t)(struct jit_oper *oper, env_t *env);
#define PREP(oper) ((oper)->prep_fn)(oper, env)
typedef void (*eval_fn_t)(struct jit_oper *oper, env_t *env);
#define EVAL(oper) ((oper)->eval_fn)(oper, env)
typedef void (*delete_fn_t)(struct jit_oper *oper);
#define DELETE(oper) ((oper)->delete_fn)(oper)

typedef struct jit_oper {
  struct jit_oper *outer;
  prep_fn_t prep_fn;
  eval_fn_t eval_fn;
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
  if (!NOUN_IS_UNDEFINED(decl->local_variable_index_map))
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

jit_binop_t *binop_new(enum binop_type type) {
  jit_binop_t *binop = ALLOC(jit_binop_t);

  binop->type = type;
  binop_as_oper(binop)->prep_fn = binop_prep;
  binop_as_oper(binop)->eval_fn = binop_eval;
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

jit_inc_t *inc_new() {
  jit_inc_t *inc = ALLOC(jit_inc_t);

  inc_as_oper(inc)->prep_fn = inc_prep;
  inc_as_oper(inc)->eval_fn = inc_eval;
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

jit_load_t *load_new(jit_address_t address) {
  jit_load_t *load = ALLOC(jit_load_t);

  load->address = address;
  load_as_oper(load)->prep_fn = load_prep;
  load_as_oper(load)->eval_fn = load_eval;
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

jit_store_t *store_new(jit_address_t address) {
  jit_store_t *store = ALLOC(jit_store_t);

  store->address = address;
  store_as_oper(store)->prep_fn = store_prep;
  store_as_oper(store)->eval_fn = store_eval;
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
      std::vector<tagged_noun_t>::iterator lit = env->next_locals.begin();
      for(std::vector<tagged_noun_t>::iterator cit = env->locals.begin(); cit != env->locals.end(); ++cit) {
	UNSHARE(*cit, LOCALS_OWNER);
	*cit = *lit;
	*lit = _UNDEFINED;
	++lit;
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

jit_loop_t *loop_new() {
  jit_loop_t *loop = ALLOC(jit_loop_t);

  loop_as_oper(loop)->prep_fn = loop_prep;
  loop_as_oper(loop)->eval_fn = loop_eval;
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

void env_eval(env_t *env, jit_oper_t *oper, tagged_noun_t args) {
  ENV_CHECK_VOID(NOUN_IS_UNDEFINED(args) == NOUN_IS_UNDEFINED(env->args_root), "Arguments mismatch");

  env_initialize_args(env, args, env->args_root);

  EVAL(oper);
}

void env_prep(env_t *env, jit_oper_t *oper) {
  PREP(oper);

  env->stack.resize(env->max_stack_index + 1, _UNDEFINED);
}

void jit_fib(tagged_noun_t args) {
  struct heap *heap = machine->heap;

  // For testing, generate the AST that the pattern matcher *would*
  // generate when parsing "fib" in Nock:

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

  env_t *env = env_new();

  jit_oper_t *root = decl_as_oper(decl_f0_f1);

  env_prep(env, root);
  env_eval(env, root, args);

  // QQQ
  if (env->failed) 
    ERROR0("Evaluation failed\n");
  else {
    tagged_noun_t popped;
    printf("fib("); noun_print(stdout, args, true); printf(")="); noun_print(stdout, popped = env_get_stack(env, 0), true); printf("\n");
    UNSHARE(popped, STACK_OWNER);
  }

  DELETE(root);
  env_delete(env);
}

void jit_dec(tagged_noun_t args) {
  struct heap *heap = machine->heap;

  // For testing, generate the AST that the pattern matcher *would*
  // generate when parsing "dec" in Nock:

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

  env_t *env = env_new();

  jit_oper_t *root = decl_as_oper(decl_counter);

  env_prep(env, root);
  env_eval(env, root, args);

  // QQQ
  if (env->failed) 
    ERROR0("Evaluation failed\n");
  else {
    tagged_noun_t popped;
    printf("dec("); noun_print(stdout, args, true); printf(")="); noun_print(stdout, popped = env_get_stack(env, 0), true); printf("\n");
    UNSHARE(popped, STACK_OWNER);
  }

  DELETE(root);
  env_delete(env);
}
