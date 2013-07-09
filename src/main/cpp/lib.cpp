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

static inline fat_noun_t
add(fat_noun_t n1, fat_noun_t n2) {
  ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
  ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

  if (n1.flags & n2.flags & NOUN_SATOM_FLAG) {
    satom_t sn1 = noun_as_satom(n1);
    satom_t sn2 = noun_as_satom(n2);
    satom_t sum = sn1 + sn2;
    if (sum >= sn1 && sum >= sn2)
      return satom_as_noun(sum);
  }

  return atom_add(n1, n2, machine->heap);
}

static inline fat_noun_t
inc(fat_noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

  if (n.flags & NOUN_SATOM_FLAG) {
    satom_t satom = noun_as_satom(n);
    if (satom < SATOM_MAX)
      return satom_as_noun(satom + 1);
  }

  return atom_increment(n, machine->heap);
}

static inline bool
eq(fat_noun_t n1, fat_noun_t n2) {
  ASSERT(noun_is_valid_atom(n1, machine->heap), "noun_is_valid_atom(n1, machine->heap)\n");
  ASSERT(noun_is_valid_atom(n2, machine->heap), "noun_is_valid_atom(n2, machine->heap)\n");

  if (n1.flags & n2.flags & NOUN_SATOM_FLAG)
    return noun_as_satom(n1) == noun_as_satom(n2);
  else
    return atom_equals(n1, n2);
}

extern fat_noun_t
fib(fat_noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine->heap), "noun_is_valid_atom(n, machine->heap)\n");

  fat_noun_t f0 = _0;
  fat_noun_t f1 = _1;
  fat_noun_t counter = _0;
  while (true) {
    if (eq(n, counter))
      return f0;
    else {
      counter = inc(counter);
      fat_noun_t sum = add(f0, f1);
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
#define ASSIGN(l, r, o) do { fat_noun_t old = l; l = SHARE(r, o) ; UNSHARE(old, o); } while (false)

typedef uint32_t jit_address_t;
#define JIT_ADDRESS_MAX UINT32_MAX

typedef struct {
  // REVISIT: replace STL uses with small C classes?
  std::vector<fat_noun_t> locals;
  std::vector<fat_noun_t> next_locals;
  std::vector<fat_noun_t> stack;
  fat_noun_t args; // ZZZ: should start as "args_placeholder" and get updated as "args_placeholder" is "pushed down" -- defines the "shape" of the input (and # of args)
  fat_noun_t args_placeholder;
  fat_noun_t local_variable_index_map;
  jit_address_t next_local_variable_index;
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

static jit_address_t
env_get_value_at_address(env_t *env, jit_address_t address) {
  fat_noun_t noun = env->local_variable_index_map;

  if (address == 1) {
    ASSERT(!NOUN_EQUALS(noun, env->args_placeholder), "!NOUN_EQUALS(noun, env->args_placeholder)\n");// ZZZ: do something
    ENV_CHECK(noun_get_type(noun) == satom_type, "Unknown failure", 0);
    satom_t satom = noun_as_satom(noun);
    ENV_CHECK((satom_t)(jit_address_t)satom == satom, "Unknown failure", 0);
    return (jit_address_t)satom;
  }

  // Run through the bits from left to right:
  int msb = (sizeof(address) * 8 - __builtin_clz(address) - 1);
  satom_t mask = (1 << (msb - 1));

  for (int i = 0; i < msb; ++i) {
    if (NOUN_EQUALS(noun, env->args_placeholder)) {
      noun = cell_new(machine->heap, env->args_placeholder, env->args_placeholder);
      if (i == 0)
	ASSIGN(env->local_variable_index_map, noun, ROOT_OWNER);
    }
    // ZZZ: check if cell else fail
    noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
    mask = (mask >> 1);
  }
  
  if (NOUN_EQUALS(noun, env->args_placeholder)) {
    //ZZZ: maps arg to locals here and adjust parent cell
  }

  ENV_CHECK(noun_get_type(noun) == satom_type, "Unknown failure", 0);
  satom_t satom = noun_as_satom(noun);
  ENV_CHECK((satom_t)(jit_address_t)satom == satom, "Unknown failure", 0);
  return (jit_address_t)satom;
}

env_t *env_new() {
  env_t *env = ALLOC(env_t);

  // Use an "impossible" value as the placeholder:
  env->args_placeholder = batom_new_ui(machine->heap, JIT_ADDRESS_MAX + 1);
  SHARE(env->args_placeholder, ROOT_OWNER);
  env->local_variable_index_map = env->args_placeholder;

  return env;
}

void env_delete(env_t *env) {
  // ZZZ: unshare locals? args, local_variable_index_map, args_placeholder?
  ENV_CHECK_VOID(env->stack.size() == 0, "Stack should be empty");
  env->stack.~vector();
  free(env);
}

void env_push(env_t *env, fat_noun_t n) {
  if (env->failed) return;
  ENV_CHECK_VOID(env->stack.size() < JIT_ADDRESS_MAX, "Stack overflow");
  SHARE(n, STACK_OWNER);
  env->stack.push_back(n);
}

fat_noun_t env_pop(env_t *env) {
  if (env->failed) return _UNDEFINED;
  ENV_CHECK(env->stack.size() > 0, "Stack underflow", _UNDEFINED);
  fat_noun_t result = env->stack.back();
  env->stack.pop_back();
  UNSHARE(result, STACK_OWNER);
  return result;
}

static void env_set_local(env_t *env, jit_address_t index, fat_noun_t new_local, bool decl) {
  if (env->failed) return;
  if (decl) {
    if (index >= env->locals.size()) {
      env->locals.resize(index + 1, _UNDEFINED);
      env->next_locals.resize(index + 1, _UNDEFINED);
    }
  } else {
    ENV_CHECK_VOID(index < env->locals.size(), "Unknown failure");
  }

  SHARE(new_local, STACK_OWNER);
  fat_noun_t old_local = env->next_locals[index];
  if (decl) {
    ENV_CHECK_VOID(IS_UNDEFINED(old_local), "Unknown failure");
  } else {
    ENV_CHECK_VOID(!IS_UNDEFINED(old_local), "Unknown failure");
    UNSHARE(old_local, STACK_OWNER);
  }
  env->next_locals[index] = new_local;
}

static fat_noun_t env_get_local(env_t *env, jit_address_t index) {
  if (env->failed) return _UNDEFINED;
  fat_noun_t result = env->locals[index];
  ENV_CHECK(!IS_UNDEFINED(result), "Unknown failure", _UNDEFINED);
  return result;
}

typedef void (*eval_fn_t)(struct jit_oper *oper, env_t *env);
typedef void (*delete_fn_t)(struct jit_oper *oper);

typedef struct jit_oper {
  struct jit_oper *outer;
  eval_fn_t eval_fn;
  delete_fn_t delete_fn;
  // TODO: source information: file, line, column
} jit_oper_t;

typedef struct jit_expr_t {
  jit_oper_t base;
} jit_expr_t;

#define expr_as_oper(expr) (&(expr)->base)

typedef struct jit_decl {
  jit_oper_t base;
  jit_oper_t *inner;
  fat_noun_t local_variable_initial_values;
} jit_decl_t;

#define decl_as_oper(decl) (&(decl)->base)
#define oper_as_decl(oper) ((jit_decl_t *)(oper))

static fat_noun_t decl_eval_impl(env_t *env, fat_noun_t local_variable_initial_values) {
  if (noun_get_type(local_variable_initial_values) == cell_type) {
    fat_noun_t left = decl_eval_impl(env, noun_get_left(local_variable_initial_values));
    fat_noun_t right = decl_eval_impl(env, noun_get_right(local_variable_initial_values));
    return cell_new(machine->heap, left, right);
  } else {
    env_set_local(env, env->next_local_variable_index, local_variable_initial_values, /* decl */ true);
    ENV_CHECK(env->next_local_variable_index < JIT_ADDRESS_MAX, "Too many local variable declarations", _UNDEFINED);
    return satom_as_noun(env->next_local_variable_index++);
  }
}

void decl_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_decl_t *decl = oper_as_decl(oper);

  fat_noun_t added_local_variable_index_map = decl_eval_impl(env, decl->local_variable_initial_values);
  fat_noun_t new_local_variable_index_map = cell_new(machine->heap, added_local_variable_index_map, env->local_variable_index_map);

  ASSIGN(env->local_variable_index_map, new_local_variable_index_map, ROOT_OWNER);

  (decl->inner->eval_fn)(decl->inner, env);
}

void decl_delete(jit_oper_t *oper) {
  jit_decl_t *decl = oper_as_decl(oper);
  UNSHARE(decl->local_variable_initial_values, ROOT_OWNER);
  (decl->inner->delete_fn)(decl->inner);
  free(decl);
}

jit_decl_t *decl_new(fat_noun_t local_variable_initial_values) {
  jit_decl_t *decl = ALLOC(jit_decl_t);

  SHARE(local_variable_initial_values, ROOT_OWNER);
  decl->local_variable_initial_values = local_variable_initial_values;
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

void binop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_binop_t *binop = oper_as_binop(oper);

  jit_oper_t *left = expr_as_oper(binop->left);
  (left->eval_fn)(left, env);

  jit_oper_t *right = expr_as_oper(binop->right);
  (right->eval_fn)(right, env);

  fat_noun_t n1 = env_pop(env);
  fat_noun_t n2 = env_pop(env);

  switch (binop->type) {
  case binop_eq_type:
    env_push(env, (eq(n1, n2) ? _YES : _NO));
    break;
  case binop_add_type:
    env_push(env, add(n1, n2));
    break;
  }
}

void binop_delete(jit_oper_t *oper) {
  jit_binop_t *binop = oper_as_binop(oper);

  (expr_as_oper(binop->left)->delete_fn)(expr_as_oper(binop->left));
  (expr_as_oper(binop->right)->delete_fn)(expr_as_oper(binop->right));

  free(binop);
}

jit_binop_t *binop_new(enum binop_type type) {
  jit_binop_t *binop = ALLOC(jit_binop_t);

  binop->type = type;
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

  env_push(env, inc(env_pop(env)));
}

void inc_delete(jit_oper_t *oper) {
  jit_inc_t *inc = oper_as_inc(oper);

  (expr_as_oper(inc->subexpr)->delete_fn)(expr_as_oper(inc->subexpr));

  free(inc);
}

jit_inc_t *inc_new() {
  jit_inc_t *inc = ALLOC(jit_inc_t);

  inc_as_oper(inc)->eval_fn = inc_eval;
  inc_as_oper(inc)->delete_fn = inc_delete;

  return inc;
}

void inc_set_as_expr(jit_inc_t *inc, jit_expr_t *expr) {
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

void load_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;
  env_push(env, env_get_local(env, env_get_value_at_address(env, oper_as_load(oper)->address)));
}

void load_delete(jit_oper_t *oper) {
  jit_load_t *load = (jit_load_t *)oper;

  free(load);
}

jit_load_t *load_new(jit_address_t address) {
  jit_load_t *load = ALLOC(jit_load_t);

  load->address = address;
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

void store_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_store_t *store = (jit_store_t *)oper;
  jit_oper_t *subexpr = expr_as_oper(store->subexpr);
  (subexpr->eval_fn)(subexpr, env);

  env_set_local(env, env_get_value_at_address(env, oper_as_load(oper)->address), env_pop(env), /* decl */ false);
}

void store_delete(jit_oper_t *oper) {
  jit_store_t *store = oper_as_store(oper);

  free(store);
}

jit_store_t *store_new(jit_address_t address) {
  jit_store_t *store = ALLOC(jit_store_t);

  store->address = address;
  store_as_oper(store)->eval_fn = store_eval;
  store_as_oper(store)->delete_fn = store_delete;

  return store;
}

void store_set_as_expr(jit_store_t *store, jit_expr_t *expr) {
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

void loop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_loop_t *loop = oper_as_loop(oper);
  while (true) {
    jit_oper_t *test = expr_as_oper(loop->test);
    (test->eval_fn)(test, env);

    fat_noun_t result = env_pop(env);
    if (eq(result, _YES)) {
      jit_oper_t *result = expr_as_oper(loop->result);
      (result->eval_fn)(result, env);
      return;
    } else {
      jit_store_list_t *store_list = loop->first_store;
      while (store_list != NULL) {
	jit_oper_t *store = store_as_oper(store_list->store);
	(store->eval_fn)(store, env);
	store_list = store_list->next;
      }
      // Copy the locals for the next iteration:
      env->locals = env->next_locals;
    }
  }
}

void loop_delete(jit_oper_t *oper) {
  jit_loop_t *loop = oper_as_loop(oper);
  jit_oper_t *test = expr_as_oper(loop->test);
  jit_oper_t *result = expr_as_oper(loop->result);
  
  (test->delete_fn)(test);
  (result->delete_fn)(result);

  jit_store_list_t *store_list = loop->first_store;
  while (store_list != NULL) {
    jit_oper_t *store = store_as_oper(store_list->store);
    (store->delete_fn)(store);
    jit_store_list_t *next = store_list->next;
    free(store_list);
    store_list = next;
  }

  free(loop);
}

jit_loop_t *loop_new() {
  jit_loop_t *loop = ALLOC(jit_loop_t);

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

void compile_fib() {
  struct heap *heap = machine->heap;

  jit_decl_t *decl_f0_f1 = decl_new(CELL(_0, _1));
  jit_decl_t *decl_counter = decl_new(_0);
  /**/ decl_set_inner(decl_f0_f1, decl_as_oper(decl_counter));
  jit_loop_t *loop = loop_new();
  /**/ decl_set_inner(decl_counter, loop_as_oper(loop));
  jit_binop_t *eq = binop_new(binop_eq_type);
  /**/ loop_set_test(loop, binop_as_expr(eq));
  jit_load_t *eq_left = load_new(15);
  /**/ binop_set_left(eq, load_as_expr(eq_left));
  jit_load_t *eq_right = load_new(6);
  /**/ binop_set_right(eq, load_as_expr(eq_right));
  jit_load_t *result = load_new(28);
  /**/ loop_set_result(loop, load_as_expr(result));

  jit_store_t *store_6 = store_new(6);
  /**/ loop_add_store(loop, store_6);
  jit_inc_t *inc_6 = inc_new();
  /**/ store_set_as_expr(store_6, inc_as_expr(inc_6));
  jit_load_t *load_6 = load_new(6);
  /**/ inc_set_as_expr(inc_6, load_as_expr(load_6));

  jit_store_t *store_28 = store_new(28);
  /**/ loop_add_store(loop, store_28);
  jit_load_t *load_29 = load_new(29);
  /**/ store_set_as_expr(store_28, load_as_expr(load_29));

  jit_store_t *store_29 = store_new(29);
  /**/ loop_add_store(loop, store_29);
  jit_binop_t *add = binop_new(binop_add_type);
  /**/ store_set_as_expr(store_29, load_as_expr(add));
  jit_load_t *add_left = load_new(28);
  /**/ binop_set_left(add, load_as_expr(add_left));
  jit_load_t *add_right = load_new(29);
  /**/ binop_set_right(add, load_as_expr(add_right));

  env_t *env = env_new();

  jit_oper_t *root = decl_as_oper(decl_f0_f1);
  (root->eval_fn)(root, env);

  // QQQ
  if (env->failed) 
    fprintf(stderr, "%s %s %d: Evaluation failed\n", __FILE__, __FUNCTION__, __LINE__);
  else
    fprintf(stdout, ":: "); noun_print(stdout, env_pop(env), true); fprintf(stdout, "\n");

  (root->delete_fn)(root);
  env_delete(env);
}
