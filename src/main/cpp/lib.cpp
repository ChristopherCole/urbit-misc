#include <stdlib.h>
#include <gmp.h>

#include "nock5k.h"

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

#define CALLOC(t) ((t *)calloc(1, sizeof(t)))
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

//QQQ: delete/free functions
//QQQ: should be fail-ing and not asserting on failure (where possible; grep for ASSERT and consider each one)

typedef struct {
  fat_noun_t locals[16]; //QQQ: TODO: should grow (up to MAX)
  fat_noun_t stack[16]; //QQQ: TODO: should grow (up to MAX)
  jit_address_t stackp;
  fat_noun_t args; // QQQ: should start as "args_placeholder" and get updated as "args_placeholder" is "pushed down" -- defines the "shape" of the input (and # of args)
  fat_noun_t args_placeholder;
  fat_noun_t vars;
  jit_address_t index;
  bool failed;
  const char *failure_message;
} env_t;

static void
env_fail(env_t *env, const char *failure_message) {
  env->failed = true;
  env->failure_message = failure_message;
}

static jit_address_t
env_noun_at(env_t *env, jit_address_t address) {
  fat_noun_t noun = env->vars;

  if (address == 1) {
    ASSERT(!NOUN_EQUALS(noun, env->args_placeholder), "!NOUN_EQUALS(noun, env->args_placeholder)\n");// ZZZ: do something
    ASSERT(noun_get_type(noun) == satom_type, "\n");
    satom_t satom = noun_as_satom(noun);
    ASSERT((satom_t)(jit_address_t)satom == satom, "(satom_t)(jit_address_t)satom == satom\n");
    return (jit_address_t)satom;
  }

  // Run through the bits from left to right:
  int msb = (sizeof(address) * 8 - __builtin_clz(address) - 1);
  satom_t mask = (1 << (msb - 1));

  for (int i = 0; i < msb; ++i) {
    if (NOUN_EQUALS(noun, env->args_placeholder)) {
      noun = cell_new(machine->heap, env->args_placeholder, env->args_placeholder);
      if (i == 0)
	ASSIGN(env->vars, noun, ROOT_OWNER);
    }
    // QQQ: check if cell else fail
    noun = (mask & address) ? noun_get_right(noun) : noun_get_left(noun);
    mask = (mask >> 1);
  }
  
  if (NOUN_EQUALS(noun, env->args_placeholder)) {
    //ZZZ: maps arg to locals here and adjust parent cell
  }

  ASSERT(noun_get_type(noun) == satom_type, "noun_get_type(noun) == satom_type\n");
  satom_t satom = noun_as_satom(noun);
  ASSERT((satom_t)(jit_address_t)satom == satom, "(satom_t)(jit_address_t)satom == satom\n");
  return (jit_address_t)satom;
}

env_t *env_new() {
  env_t *env = CALLOC(env_t);

#if NOCK_ASSERT
  for (jit_address_t i = 0; i < sizeof(env->locals) / sizeof(env->locals[0]); ++i)
    env->locals[i] = _NULL;
#endif

  env->args_placeholder = batom_new_ui(machine->heap, 12345); // QQQ: some other distinguishing value?
  SHARE(env->args_placeholder, ROOT_OWNER);
  env->vars = env->args_placeholder;

  return env;
}

void env_push(env_t *env, fat_noun_t n) {
  // QQQ: ref count? 
  if (env->failed) return;
  if (env->stackp == JIT_ADDRESS_MAX) {
    env_fail(env, "Stack overflow");
    return;
  }
  env->stack[env->stackp++] = n;
}

fat_noun_t env_pop(env_t *env) {
  // QQQ: ref count?
  if (env->failed) return _NULL;
  if (env->stackp == 0) {
    env_fail(env, "Stack underflow");
    return _NULL;
  }
  return env->stack[--env->stackp];
}

typedef void (*eval_fn_t)(struct jit_oper *oper, env_t *env);

typedef struct jit_oper {
  struct jit_oper *outer;
  eval_fn_t eval_fn;
  uint32_t line; // QQQ: TODO
  uint32_t column; // QQQ: TODO
} jit_oper_t;

typedef struct jit_expr_t {
  jit_oper_t base;
} jit_expr_t;

#define expr_as_oper(expr) (&(expr)->base)

typedef struct jit_decl {
  jit_oper_t base;
  jit_oper_t *inner;
  fat_noun_t vars;
} jit_decl_t;

#define decl_as_oper(decl) (&(decl)->base)

static fat_noun_t decl_eval_impl(env_t *env, fat_noun_t vars) {
  if (noun_get_type(vars) == cell_type) {
    fat_noun_t left = decl_eval_impl(env, noun_get_left(vars));
    fat_noun_t right = decl_eval_impl(env, noun_get_right(vars));
    return cell_new(machine->heap, left, right);
  } else {
    env->locals[env->index] = vars;
    SHARE(vars, STACK_OWNER);
    // QQQ: check for index overflow
    return satom_as_noun(env->index++);
  }
}

void decl_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_decl_t *decl = (jit_decl_t *)oper;

  fat_noun_t added_vars = decl_eval_impl(env, decl->vars);
  fat_noun_t new_env_vars = cell_new(machine->heap, added_vars, env->vars);

  ASSIGN(env->vars, new_env_vars, ROOT_OWNER);

  (decl->inner->eval_fn)(decl->inner, env);
}

jit_decl_t *decl_new(fat_noun_t vars) {
  jit_decl_t *decl = CALLOC(jit_decl_t);

  decl->vars = vars;
  decl_as_oper(decl)->eval_fn = decl_eval;

  return decl;
}

void decl_set_inner(jit_decl_t *decl, jit_oper_t *inner) {
  ASSERT(decl->inner == NULL, "decl->inner == NULL\n");
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

void binop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_binop_t *binop = (jit_binop_t *)oper;

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

jit_binop_t *binop_new(enum binop_type type) {
  jit_binop_t *binop = CALLOC(jit_binop_t);

  binop->type = type;
  binop_as_oper(binop)->eval_fn = binop_eval;

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

void inc_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  env_push(env, inc(env_pop(env)));
}

jit_inc_t *inc_new() {
  jit_inc_t *inc = CALLOC(jit_inc_t);

  inc_as_oper(inc)->eval_fn = inc_eval;

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

void load_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  fat_noun_t result = env->locals[env_noun_at(env, ((jit_load_t *)oper)->address)];
  ASSERT(!IS_NULL(result), "!IS_NULL(result)\n");
  env_push(env, result);
}

jit_load_t *load_new(jit_address_t address) {
  jit_load_t *load = CALLOC(jit_load_t);

  load->address = address;
  load_as_oper(load)->eval_fn = load_eval;

  return load;
}

typedef struct jit_store {
  jit_expr_t expr;
  jit_address_t address;
  jit_expr_t *subexpr;
} jit_store_t;

#define store_as_expr(store) (&(store)->expr)
#define store_as_oper(store) expr_as_oper(store_as_expr(store))

void store_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_store_t *store = (jit_store_t *)oper;
  jit_oper_t *subexpr = expr_as_oper(store->subexpr);
  (subexpr->eval_fn)(subexpr, env);

  ASSERT(env->stackp > 0, "env->stackp > 0\n");
  // QQQ: ref count?
  env->locals[env_noun_at(env, ((jit_load_t *)oper)->address)] = env_pop(env);
}

jit_store_t *store_new(jit_address_t address) {
  jit_store_t *store = CALLOC(jit_store_t);

  store->address = address;
  store_as_oper(store)->eval_fn = store_eval;

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

void loop_eval(jit_oper_t *oper, env_t *env) {
  if (env->failed) return;

  jit_loop_t *loop = (jit_loop_t *)oper;
  while (true) {
    jit_oper_t *test = expr_as_oper(loop->test);
    (test->eval_fn)(test, env);

    fat_noun_t result = env_pop(env);
    if (eq(result, _YES)) {
      jit_oper_t *result = expr_as_oper(loop->result);
      (result->eval_fn)(result, env);
      return;
    } else {
      // QQQ: make copies of local vars first?!
      jit_store_list_t *store_list = loop->first_store;
      while (store_list != NULL) {
	jit_oper_t *store = store_as_oper(store_list->store);
	(store->eval_fn)(store, env);
	store_list = store_list->next;
      }
    }
  }
}

jit_loop_t *loop_new() {
  jit_loop_t *loop = CALLOC(jit_loop_t);

  loop_as_oper(loop)->eval_fn = loop_eval;

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
  jit_store_list_t *store_list = CALLOC(jit_store_list_t);
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

  //QQQ
  if (env->failed) 
    fprintf(stderr, "%s %d: Evaluation failed\n", __FUNCTION__, __LINE__);
  else
    fprintf(stdout, ":: "); noun_print(stdout, env_pop(env), true); fprintf(stdout, "\n");
}
