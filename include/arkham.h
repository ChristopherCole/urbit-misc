/*
 * Copyright 2013 Christopher Cole
 */

#if !defined(ARKHAM_H)
#define ARKHAM_H

/* gmp.h likes to be included outside of any extern "C" blocks. */
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __STDC_FORMAT_MACROS
/* To pick up PRIu64 and friends: */
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <config.h>
#include <stdio.h>

#define ASSERT(p, ...) do { if (ARKHAM_ASSERT && !(p)) arkham_fail(#p, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while(false)
#define ASSERT0(p) do { if (ARKHAM_ASSERT && !(p)) arkham_fail(#p, __FILE__, __FUNCTION__, __LINE__, NULL); } while(false)
#define CRASH(machine) arkham_crash(machine, "Crash: %s: %d\n", __FUNCTION__, __LINE__)
#define IS_DEBUG (ARKHAM_LOG >= ARKHAM_DEBUG)
#define DEBUG_PREFIX "DEBUG:"
#define DEBUG(f, ...) do { if (IS_DEBUG) arkham_log(DEBUG_PREFIX " %s %s %d: " f, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define DEBUG0(s) do { if (ARKHAM_LOG >= ARKHAM_DEBUG) arkham_log(DEBUG_PREFIX " " s); } while (false)
#define IS_INFO (ARKHAM_LOG >= ARKHAM_INFO)
#define INFO_PREFIX "INFO:"
#define INFO(f, ...) do { if (IS_INFO) arkham_log(INFO_PREFIX " %s %s %d: " f, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define INFO0(s) do { if (ARKHAM_LOG >= ARKHAM_INFO) arkham_log(INFO_PREFIX " " s); } while (false)
#define IS_ERROR (ARKHAM_LOG >= ARKHAM_ERROR)
#define ERROR_PREFIX "ERROR:"
#define ERROR(f, ...) do { if (IS_ERROR) arkham_log(ERROR_PREFIX " %S %s %d: " f, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define ERROR0(s) do { if (ARKHAM_LOG >= ARKHAM_ERROR) arkham_log(ERROR_PREFIX " " s); } while (false)
#define IS_WARN (ARKHAM_LOG >= ARKHAM_WARN)
#define WARN_PREFIX "WARN:"
#define WARN(f, ...) do { if (IS_WARN) arkham_log(WARN_PREFIX " %S %s %d: " f, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define WARN0(s) do { if (ARKHAM_LOG >= ARKHAM_WARN) arkham_log(WARN_PREFIX " " s); } while (false)

/* TODO: more details on noun/atom representation */

static mpz_t SATOM_MAX_MPZ;

#if UINTPTR_MAX == UINT64_MAX
/* 64 bit pointers */
typedef uint64_t satom_t;
#define SATOM_FMT PRIu64
#define SATOM_T_MAX UINT64_MAX
#elif UINTPTR_MAX == UINT32_MAX
/* 32 bit pointers */
typedef uint32_t satom_t;
#define SATOM_FMT PRIu32
#define SATOM_T_MAX UINT32_MAX
#else
/* PDP-10, is that you? */
#error Unsupported pointer size (require 32 or 64 bits)
#endif

typedef struct noun { } noun_t;

#if FAT_NOUNS
typedef struct { noun_t *ptr; int flags; } tagged_noun_t;
typedef noun_t *cell_ref_t;
#else
typedef satom_t tagged_noun_t;
typedef tagged_noun_t cell_ref_t;
#endif

typedef struct base { 
#if INLINE_REFS
  satom_t refs;
#endif
#if ALLOC_DEBUG
  struct base **owners;
  struct base *next;
  unsigned long id;
#endif
  cell_ref_t left;
} base_t;

typedef struct cell {
  base_t base;
  cell_ref_t right;
} cell_t;

typedef struct {
  base_t base;
  mpz_t val;
} batom_t;

enum noun_type {
  cell_type,
  batom_type,
  satom_type
};

#if ARKHAM_LLVM
void llvm_init_global();

struct llvm_s *llvm_new(const char *module_name);

void llvm_delete(struct llvm_s *llvm);
#endif

struct fstack;

struct frame;

/* The machine struct represents the execution state of the runtime. */
typedef struct machine {
  struct fstack *stack;
  struct heap *heap;
  FILE *file;
#if ARKHAM_LLVM
  struct llvm_s *llvm;
#endif
  bool trace_flag;
#if ARKHAM_STATS
  unsigned long ops;
#endif  
} machine_t;

/* Note: We use pointer tagging to distinguish types.  Implicitly,
 * this means that we assume that allocations will give us the low two
 * bits to play with (aligned on at least 4 byte boundary). We assert
 * this (TODO). */
#if FAT_NOUNS
#define NOUN_SATOM_FLAG 1
#define NOUN_PTR_SATOM_LEFT_FLAG 1
#define NOUN_PTR_SATOM_RIGHT_FLAG 2
#define NOUN_PTR_FLAGS (NOUN_PTR_SATOM_LEFT_FLAG | NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_IS_LEFT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_LEFT_FLAG) == NOUN_PTR_SATOM_LEFT_FLAG)
#define NOUN_IS_RIGHT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_RIGHT_FLAG) == NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_RAW_PTR(noun_ptr) ((void *)(((satom_t)noun_ptr) & ~(satom_t)NOUN_PTR_FLAGS))
#define NOUN_AS_BASE(noun) ((base_t *)NOUN_RAW_PTR((noun).ptr))
#define NOUN_EQUALS(n1, n2) ((n1).ptr == (n2).ptr && (n1).flags == (n2).flags)
#define BATOM_AS_NOUN(batom) ((tagged_noun_t){ .ptr = (noun_t *)(batom), .flags = 0 })
#define NOUN_AS_SATOM(noun) ((satom_t)((noun).ptr))
#define SATOM_AS_NOUN(satom) ((tagged_noun_t){ .ptr = (noun_t *)(satom), .flags = NOUN_SATOM_FLAG })
#define NOUN_IS_SATOM(noun) (((noun).flags & NOUN_SATOM_FLAG) == NOUN_SATOM_FLAG)
#define NOUN_IS_BATOM(noun) (((base_t *)((NOUN_AS_BASE(noun))->left)) == NOUN_AS_BASE(noun))
#define NOUN_IS_CELL(noun) (((base_t *)((NOUN_AS_BASE(noun))->left)) != NOUN_AS_BASE(noun))
#define CELL_REF_NULL NULL
#define SATOM_MAX ((satom_t)SATOM_T_MAX)
#else /* !FAT_NOUNS */
#define NOUN_NOT_SATOM_FLAG 1
#define NOUN_CELL_FLAG 2
#define NOUN_FLAGS (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG)
#define NOUN_AS_PTR(noun) ((noun) & ~(tagged_noun_t)NOUN_FLAGS)
#define NOUN_AS_BASE(noun) ((base_t *)NOUN_AS_PTR(noun))
#define CELL_AS_NOUN(cell) (((tagged_noun_t)(cell)) | NOUN_CELL_FLAG | NOUN_NOT_SATOM_FLAG)
#define NOUN_EQUALS(n1, n2) ((n1) == (n2))
#define BATOM_AS_NOUN(batom) (((tagged_noun_t)(batom)) | NOUN_NOT_SATOM_FLAG)
#define SATOM_AS_NOUN(satom) ((tagged_noun_t)((satom)<<1))
#define NOUN_AS_SATOM(noun) ((satom_t)((noun)>>1))
#define NOUN_IS_SATOM(noun) ((((noun) & NOUN_NOT_SATOM_FLAG)) == 0)
#define NOUN_IS_CELL(noun) ((((noun) & (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))) == (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))
#define NOUN_IS_BATOM(noun) ((((noun) & (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))) == NOUN_NOT_SATOM_FLAG)
#define CELL_REF_NULL ((cell_ref_t)0)
#define SATOM_MAX (((satom_t)SATOM_T_MAX)>>1)
#define SATOM_OVERLOW_BIT (((satom_t)1)<<(sizeof(satom_t)*8-1))
#endif /* !FAT_NOUNS */

#define _UNDEFINED BATOM_AS_NOUN(NULL)
#define NOUN_AS_CELL(noun) ((cell_t *)NOUN_AS_BASE(noun))
#define NOUN_AS_BATOM(noun) ((batom_t *)NOUN_AS_BASE(noun))
#define NOUN_IS_UNDEFINED(noun) NOUN_EQUALS(noun, _UNDEFINED)
#define NOUN_IS_DEFINED(noun) !NOUN_IS_UNDEFINED(noun)
#define CELL(left, right) cell_new(heap, left, right)

#if ALLOC_DEBUG
/* Owners from the "root set": */
#define STACK_OWNER ((base_t *)1) /* For the stack */
#define ROOT_OWNER ((base_t *)2) /* For interpreter locals */
#define COND2_OWNER ((base_t *)3) /* Special for the "cond" function */
#define HEAP_OWNER ((base_t *)4) /* For static variables */
#define ENV_OWNER ((base_t *)5) /* For the environment during compilation */
#define AST_OWNER ((base_t *)6) /* For the AST during compilation */
#define LOCALS_OWNER ((base_t *)7) /* For the local variables during abstract interpretation */
#endif

#if NO_SATOMS
extern tagged_noun_t _UNDEFINED;
extern tagged_noun_t _0;
extern tagged_noun_t _1;
extern tagged_noun_t _2;
extern tagged_noun_t _3;
extern tagged_noun_t _4;
extern tagged_noun_t _5;
extern tagged_noun_t _6;
extern tagged_noun_t _7;
extern tagged_noun_t _8;
extern tagged_noun_t _9;
extern tagged_noun_t _10;
#else
#define _0 SATOM_AS_NOUN(0)
#define _1 SATOM_AS_NOUN(1)
#define _2 SATOM_AS_NOUN(2)
#define _3 SATOM_AS_NOUN(3)
#define _4 SATOM_AS_NOUN(4)
#define _5 SATOM_AS_NOUN(5)
#define _6 SATOM_AS_NOUN(6)
#define _7 SATOM_AS_NOUN(7)
#define _8 SATOM_AS_NOUN(8)
#define _9 SATOM_AS_NOUN(9)
#define _10 SATOM_AS_NOUN(10)
#endif

#define _YES _0
#define _NO _1

/* Gets the thread-local variable holding the pointer to the machine. */
machine_t *machine_get();

/* Sets the thread-local variable holding the pointer to the machine. */
void machine_set(machine_t *m);

void arkham_crash(machine_t *machine, const char *format, ...);

void arkham_fail(const char *predicate, const char *file, const char *function, int line_number, const char *format, ...);

void arkham_log(const char *format, ...);

static inline enum noun_type
noun_get_type(tagged_noun_t noun) {
  if (NOUN_IS_SATOM(noun))
    return satom_type;
  else if (NOUN_IS_CELL(noun))
    return cell_type;
  else
    return batom_type;
}

static inline satom_t
noun_as_satom(tagged_noun_t noun) {
  ASSERT0(noun_get_type(noun) == satom_type);
  return NOUN_AS_SATOM(noun);
}

static inline tagged_noun_t
satom_as_noun(satom_t satom) {
  return SATOM_AS_NOUN(satom);
}

static inline batom_t *
noun_as_batom(tagged_noun_t noun) {
  ASSERT0(noun_get_type(noun) == batom_type);
  return NOUN_AS_BATOM(noun);
}

static inline cell_t *
noun_as_cell(tagged_noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
  return NOUN_AS_CELL(noun);
}

static inline tagged_noun_t
noun_get_left(tagged_noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
#if FAT_NOUNS
  return (tagged_noun_t){ .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->base.left,
      .flags = NOUN_IS_LEFT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
#else
  return noun_as_cell(noun)->base.left;
#endif
}

static inline tagged_noun_t
noun_get_right(tagged_noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
#if FAT_NOUNS
  return (tagged_noun_t){ 
    .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->right,
      .flags = NOUN_IS_RIGHT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
#else
  return noun_as_cell(noun)->right;
#endif
}

tagged_noun_t cell_set_left(tagged_noun_t noun, tagged_noun_t left, struct heap *heap);

tagged_noun_t cell_set_right(tagged_noun_t noun, tagged_noun_t left, struct heap *heap);

void noun_print(FILE *file, tagged_noun_t noun, bool brackets);

const char *noun_type_to_string(enum noun_type noun_type);

tagged_noun_t cell_new(struct heap *heap, tagged_noun_t left, tagged_noun_t right);

bool noun_is_valid_atom(tagged_noun_t noun, struct heap *heap);

tagged_noun_t atom_add(tagged_noun_t n1, tagged_noun_t n2);

tagged_noun_t atom_equals(tagged_noun_t n1, tagged_noun_t n2);

tagged_noun_t atom_increment(tagged_noun_t noun);

tagged_noun_t batom_new(struct heap *heap, mpz_t val, bool clear);

tagged_noun_t batom_new_ui(struct heap *heap, unsigned long val);

#if ALLOC_DEBUG
tagged_noun_t noun_share(tagged_noun_t noun, struct heap *heap, base_t *owner);

void noun_unshare(tagged_noun_t noun, struct heap *heap, bool toplevel, base_t *owner);
#else
tagged_noun_t noun_share(tagged_noun_t noun, struct heap *heap);

void noun_unshare(tagged_noun_t noun, struct heap *heap, bool toplevel);
#endif

typedef struct vec_s {
  size_t elem_count;
  size_t elem_size;
  size_t elem_capacity;
  char *elems;
} vec_t;

void vec_init(vec_t *vec, size_t elem_size);

vec_t *vec_new(size_t elem_size);

void vec_destroy(vec_t *vec);

void vec_delete(vec_t *vec);

void vec_expand(vec_t *vec);

void vec_resize(vec_t *vec, size_t new_elem_count, void *elem);

static inline size_t vec_size(vec_t *vec) {
  return vec->elem_count;
}

static inline void vec_clear(vec_t *vec) {
  vec->elem_count = 0;
}

static inline void *vec_get(vec_t *vec, size_t index) {
  ASSERT0(index < vec->elem_count);
  return (void *)(vec->elems + (vec->elem_size * index));
}

static inline void vec_set(vec_t *vec, size_t index, void *elem) {
  ASSERT0(index < vec->elem_count);
  memcpy(vec->elems + (vec->elem_size * index), elem, vec->elem_size);
}

static inline void vec_set_top(vec_t *vec, void *elem) {
  ASSERT0(vec->elem_count > 0);
  vec_set(vec, vec->elem_count - 1, elem);
}

static inline void vec_push(vec_t *vec, void *elem) {
  if (vec->elem_count == vec->elem_capacity)
    vec_expand(vec);
  ASSERT0(vec->elem_capacity > vec->elem_count);

  ++vec->elem_count;
  vec_set_top(vec, elem);
}

static inline void *vec_get_top(vec_t *vec) {
  ASSERT0(vec->elem_count > 0);
  return vec_get(vec, vec->elem_count - 1);
}

static inline void *vec_pop(vec_t *vec) {
  ASSERT0(vec->elem_count > 0);
  void *result = vec_get_top(vec);
  --vec->elem_count;
  return result;
}

void test_jit(tagged_noun_t args); //QQQ

#ifdef __cplusplus
}
#endif

#endif /* #if !defined(ARKHAM_H) */
