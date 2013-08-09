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
#define FAIL(p, ...) do { if (!(p)) arkham_fail(#p, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); } while(false)
#define ASSERT0(p) do { if (ARKHAM_ASSERT && !(p)) arkham_fail(#p, __FILE__, __FUNCTION__, __LINE__, NULL); } while(false)
#define FAIL0(p) do { if (!(p)) arkham_fail(#p, __FILE__, __FUNCTION__, __LINE__, NULL); } while(false)
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

#if ARKHAM_URC
#define URC_INLINE inline
#else
#define URC_INLINE
#endif

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

typedef struct { satom_t value; } noun_t;

typedef struct noun_header { 
#if INLINE_REFS
  satom_t refs;
#endif
#if ALLOC_DEBUG
  struct noun_header **owners;
  struct noun_header *next;
  satom_t id;
#endif

#if (ALLOC_DEBUG && !INLINE_REFS) || (!ALLOC_DEBUG && INLINE_REFS)
  satom_t _padding;
#endif
} noun_header_t;

typedef struct cell {
  noun_header_t header;
  noun_t left;
  noun_t right;
} cell_t;

#if !INLINE_REFS
typedef struct fat_cell {
  satom_t refs;
  satom_t _padding;
  cell_t cell;
} fat_cell_t;
#endif

typedef struct {
  noun_header_t header;
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
#define NOUN_NOT_SATOM_FLAG 1
#define NOUN_CELL_FLAG 2
#define NOUN_FLAGS (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG)
#define NOUN_AS_PTR(noun) ((noun).value & ~(satom_t)NOUN_FLAGS)
#define NOUN_AS_NOUN_HEADER(noun) ((noun_header_t *)NOUN_AS_PTR(noun))
#define CELL_AS_NOUN(cell) ((noun_t){ .value = (satom_t)(cell) | NOUN_CELL_FLAG | NOUN_NOT_SATOM_FLAG })
#define NOUN_EQUALS(n1, n2) ((n1).value == (n2).value)
#define BATOM_AS_NOUN(batom) ((noun_t){ .value = (satom_t)(batom) | NOUN_NOT_SATOM_FLAG })
#define SATOM_AS_NOUN(satom) ((noun_t){ .value = ((satom)<<1)})
#define RAW_VALUE_AS_NOUN(raw_value) ((noun_t){ .value = raw_value })
#define NOUN_AS_SATOM(noun) ((satom_t)((noun).value>>1))
#define NOUN_IS_SATOM(noun) ((((noun).value & NOUN_NOT_SATOM_FLAG)) == 0)
#define NOUN_IS_CELL(noun) ((((noun).value & (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))) == (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))
#define NOUN_IS_BATOM(noun) ((((noun).value & (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))) == NOUN_NOT_SATOM_FLAG)
#define SATOM_MAX (((satom_t)SATOM_T_MAX)>>1)
#define SATOM_OVERFLOW_BIT (((satom_t)1)<<(sizeof(satom_t)*8-1))

#define _UNDEFINED BATOM_AS_NOUN(NULL)
#define NOUN_AS_CELL(noun) ((cell_t *)NOUN_AS_NOUN_HEADER(noun))
#define NOUN_AS_BATOM(noun) ((batom_t *)NOUN_AS_NOUN_HEADER(noun))
#define NOUN_IS_UNDEFINED(noun) NOUN_EQUALS(noun, _UNDEFINED)
#define NOUN_IS_DEFINED(noun) !NOUN_IS_UNDEFINED(noun)
#define CELL(left, right) cell_new(heap, left, right)

/* Owners from the "root set": */
#define STACK_OWNER ((noun_header_t *)1) /* For the stack */
#define ROOT_OWNER ((noun_header_t *)2) /* For interpreter locals */
#define COND2_OWNER ((noun_header_t *)3) /* Special for the "cond" function */
#define HEAP_OWNER ((noun_header_t *)4) /* For static variables */
#define ENV_OWNER ((noun_header_t *)5) /* For the environment during compilation */
#define AST_OWNER ((noun_header_t *)6) /* For the AST during compilation */
#define LOCALS_OWNER ((noun_header_t *)7) /* For the local variables during abstract interpretation */

#if NO_SATOMS
extern noun_t _UNDEFINED;
extern noun_t _0;
extern noun_t _1;
extern noun_t _2;
extern noun_t _3;
extern noun_t _4;
extern noun_t _5;
extern noun_t _6;
extern noun_t _7;
extern noun_t _8;
extern noun_t _9;
extern noun_t _10;
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
noun_get_type(noun_t noun) {
  if (NOUN_IS_SATOM(noun))
    return satom_type;
  else if (NOUN_IS_CELL(noun))
    return cell_type;
  else
    return batom_type;
}

static inline satom_t
noun_as_satom(noun_t noun) {
  ASSERT0(noun_get_type(noun) == satom_type);
  return NOUN_AS_SATOM(noun);
}

static inline noun_t
satom_as_noun(satom_t satom) {
  return SATOM_AS_NOUN(satom);
}

static inline batom_t *
noun_as_batom(noun_t noun) {
  ASSERT0(noun_get_type(noun) == batom_type);
  return NOUN_AS_BATOM(noun);
}

static inline cell_t *
noun_as_cell(noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
  return NOUN_AS_CELL(noun);
}

static inline noun_t
noun_get_left(noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
  return noun_as_cell(noun)->left;
}

static inline noun_t
noun_get_right(noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
  return noun_as_cell(noun)->right;
}

noun_t cell_set_left(noun_t noun, noun_t left, struct heap *heap);

noun_t cell_set_right(noun_t noun, noun_t left, struct heap *heap);

void noun_print(FILE *file, noun_t noun, bool brackets);

const char *noun_type_to_string(enum noun_type noun_type);

noun_t cell_new(struct heap *heap, noun_t left, noun_t right);

bool noun_is_valid_atom(noun_t noun, struct heap *heap);

noun_t atom_add(noun_t n1, noun_t n2);

noun_t atom_equals(noun_t n1, noun_t n2);

noun_t atom_increment(noun_t noun);

noun_t batom_new(struct heap *heap, mpz_t val, bool clear);

noun_t batom_new_ui(struct heap *heap, unsigned long val);

#if ALLOC_DEBUG
noun_t noun_share(noun_t noun, struct heap *heap, noun_header_t *owner);

void noun_unshare(noun_t noun, struct heap *heap, bool toplevel, noun_header_t *owner);
#else
noun_t noun_share(noun_t noun, struct heap *heap);

void noun_unshare(noun_t noun, struct heap *heap, bool toplevel);
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

void test_jit(noun_t args); //QQQ

#ifdef __cplusplus
}
#endif

#endif /* #if !defined(ARKHAM_H) */
