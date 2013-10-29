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

#include "fnv.h"

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

#if ARKHAM_USE_NURSERY
#define ARKHAM_USE_NURSERY_INLINE inline
#else
#define ARKHAM_USE_NURSERY_INLINE
#endif

/* TODO: more details on noun/atom representation */

static mpz_t SATOM_MAX_MPZ;

#if UINTPTR_MAX == UINT64_MAX
/* 64 bit pointers */
typedef uint64_t satom_t;
#define SATOM_FMT PRIu64
#define SATOM_X_FMT PRIx64
#define SATOM_T_MAX UINT64_MAX
typedef Fnv64_t Fnv_t;
#define FNV1_INIT FNV1_64_INIT
#define FNV_STR fnv_64_str
#define FNV_BUF fnv_64_buf
#elif UINTPTR_MAX == UINT32_MAX
/* 32 bit pointers */
typedef uint32_t satom_t;
#define SATOM_FMT PRIu32
#define SATOM_X_FMT PRIx32
#define SATOM_T_MAX UINT32_MAX
typedef Fnv32_t Fnv_t;
#define FNV1_INIT FNV1_32_INIT
#define FNV_STR fnv_32_str
#define FNV_BUF fnv_32_buf
#else
/* PDP-10, is that you? */
#error Unsupported pointer size (require 32 or 64 bits)
#endif

typedef struct { satom_t value; } noun_t;

#define ARKHAM_PADDING (ALLOC_DEBUG && !INLINE_REFS) || \
  (!ALLOC_DEBUG && INLINE_REFS)

enum noun_type {
  cell_type,
  batom_type,
  satom_type
};

typedef struct noun_metainfo { 
#if INLINE_REFS
  satom_t refs;
#endif
#if ALLOC_DEBUG
  struct noun_metainfo **owners;
  struct noun_metainfo *next;
  satom_t id;
  enum noun_type type;
#endif

#if ARKHAM_PADDING
  satom_t _padding;
#endif
} noun_metainfo_t;

typedef struct cell_base {
  noun_t left;
  noun_t right;
} cell_base_t;

//XXX: cell->tagged_cell ; cell_base->cell ; assert non-nursery on calls 
//XXX: to query metainfo
typedef struct cell {
  noun_metainfo_t metainfo;
  cell_base_t base;
} cell_t;

#if !INLINE_REFS
typedef struct fat_cell {
  satom_t refs;
  satom_t _padding;
  cell_t cell;
} fat_cell_t;
#endif

typedef struct {
  noun_metainfo_t metainfo;
  mpz_t val;
} batom_t;

#if ARKHAM_LLVM
void llvm_init_global();

struct llvm_s *llvm_new(const char *module_name);

void llvm_delete(struct llvm_s *llvm);
#endif

struct fstack;

struct frame;

typedef struct root {
  noun_t noun;
  struct root *previous;
  struct root *next;
} root_t;

typedef struct write_log {
  noun_t *address;
  noun_t noun;
#if ALLOC_DEBUG
  noun_metainfo_t *owner;
#endif
} write_log_t;

typedef struct heap {
#if ARKHAM_STATS
  unsigned long cell_alloc;
  unsigned long cell_free;
  unsigned long cell_free_list_alloc;
  unsigned long cell_free_list_free;
  unsigned long cells_max;
  unsigned long cell_shared;
  unsigned long cells_max_shared;
  unsigned long cell_max_refs;
  unsigned long cell_to_shared;
  unsigned long cell_to_unshared;
  unsigned long cell_overflow_to_shared;
  unsigned long cell_stably_shared;
  unsigned long batom_alloc;
  unsigned long batom_free;
  unsigned long batoms_max;
  unsigned long batom_shared;
  unsigned long batoms_max_shared;
  unsigned long batom_max_refs;
  unsigned long batom_to_shared;
  unsigned long batom_to_unshared;
  unsigned long root_alloc;
  unsigned long root_free;
  unsigned long gc_count;
#endif
#if ARKHAM_USE_NURSERY
  root_t *first_root;
  root_t *last_root;
  char *nursery_start;
  char *nursery_current;
  char *nursery_end;
  write_log_t *write_log_start;
  write_log_t *write_log_current;
  write_log_t *write_log_end;
#endif /* ARKHAM_USE_NURSERY */
#if ALLOC_DEBUG
  // A linked list of all allocated cells:
  unsigned long current_id;
  noun_metainfo_t *first;
  noun_metainfo_t *last;
#endif
#if CELL_FREE_LIST
  // A circular buffer of freed cells:
  unsigned int cell_free_list_start;
  unsigned int cell_free_list_size;
  cell_t *cell_free_list[CELL_FREE_LIST_SIZE];
#endif
#if SHARED_CELL_LIST
  // TODO: Keep the pointers to cell_t* as well (for updating in place).
  unsigned int shared_cell_list_size;
  cell_t *shared_cell_list[SHARED_CELL_LIST_SIZE];
#endif
} heap_t;

/* The machine struct represents the execution state of the runtime. */
typedef struct machine {
  struct fstack *stack;
  heap_t *heap;
  FILE *out_file;
  FILE *log_file;
  FILE *trace_file;
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
//XXX: cell->tagged_cell ; cell_base->cell ; assert non-nursery on calls 
//XXX: to query metainfo
#define NOUN_AS_PTR(noun) ((noun).value & ~(satom_t)NOUN_FLAGS)
//XXX: cell->tagged_cell ; cell_base->cell ; assert non-nursery on calls 
//XXX: to query metainfo (have inline call noun_get_metainfo w/ ASSERT
#define NOUN_AS_NOUN_METAINFO(noun) ((noun_metainfo_t *)NOUN_AS_PTR(noun))
#define CELL_AS_NOUN(cell) ((noun_t){ .value = (satom_t)(cell) | \
  NOUN_CELL_FLAG | NOUN_NOT_SATOM_FLAG })
#define NOUN_EQUALS(n1, n2) ((n1).value == (n2).value)
#define BATOM_AS_NOUN(batom) ((noun_t){ .value = (satom_t)(batom) | \
  NOUN_NOT_SATOM_FLAG })
#define SATOM_AS_NOUN(satom) ((noun_t){ .value = ((satom)<<1)})
#define RAW_VALUE_AS_NOUN(raw_value) ((noun_t){ .value = raw_value })
#define NOUN_AS_SATOM(noun) ((satom_t)((noun).value>>1))
#define NOUN_IS_SATOM(noun) ((((noun).value & NOUN_NOT_SATOM_FLAG)) == 0)
#define NOUN_IS_CELL(noun) ((((noun).value & (NOUN_NOT_SATOM_FLAG | \
  NOUN_CELL_FLAG))) == (NOUN_NOT_SATOM_FLAG | NOUN_CELL_FLAG))
#define NOUN_IS_BATOM(noun) ((((noun).value & (NOUN_NOT_SATOM_FLAG | \
  NOUN_CELL_FLAG))) == NOUN_NOT_SATOM_FLAG)
#define SATOM_MAX (((satom_t)SATOM_T_MAX) >> 1)
#define SATOM_OVERFLOW_BIT (((satom_t)1) << (sizeof(satom_t)*8-1))

#define _FORWARDED_MARKER BATOM_AS_NOUN((void *)(-1 & ~NOUN_FLAGS))
#define _UNDEFINED BATOM_AS_NOUN(NULL)
#define NOUN_AS_CELL(noun) ((cell_t *)NOUN_AS_NOUN_METAINFO(noun))
#define NOUN_AS_BATOM(noun) ((batom_t *)NOUN_AS_NOUN_METAINFO(noun))
#define NOUN_IS_UNDEFINED(noun) NOUN_EQUALS(noun, _UNDEFINED)
#define NOUN_IS_DEFINED(noun) !NOUN_EQUALS(noun, _UNDEFINED)
#define NOUN_IS_FORWARDED_MARKER(noun) NOUN_EQUALS(noun, _FORWARDED_MARKER)
#if ARKHAM_USE_NURSERY
#if ARKHAM_ASSERT
#define CELLS(count) \
  cell_t *cellp[1]; \
  int _requested = count; \
  bool possible_data_motion = false; \
  cellp[0] = heap_alloc_cells(heap, count, &possible_data_motion); \
  cell_t *_first = cellp[0]
#define DATA_MOVED() possible_data_motion
#define CELLS_ARG cellp
#define CELLS_DECL cell_t *cellp[1]
#define CELL(left, right) CELL_AS_NOUN(cell_new_nursery(&(cellp[0]), \
  left, right))
#define END_CELLS() ASSERT(_requested == (cellp[0] - _first), \
  "Wrong number of allocations\n");
#else /* #if !ARKHAM_ASSERT */
#define CELLS(count) \
  cell_t *cellp[1]; \
  bool possible_data_motion = false; \
  cellp[0] = heap_alloc_cells(heap, count, &possible_data_motion);
#define DATA_MOVED() possible_data_motion
#define CELLS_ARG cellp
#define CELLS_DECL cell_t *cellp[1]
#define CELL(left, right) CELL_AS_NOUN(cell_new_nursery(&(cellp[0]), \
  left, right))
#define END_CELLS() do { } while (false)
#endif /* #if ARKHAM_ASSERT */
#else /* #if !ARKHAM_USE_NURSERY */
#define CELLS(count) do { } while (false)
#define DATA_MOVED() false
#define CELLS_ARG NULL
#define CELLS_DECL void *cellp
#define CELL(left, right) CELL_AS_NOUN(cell_new(heap, left, right))
#define END_CELLS() do { } while (false)
#endif /* #if ARKHAM_USE_NURSERY */

/* Owners from the "root set": */
/* For the stack */
#define STACK_OWNER ((noun_metainfo_t *)1)
/* For interpreter locals */
#define ROOT_OWNER ((noun_metainfo_t *)2)
/* Special for the "cond" function */
#define COND2_OWNER ((noun_metainfo_t *)3)
/* For static variables */
#define HEAP_OWNER ((noun_metainfo_t *)4)
/* For the environment during compilation */
#define ENV_OWNER ((noun_metainfo_t *)5)
/* For the AST during compilation */
#define AST_OWNER ((noun_metainfo_t *)6)
/* For the local variables during abstract interpretation */
#define LOCALS_OWNER ((noun_metainfo_t *)7)

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

void arkham_fail(const char *predicate, const char *file, 
                 const char *function, int line_number, 
                 const char *format, ...);

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
  return noun_as_cell(noun)->base.left;
}

static inline noun_t
noun_get_right(noun_t noun) {
  ASSERT0(noun_get_type(noun) == cell_type);
  return noun_as_cell(noun)->base.right;
}

noun_t cell_set_left(noun_t noun, noun_t left, heap_t *heap);

noun_t cell_set_right(noun_t noun, noun_t left, heap_t *heap);

Fnv_t noun_hash(noun_t noun, Fnv_t hash);

void noun_print(FILE *file, noun_t noun, bool brackets, bool metainfo);

#if ALLOC_DEBUG
void noun_metainfo_print_metainfo(FILE *file, const char *prefix,
  noun_metainfo_t *noun_metainfo, const char *suffix);
#endif

const char *noun_type_to_string(enum noun_type noun_type);

#if ARKHAM_USE_NURSERY
cell_t *cell_new_nursery(struct cell **cellp, noun_t left, noun_t right);
#endif

cell_t *cell_new(heap_t *heap, noun_t left, noun_t right);

bool noun_is_valid_atom(noun_t noun, heap_t *heap);

noun_t atom_add(noun_t n1, noun_t n2);

noun_t atom_equals(noun_t n1, noun_t n2);

noun_t atom_increment(noun_t noun);

noun_t batom_new(heap_t *heap, mpz_t val, bool clear);

noun_t batom_new_ui(heap_t *heap, unsigned long val);

#if ALLOC_DEBUG
noun_t noun_share(noun_t noun, heap_t *heap, noun_metainfo_t *owner);

void noun_unshare(noun_t noun, heap_t *heap, bool toplevel,
  noun_metainfo_t *owner);
#else
noun_t noun_share(noun_t noun, heap_t *heap);

void noun_unshare(noun_t noun, heap_t *heap, bool toplevel);
#endif

#if ARKHAM_STATS
void heap_alloc_cells_stats(heap_t *heap, int count);
#endif

void collect_garbage(size_t size);

static inline char *
heap_alloc(heap_t *heap, size_t size, bool *possible_data_motion) {
  char *chunk;

#if ARKHAM_USE_NURSERY
  char *nursery_next = heap->nursery_current + size;
  if (nursery_next > heap->nursery_end) {
    if (possible_data_motion != NULL)
      *possible_data_motion = true;
    collect_garbage(size);
    nursery_next = heap->nursery_current + size;
  }
  chunk = heap->nursery_current;
  heap->nursery_current = nursery_next;
  ASSERT0(heap->nursery_current <= heap->nursery_end);
#else /* #if !ARKHAM_USE_NURSERY */
  chunk = (cell_t *)calloc(1, size);
#endif /* #if ARKHAM_USE_NURSERY */

  return chunk;
}

static inline cell_t *
heap_alloc_cells(heap_t *heap, int count, bool *possible_data_motion) {
  cell_t *cell = (cell_t *)heap_alloc(heap, count * sizeof(cell_t),
                                      possible_data_motion);

#if ARKHAM_STATS && !ARKHAM_USE_NURSERY
  heap_alloc_cells_stats(heap, count);
#endif

  return cell;
}

root_t *root_new(heap_t *heap, noun_t noun);

void root_delete(heap_t *heap, root_t *root);

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

noun_t accelerate(noun_t subject, noun_t formula, noun_t hint);

#ifdef __cplusplus
}
#endif

#endif /* #if !defined(ARKHAM_H) */
