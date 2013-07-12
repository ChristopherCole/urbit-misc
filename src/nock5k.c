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
#include <gmp.h>

#include "nock5k.h"

#if ALLOC_DEBUG
/* When doing allocation debugging we need ownership information: */
#define SHARE(noun, o) noun_share(noun, heap, o)
#define UNSHARE(noun, o) noun_unshare(noun, heap, true, o)
#define UNSHARE_CHILD(noun, o) noun_unshare(noun, heap, false, o)
#else
#define SHARE(noun, o) noun_share(noun, heap)
#define UNSHARE(noun, o) noun_unshare(noun, heap, true)
#define UNSHARE_CHILD(noun, o) noun_unshare(noun, heap, false)
#endif

void
nock_log(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stdout, format, args);
  va_end(args);
}

void
fail(const char *predicate, const char *file, const char *function, int line_number, const char *format, ...) {
  fprintf(stderr, ERROR_PREFIX " Failed predicate: predicate = '%s', file = '%s', function = '%s', line = %d\n", predicate, file, function, line_number);
  if (format != NULL) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }
  abort();
}

static void
usage(const char *format, ...) {
  if (format != NULL) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }

  fprintf(stderr, "%s", "Usage: nock5k [options] [<file1> <file2> ...]\n\n  --enable-tracing\n        turn tracing on\n  --disable-tracing\n        turn tracing off\n  --help\n        prints this usage text\n  <file1> <file2> ...\n        files to interpret (use \"-\" for standard input)\n");
  exit(1);
}

void vec_init(vec_t *vec, size_t elem_size) {
  vec->elem_size = elem_size;
  vec->elem_capacity = 0;
}

vec_t *vec_new(size_t elem_size) {
  vec_t *vec = (vec_t *)calloc(1, sizeof(vec_t));

  vec_init(vec, elem_size);

  return vec;
}

void vec_destroy(vec_t *vec) {
  if (vec->elems != NULL) free(vec->elems);
}

void vec_delete(vec_t *vec) {
  vec_delete(vec);
  free(vec);
}

void vec_resize(vec_t *vec, size_t new_elem_count, void *elem) {
  while (vec->elem_count < new_elem_count)
    vec_push(vec, elem);
  vec->elem_count = new_elem_count;
}

void vec_expand(vec_t *vec) {
  if (vec->elem_capacity == 0) {
    vec->elem_capacity = 1;
    vec->elems = (char *)calloc(vec->elem_capacity, vec->elem_size);    
  } else {
    vec->elem_capacity *= 2;
    vec->elems = (char *)realloc(vec->elems, vec->elem_capacity * vec->elem_size);
  }
}

typedef struct {
  const char *name;
  FILE *file;
} infile_t;

static void noun_print_decl(FILE *file, tagged_noun_t noun);

static inline satom_t
base_get_refs(base_t *base) {
#if INLINE_REFS
  return base->refs;
#endif
}

static inline void
base_inc_refs(base_t *base) {
#if INLINE_REFS
  base->refs += 1;
#endif
}

static inline void
base_dec_refs(base_t *base) {
#if INLINE_REFS
  base->refs -= 1;
#endif
}

#if ALLOC_DEBUG
#define OWNERS_SIZE 16

static void
base_print_header(FILE *file, const char *prefix, base_t *base, const char *suffix) {
  if (base_get_refs(base) == ALLOC_FREE_MARKER)
    fprintf(file, "%s{%lu,###}%s", prefix, base->id, suffix);
  else
    fprintf(file, "%s{%lu,%" SATOM_FMT "}%s", prefix, base->id, base_get_refs(base), suffix);
}

static void
base_print_owners(FILE *file, const char *prefix, base_t *base, const char *suffix) {
  const char *p = "";

  fprintf(file, "%s", prefix);
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (base->owners[i] != NULL) {
      base_t *owner = base->owners[i];
      if (owner == STACK_OWNER)
	fprintf(file, "%sSTACK", p);
      else if (owner == ROOT_OWNER)
	fprintf(file, "%sROOT", p);
      else if (owner == COND2_OWNER)
	fprintf(file, "%sCOND2", p);
      else if (owner == HEAP_OWNER)
	fprintf(file, "%sHEAP", p);
      else
	base_print_header(file, p, owner, "");
      p = ", ";
    }
  }
  fprintf(file, "%s", suffix);
}

static void
base_add_owner(base_t *base, base_t *owner) {
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (base->owners[i] == NULL) {
      base->owners[i] = owner;
      return;
    }
  }
  ASSERT(false, "Couldn't add owner\n");
}

static void
base_remove_owner(base_t *base, base_t *owner) {
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (base->owners[i] == owner) {
      base->owners[i] = NULL;
      return;
    }
  }
  ASSERT(false, "Couldn't remove owner\n");
}
#endif

const char *
noun_type_to_string(enum noun_type noun_type)
{
  switch (noun_type) {
  case cell_type: return "cell_type";
  case satom_type: return "cell_satom";
  case batom_type: return "cell_batom";
  }
}

typedef struct heap {
#if NOCK_STATS
  unsigned long cell_alloc;
  unsigned long cell_free_list_alloc;
  unsigned long cell_free;
  unsigned long cell_free_list_free;
  unsigned long cell_max;
  unsigned long cell_shared;
  unsigned long cell_max_shared;
  unsigned long cell_to_shared;
  unsigned long cell_to_unshared;
  unsigned long cell_overflow_to_shared;
  unsigned long cell_stably_shared;
  unsigned long batom_alloc;
  unsigned long batom_free;
  unsigned long batom_max;
  unsigned long batom_shared;
  unsigned long batom_max_shared;
  unsigned long batom_to_shared;
  unsigned long batom_to_unshared;
#endif
#if ALLOC_DEBUG
  // A linked list of all allocated cells:
  unsigned long current_id;
  base_t *first;
  base_t *last;
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

static void
heap_print_stats(heap_t *heap, FILE *file) {
#if NOCK_STATS
  fprintf(file, "cell_alloc=%lu\n", heap->cell_alloc);
  fprintf(file, "cell_free_list_alloc=%lu\n", heap->cell_free_list_alloc);
  fprintf(file, "cell_free=%lu\n", heap->cell_free);
  fprintf(file, "cell_free_list_free=%lu\n", heap->cell_free_list_free);
  fprintf(file, "cell_max=%lu\n", heap->cell_max);
  fprintf(file, "cell_shared=%lu\n", heap->cell_shared);
  fprintf(file, "cell_max_shared=%lu\n", heap->cell_max_shared);
  fprintf(file, "cell_to_shared=%lu\n", heap->cell_to_shared);
  fprintf(file, "cell_to_unshared=%lu\n", heap->cell_to_unshared);
  fprintf(file, "cell_overflow_to_shared=%lu\n", heap->cell_overflow_to_shared);
  fprintf(file, "cell_stably_shared=%lu\n", heap->cell_stably_shared);
  fprintf(file, "batom_alloc=%lu\n", heap->batom_alloc);
  fprintf(file, "batom_free=%lu\n", heap->batom_free);
  fprintf(file, "batom_max=%lu\n", heap->batom_max);
  fprintf(file, "batom_shared=%lu\n", heap->batom_shared);
  fprintf(file, "batom_max_shared=%lu\n", heap->batom_max_shared);
  fprintf(file, "batom_to_shared=%lu\n", heap->batom_to_shared);
  fprintf(file, "batom_to_unshared=%lu\n", heap->batom_to_unshared);
#endif
#if ALLOC_DEBUG
  for (base_t *base = heap->first; base != NULL; base = base->next) {
    if (base_get_refs(base) != ALLOC_FREE_MARKER) {
      base_print_header(file, "not freed: ", base, "\n");
      base_print_owners(file, "   owners: ", base, "\n");
    }
  }
#endif
}

static heap_t *
heap_new() {
  heap_t *heap = (heap_t *)calloc(1, sizeof(heap_t));
  return heap;
}

static void
heap_free_free_list(heap_t *heap) {
#if CELL_FREE_LIST
  for (int i = 0; i < heap->cell_free_list_size; ++i) {
#if !ALLOC_DEBUG
    free(heap->cell_free_list[(heap->cell_free_list_start + i) % CELL_FREE_LIST_SIZE]);
#endif
#if NOCK_STATS
    ++heap->cell_free;
#endif
  }
#endif
}

static void
heap_free(heap_t *heap) {
  free(heap);
}

#if ALLOC_DEBUG
static void
heap_register_debug(heap_t *heap, base_t *base) {
  base->owners = (base_t **)calloc(1, sizeof(base_t *) * OWNERS_SIZE);
  base->id = ++heap->current_id;
  if (heap->last != NULL)
    heap->last->next = base;
  else
    heap->first = base;
  heap->last = base;
}
#endif

static cell_t *
heap_alloc_cell(heap_t *heap) {
  cell_t *cell;
#if CELL_FREE_LIST
  if (heap->cell_free_list_size > 0) {
    cell = (cell_t *)heap->cell_free_list[heap->cell_free_list_start];
    if (++heap->cell_free_list_start == CELL_FREE_LIST_SIZE)
      heap->cell_free_list_start = 0;
    --heap->cell_free_list_size;
#if NOCK_STATS
    ++heap->cell_free_list_alloc;
#endif
  } else {
#endif
    cell = (cell_t *)calloc(1, sizeof(cell_t));
#if NOCK_STATS
    ++heap->cell_alloc;
    int active_cell = heap->cell_alloc - heap->cell_free;
    if (active_cell > heap->cell_max) {
      heap->cell_max = active_cell;
    }
#endif
#if CELL_FREE_LIST
  }
#endif
  base_t *base = &(cell->base);
#if INLINE_REFS
  base->refs = 0;
#endif
  base->left = CELL_REF_NULL;
  cell->right = CELL_REF_NULL;
#if ALLOC_DEBUG
  heap_register_debug(heap, &(cell->base));
#endif
  return cell;
}

static batom_t *
heap_alloc_batom(heap_t *heap) {
#if NOCK_STATS
  ++heap->batom_alloc;
  int active_batom = heap->batom_alloc - heap->batom_free;
  if (active_batom > heap->batom_max) {
    heap->batom_max = active_batom;
  }
#endif
  batom_t *batom = (batom_t *)calloc(1, sizeof(batom_t));
  base_t *base = &(batom->base);
#if INLINE_REFS
  base->refs = 0;
#endif
 // A cell can't point to itself. This distinguishes a batom from a cell.
  base->left = (cell_ref_t)base;
#if ALLOC_DEBUG
  heap_register_debug(heap, base);
#endif
  return batom;
}

static void
heap_free_cell(heap_t *heap, cell_t *cell) {
  ASSERT0(cell->base.refs != ALLOC_FREE_MARKER);
  cell->base.refs = ALLOC_FREE_MARKER;
#if CELL_FREE_LIST
  if (heap->cell_free_list_size < CELL_FREE_LIST_SIZE) {
    heap->cell_free_list[(heap->cell_free_list_start + heap->cell_free_list_size) % CELL_FREE_LIST_SIZE] = cell;
    ++heap->cell_free_list_size;
#if NOCK_STATS
    ++heap->cell_free_list_free;
#endif
  } else {
#endif
#if !ALLOC_DEBUG
    free(cell);
#endif
#if NOCK_STATS
    ASSERT0(heap->cell_free < heap->cell_alloc);
    ++heap->cell_free;
#endif
#if CELL_FREE_LIST
  }
#endif
}

static void
heap_free_batom(heap_t *heap, batom_t *batom) {
#if NOCK_STATS
  ASSERT0(heap->batom_free < heap->batom_alloc);
  ++heap->batom_free;
#endif
  ASSERT0(batom->base.refs != ALLOC_FREE_MARKER);
  batom->base.refs = ALLOC_FREE_MARKER;
#if !ALLOC_DEBUG
  free(batom);
#endif
}

bool
noun_is_freed(tagged_noun_t noun, heap_t *heap) {
  switch (noun_get_type(noun)) {
  case satom_type: return false;
  case batom_type:
  case cell_type: {
    base_t *base = NOUN_AS_BASE(noun);
    return base_get_refs(base) == ALLOC_FREE_MARKER;
  }
  }
}

bool
noun_is_valid_atom(tagged_noun_t noun, heap_t *heap) {
  return !noun_is_freed(noun, heap) && noun_get_type(noun) != cell_type;
}

static bool
noun_is_shared(tagged_noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  switch (noun_get_type(noun)) {
  case satom_type: return true;
  case batom_type:
  case cell_type: {
    base_t *base = NOUN_AS_BASE(noun);
    return base_get_refs(base) > 1;
  }
  }
}

#if ALLOC_DEBUG
static unsigned long
noun_get_id(tagged_noun_t noun) {
  switch (noun_get_type(noun)) {
  case satom_type: ASSERT0(noun_get_type(noun) != satom_type);
  case batom_type:
  case cell_type: {
    base_t *base = NOUN_AS_BASE(noun);
    return base->id;
  }
  }
}
#endif

#if ALLOC_DEBUG
tagged_noun_t
noun_share(tagged_noun_t noun, heap_t *heap, base_t *owner) {
#else
tagged_noun_t
noun_share(tagged_noun_t noun, heap_t *heap) {
#endif
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return noun;
  case batom_type:
  case cell_type: {
    base_t *base = NOUN_AS_BASE(noun);
#if ALLOC_DEBUG
    base_add_owner(base, owner);
#endif
    satom_t refs = base_get_refs(base);
    ASSERT0(refs != ALLOC_FREE_MARKER);
    if (refs == 1) {
      if (type == cell_type) {
#if SHARED_CELL_LIST
	if (heap->shared_cell_list_size < SHARED_CELL_LIST_SIZE) {
	  // Defer the expense of reference counting.
	  // See "noun_unshare".
	  heap->shared_cell_list[heap->shared_cell_list_size++] = (cell_t *)base;
	  // Return early (avoid the reference counting cost):
	  return noun;
	}
#if NOCK_STATS
	else
	  ++heap->cell_overflow_to_shared;
#endif // NOCK_STATS
#endif // SHARED_CELL_LIST
#if NOCK_STATS
	++heap->cell_shared;
	++heap->cell_to_shared;
	if (heap->cell_shared > heap->cell_max_shared)
	  heap->cell_max_shared = heap->cell_shared;
#endif
      } else {
#if NOCK_STATS
	++heap->batom_shared;
	++heap->batom_to_shared;
	if (heap->batom_shared > heap->batom_max_shared)
	  heap->batom_max_shared = heap->batom_shared;
#endif
      }
    }
    base_inc_refs(base);
    return noun;
  }
  }
}

#if ALLOC_DEBUG
void
noun_unshare(tagged_noun_t noun, heap_t *heap, bool toplevel, base_t *owner) {
#else
void
noun_unshare(tagged_noun_t noun, heap_t *heap, bool toplevel) {
#endif
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return;
  case batom_type:
  case cell_type: {
    base_t *base = NOUN_AS_BASE(noun);
#if ALLOC_DEBUG
    base_remove_owner(base, owner);
#endif
    satom_t refs = base_get_refs(base);
#if SHARED_CELL_LIST
    if (type == cell_type) {
      unsigned int sz = heap->shared_cell_list_size;
      for (int i = 0; i < sz; ++i)
	if (heap->shared_cell_list[i] == (cell_t *)base) {
	  // This unshare matches a deferred pending share. Cancel them.
	  // See "noun_share".
	  heap->shared_cell_list[i] = heap->shared_cell_list[sz - 1];
	  --heap->shared_cell_list_size;
	  // Return early (avoid the reference counting cost):
	  return;
	}
    }
#endif // SHARED_CELL_LIST
    ASSERT0(refs >= 1);
    ASSERT0(refs != ALLOC_FREE_MARKER);
    if (refs == 1) {
      if (type == cell_type) {
	UNSHARE_CHILD(noun_get_left(noun), base);
	UNSHARE_CHILD(noun_get_right(noun), base);
	heap_free_cell(heap, noun_as_cell(noun));
#if SHARED_CELL_LIST
	if (toplevel) {
	  for (int i = 0; i < heap->shared_cell_list_size; ++i)
	    if (heap->shared_cell_list[i] != NULL) {
	      ++heap->cell_stably_shared;
	    }
	  heap->shared_cell_list_size = 0;
	}
#endif // SHARED_CELL_LIST
      } else {
	batom_t *batom = noun_as_batom(noun);
	mpz_clear(batom->val);
	heap_free_batom(heap, batom);
      }
    } else {
#if NOCK_STATS
      if (refs == 2) {
	if (type == cell_type) {
	  --heap->cell_shared;
	  ++heap->cell_to_unshared;
	} else {
	  --heap->batom_shared;
	  ++heap->batom_to_unshared;
	}
      }
#endif
      base_dec_refs(base);
    }
  }
  }
}

tagged_noun_t
cell_set_left(tagged_noun_t noun, tagged_noun_t left, heap_t *heap) {
  ASSERT0(noun_get_type(noun) == cell_type);
  cell_t *cell = noun_as_cell(noun);
  SHARE(left, &(cell->base));
  UNSHARE(noun_get_left(noun), &(cell->base));
#if FAT_NOUNS
  cell->base.left = left.ptr;
  return (tagged_noun_t){
    .ptr = (noun_t *)
    ((((satom_t)noun.ptr) & ~NOUN_PTR_SATOM_LEFT_FLAG) |
     ((noun_get_type(left) == satom_type) ? NOUN_PTR_SATOM_LEFT_FLAG : 0)),
    .flags = 0
  };
#else /* !FAT_NOUNS */
  cell->base.left = left;
  return CELL_AS_NOUN(cell);
#endif
}

tagged_noun_t
cell_set_right(tagged_noun_t noun, tagged_noun_t right, heap_t *heap) {
  ASSERT0(noun_get_type(noun) == cell_type);
  cell_t *cell = noun_as_cell(noun);
  SHARE(right, &(cell->base));
  UNSHARE(noun_get_right(noun), &(cell->base));
#if FAT_NOUNS
  cell->right = right.ptr;
  return (tagged_noun_t){
    .ptr = (noun_t *)
    ((((satom_t)noun.ptr) & ~NOUN_PTR_SATOM_RIGHT_FLAG) |
     ((noun_get_type(right) == satom_type) ? NOUN_PTR_SATOM_RIGHT_FLAG : 0)),
    .flags = 0
  };
#else /* !FAT_NOUNS */
  cell->right = right;
  return CELL_AS_NOUN(cell);
#endif
}

tagged_noun_t
cell_new(heap_t *heap, tagged_noun_t left, tagged_noun_t right) {
  cell_t *cell = heap_alloc_cell(heap);
#if FAT_NOUNS
  cell->base.left = left.ptr;
  cell->right = right.ptr;
#else /* !FAT_NOUNS */
  cell->base.left = left;
  cell->right = right;
#endif
  cell->base.refs = 0;
  SHARE(left, &(cell->base));
  SHARE(right, &(cell->base));
#if FAT_NOUNS
  return (tagged_noun_t){
    .ptr = (noun_t *)
    (((satom_t)cell) |
     ((noun_get_type(left) == satom_type) ? NOUN_PTR_SATOM_LEFT_FLAG : 0) |
     ((noun_get_type(right) == satom_type) ? NOUN_PTR_SATOM_RIGHT_FLAG : 0)),
    .flags = 0
  };
#else /* !FAT_NOUNS */
  return CELL_AS_NOUN(cell);
#endif
}

tagged_noun_t
batom_new(heap_t *heap, mpz_t val, bool clear) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init(batom->val);
  mpz_set(batom->val, val);
  if (clear)
    mpz_clear(val);
  return BATOM_AS_NOUN(batom);
}

tagged_noun_t
batom_new_ui(heap_t *heap, unsigned long val) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init_set_ui(batom->val, val);
  return BATOM_AS_NOUN(batom);
}

static tagged_noun_t
batom_copy(tagged_noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  ASSERT0(noun_get_type(noun) == batom_type);
  batom_t *batom = (batom_t *)NOUN_AS_BASE(noun);
  return batom_new(heap, batom->val, false);
}

static tagged_noun_t
atom_new(heap_t *heap, const char *str) {
  mpz_t val;
  mpz_init_set_str(val, str, 10);
  if (!NO_SATOMS && mpz_cmp(val, SATOM_MAX_MPZ) <= 0)
    return satom_as_noun((satom_t)mpz_get_ui(val));
  else
    return batom_new(heap, val, true);
}

tagged_noun_t
atom_increment(tagged_noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  ASSERT0(noun_get_type(noun) != cell_type);

  if (noun_get_type(noun) == satom_type) {
    satom_t satom = noun_as_satom(noun);
    if (satom != SATOM_MAX)
      return satom_as_noun(satom + 1);
    else {
      noun = batom_new_ui(heap, SATOM_MAX);
    }
  } else {
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);
  }

  batom_t *batom = noun_as_batom(noun);
  mpz_add_ui(batom->val, batom->val, 1);
  return noun;
}

bool
atom_equals(tagged_noun_t a, tagged_noun_t b) {
  enum noun_type a_type = noun_get_type(a);
  enum noun_type b_type = noun_get_type(b);

  ASSERT0(a_type != cell_type);
  ASSERT0(b_type != cell_type);

  // Assume that atoms are normalized:
  if (a_type != b_type) return false;
  if (a_type == satom_type)
    return NOUN_AS_SATOM(a) == NOUN_AS_SATOM(b);
  else
    return mpz_cmp(NOUN_AS_BATOM(a)->val, NOUN_AS_BATOM(b)->val) == 0;
}

tagged_noun_t
atom_add(tagged_noun_t n1, tagged_noun_t n2, heap_t *heap) {
  ASSERT0(noun_is_valid_atom(n1, heap));
  ASSERT0(noun_is_valid_atom(n2, heap));

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

  tagged_noun_t sum;

  if (NOUN_IS_SATOM(n1))
    sum = batom_new_ui(heap, noun_as_satom(n1));
  else
    sum = batom_new(heap, noun_as_batom(n1)->val, /* clear */ false);

  batom_t *bsum = noun_as_batom(sum);

  if (NOUN_IS_SATOM(n2))
    mpz_add_ui(bsum->val, bsum->val, noun_as_satom(n2));
  else
    mpz_add(bsum->val, bsum->val, noun_as_batom(n2)->val);
  
  return sum;
}

static bool
atom_is_even(tagged_noun_t noun) {
  enum noun_type type = noun_get_type(noun);
  ASSERT0(type != cell_type);
  if (type == satom_type)
    return (NOUN_AS_SATOM(noun) & 1) == 0;
  else {
    return mpz_tstbit(noun_as_batom(noun)->val, 0) == 0;
  }
}

static tagged_noun_t
batom_normalize(tagged_noun_t noun, heap_t *heap) {
  batom_t *batom = noun_as_batom(noun);
  if (!NO_SATOMS && mpz_cmp(batom->val, SATOM_MAX_MPZ) <= 0) {
    tagged_noun_t result = satom_as_noun((satom_t)mpz_get_ui(batom->val));
    UNSHARE(noun, NULL);
    return result;
  } else {
    return noun;
  }
}

static satom_t
atom_get_satom(tagged_noun_t noun, bool *fits) {
  ASSERT0(noun_get_type(noun) != cell_type);
  if (noun_get_type(noun) == satom_type) {
    *fits = true;
    return noun_as_satom(noun);
  } else {
    batom_t *batom = noun_as_batom(noun);
    if (mpz_cmp(batom->val, SATOM_MAX_MPZ) <= 0) {
      *fits = true;
      return (satom_t)mpz_get_ui(batom->val);
    } else {
      *fits = false;
      return SATOM_MAX;
    }
  }
}

static tagged_noun_t
atom_div2(tagged_noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  ASSERT0(type != cell_type);
  if (type == satom_type)
    return SATOM_AS_NOUN(NOUN_AS_SATOM(noun) / 2);
  else {
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);

    batom_t *batom = noun_as_batom(noun);
    mpz_divexact_ui(batom->val, batom->val, 2);
    return batom_normalize(noun, heap);
  }
}

static tagged_noun_t
atom_dec_div2(tagged_noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  ASSERT0(type != cell_type);
  if (type == satom_type)
    return SATOM_AS_NOUN((NOUN_AS_SATOM(noun) - 1) / 2);
  else {
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);

    batom_t *batom = noun_as_batom(noun);
    mpz_sub_ui(batom->val, batom->val, 1);
    mpz_divexact_ui(batom->val, batom->val, 2);
    tagged_noun_t result = batom_normalize(noun, heap);
    return result;
  }
}

static void
batom_print(FILE *file, batom_t *atom) {
  char *str = mpz_get_str(NULL, 10, atom->val);
  fprintf(file, "%s", str);
  free(str);
}

static void
cell_print(FILE *file, tagged_noun_t cell, bool brackets) {
  ASSERT0(noun_get_type(cell) == cell_type);
  if (brackets) fprintf(file, "[");
#if ALLOC_DEBUG_PRINT
  base_print_header(file, "", &(noun_as_cell(cell)->base), "");
  fprintf(file, " ");
#endif
  noun_print(file, noun_get_left(cell), true);
  fprintf(file, " ");
  noun_print(file, noun_get_right(cell), ALLOC_DEBUG_PRINT ? true : false);
  if (brackets) fprintf(file, "]");
}

static void
cell_print_decl(FILE *file, tagged_noun_t cell) {
  ASSERT0(noun_get_type(cell) == cell_type);
  fprintf(file, "CELL(");
  noun_print_decl(file, noun_get_left(cell));
  fprintf(file, ", ");
  noun_print_decl(file, noun_get_right(cell));
  fprintf(file, ")");
}

void
noun_print(FILE *file, tagged_noun_t noun, bool brackets) {
  switch (noun_get_type(noun)) {
  case cell_type:
    {
      cell_print(file, noun, brackets);
      break;
    }
  case batom_type:
    {
#if ALLOC_DEBUG_PRINT
      base_print_header(file, "", &(noun_as_batom(noun)->base), "");
#endif
      batom_print(file, noun_as_batom(noun));
      break;
    }
  case satom_type:
    {
      fprintf(file, "%" SATOM_FMT, noun_as_satom(noun));
      break;
    }
  }
}

static void
noun_print_decl(FILE *file, tagged_noun_t noun) {
  switch (noun_get_type(noun)) {
  case cell_type:
    {
      cell_print_decl(file, noun);
      break;
    }
  case batom_type:
    {
      batom_print(file, noun_as_batom(noun));
      break;
    }
  case satom_type:
    {
      satom_t satom = noun_as_satom(noun);
      const char *prefix = ((satom <= 10) ? "_" : "");
      fprintf(file, "%s%" SATOM_FMT, prefix, noun_as_satom(noun));
      break;
    }
  }
}

enum op_t { 
  slash_op, cell_op, inc_op, equals_op, nock_op, /* real (visible) operators */
  cond_op, crash_op, ret_op /* fictitious (invisible) operators */
};

static const char *op_to_string(enum op_t op) {
  const char *op_string;
  switch (op) {
  case slash_op: { op_string = "/"; break; }
  case cell_op: { op_string = "?"; break; }
  case inc_op: { op_string = "+"; break; }
  case equals_op: { op_string = "="; break; }
  case nock_op: { op_string = "*"; break; }
  default: { op_string = NULL; break; }
  }
  ASSERT0(op_string != NULL);
  return op_string;
}

typedef struct { tagged_noun_t root; enum op_t op; } fn_ret_t;

typedef fn_ret_t (*fn_t)(struct machine *machine, struct frame *frame, tagged_noun_t root);

typedef struct frame { fn_t fn; tagged_noun_t data; } frame_t;

typedef struct fstack { 
  size_t capacity; 
  size_t size; 
#if NOCK_STATS
  size_t max_size;
#endif
  frame_t frames[0];
} fstack_t;

void
crash(machine_t *machine, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    abort();
}

static void
stack_print_stats(fstack_t *stack, FILE *file) {
#if NOCK_STATS
  fprintf(file, "max_size=%lu\n", stack->max_size);
#endif
}

static fstack_t *
stack_new(int capacity) {
  fstack_t *stack = (fstack_t *)calloc(1, sizeof(fstack_t) + capacity * sizeof(frame_t));
  stack->capacity = capacity;
  return stack;
}

static void
stack_free(fstack_t *stack) {
  free(stack);
}

static fstack_t *
stack_push(fstack_t *stack, frame_t frame, bool share, heap_t *heap) {
  if (share)
    SHARE(frame.data, STACK_OWNER);
  if (stack->size >= stack->capacity) {
    stack->capacity = stack->capacity * 2;
    stack = (fstack_t *)realloc(stack, sizeof(fstack_t) + stack->capacity * sizeof(frame_t));
  }
  stack->frames[stack->size++] = frame;
#if NOCK_STATS
  if (stack->size > stack->max_size)
    stack->max_size = stack->size;
#endif
  return stack;
}

static bool
stack_is_empty(fstack_t *stack) {
  return stack->size == 0;
}

static size_t
stack_size(fstack_t *stack) {
  return stack->size;
}

static frame_t *
stack_current_frame(fstack_t *stack) {
  ASSERT0(!stack_is_empty(stack));
  return &(stack->frames[stack->size - 1]);
}

static fstack_t *
stack_pop(fstack_t *stack, bool unshare, heap_t *heap) {
  ASSERT0(!stack_is_empty(stack));
  if (unshare)
    UNSHARE(stack_current_frame(stack)->data, STACK_OWNER);
  --stack->size;
  return stack;
}

static tagged_noun_t parse(machine_t *machine, infile_t *input, bool *eof) {
  heap_t *heap = machine->heap;
  vec_t token;
  vec_init(&token, sizeof(char));
  vec_t stack;
  vec_init(&stack, sizeof(tagged_noun_t));
  int row = 1;
  int column = 1;
  vec_t count;
  vec_init(&count, sizeof(int));
  bool started = false;

  while (true) {
    int c = fgetc(input->file);
    if (c == EOF) {
      *eof = true;
      if (vec_size(&token) > 0) {
	char nul = 0;
	vec_push(&token, &nul);
	satom_t atom = atom_new(heap, vec_get(&token, 0));
	vec_push(&stack, &atom);
	vec_clear(&token);
	if (vec_size(&count) == 0) {
	  fprintf(stderr, "Parse error: raw atom\n");
	  exit(4); // TODO: recover instead of exit
	}
	int n = (*(int *)vec_get_top(&count)) + 1;
	vec_set_top(&count, &n);
      }
      if (!started) return _UNDEFINED;
      if (vec_size(&stack) != 1) {
	fprintf(stderr, "Parse error: unclosed '['\n");
	exit(4); // TODO: recover instead of exit
      }
      if (vec_size(&count) > 0) {
	fprintf(stderr, "Parse error: unclosed '['\n");
	exit(4); // TODO: recover instead of exit
      }
      break;
    }
    if (vec_size(&token) == 0) {
  redo:
      if (c == '[') {
	started = true;
	int n = 0;
	vec_push(&count, &n);
      } else if (c == ']') {
	started = true;
	if (vec_size(&count) == 0) {
	  fprintf(stderr, "Parse error: unmatched ']' at column %d\n", column);
	  exit(4); // TODO: recover instead of exit
	}
	if (vec_size(&stack) < 2) {
	  fprintf(stderr, "Parse error: too few atoms (%d) in a cell at column %d\n", *(int *)vec_get_top(&count), column);
	  exit(4); // TODO: recover instead of exit
	}
	for (int i = 1; i < *(int*)vec_get_top(&count); ++i) {
	  tagged_noun_t right = *(tagged_noun_t *)vec_pop(&stack);
	  tagged_noun_t left = *(tagged_noun_t *)vec_pop(&stack);
	  tagged_noun_t cell = cell_new(heap, left, right);
	  vec_push(&stack, &cell);
	}
	vec_pop(&count);
	if (vec_size(&count) > 0)
	  ++(*(int *)vec_get_top(&count));
	if (vec_size(&stack) == 1 && vec_size(&count) == 0) {
	  return *(tagged_noun_t *)vec_get_top(&stack);
	}
      } else if (c >= '0' && c <= '9') {
	started = true;
	vec_push(&token, &c);
      } else if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
	if (c == '\n') {
	  ++row;
	  column = 1;
	}
	continue;
      } else {
	fprintf(stderr, "Parse error: unexpected character '%c' at column %d\n", c, column);
	exit(4); // TODO: recover instead of exit
      }
    } else {
      if (c == '[' || c == ']' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
	if (c == '\n') {
	  ++row;
	  column = 1;
	}
	if (vec_size(&token) > 0) {
	  char nul = 0;
	  vec_push(&token, &nul);
	  tagged_noun_t atom = atom_new(heap, vec_get(&token, 0));
	  vec_clear(&token);
	  vec_push(&stack, &atom);
	  if (vec_size(&count) == 0) {
	    fprintf(stderr, "Parse error: raw atom\n");
	    exit(4); // TODO: recover instead of exit
	  }
	  ++(*(int *)vec_get_top(&count));
	}
	goto redo;
      } else if (c >= '0' && c <= '9') {
	vec_push(&token, &c);
      } else {
	fprintf(stderr, "Parse error: unexpected character '%c' at column %d\n", c, column);
	exit(4); // TODO: recover instead of exit
      }
    }

    ++column;
  }

  return *(tagged_noun_t *)vec_get_top(&stack);
}

static void cite(FILE *file, int line, const char *suffix) {
  fprintf(file, "  ::  #%d%s", line, suffix);
}

static void trace(machine_t *machine, enum op_t op, tagged_noun_t noun) {
  FILE *file = machine->file;
  for (int i = 0; i < stack_size(machine->stack); ++i)
    fprintf(file, "__ ");
  fprintf(file, "%s", op_to_string(op));
  noun_print(file, noun, true);
}

#define TRACE() if (trace_flag) trace(machine, op, root)
#define CITE(line) if (trace_flag) cite(file, line, "\n")
#define CITE_INLINE(line) if (trace_flag) cite(file, line, "")
#define CITE_END(p) if (trace_flag && (p)) fprintf(file, "\n")
#define PR(noun) do { fprintf(file, "%s: ", #noun); noun_print(file, noun, true); fprintf(file, "\n"); } while (false)
#define ASSIGN(l, r, o) do { tagged_noun_t old = l; l = SHARE(r, o) ; UNSHARE(old, o); } while (false)
#define L(noun) noun_get_left(noun)
#define R(noun) noun_get_right(noun)
#define T(noun) noun_get_type(noun)
#define FRAME(cf, cd) (frame_t){ .fn = cf, .data = cd }
#define FN tagged_noun_t
#if NO_SATOMS
tagged_noun_t _UNDEFINED;
tagged_noun_t _0;
tagged_noun_t _1;
tagged_noun_t _2;
tagged_noun_t _3;
tagged_noun_t _4;
tagged_noun_t _5;
tagged_noun_t _6;
tagged_noun_t _7;
tagged_noun_t _8;
tagged_noun_t _9;
tagged_noun_t _10;
#endif

static void dump(machine_t *machine, frame_t *frame, tagged_noun_t root, const char *function) {
  FILE *file = machine->file;
  fprintf(file, "root: "); noun_print(file, root, true); fprintf(file, "\n");
  fprintf(file, "data: "); noun_print(file, frame->data, true); fprintf(file, "\n");
  ASSERT(false, "%s\n", function);
}

#define TF() if (machine->trace_flag && TRACE_FUNCTIONS) fprintf(machine->file, "function = %s\n", __FUNCTION__)

static fn_ret_t f13(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  machine->stack = stack_pop(machine->stack, /* unshare */ false, machine->heap);
  heap_t *heap = machine->heap;
  return (fn_ret_t){ .root = SHARE(CELL(_2, root), ROOT_OWNER), .op = slash_op };
}

static fn_ret_t f14(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  machine->stack = stack_pop(machine->stack, /* unshare */ false, machine->heap);
  heap_t *heap = machine->heap;
  return (fn_ret_t){ .root = SHARE(CELL(_3, root), ROOT_OWNER), .op = slash_op };
}

static fn_ret_t f16p2(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t next_root = SHARE(CELL(frame->data, root), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = ret_op };
}

static fn_ret_t f16p1(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t next_root = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f16p2;
  ASSIGN(frame->data, root, STACK_OWNER);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f20p2(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t next_root = SHARE(CELL(frame->data, root), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f20p1(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  FILE *file = machine->file;
  tagged_noun_t next_root = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f20p2;
  ASSIGN(frame->data, root, STACK_OWNER);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f21(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = cell_op };
}

static fn_ret_t f22(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = inc_op };
}

static fn_ret_t f23(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = equals_op };
}

static fn_ret_t f26(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t next_root = SHARE(CELL(root, frame->data), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f27(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t next_root = SHARE(CELL(CELL(root, L(frame->data)), R(R(R(frame->data)))), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t cond2(machine_t *machine, frame_t *frame, tagged_noun_t root) {
  TF();
  tagged_noun_t data = frame->data;
  heap_t *heap = machine->heap;
  SHARE(data, COND2_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true, machine->heap);
  if (T(root) != cell_type) {
    bool fits;
    satom_t satom = atom_get_satom(root, &fits);
    if (!fits || (satom != 0 && satom != 1))
      CRASH(machine);
    heap_t *heap = machine->heap;
    tagged_noun_t r = R(data);
    tagged_noun_t next_root = SHARE(CELL(L(data), (satom == 0 ? L(r) : R(r))), ROOT_OWNER);
    UNSHARE(data, COND2_OWNER);
    tagged_noun_t discard = (satom == 0 ? R(r) : L(r));
    return (fn_ret_t){ .root = next_root, .op = nock_op };
  } else {
    CRASH(machine);
    // Make the compiler happy:
    return (fn_ret_t){ .root = root, .op = crash_op };
  }
}

static fn_ret_t cond1(machine_t *machine, tagged_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  tagged_noun_t a = L(root);
  tagged_noun_t r = R(root);
  tagged_noun_t rr = R(r);
  tagged_noun_t b = L(rr);
  tagged_noun_t rrr = R(rr);
  tagged_noun_t c = L(rrr);
  tagged_noun_t d = R(rrr);
  tagged_noun_t next_root;
  bool implement_directly = true;
  if (implement_directly) {
    next_root = SHARE(CELL(a, b), ROOT_OWNER);
    stack_push(machine->stack, FRAME(cond2, CELL(a, CELL(c, d))), /* share */ true, heap);
  } else {
    next_root = SHARE(CELL(a, CELL(_2, CELL(CELL(_0, _1), CELL(_2, CELL(CELL(_1, CELL(c, d)), CELL(CELL(_1, _0), CELL(_2, CELL(CELL(_1, CELL(_2, _3)), CELL(CELL(_1, _0), CELL(_4, CELL(_4, b))))))))))), ROOT_OWNER);
  }
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static tagged_noun_t nock5k_run_impl(machine_t *machine, enum op_t op, tagged_noun_t root) {
  heap_t *heap = machine->heap;
  FILE *file = machine->file;
  bool trace_flag = machine->trace_flag;

#define CALL0(o, noun, cf) machine->stack = stack_push(machine->stack, FRAME(cf, _UNDEFINED), /* share */ false, heap); ASSIGN(root, noun, ROOT_OWNER); op = o; goto call
#define CALL1(o, noun, cf, cd) machine->stack = stack_push(machine->stack, FRAME(cf, cd), /* share */ true, heap); ASSIGN(root, noun, ROOT_OWNER); op = o; goto call
#define TAIL_CALL(o, noun) ASSIGN(root, noun, ROOT_OWNER); op = o; goto call
#define RET(noun) ASSIGN(root, noun, ROOT_OWNER); goto ret

  SHARE(root, ROOT_OWNER);

  /* interpreter */
  while (true) {
  call:
    TRACE();

#if NOCK_STATS
    ++machine->ops;
#endif

    switch (op) {
    case nock_op: {
      if (T(root) == cell_type) {
	tagged_noun_t r = R(root);
	if (T(r) == cell_type) {
	  tagged_noun_t rl = L(r);
	  if (T(rl) == cell_type) {
	    CITE(16); tagged_noun_t l = L(root); tagged_noun_t nxt1 = CELL(l, CELL(L(rl), R(rl))); 
	    tagged_noun_t nxt2 = CELL(l, R(r)); CALL1(nock_op, nxt1, f16p1, nxt2); 
	  } else /* if (T(rl) != cell_type) */ {
	    bool fits;
	    satom_t satom = atom_get_satom(rl, &fits);
	    if (fits) {
	      switch (satom) {
	      case 0: { CITE(18); tagged_noun_t nxt = CELL(R(r), L(root)); TAIL_CALL(slash_op, nxt); }
	      case 1: { CITE(19); tagged_noun_t nxt = R(r); tagged_noun_t l = L(root); RET(nxt); }
	      case 2: { tagged_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(20); 
		  tagged_noun_t l = L(root);
		  tagged_noun_t nxt1 = CELL(l, L(rr));
		  tagged_noun_t nxt2 = CELL(l, R(rr));
		  CALL1(nock_op, nxt1, f20p1, nxt2);
		} else CRASH(machine);
	      }
	      case 3: { CITE(21); tagged_noun_t nxt = CELL(L(root), R(r)); CALL0(nock_op, nxt, f21); }
	      case 4: { CITE(22); tagged_noun_t nxt = CELL(L(root), R(r)); CALL0(nock_op, nxt, f22); }
	      case 5: { CITE(23); tagged_noun_t nxt = CELL(L(root), R(r)); CALL0(nock_op, nxt, f23); }
	      case 6: { CITE(25); fn_ret_t fn_ret = cond1(machine, root); op = fn_ret.op; UNSHARE(root, ROOT_OWNER); root = fn_ret.root; continue; }
	      case 7: { tagged_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(26); 
		  bool implement_directly = true;
		  if (implement_directly) {
		    // 7r ::     *[a 7 b c]         *[*[a b] c]
		    tagged_noun_t nxt1 = CELL(L(root), L(rr)); tagged_noun_t nxt2 = R(rr); CALL1(nock_op, nxt1, f26, nxt2);
		  } else {
		    tagged_noun_t nxt = CELL(L(root), CELL(_2, CELL(L(rr), CELL(_1, R(rr)))));
		    TAIL_CALL(nock_op, nxt);
		  }
		} else CRASH(machine);
	      }
	      case 8: { tagged_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(27); 
		  bool implement_directly = true;
		  if (implement_directly) {
		    // 8r ::     *[a 8 b c]        *[[*[a b] a] c]
		    tagged_noun_t l = L(root); tagged_noun_t nxt1 = CELL(l, L(rr)); CALL1(nock_op, nxt1, f27, root);
		  } else {
		    tagged_noun_t nxt = CELL(L(root), CELL(_7, CELL(CELL(CELL(_7, CELL(CELL(_0, _1), L(rr))), CELL(_0, _1)), R(rr))));
		    TAIL_CALL(nock_op, nxt);
		  }
		} else CRASH(machine);
	      }
	      case 9: { tagged_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(28); 
		  // TODO: implement direct reduction
		  tagged_noun_t nxt = CELL(L(root), CELL(_7, CELL(R(rr), CELL(_2, CELL(CELL(_0, _1), CELL(_0, L(rr)))))));
		  TAIL_CALL(nock_op, nxt);
		} else CRASH(machine);
	      }
	      case 10: { tagged_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(29); 
		  tagged_noun_t rrl = L(rr);
		  tagged_noun_t nxt;
		  if (T(rrl) == cell_type) { 
		    // TODO: implement direct reduction
		    nxt = CELL(L(root), CELL(_8, CELL(R(rrl), CELL(_7, CELL(CELL(_0, _2), R(rr))))));
		  } else {
		    nxt = CELL(L(root), rrl);
		  }
		  TAIL_CALL(nock_op, nxt);
		} else CRASH(machine);
	      }
	      default: CRASH(machine);
	      }
	    }
	    CRASH(machine);
	  }
	} else /* if (T(r) != cell_type) */ {
	  CRASH(machine);
	}
      } else /* if (T(root) != cell_type) */ {
	CITE(35); CRASH(machine);
      }
    }

    case slash_op: {
      if (T(root) == cell_type) {
	tagged_noun_t l = L(root);
	if (T(l) == cell_type) CRASH(machine);
	else {
	  bool fits;
	  satom_t satom = atom_get_satom(l, &fits);
	  if (fits) {
	    if (satom == 1) { CITE(10); tagged_noun_t nxt = R(root); RET(nxt); }
	    else {
	      tagged_noun_t r = R(root);
	      if (T(r) == cell_type) {
		bool implement_directly = true;
		if (implement_directly) {
		  // Run through the bits from left to right:
		  int msb = (sizeof(satom) * 8 - __builtin_clzl(satom) - 1);
		  satom_t mask = (1 << (msb - 1));
		  tagged_noun_t nxt = r;
		  for (int i = 0; i < msb; ++i) {
		    if (mask & satom) {
		      CITE_INLINE(12); nxt = R(nxt);
		    } else {
		      CITE_INLINE(11); nxt = L(nxt);
		    }
		    mask = (mask >> 1);
		  }
		  CITE_END(msb > 0);
		  RET(nxt);
		} else {
		  if (satom == 2) { CITE(11); tagged_noun_t nxt = L(r); tagged_noun_t rr = R(r); RET(nxt); }
		  else if (satom == 3) { CITE(12); tagged_noun_t nxt = R(r); tagged_noun_t lr = L(r); RET(nxt); }
		  /* else fall through to even/odd check */
		}
	      } else /* if (T(r) != cell_type) */ {
		CITE(34); CRASH(machine);
	      }
	    }
	  } /* else fall through to even/odd check */
	  if (atom_is_even(l)) { CITE(13); tagged_noun_t nxt = CELL(atom_div2(l, heap), R(root)); CALL0(slash_op, nxt, f13); }
	  else { CITE(14); tagged_noun_t nxt = CELL(atom_dec_div2(l, heap), R(root)); CALL0(slash_op, nxt, f14); }
	}
      } else /* if (T(root) != cell_type) */ {
	CITE(34); CRASH(machine);
      }
    }

    case cell_op: {
      if (T(root) == cell_type) {
	CITE(4); RET(_0);
      } else {
	CITE(5); RET(_1);
      }
    }

    case inc_op: {
      if (T(root) != cell_type) {
	CITE(6); RET(atom_increment(root, heap));
      } else {
	CRASH(machine);
      }
    }

    case equals_op: {
      if (T(root) == cell_type) {
	tagged_noun_t l = L(root);
	if (T(l) != cell_type) {
	  tagged_noun_t r = R(root);
	  if (T(r) != cell_type && atom_equals(l, r)) {
	    CITE(7) ; RET(_0);	    
	  } else {
	    CITE(8) ; RET(_1);
	  }
	} else {
	  CRASH(machine);
	}
      } else {
	CITE(33); CRASH(machine);
      }
    }

    case ret_op: { ASSERT0(op != ret_op); }
    case crash_op: { ASSERT0(op != crash_op); }
    case cond_op: { ASSERT0(op != cond_op); }
    }

  ret:
    if (stack_is_empty(machine->stack)) {
      return root;
    } else {
      frame_t *frame = stack_current_frame(machine->stack);
      fn_ret_t fn_ret = frame->fn(machine, frame, root);
      op = fn_ret.op;
      UNSHARE(root, ROOT_OWNER);
      root = fn_ret.root;
      if (op == ret_op)
	goto ret;
    }
  }
}

static void alloc_atoms(heap_t *heap) {
#if NO_SATOMS
  _UNDEFINED = SHARE(batom_new_ui(heap, SATOM_MAX), HEAP_OWNER);
  _0 = SHARE(batom_new_ui(heap, 0), HEAP_OWNER);
  _1 = SHARE(batom_new_ui(heap, 1), HEAP_OWNER);
  _2 = SHARE(batom_new_ui(heap, 2), HEAP_OWNER);
  _3 = SHARE(batom_new_ui(heap, 3), HEAP_OWNER);
  _4 = SHARE(batom_new_ui(heap, 4), HEAP_OWNER);
  _5 = SHARE(batom_new_ui(heap, 5), HEAP_OWNER);
  _6 = SHARE(batom_new_ui(heap, 6), HEAP_OWNER);
  _7 = SHARE(batom_new_ui(heap, 7), HEAP_OWNER);
  _8 = SHARE(batom_new_ui(heap, 8), HEAP_OWNER);
  _9 = SHARE(batom_new_ui(heap, 9), HEAP_OWNER);
  _10 = SHARE(batom_new_ui(heap, 10), HEAP_OWNER);
#endif
}

static void free_atoms(heap_t *heap) {
#if NO_SATOMS
  UNSHARE(_UNDEFINED, HEAP_OWNER);
  UNSHARE(_0, HEAP_OWNER);
  UNSHARE(_1, HEAP_OWNER);
  UNSHARE(_2, HEAP_OWNER);
  UNSHARE(_3, HEAP_OWNER);
  UNSHARE(_4, HEAP_OWNER);
  UNSHARE(_5, HEAP_OWNER);
  UNSHARE(_6, HEAP_OWNER);
  UNSHARE(_7, HEAP_OWNER);
  UNSHARE(_8, HEAP_OWNER);
  UNSHARE(_9, HEAP_OWNER);
  UNSHARE(_10, HEAP_OWNER);
#endif
}

static void nock5k_run(int n_inputs, infile_t *inputs, bool trace_flag, bool interactive_flag, const char *module_name) {
  for (int i = 0; i < n_inputs; ++i) {
    infile_t *input = inputs + i;
    if (input->name != NULL) 
      INFO("Input file: %s\n", input->name);
    else
      INFO0("Input file: standard input\n");

    machine_t machine;
#if NOCK_STATS
    machine.ops = 0;
#endif
    machine.heap = heap_new();
    alloc_atoms(machine.heap);
    machine.stack = stack_new(1);
#if NOCK_LLVM
    machine.llvm = llvm_new(module_name);
#endif
    machine.file = stdout;
    machine.trace_flag = trace_flag;

    machine_set(&machine);

    if (true) { //QQQ
      void jit(tagged_noun_t args); jit(satom_as_noun(200));
    } else {
    bool eof = false;
    do {
      // TODO: use readline (or editline)
      if (interactive_flag) printf("> ");
      tagged_noun_t top = parse(&machine, input, &eof);
      if (NOUN_IS_DEFINED(top)) {
	noun_print(stdout, nock5k_run_impl(&machine, nock_op, top), true); printf("\n");
      }
    } while (interactive_flag && !eof);
    }

    free_atoms(machine.heap);
    heap_free_free_list(machine.heap);
#if NOCK_STATS
    printf("heap stats:\n");
    heap_print_stats(machine.heap, stdout);
    printf("stack stats:\n");
    stack_print_stats(machine.stack, stdout);
    printf("op stats:\n");
    printf("ops=%lu\n", machine.ops);
#endif
#if NOCK_LLVM
    llvm_delete(machine.llvm);
#endif
    heap_free(machine.heap);
    stack_free(machine.stack);
  }
}

#define BEGIN_MATCH_STRING(x) do { const char *___arg = x;
#define STRCMP_CASE(s, code) if (strcmp(___arg, s) == 0) { code; break; }
#define TRUE_CASE(var, code) { const char *var = ___arg; code; break; }
#define END_MATCH_STRING() } while (false)

int
main(int argc, const char *argv[]) {
  mpz_init(SATOM_MAX_MPZ);
  mpz_set_ui(SATOM_MAX_MPZ, SATOM_MAX);

#if NOCK_LLVM
  llvm_init_global();
#endif

  // REVISIT: use getopt?

  const char *trace_env = getenv("NOCK_TRACE");
  if (trace_env == NULL) trace_env = "false";
  bool trace = !(strcasecmp(trace_env, "no") == 0 || strcmp(trace_env, "0") == 0 || strcasecmp(trace_env, "false") == 0);
  bool interactive = false;
  infile_t *inputs = (infile_t *)calloc(1, argc * sizeof(infile_t));
  int n_inputs = 0;
  for (int i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    BEGIN_MATCH_STRING(arg);
    STRCMP_CASE("--help", usage(NULL));
    STRCMP_CASE("--interactive", interactive = true);
    STRCMP_CASE("-i", interactive = true);
    STRCMP_CASE("--enable-tracing", trace = true);
    STRCMP_CASE("--disable-tracing", trace = false);
    STRCMP_CASE("-", { inputs[n_inputs].name = NULL; inputs[n_inputs].file = stdin; ++n_inputs; });
    TRUE_CASE(file, {
	if (strncmp(file, "-", 1) == 0)
	  usage("Unknown option: '%s'\n", file);
	else
	  { FILE *f = fopen(file, "r"); if (f != NULL) { inputs[n_inputs].name = file; inputs[n_inputs].file = f; ++n_inputs; } else usage("File not found: %s\n", file); }
      });
    END_MATCH_STRING();
  }
  if (n_inputs == 0) {
    // Drop into REPL if there are no file specified:
    inputs[n_inputs].name = NULL; inputs[n_inputs].file = stdin; ++n_inputs;
    interactive = true;
  }
  nock5k_run(n_inputs, inputs, trace, interactive, argv[0]);
}
