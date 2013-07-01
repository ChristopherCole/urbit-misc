#define __STDC_FORMAT_MACROS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <gmp.h>

#include <stack>
#include <string>

// TODO: INLINE_REFS
#define INLINE_REFS true
#define PRODUCTION true
#define SHARED_CELL_LIST_SIZE 0
#define SHARED_CELL_LIST SHARED_CELL_LIST_SIZE > 0
#define CELL_FREE_LIST_SIZE 16
#define CELL_FREE_LIST CELL_FREE_LIST_SIZE > 0
#define NO_SATOMS false
#define ALLOC_DEBUG (!CELL_FREE_LIST && !PRODUCTION)
#define ALLOC_DEBUG_PRINT (ALLOC_DEBUG && !PRODUCTION)
#define ALLOC_FREE_MARKER 0xfeef1ef0
#define TRACE_FUNCTIONS (false && !PRODUCTION)
#define _ASSERT (true && !PRODUCTION)
#define _DEBUG 4
#define _INFO 3
#define _WARN 2
#define _ERROR 1
#define _LOG 3
#define _STATS true

#define ASSERT(p, ...) do { if (_ASSERT && !(p)) fail(__VA_ARGS__); } while(false)
#define CRASH(machine) crash(machine, "Crash: %s: %d\n", __FUNCTION__, __LINE__)
#define IS_DEBUG (_LOG >= _DEBUG)
#define DEBUG(f, ...) do { if (IS_DEBUG) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define DEBUG0(s) do { if (_LOG >= _DEBUG) printf(s); } while (false)
#define IS_INFO (_LOG >= _INFO)
#define INFO(f, ...) do { if (IS_INFO) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define INFO0(s) do { if (_LOG => _INFO) printf(s); } while (false)

static void
fail(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
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

typedef struct {
  const char *name;
  FILE *file;
} infile_t;

/* representation */
struct cell;

typedef struct noun { } noun_t;

static mpz_t SATOM_MAX_MPZ;

#if UINTPTR_MAX == UINT64_MAX
typedef uint64_t satom_t;
#define SATOM_FMT PRIu64
#define SATOM_MAX UINT64_MAX
#elif UINTPTR_MAX == UINT32_MAX
typedef uint32_t satom_t;
#define SATOM_FMT PRIu32
#define SATOM_MAX UINT32_MAX
#else
#error unsupported pointer size
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
  noun_t *left;
} base_t;

typedef struct cell {
  base_t base;
  noun_t *right;
} cell_t;

typedef struct {
  base_t base;
  mpz_t val;
} batom_t;

typedef struct {
  noun_t *ptr;
  int flags;
} fat_noun_t;

enum noun_type {
  cell_type,
  batom_type,
  satom_type
};

static void noun_print(FILE *file, fat_noun_t noun, bool brackets);

static satom_t
base_get_refs(base_t *base) {
#if INLINE_REFS
  return base->refs;
#endif
}

#if ALLOC_DEBUG
#define OWNERS_SIZE 16
#define STACK_OWNER ((base_t *)1)
#define ROOT_OWNER ((base_t *)2)
#define COND2_OWNER ((base_t *)3)
#define HEAP_OWNER ((base_t *)4)
#define LAST_OWNER HEAP_OWNER

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

/* note: use pointer tagging to distinguish types */
#define NOUN_SATOM_FLAG 1
#define NOUN_PTR_SATOM_LEFT_FLAG 1
#define NOUN_PTR_SATOM_RIGHT_FLAG 2
#define NOUN_PTR_FLAGS (NOUN_PTR_SATOM_LEFT_FLAG | NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_IS_LEFT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_LEFT_FLAG) == NOUN_PTR_SATOM_LEFT_FLAG)
#define NOUN_IS_RIGHT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_RIGHT_FLAG) == NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_RAW_PTR(noun_ptr) ((void *)(((satom_t)noun_ptr) & ~(satom_t)NOUN_PTR_FLAGS))

static enum noun_type
noun_get_type(fat_noun_t noun) {
  if ((noun.flags & NOUN_SATOM_FLAG) == NOUN_SATOM_FLAG)
    return satom_type;
  else {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    // A cell can't point to itself. This distinguishes a batom from a cell.
    return ((base_t *)base->left) == base ? batom_type : cell_type;
  }
}

static satom_t
noun_as_satom(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == satom_type, "noun_get_type(noun) == satom_type\n");
  return (satom_t)noun.ptr;
}

static fat_noun_t
satom_as_noun(satom_t satom) {
  return (fat_noun_t){ .ptr = (noun_t *)satom, .flags = NOUN_SATOM_FLAG };
}

static batom_t *
noun_as_batom(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == batom_type, "noun_get_type(noun) == batom_type\n");
  return (batom_t *)NOUN_RAW_PTR(noun.ptr);
}

static cell_t *
noun_as_cell(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (cell_t *)NOUN_RAW_PTR(noun.ptr);
}

static fat_noun_t
noun_get_left(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t){ .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->base.left,
      .flags = NOUN_IS_LEFT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

static fat_noun_t
noun_get_right(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t){ 
    .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->right,
      .flags = NOUN_IS_RIGHT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

typedef struct {
#if _STATS
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
  unsigned long current_id;
  base_t *first;
  base_t *last;
#endif
#if CELL_FREE_LIST
  unsigned int cell_free_list_start;
  unsigned int cell_free_list_size;
  cell_t *cell_free_list[CELL_FREE_LIST_SIZE];
#endif
#if SHARED_CELL_LIST
  unsigned int shared_cell_list_size;
  cell_t *shared_cell_list[SHARED_CELL_LIST_SIZE];
#endif
} heap_t;

static void
heap_print_stats(heap_t *heap, FILE *file) {
#if _STATS
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
      base_print_owners(file, "    ", base, "\n");
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
#if _STATS
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
#if _STATS
    ++heap->cell_free_list_alloc;
#endif
  } else {
#endif
    cell = (cell_t *)calloc(1, sizeof(cell_t));
#if _STATS
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
  base->left = NULL;
  cell->right = NULL;
#if ALLOC_DEBUG
  heap_register_debug(heap, &(cell->base));
#endif
  return cell;
}

static batom_t *
heap_alloc_batom(heap_t *heap) {
#if _STATS
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
  base->left = (noun_t *)base;
#if ALLOC_DEBUG
  heap_register_debug(heap, base);
#endif
  return batom;
}

static void
heap_free_cell(heap_t *heap, cell_t *cell) {
  ASSERT(cell->base.refs != ALLOC_FREE_MARKER, "cell->base.refs != ALLOC_FREE_MARKER\n");
  cell->base.refs = ALLOC_FREE_MARKER;
#if CELL_FREE_LIST
  if (heap->cell_free_list_size < CELL_FREE_LIST_SIZE) {
    heap->cell_free_list[(heap->cell_free_list_start + heap->cell_free_list_size) % CELL_FREE_LIST_SIZE] = cell;
    ++heap->cell_free_list_size;
#if _STATS
    ++heap->cell_free_list_free;
#endif
  } else {
#endif
#if !ALLOC_DEBUG
    free(cell);
#endif
#if _STATS
    ASSERT(heap->cell_free < heap->cell_alloc, "heap->cell_free < heap->cell_alloc\n");
    ++heap->cell_free;
#endif
#if CELL_FREE_LIST
  }
#endif
}

static void
heap_free_batom(heap_t *heap, batom_t *batom) {
#if _STATS
  ASSERT(heap->batom_free < heap->batom_alloc, "heap->batom_free < heap->batom_alloc\n");
  ++heap->batom_free;
#endif
  ASSERT(batom->base.refs != ALLOC_FREE_MARKER, "batom->base.refs != ALLOC_FREE_MARKER\n");
  batom->base.refs = ALLOC_FREE_MARKER;
#if !ALLOC_DEBUG
  free(batom);
#endif
}

static bool
noun_is_freed(fat_noun_t noun, heap_t *heap) {
  switch (noun_get_type(noun)) {
  case satom_type: return false;
  case batom_type:
  case cell_type: {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    return base_get_refs(base) == ALLOC_FREE_MARKER;
  }
  }
}

static bool
noun_is_shared(fat_noun_t noun, heap_t *heap) {
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  switch (noun_get_type(noun)) {
  case satom_type: return true;
  case batom_type:
  case cell_type: {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    return base_get_refs(base) > 1;
  }
  }
}

#if ALLOC_DEBUG
static unsigned long
noun_get_id(fat_noun_t noun) {
  switch (noun_get_type(noun)) {
  case satom_type: ASSERT(noun_get_type(noun) != satom_type, "noun_get_type(noun) != satom_type\n");
  case batom_type:
  case cell_type: {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    return base->id;
  }
  }
}
#endif

#if ALLOC_DEBUG
static fat_noun_t
noun_share(fat_noun_t noun, heap_t *heap, base_t *owner) {
#else
static fat_noun_t
noun_share(fat_noun_t noun, heap_t *heap) {
#endif
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return noun;
  case batom_type:
  case cell_type: {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
#if ALLOC_DEBUG
    base_add_owner(base, owner);
#endif
    satom_t refs = base_get_refs(base);
    ASSERT(refs != ALLOC_FREE_MARKER, "base->refs != ALLOC_FREE_MARKER\n");
#if INLINE_REFS
    ++base->refs;
#endif
    if (refs == 1) {
      if (type == cell_type) {
#if SHARED_CELL_LIST
	if (heap->shared_cell_list_size < SHARED_CELL_LIST_SIZE)
	  heap->shared_cell_list[heap->shared_cell_list_size++] = (cell_t *)base;
#if _STATS
	else
	  ++heap->cell_overflow_to_shared;
#endif // _STATS
#endif // SHARED_CELL_LIST
#if _STATS
	++heap->cell_shared;
	++heap->cell_to_shared;
	if (heap->cell_shared > heap->cell_max_shared)
	  heap->cell_max_shared = heap->cell_shared;
#endif
      } else {
#if _STATS
	++heap->batom_shared;
	++heap->batom_to_shared;
	if (heap->batom_shared > heap->batom_max_shared)
	  heap->batom_max_shared = heap->batom_shared;
#endif
      }
    }
    return noun;
  }
  }
}

#if ALLOC_DEBUG
static void
noun_unshare(fat_noun_t noun, heap_t *heap, bool toplevel, base_t *owner) {
#else
static void
noun_unshare(fat_noun_t noun, heap_t *heap, bool toplevel) {
#endif
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return;
  case batom_type:
  case cell_type: {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
#if ALLOC_DEBUG
    base_remove_owner(base, owner);
#endif
    satom_t refs = base_get_refs(base);
#if SHARED_CELL_LIST
    if (type == cell_type) {
      unsigned int sz = heap->shared_cell_list_size;
      for (int i = 0; i < sz; ++i)
	if (heap->shared_cell_list[i] == (cell_t *)base) {
	  heap->shared_cell_list[i] = heap->shared_cell_list[sz - 1];
	  --heap->shared_cell_list_size;
	  // ZZZ: ++refs;
	  break;
	}
    }
#endif // SHARED_CELL_LIST
    ASSERT(refs >= 1, "base->refs >= 1\n");
    ASSERT(refs != ALLOC_FREE_MARKER, "base->refs != ALLOC_FREE_MARKER\n");
    if (refs == 1) {
      if (type == cell_type) {
	noun_unshare(noun_get_left(noun), heap, false
#if ALLOC_DEBUG
		     , base
#endif
		     );
	noun_unshare(noun_get_right(noun), heap, false
#if ALLOC_DEBUG
		     , base
#endif
		     );
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
#if _STATS
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
#if INLINE_REFS
      --base->refs;
#endif
    }
  }
  }
}

static fat_noun_t
cell_new(heap_t *heap, fat_noun_t left, fat_noun_t right) {
  cell_t *cell = heap_alloc_cell(heap);
  cell->base.left = left.ptr;
  cell->right = right.ptr;
  cell->base.refs = 0;
  noun_share(left, heap
#if ALLOC_DEBUG
	     , &(cell->base)
#endif
	     );
  noun_share(right, heap 
#if ALLOC_DEBUG
	     , &(cell->base)
#endif
	     );
  fat_noun_t result = (fat_noun_t){
    .ptr = (noun_t *)
      (((satom_t)cell) |
       ((noun_get_type(left) == satom_type) ? NOUN_PTR_SATOM_LEFT_FLAG : 0) |
       ((noun_get_type(right) == satom_type) ? NOUN_PTR_SATOM_RIGHT_FLAG : 0)),
      .flags = 0
      };
  return result;
}

static fat_noun_t
batom_new(heap_t *heap, mpz_t val, bool clear) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init(batom->val);
  mpz_set(batom->val, val);
  if (clear)
    mpz_clear(val);
  return (fat_noun_t){ .ptr = (noun_t *)batom, .flags = 0 };
}

static fat_noun_t
batom_new_ui(heap_t *heap, unsigned long val) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init_set_ui(batom->val, val);
  return (fat_noun_t){ .ptr = (noun_t *)batom, .flags = 0 };
}

static fat_noun_t
batom_copy(fat_noun_t noun, heap_t *heap) {
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  ASSERT(noun_get_type(noun) == batom_type, "noun_get_type(noun) == batom_type\n");
  batom_t *batom = (batom_t *)NOUN_RAW_PTR(noun.ptr);
  return batom_new(heap, batom->val, false);
}

static fat_noun_t
atom_new(heap_t *heap, const char *str) {
  mpz_t val;
  mpz_init_set_str(val, str, 10);
  if (!NO_SATOMS && mpz_cmp(val, SATOM_MAX_MPZ) <= 0)
    return satom_as_noun((satom_t)mpz_get_ui(val));
  else
    return batom_new(heap, val, true);
}

static fat_noun_t
atom_increment(fat_noun_t noun, heap_t *heap) {
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  ASSERT(noun_get_type(noun) != cell_type, "noun_get_type(noun) != cell_type\n");
  if (noun_get_type(noun) == satom_type) {
    satom_t satom = noun_as_satom(noun);
    if (satom != SATOM_MAX)
      return satom_as_noun(satom + 1);
    else {
      noun = batom_new_ui(heap, SATOM_MAX);
      goto unshared;
    }
  }
  
  if (noun_is_shared(noun, heap))
    noun = batom_copy(noun, heap);

 unshared:

  batom_t *batom = noun_as_batom(noun);
  mpz_add_ui(batom->val, batom->val, 1);
  return noun;
}

static bool
atom_equals(fat_noun_t a, fat_noun_t b) {
  enum noun_type a_type = noun_get_type(a);
  enum noun_type b_type = noun_get_type(b);
  ASSERT(a_type != cell_type, "a_type != cell_type\n");
  ASSERT(b_type != cell_type, "b_type != cell_type\n");
  // Assume that atoms are normalized:
  if (a_type != b_type) return false;
  if (a_type == satom_type)
    return ((satom_t)a.ptr) == ((satom_t)b.ptr);
  else {
    return mpz_cmp(((batom_t *)a.ptr)->val, ((batom_t *)b.ptr)->val) == 0;
  }
}

static bool
atom_is_even(fat_noun_t noun) {
  enum noun_type type = noun_get_type(noun);
  ASSERT(type != cell_type, "type != cell_type\n");
  if (type == satom_type)
    return (((satom_t)noun.ptr) & 1) == 0;
  else {
    return mpz_tstbit(noun_as_batom(noun)->val, 0) == 0;
  }
}

static fat_noun_t
batom_normalize(fat_noun_t noun, heap_t *heap) {
  batom_t *batom = noun_as_batom(noun);
  if (!NO_SATOMS && mpz_cmp(batom->val, SATOM_MAX_MPZ) <= 0) {
    fat_noun_t result = satom_as_noun((satom_t)mpz_get_ui(batom->val));
    noun_unshare(noun, heap, true
#if ALLOC_DEBUG
		 , NULL
#endif
		 );
    return result;
  } else {
    return noun;
  }
}

static satom_t
atom_get_satom(fat_noun_t noun, bool *fits) {
  ASSERT(noun_get_type(noun) != cell_type, "noun_get_type(noun) != cell_type\n");
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

static fat_noun_t
atom_div2(fat_noun_t noun, heap_t *heap) {
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  enum noun_type type = noun_get_type(noun);
  ASSERT(type != cell_type, "type != cell_type\n");
  if (type == satom_type)
    return (fat_noun_t){ .ptr = (noun_t *)(((satom_t)noun.ptr) / 2), .flags = NOUN_SATOM_FLAG };
  else {
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);

    batom_t *batom = noun_as_batom(noun);
    mpz_divexact_ui(batom->val, batom->val, 2);
    return batom_normalize(noun, heap);
  }
}

static fat_noun_t
atom_dec_div2(fat_noun_t noun, heap_t *heap) {
  ASSERT(!noun_is_freed(noun, heap), "!noun_is_freed(noun, heap)\n");
  enum noun_type type = noun_get_type(noun);
  ASSERT(type != cell_type, "type != cell_type\n");
  if (type == satom_type)
    return (fat_noun_t){ .ptr = (noun_t *)((((satom_t)noun.ptr) - 1) / 2), .flags = NOUN_SATOM_FLAG };
  else {
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);

    batom_t *batom = noun_as_batom(noun);
    mpz_sub_ui(batom->val, batom->val, 1);
    mpz_divexact_ui(batom->val, batom->val, 2);
    fat_noun_t result = batom_normalize(noun, heap);
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
cell_print(FILE *file, fat_noun_t cell, bool brackets) {
  ASSERT(noun_get_type(cell) == cell_type, "noun_get_type(cell) == cell_type\n");
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
noun_print(FILE *file, fat_noun_t noun, bool brackets) {
  switch (noun_get_type(noun)) {
  case cell_type:
    {
      cell_print(file, noun, brackets);
      break;
    }
  case batom_type:
    {
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
  ASSERT(op_string != NULL, "op_string != NULL\n");
  return op_string;
}

struct fstack;
struct frame;
struct machine;
typedef struct { fat_noun_t root; enum op_t op; } fn_ret_t;
typedef fn_ret_t (*fn_t)(struct machine *machine, struct frame *frame, fat_noun_t root);
typedef struct frame { fn_t fn; fat_noun_t data; } frame_t;
typedef struct fstack { 
  size_t capacity; 
  size_t size; 
#if _STATS
  size_t max_size;
#endif
  frame_t frames[0];
} fstack_t;
typedef struct machine {
  fstack_t *stack;
  heap_t *heap;
  FILE *file;
  bool trace_flag;
#if _STATS
  unsigned long ops;
#endif
} machine_t;

static void
crash(machine_t *machine, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    abort();
}

static void
stack_print_stats(fstack_t *stack, FILE *file) {
#if _STATS
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
stack_push(fstack_t *stack, frame_t frame, heap_t *heap) {
  noun_share(frame.data, heap
#if ALLOC_DEBUG
	     , STACK_OWNER
#endif
	     );
  if (stack->size >= stack->capacity) {
    stack->capacity = stack->capacity * 2;
    stack = (fstack_t *)realloc(stack, sizeof(fstack_t) + stack->capacity * sizeof(frame_t));
  }
  stack->frames[stack->size++] = frame;
#if _STATS
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
  ASSERT(!stack_is_empty(stack), "!stack_is_empty(stack)\n");
  return &(stack->frames[stack->size - 1]);
}

static fstack_t *
stack_pop(fstack_t *stack, heap_t *heap) {
  ASSERT(!stack_is_empty(stack), "!stack_is_empty(stack)\n");
  noun_unshare(stack_current_frame(stack)->data, heap, true
#if ALLOC_DEBUG
	       , STACK_OWNER
#endif
	       );
  --stack->size;
  return stack;
}

static fat_noun_t parse(machine_t *machine, infile_t *input) {
  heap_t *heap = machine->heap;
  std::string token;
  std::stack<fat_noun_t> stack;
  int row = 1;
  int column = 1;
  std::stack<int> count;

  while (true) {
    int c = fgetc(input->file);
    if (c == EOF) {
      if (stack.size() != 1) {
	fprintf(stderr, "Parse error: unclosed '['\n");
	exit(4);
      }
      if (count.size() > 0) {
	fprintf(stderr, "Parse error: unclosed '['\n");
	exit(4);
      }
      break;
    }
    if (token.size() == 0) {
  redo:
      if (c == '[') {
	count.push(0);
      } else if (c == ']') {
	if (count.size() == 0) {
	  fprintf(stderr, "Parse error: unmatched ']' at column %d\n", column);
	  exit(4);
	}
	if (stack.size() < 2) {
	  fprintf(stderr, "Parse error: too few atoms (%d) in a cell at column %d\n", count.top(), column);
	  exit(4);
	}
	for (int i = 1; i < count.top(); ++i) {
	  fat_noun_t right = stack.top();
	  stack.pop();
	  fat_noun_t left = stack.top();
	  stack.pop();
	  stack.push(cell_new(heap, left, right));
	}
	count.pop();
	if (count.size() > 0)
	  ++count.top();
      } else if (c >= '0' && c <= '9') {
	token.push_back((char)c);
      } else if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
	if (c == '\n') {
	  ++row;
	  column = 1;
	}
	continue;
      } else {
	fprintf(stderr, "Parse error: unexpected character '%c' at column %d\n", c, column);
	exit(4);
      }
    } else {
      if (c == '[' || c == ']' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
	if (c == '\n') {
	  ++row;
	  column = 1;
	}
	if (token.size() > 0) {
	  stack.push(atom_new(heap, token.c_str()));
	  ++count.top();
	  token.clear();
	}
	goto redo;
      } else if (c >= '0' && c <= '9') {
	token.push_back((char)c);
      } else {
	fprintf(stderr, "Parse error: unexpected character '%c' at column %d\n", c, column);
	exit(4);
      }
    }

    ++column;
  }

  return stack.top();
}

static void cite(FILE *file, int line) {
  fprintf(file, "  ::  #%d\n", line);
}

static void trace(machine_t *machine, enum op_t op, fat_noun_t noun) {
  FILE *file = machine->file;
  for (int i = 0; i < stack_size(machine->stack); ++i)
    fprintf(file, "__ ");
  fprintf(file, "%s", op_to_string(op));
  noun_print(file, noun, true);
}

#define TRACE() if (trace_flag) trace(machine, op, root)
#define CITE(line) if (trace_flag) cite(file, line)
#define PR(noun) do { fprintf(file, "%s: ", #noun); noun_print(file, noun, true); fprintf(file, "\n"); } while (false)
#define CELL(left, right) cell_new(heap, left, right)
#if ALLOC_DEBUG
#define ASSIGN(l, r, o) do { fat_noun_t old = l; l = noun_share(r, heap, o) ; noun_unshare(old, heap, true, o); } while (false)
#define SHARE(noun, o) noun_share(noun, heap, o)
#define UNSHARE(noun, o) noun_unshare(noun, heap, true, o)
#else
#define ASSIGN(l, r, o) do { fat_noun_t old = l; l = noun_share(r, heap) ; noun_unshare(old, heap, true); } while (false)
#define SHARE(noun, o) noun_share(noun, heap)
#define UNSHARE(noun, o) noun_unshare(noun, heap, true)
#endif
#define L(noun) noun_get_left(noun)
#define R(noun) noun_get_right(noun)
#define T(noun) noun_get_type(noun)
#define FRAME(cf, cd) (frame_t){ .fn = cf, .data = cd }
#define FN fat_noun_t
#if NO_SATOMS
static fat_noun_t _NAN;
static fat_noun_t _0;
static fat_noun_t _1;
static fat_noun_t _2;
static fat_noun_t _3;
static fat_noun_t _4;
static fat_noun_t _5;
static fat_noun_t _6;
static fat_noun_t _7;
static fat_noun_t _8;
#else
#define _NAN ((fat_noun_t){ .ptr = (noun_t *)SATOM_MAX, .flags = NOUN_SATOM_FLAG })
#define _0 ((fat_noun_t){ .ptr = (noun_t *)0, .flags = NOUN_SATOM_FLAG })
#define _1 ((fat_noun_t){ .ptr = (noun_t *)1, .flags = NOUN_SATOM_FLAG })
#define _2 ((fat_noun_t){ .ptr = (noun_t *)2, .flags = NOUN_SATOM_FLAG })
#define _3 ((fat_noun_t){ .ptr = (noun_t *)3, .flags = NOUN_SATOM_FLAG })
#define _4 ((fat_noun_t){ .ptr = (noun_t *)4, .flags = NOUN_SATOM_FLAG })
#define _5 ((fat_noun_t){ .ptr = (noun_t *)5, .flags = NOUN_SATOM_FLAG })
#define _6 ((fat_noun_t){ .ptr = (noun_t *)6, .flags = NOUN_SATOM_FLAG })
#define _7 ((fat_noun_t){ .ptr = (noun_t *)7, .flags = NOUN_SATOM_FLAG })
#define _8 ((fat_noun_t){ .ptr = (noun_t *)8, .flags = NOUN_SATOM_FLAG })
#endif

static void dump(machine_t *machine, frame_t *frame, fat_noun_t root, const char *function) {
  FILE *file = machine->file;
  fprintf(file, "root: "); noun_print(file, root, true); fprintf(file, "\n");
  fprintf(file, "data: "); noun_print(file, frame->data, true); fprintf(file, "\n");
  ASSERT(false, "%s\n", function);
}

#define TF() if (machine->trace_flag && TRACE_FUNCTIONS) fprintf(machine->file, "function = %s\n", __FUNCTION__)

static fn_ret_t f13(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  machine->stack = stack_pop(machine->stack, machine->heap);
  heap_t *heap = machine->heap;
  return (fn_ret_t){ .root = SHARE(CELL(_2, root), ROOT_OWNER), .op = slash_op };
}

static fn_ret_t f14(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  machine->stack = stack_pop(machine->stack, machine->heap);
  heap_t *heap = machine->heap;
  return (fn_ret_t){ .root = SHARE(CELL(_3, root), ROOT_OWNER), .op = slash_op };
}

static fn_ret_t f16p2(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  fat_noun_t next_root = SHARE(CELL(frame->data, root), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, heap);
  return (fn_ret_t){ .root = next_root, .op = ret_op };
}

static fn_ret_t f16p1(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  fat_noun_t data = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f16p2;
  ASSIGN(frame->data, root, STACK_OWNER);
  return (fn_ret_t){ .root = data, .op = nock_op };
}

static fn_ret_t f20p2(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  fat_noun_t next_root = SHARE(CELL(frame->data, root), ROOT_OWNER);
  machine->stack = stack_pop(machine->stack, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f20p1(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  FILE *file = machine->file;
  fat_noun_t data = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f20p2;
  ASSIGN(frame->data, root, STACK_OWNER);
  return (fn_ret_t){ .root = data, .op = nock_op };
}

static fn_ret_t f21(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = cell_op };
}

static fn_ret_t f22(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = inc_op };
}

static fn_ret_t f23(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, heap);
  return (fn_ret_t){ .root = SHARE(root, ROOT_OWNER), .op = equals_op };
}

static fn_ret_t cond2(machine_t *machine, frame_t *frame, fat_noun_t root) {
  TF();
  fat_noun_t data = frame->data;
  heap_t *heap = machine->heap;
  SHARE(data, COND2_OWNER);
  machine->stack = stack_pop(machine->stack, machine->heap);
  if (T(root) != cell_type) {
    bool fits;
    satom_t satom = atom_get_satom(root, &fits);
    if (!fits || (satom != 0 && satom != 1))
      CRASH(machine);
    heap_t *heap = machine->heap;
    fat_noun_t r = R(data);
    fat_noun_t next_root = SHARE(CELL(L(data), (satom == 0 ? L(r) : R(r))), ROOT_OWNER);
    UNSHARE(data, COND2_OWNER);
    fat_noun_t discard = (satom == 0 ? R(r) : L(r));
    return (fn_ret_t){ .root = next_root, .op = nock_op };
  } else {
    CRASH(machine);
    // Make the compiler happy:
    return (fn_ret_t){ .root = root, .op = crash_op };
  }
}

static fn_ret_t cond1(machine_t *machine, fat_noun_t root) {
  TF();
  heap_t *heap = machine->heap;
  bool reduce = false;
  fat_noun_t a = L(root);
  fat_noun_t r = R(root);
  fat_noun_t rr = R(r);
  fat_noun_t b = L(rr);
  fat_noun_t rrr = R(rr);
  fat_noun_t c = L(rrr);
  fat_noun_t d = R(rrr);
  fat_noun_t next_root;
  if (reduce) {
    next_root = SHARE(CELL(a, CELL(_2, CELL(CELL(_0, _1), CELL(_2, CELL(CELL(_1, CELL(c, d)), CELL(CELL(_1, _0), CELL(_2, CELL(CELL(_1, CELL(_2, _3)), CELL(CELL(_1, _0), CELL(_4, CELL(_4, b))))))))))), ROOT_OWNER);
  } else {
    next_root = SHARE(CELL(a, b), ROOT_OWNER);
    stack_push(machine->stack, FRAME(cond2, CELL(a, CELL(c, d))), heap);
  }
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fat_noun_t nock5k_run_impl(machine_t *machine, enum op_t op, fat_noun_t root) {
  heap_t *heap = machine->heap;
  FILE *file = machine->file;
  bool trace_flag = machine->trace_flag;

#define CALL(o, noun, cf, cd) machine->stack = stack_push(machine->stack, FRAME(cf, cd), heap); ASSIGN(root, noun, ROOT_OWNER); op = o; goto call
#define TAIL_CALL(o, noun) ASSIGN(root, noun, ROOT_OWNER); op = o; goto call
#define RET(noun) ASSIGN(root, noun, ROOT_OWNER); goto ret

  noun_share(root, heap
#if ALLOC_DEBUG
	     , ROOT_OWNER
#endif
	     );

  /* interpreter */
  while (true) {
  call:
    TRACE();

#if _STATS
    ++machine->ops;
#endif

    switch (op) {
    case nock_op: {
      if (T(root) == cell_type) {
	fat_noun_t r = R(root);
	if (T(r) == cell_type) {
	  fat_noun_t rl = L(r);
	  if (T(rl) == cell_type) {
	    CITE(16); fat_noun_t l = L(root); fat_noun_t nxt1 = CELL(l, CELL(L(rl), R(rl))); 
	    fat_noun_t nxt2 = CELL(l, R(r)); CALL(nock_op, nxt1, f16p1, nxt2); 
	  } else /* if (T(rl) != cell_type) */ {
	    bool fits;
	    satom_t satom = atom_get_satom(rl, &fits);
	    if (fits) {
	      switch (satom) {
	      case 0: { CITE(18); fat_noun_t nxt = CELL(R(r), L(root)); TAIL_CALL(slash_op, nxt); }
	      case 1: { CITE(19); fat_noun_t nxt = R(r); fat_noun_t l = L(root); RET(nxt); }
	      case 2: { fat_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(20); 
		  fat_noun_t l = L(root);
		  fat_noun_t nxt1 = CELL(l, L(rr));
		  fat_noun_t nxt2 = CELL(l, R(rr));
		  CALL(nock_op, nxt1, f20p1, nxt2);
		} else CRASH(machine);
	      }
	      case 3: { CITE(21); fat_noun_t nxt = CELL(L(root), R(r)); CALL(nock_op, nxt, f21, _NAN); }
	      case 4: { CITE(22); fat_noun_t nxt = CELL(L(root), R(r)); CALL(nock_op, nxt, f22, _NAN); }
	      case 5: { CITE(23); fat_noun_t nxt = CELL(L(root), R(r)); CALL(nock_op, nxt, f23, _NAN); }
	      case 6: { CITE(25); fn_ret_t fn_ret = cond1(machine, root); op = fn_ret.op; UNSHARE(root, ROOT_OWNER); root = fn_ret.root; continue; }
	      case 7: { fat_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(26); 
		  fat_noun_t nxt = CELL(L(root), CELL(_2, CELL(L(rr), CELL(_1, R(rr)))));
		  TAIL_CALL(nock_op, nxt);
		} else CRASH(machine);
	      }
	      case 8: { fat_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(27); 
		  fat_noun_t nxt = CELL(L(root), CELL(_7, CELL(CELL(CELL(_7, CELL(CELL(_0, _1), L(rr))), CELL(_0, _1)), R(rr))));
		  TAIL_CALL(nock_op, nxt);
		} else CRASH(machine);
	      }
	      case 9: { fat_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(28); 
		  fat_noun_t nxt = CELL(L(root), CELL(_7, CELL(R(rr), CELL(_2, CELL(CELL(_0, _1), CELL(_0, L(rr)))))));
		  TAIL_CALL(nock_op, nxt);
		} else CRASH(machine);
	      }
	      case 10: { fat_noun_t rr = R(r);
		if (T(rr) == cell_type) { 
		  CITE(29); 
		  fat_noun_t rrl = L(rr);
		  fat_noun_t nxt;
		  if (T(rrl) == cell_type) { 
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
	fat_noun_t l = L(root);
	if (T(l) == cell_type) CRASH(machine);
	else {
	  bool fits;
	  satom_t satom = atom_get_satom(l, &fits);
	  if (fits) {
	    if (satom == 1) { CITE(10); fat_noun_t nxt = R(root); RET(nxt); }
	    else {
	      fat_noun_t r = R(root);
	      if (T(r) == cell_type) {
		if (satom == 2) { CITE(11); fat_noun_t nxt = L(r); fat_noun_t rr = R(r); RET(nxt); }
		else if (satom == 3) { CITE(12); fat_noun_t nxt = R(r); fat_noun_t lr = L(r); RET(nxt); }
	      } /* else fall through to even/odd check */
	    }
	  } /* else fall through to even/odd check */
	  if (atom_is_even(l)) { CITE(13); fat_noun_t nxt = CELL(atom_div2(l, heap), R(root)); CALL(slash_op, nxt, f13, _NAN); }
	  else { CITE(14); fat_noun_t nxt = CELL(atom_dec_div2(l, heap), R(root)); CALL(slash_op, nxt, f14, _NAN); }
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
	fat_noun_t l = L(root);
	if (T(l) != cell_type) {
	  fat_noun_t r = R(root);
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

    case ret_op: { ASSERT(op != ret_op, "op != ret_op\n"); }
    case crash_op: { ASSERT(op != crash_op, "op != crash_op\n"); }
    case cond_op: { ASSERT(op != cond_op, "op != cond_op\n"); }
    }

  ret:
    if (stack_is_empty(machine->stack)) {
      return root;
    } else {
      frame_t *frame = stack_current_frame(machine->stack);
      fn_ret_t fn_ret = frame->fn(machine, frame, root);
      op = fn_ret.op;
      noun_unshare(root, heap, true
#if ALLOC_DEBUG
		   , ROOT_OWNER
#endif
		   );
      root = fn_ret.root;
      if (op == ret_op)
	goto ret;
    }
  }
}

static void alloc_atoms(heap_t *heap) {
#if NO_SATOMS
  _NAN = noun_share(batom_new_ui(heap, SATOM_MAX), heap, HEAP_OWNER);
  _0 = noun_share(batom_new_ui(heap, 0), heap, HEAP_OWNER);
  _1 = noun_share(batom_new_ui(heap, 1), heap, HEAP_OWNER);
  _2 = noun_share(batom_new_ui(heap, 2), heap, HEAP_OWNER);
  _3 = noun_share(batom_new_ui(heap, 3), heap, HEAP_OWNER);
  _4 = noun_share(batom_new_ui(heap, 4), heap, HEAP_OWNER);
  _5 = noun_share(batom_new_ui(heap, 5), heap, HEAP_OWNER);
  _6 = noun_share(batom_new_ui(heap, 6), heap, HEAP_OWNER);
  _7 = noun_share(batom_new_ui(heap, 7), heap, HEAP_OWNER);
#endif
}

static void free_atoms(heap_t *heap) {
#if NO_SATOMS
  noun_unshare(_NAN, heap, true, HEAP_OWNER);
  noun_unshare(_0, heap, true, HEAP_OWNER);
  noun_unshare(_1, heap, true, HEAP_OWNER);
  noun_unshare(_2, heap, true, HEAP_OWNER);
  noun_unshare(_3, heap, true, HEAP_OWNER);
  noun_unshare(_4, heap, true, HEAP_OWNER);
  noun_unshare(_5, heap, true, HEAP_OWNER);
  noun_unshare(_6, heap, true, HEAP_OWNER);
  noun_unshare(_7, heap, true, HEAP_OWNER);
#endif
}

static void nock5k_run(int n_inputs, infile_t *inputs, bool trace_flag) {
  for (int i = 0; i < n_inputs; ++i) {
    infile_t *input = inputs + i;
    if (input->name != NULL) 
      printf("file: %s\n", input->name);
    else
      printf("file: standard input\n");

    machine_t machine;
#if _STATS
    machine.ops = 0;
#endif
    machine.heap = heap_new();
    alloc_atoms(machine.heap);
    machine.stack = stack_new(1);
    machine.file = stdout;
    machine.trace_flag = trace_flag;
    noun_print(stdout, nock5k_run_impl(&machine, nock_op, parse(&machine, input)), true);
    printf("\n");
    free_atoms(machine.heap);
    heap_free_free_list(machine.heap);
#if _STATS
    printf("heap stats:\n");
    heap_print_stats(machine.heap, stdout);
    printf("stack stats:\n");
    stack_print_stats(machine.stack, stdout);
    printf("op stats:\n");
    printf("ops=%lu\n", machine.ops);
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

  const char *trace_env = getenv("NOCK_TRACE");
  if (trace_env == NULL) trace_env = "false";
  bool trace = !(strcasecmp(trace_env, "no") == 0 || strcmp(trace_env, "0") == 0 || strcasecmp(trace_env, "false") == 0);
  infile_t *inputs = (infile_t *)calloc(1, argc * sizeof(infile_t));
  int n_inputs = 0;
  for (int i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    BEGIN_MATCH_STRING(arg);
    STRCMP_CASE("--help", usage(NULL));
    STRCMP_CASE("--enable-tracing", trace = true);
    STRCMP_CASE("--disable-tracing", trace = false);
    STRCMP_CASE("-", { inputs[n_inputs].name = NULL; inputs[n_inputs].file = stdin; ++n_inputs; });
    TRUE_CASE(file, {
	if (strncmp(file, "-", 1) == 0)
	  usage("Unknown option: '%s'", file);
	else
	  { FILE *f = fopen(file, "r"); if (f != NULL) { inputs[n_inputs].name = file; inputs[n_inputs].file = f; ++n_inputs; } else usage("File not found: %s", file); }
      });
    END_MATCH_STRING();
  }
  if (n_inputs == 0) usage("No files specified");
  nock5k_run(n_inputs, inputs, trace);
}
