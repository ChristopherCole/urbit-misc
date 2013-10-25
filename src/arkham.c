/*
 * Copyright 2013 Christopher Cole
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <strings.h>
#include <inttypes.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <gmp.h>
#include <jemalloc/jemalloc.h>

#include "arkham.h"
#include "fnv.h"

static inline noun_t
noun_nop(noun_t noun) {
  return noun;
}

#if ALLOC_DEBUG
/* When doing allocation debugging we need ownership information: */
#define SHARE_RC_SPACE(noun, o) noun_share(noun, heap, o)
#define UNSHARE_RC_SPACE(noun, o) noun_unshare(noun, heap, true, o)
#define UNSHARE_CHILD_RC_SPACE(noun, o) noun_unshare(noun, heap, false, o)
#else /* #if !ALLOC_DEBUG */
#define SHARE_RC_SPACE(noun, o) noun_share(noun, heap)
#define UNSHARE_RC_SPACE(noun, o) noun_unshare(noun, heap, true)
#define UNSHARE_CHILD_RC_SPACE(noun, o) noun_unshare(noun, heap, false)
#endif /* #if ALLOC_DEBUG */

#if ARKHAM_URC
#define SHARE(noun, o) noun_nop(noun)
#define UNSHARE(noun, o)
#define UNSHARE_CHILD(noun, o)
#else /* #if !ARKHAM_URC */
#define SHARE(noun, o) SHARE_RC_SPACE(noun, o)
#define UNSHARE(noun, o) UNSHARE_RC_SPACE(noun, o)
#define UNSHARE_CHILD(noun, o) UNSHARE_CHILD_RC_SPACE(noun, o)
#endif /* #if ARKHAM_URC */

enum op_t { 
  /* real (visible) operators */
  slash_op,
  cell_op,
  inc_op,
  equals_op,
  nock_op,
  /* fictitious (invisible) operators */
  cond_op,
  crash_op,
  ret_op
};

typedef struct { noun_t root; enum op_t op; } fn_ret_t;

typedef fn_ret_t (*fn_t)(struct machine *machine, struct frame *frame,
    root_t *root);

typedef struct frame { fn_t fn; noun_t data; } frame_t;

typedef struct fstack { 
  size_t capacity; 
  size_t size; 
#if ARKHAM_STATS
  size_t max_size;
#endif
  frame_t frames[0];
} fstack_t;

typedef struct {
  const char *name;
  FILE *file;
} infile_t;

void
arkham_log(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(machine_get()->log_file, format, args);
  va_end(args);
}

void
arkham_fail(const char *predicate, const char *file, const char *function,
    int line_number, const char *format, ...) {
  fprintf(stderr, ERROR_PREFIX " Failed predicate: predicate = '%s', "
          "file = '%s', function = '%s', line = %d\n", predicate, file,
          function, line_number);

  if (format != NULL) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }

  abort();
}

static void
arkham_usage(const char *format, ...) {
  if (format != NULL) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }

  fprintf(stderr, "%s", "Usage: arkham [options] [<file1> <file2> ...]\n\n  "
          "--enable-tracing\n        turn tracing on\n  --disable-tracing\n "
          "       turn tracing off\n  --help\n        prints this usage "
          "text\n  <file1> <file2> ...\n        files to interpret "
          "(use \"-\" for standard input)\n");
  exit(1);
}

static void vec_init_impl(vec_t *vec, size_t elem_size) {
  vec->elem_size = elem_size;
  vec->elem_capacity = 0;
}

void vec_init(vec_t *vec, size_t elem_size) {
  memset(vec, 0, sizeof(vec_t));

  vec_init_impl(vec, elem_size);
}

vec_t *vec_new(size_t elem_size) {
  vec_t *vec = (vec_t *)calloc(1, sizeof(vec_t));

  vec_init_impl(vec, elem_size);

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
    vec->elems = (char *)realloc(vec->elems, vec->elem_capacity *
                                 vec->elem_size);
  }
}

static void noun_print_decl(FILE *file, noun_t noun);

static inline satom_t
noun_metainfo_get_refs(noun_metainfo_t *noun_metainfo) {
#if INLINE_REFS
  return noun_metainfo->refs;
#endif
}

static inline void
noun_metainfo_inc_refs(noun_metainfo_t *noun_metainfo) {
#if INLINE_REFS
  noun_metainfo->refs += 1;
#endif
}

static inline void
noun_metainfo_dec_refs(noun_metainfo_t *noun_metainfo) {
#if INLINE_REFS
  noun_metainfo->refs -= 1;
#endif
}

#if ALLOC_DEBUG

// TODO: Adjustable owners array size
#define OWNERS_SIZE 32

void
noun_metainfo_print_metainfo(FILE *file, const char *prefix,
    noun_metainfo_t *noun_metainfo, const char *suffix) {
  if (noun_metainfo == STACK_OWNER)
    fprintf(file, "%sSTACK%s", prefix, suffix);
  else if (noun_metainfo == ROOT_OWNER)
    fprintf(file, "%sROOT%s", prefix, suffix);
  else if (noun_metainfo == COND2_OWNER)
    fprintf(file, "%sCOND2%s", prefix, suffix);
  else if (noun_metainfo == HEAP_OWNER)
    fprintf(file, "%sHEAP%s", prefix, suffix);
  else if (noun_metainfo_get_refs(noun_metainfo) == ALLOC_FREE_MARKER)
    fprintf(file, "%s{id=%" SATOM_FMT ",rc->0}%s", prefix, noun_metainfo->id,
            suffix);
  else
    fprintf(file, "%s{id=%" SATOM_FMT ",rc=%" SATOM_FMT "}%s", prefix,
            noun_metainfo->id, noun_metainfo_get_refs(noun_metainfo), suffix);
}

static void
noun_metainfo_print_metainfo_node(FILE *file, const char *prefix,
    noun_metainfo_t *noun_metainfo, const char *suffix) {
  if (noun_metainfo == STACK_OWNER)
    fprintf(file, "%sSTACK%s", prefix, suffix);
  else if (noun_metainfo == ROOT_OWNER)
    fprintf(file, "%sROOT%s", prefix, suffix);
  else if (noun_metainfo == COND2_OWNER)
    fprintf(file, "%sCOND2%s", prefix, suffix);
  else if (noun_metainfo == HEAP_OWNER)
    fprintf(file, "%sHEAP%s", prefix, suffix);
  else
    fprintf(file, "%s%" SATOM_FMT "%s", prefix, noun_metainfo->id, suffix);
}

static void
noun_metainfo_print_owners(FILE *file, const char *prefix,
    noun_metainfo_t *noun_metainfo, const char *suffix) {
  const char *p = "";

  fprintf(file, "%s", prefix);
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (noun_metainfo->owners[i] != NULL) {
      noun_metainfo_t *owner = noun_metainfo->owners[i];
      noun_metainfo_print_metainfo(file, p, owner, "");
      p = ", ";
    }
  }
  fprintf(file, "%s", suffix);
}

static void
noun_metainfo_add_owner(noun_metainfo_t *noun_metainfo, noun_metainfo_t *owner) {
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (noun_metainfo->owners[i] == NULL) {
      noun_metainfo->owners[i] = owner;
      return;
    }
  }
  noun_metainfo_print_metainfo(stdout, "noun: ", noun_metainfo, "\n");//XXX: stdout
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (noun_metainfo->owners[i] != NULL)
      noun_metainfo_print_metainfo(stdout, "noun owner: ", noun_metainfo->owners[i], "\n");//XXX: stdout
  }
  noun_metainfo_print_metainfo(stdout, "owner: ", owner, "\n");//XXX: stdout
  ASSERT(false, "Couldn't add owner\n");
}

static void
noun_metainfo_remove_owner(noun_metainfo_t *noun_metainfo, noun_metainfo_t *owner) {
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (noun_metainfo->owners[i] == owner) {
      noun_metainfo->owners[i] = NULL;
      return;
    }
  }
  noun_metainfo_print_metainfo(stdout, "noun: ", noun_metainfo, "\n");//XXX: stdout
  for (int i = 0; i < OWNERS_SIZE; ++i) {
    if (noun_metainfo->owners[i] != NULL)
      noun_metainfo_print_metainfo(stdout, "noun owner: ", noun_metainfo->owners[i], "\n");//XXX: stdout
  }
  noun_metainfo_print_metainfo(stdout, "owner: ", owner, "\n");//XXX: stdout
  ASSERT(false, "Couldn't remove owner\n");
}
#endif /* #if ALLOC_DEBUG */

const char *
noun_type_to_string(enum noun_type noun_type)
{
  switch (noun_type) {
  case cell_type: return "cell_type";
  case satom_type: return "cell_satom";
  case batom_type: return "cell_batom";
  }
}

static void
heap_print_stats(heap_t *heap, FILE *file) {
#if ARKHAM_STATS
  fprintf(file, "cell_alloc=%lu\n", heap->cell_alloc);
  fprintf(file, "cell_free=%lu\n", heap->cell_free);
  fprintf(file, "cell_free_list_alloc=%lu\n", heap->cell_free_list_alloc);
  fprintf(file, "cell_free_list_free=%lu\n", heap->cell_free_list_free);
  fprintf(file, "cells_max=%lu\n", heap->cells_max);
  fprintf(file, "cell_shared=%lu\n", heap->cell_shared);
  fprintf(file, "cells_max_shared=%lu\n", heap->cells_max_shared);
  fprintf(file, "cell_max_refs=%lu\n", heap->cell_max_refs);
  fprintf(file, "cell_to_shared=%lu\n", heap->cell_to_shared);
  fprintf(file, "cell_to_unshared=%lu\n", heap->cell_to_unshared);
  fprintf(file, "cell_overflow_to_shared=%lu\n",
          heap->cell_overflow_to_shared);
  fprintf(file, "cell_stably_shared=%lu\n", heap->cell_stably_shared);
  fprintf(file, "batom_alloc=%lu\n", heap->batom_alloc);
  fprintf(file, "batom_free=%lu\n", heap->batom_free);
  fprintf(file, "batoms_max=%lu\n", heap->batoms_max);
  fprintf(file, "batom_shared=%lu\n", heap->batom_shared);
  fprintf(file, "batoms_max_shared=%lu\n", heap->batoms_max_shared);
  fprintf(file, "batom_max_refs=%lu\n", heap->batom_max_refs);
  fprintf(file, "batom_to_shared=%lu\n", heap->batom_to_shared);
  fprintf(file, "batom_to_unshared=%lu\n", heap->batom_to_unshared);
  fprintf(file, "root_alloc=%lu\n", heap->root_alloc);
  fprintf(file, "root_free=%lu\n", heap->root_free);
  fprintf(file, "gc_count=%lu\n", heap->gc_count);

#if ARKHAM_URC
  fprintf(file, "nursery used=%lu\n", (heap->nursery_current -
    heap->nursery_start));
  fprintf(file, "nursery size=%lu\n", (heap->nursery_end -
    heap->nursery_start));
  fprintf(file, "write_log used=%lu\n", (heap->write_log_current -
    heap->write_log_start));
  fprintf(file, "write_log size=%lu\n", (heap->write_log_end -
    heap->write_log_start));
#endif /* #if ARKHAM_URC */
#endif /* #if ARKHAM_STATS */

#if ALLOC_DEBUG
  for (noun_metainfo_t *noun_metainfo = heap->first; noun_metainfo != NULL; 
       noun_metainfo = noun_metainfo->next) {
    if (noun_metainfo_get_refs(noun_metainfo) != ALLOC_FREE_MARKER) {
      noun_metainfo_print_metainfo(file, "noun: ", noun_metainfo, "\n");
      noun_metainfo_print_owners(file, "  owners: ", noun_metainfo, "\n");
    }
  }
  // Output as DOT graph description:
  // TODO: Include satoms in graph output
  fprintf(file, "digraph sample {\n");
  for (noun_metainfo_t *noun_metainfo = heap->first; noun_metainfo != NULL; 
       noun_metainfo = noun_metainfo->next) {
    if (noun_metainfo_get_refs(noun_metainfo) != ALLOC_FREE_MARKER) {
      for (int i = 0; i < OWNERS_SIZE; ++i) {
        if (noun_metainfo->owners[i] != NULL) {
          noun_metainfo_print_metainfo_node(file, "", noun_metainfo->owners[i],
                                            "");
          noun_metainfo_print_metainfo_node(file, " -> ", noun_metainfo, ";\n");
        }
      }
    }
  }
  fprintf(file, "}\n");
#endif /* #if ALLOC_DEBUG */
}

#if ARKHAM_URC
#define NURSERY_SIZE (512 * 1024 * 1024)
#define WRITE_LOG_SIZE (512 * 1024 * 1024)
#endif

#define ALIGN(s1, s2) ((((s1)+(s2)-1)/(s2))*(s2))

static heap_t *
heap_new() {
  heap_t *heap;

#if ARKHAM_URC
  size_t heap_size = ALIGN(sizeof(heap_t), sizeof(write_log_t));
  void *mapped = mmap(NULL, heap_size + NURSERY_SIZE + WRITE_LOG_SIZE,
    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  FAIL(mapped != MAP_FAILED, "Memory map failed: size = %lu, errno = %d, "
    "error = %s\n", (size_t)NURSERY_SIZE, errno, strerror(errno));
  heap = (heap_t *)mapped;
#else /* #if !ARKHAM_URC */
  heap = (heap_t *)calloc(1, sizeof(heap_t));
#endif /* #if ARKHAM_URC */

#if ARKHAM_URC
  heap->nursery_start = ((char *)heap) + heap_size;
  heap->nursery_current = heap->nursery_start;
  heap->nursery_end = ((char *)heap) + NURSERY_SIZE;

  heap->write_log_start = (write_log_t *)heap->nursery_end;
  heap->write_log_current = heap->write_log_start;
#if ARKHAM_ASSERT
  heap->write_log_end = (write_log_t *)(((char *)heap) + WRITE_LOG_SIZE);
#endif

  heap->first_root = NULL;
  heap->last_root = NULL;
#endif /* #if ARKHAM_URC */

  return heap;
}

static void
heap_free_free_list(heap_t *heap) {
#if CELL_FREE_LIST
  for (int i = 0; i < heap->cell_free_list_size; ++i) {
#if !ALLOC_DEBUG
    free(heap->cell_free_list[(heap->cell_free_list_start + i) %
      CELL_FREE_LIST_SIZE]);
#endif
#if ARKHAM_STATS
    ++heap->cell_free;
#endif
  }
#endif
}

static void
heap_free(heap_t *heap) {
#if ARKHAM_URC
  munmap(heap, NURSERY_SIZE);
#else
  free(heap);
#endif
}

#if ALLOC_DEBUG
static void
heap_register_debug(heap_t *heap, noun_metainfo_t *noun_metainfo,
                    enum noun_type type) {
  noun_metainfo->owners = (noun_metainfo_t **)calloc(1, sizeof(noun_metainfo_t *) *
    OWNERS_SIZE);
  noun_metainfo->id = ++heap->current_id;
  noun_metainfo->type = type;
  if (heap->last != NULL)
    heap->last->next = noun_metainfo;
  else
    heap->first = noun_metainfo;
  heap->last = noun_metainfo;
}
#endif /* #if ALLOC_DEBUG */

#if ARKHAM_URC
static bool
heap_is_nursery(heap_t *heap, void *ptr) {
  return (char*)ptr >= heap->nursery_start && (char*)ptr < heap->nursery_end;
}
#endif

#if ARKHAM_URC
void
heap_trace_nursery(noun_t *address, noun_metainfo_t *owner, heap_t *heap) {
  // TODO: Batoms in nursery
  noun_t noun = *address;

  if (NOUN_IS_CELL(noun)) {
    cell_t *cell = NOUN_AS_CELL(noun);
    noun_t rc_space_noun;

    if (NOUN_IS_FORWARDED_MARKER(cell->base.left)) {
      rc_space_noun = cell->base.right;
    } else {
      if (heap_is_nursery(heap, cell)) {
        satom_t left = cell->base.left.value;
        satom_t right = cell->base.right.value;

        cell_t *rc_space_cell = cell_new(heap, cell->base.left,
          cell->base.right);
        rc_space_noun = CELL_AS_NOUN(rc_space_cell);

        // Mark the cell as forwarded:
        cell->base.left = _FORWARDED_MARKER;
        cell->base.right = rc_space_noun;

        // Recurse:
        noun_metainfo_t *rc_space_owner = &(rc_space_cell->metainfo);
        heap_trace_nursery(&(rc_space_cell->base.left), rc_space_owner, heap);
        heap_trace_nursery(&(rc_space_cell->base.right), rc_space_owner, heap);
      } else {
        // This is not a nursery cell.
        rc_space_noun = noun;
      }
    }

    // Adjust the pointer and increment the referece count:
    *address = rc_space_noun;
    SHARE_RC_SPACE(rc_space_noun, owner);
  } else if (NOUN_IS_BATOM(noun) && NOUN_IS_DEFINED(noun)) {
    machine_t *machine = machine_get();
    fprintf(machine->trace_file, "batom: ");
    noun_print(machine->trace_file, noun, true, true);
    fprintf(machine->trace_file, "\n");
    ASSERT0(false); //XXX: TODO
  }
}
#endif /* #if ARKHAM_URC */

typedef void (*do_roots_fn_t)(machine_t *machine, noun_t *address,
                              noun_metainfo_t *owner, void *data);

static void
do_roots(machine_t *machine, do_roots_fn_t fn, void *data) {
  heap_t *heap = machine->heap;
  for (root_t *root = heap->first_root; root != NULL; root = root->next)
    fn(machine, &(root->noun), ROOT_OWNER, data);

  fstack_t *stack = machine->stack;
  for (size_t frame = 0; frame < stack->size; ++frame)
    fn(machine, &(stack->frames[frame].data), STACK_OWNER, data);
}

static void roots_hash(machine_t *machine, noun_t *address, 
                       noun_metainfo_t *owner, void *data) {
  if (NOUN_IS_DEFINED(*address))
    *(Fnv_t *)data = noun_hash(*address, *(Fnv_t *)data);
}

static void roots_sanity(machine_t *machine, noun_t *address, 
                         noun_metainfo_t *owner, void *data) {
#if INLINE_REFS
  noun_t noun = *address;
  if (NOUN_IS_CELL(noun) && NOUN_IS_DEFINED(noun) &&
      !heap_is_nursery(machine->heap, NOUN_AS_CELL(noun)))
    ASSERT0(noun_metainfo_get_refs(NOUN_AS_NOUN_METAINFO(noun)) < 4096);
#endif
}

static void roots_print(machine_t *machine, noun_t *address, 
                       noun_metainfo_t *owner, void *data) {
  //XXX: stdout
#if ALLOC_DEBUG
  noun_metainfo_print_metainfo(stdout, "owner: ", owner, ", noun: ");
#else
  fprintf(stdout, "noun: ");
#endif
  if (NOUN_IS_DEFINED(*address))
    noun_print(stdout, *address, true, true);
  else
    fprintf(stdout, "<undefined>");
  fprintf(stdout, "\n");
}

#if ARKHAM_URC
static void roots_trace_nursery(machine_t *machine, noun_t *address, 
                                noun_metainfo_t *owner, void *data) {
  heap_trace_nursery(address, owner, machine->heap);
}
#endif /* #if ARKHAM_URC */

#if ARKHAM_URC
static void roots_build_write_log(machine_t *machine, noun_t *address,
                                  noun_metainfo_t *owner, void *data) {
  if (NOUN_IS_DEFINED(*address))
    *machine->heap->write_log_current++ = 
      (write_log_t){ 
      .address = address,
      .noun = *address
#if ALLOC_DEBUG
      , .owner = owner
#endif
    };
}
#endif /* #if ARKHAM_URC */

#if ARKHAM_URC
void
collect_garbage(size_t size) {
  // TODO: add timing and logging

  //XXX: assert size < nursery size

  machine_t *machine = machine_get();
  heap_t *heap = machine->heap;
  fstack_t *stack = machine->stack;

  /* do_roots(machine, roots_print, NULL); */
  /* { //XXX: stdout */
  /*   Fnv_t hash = FNV1_INIT; */
  /*   do_roots(machine, roots_hash, &hash); */
  /*   fprintf(stdout, "roots hash (before): %" SATOM_X_FMT "\n", hash); */
  /* } */

  /* heap_print_stats(heap, machine->trace_file); */

  do_roots(machine, roots_trace_nursery, NULL);

  // Reset the nursery:
  heap->nursery_current = heap->nursery_start;

  for (write_log_t *w = heap->write_log_start; w < heap->write_log_current; 
       ++w) {
    noun_metainfo_t *owner;
#if ALLOC_DEBUG
    owner = w->owner;
#else
    owner = ROOT_OWNER;
#endif
    UNSHARE_RC_SPACE(w->noun, owner);
  }

  // Reset the write log:
  heap->write_log_current = heap->write_log_start;

  if (ARKHAM_ASSERT)
    memset(heap->nursery_start, 'x', heap->nursery_end - heap->nursery_start);

  do_roots(machine, roots_build_write_log, NULL);

#if ARKHAM_STATS
  ++heap->gc_count;
#endif

  /* heap_print_stats(heap, machine->trace_file); */

  /* do_roots(machine, roots_print, NULL); */
  /* { //XXX: stdout */
  /*   Fnv_t hash = FNV1_INIT; */
  /*   do_roots(machine, roots_hash, &hash); */
  /*   fprintf(stdout, "roots hash (after): %" SATOM_X_FMT "\n", hash); */
  /* } */
}
#endif /* #if ARKHAM_URC */

root_t *
root_new(heap_t *heap, noun_t noun) {
  root_t *root = calloc(1, sizeof(root_t));
  if (heap->first_root == NULL)
    heap->first_root = heap->last_root = root;
  else {
    root->previous = heap->last_root;
    heap->last_root->next = root;
    heap->last_root = root;
  }
  root->noun = noun;
#if ARKHAM_STATS
  ++heap->root_alloc;
#endif
  return root;
}

void
root_delete(heap_t *heap, root_t *root) {
  if (root->previous != NULL)
    root->previous->next = root->next;
  else
    heap->first_root = root->next;
  if (root->next != NULL)
    root->next->previous = root->previous;
  else
    heap->last_root = root->previous;
#if ARKHAM_STATS
  ++heap->root_free;
#endif
  free(root);
}

#if ARKHAM_STATS
void
heap_alloc_cells_stats(heap_t *heap, int count) {
  heap->cell_alloc += count;

  int active_cells = heap->cell_alloc - heap->cell_free;
  if (active_cells > heap->cells_max) {
    heap->cells_max = active_cells;
  }
}
#endif /* #if ARKHAM_STATS */

static URC_INLINE batom_t *
heap_alloc_batoms(heap_t *heap, int count) {
  // XXX: we have no way of adjusting to data motion -> make batoms like cells
  batom_t *batom = (batom_t *)heap_alloc(heap, count * sizeof(batom_t), NULL);

#if ARKHAM_STATS
  heap->batom_alloc += count;
  int active_batom = heap->batom_alloc - heap->batom_free;
  if (active_batom > heap->batoms_max) {
    heap->batoms_max = active_batom;
  }
#endif

  return batom;
}

static URC_INLINE batom_t *
heap_alloc_batom(heap_t *heap) {
  batom_t *batom = heap_alloc_batoms(heap, 1);

#if ALLOC_DEBUG
  heap_register_debug(heap, &(batom->metainfo), batom_type);
#endif

  return batom;
}

static URC_INLINE void
heap_free_cell(heap_t *heap, cell_t *cell) {
  ASSERT0(cell->metainfo.refs != ALLOC_FREE_MARKER);
  cell->metainfo.refs = ALLOC_FREE_MARKER;
#if CELL_FREE_LIST
  if (heap->cell_free_list_size < CELL_FREE_LIST_SIZE) {
    heap->cell_free_list[(heap->cell_free_list_start +
      heap->cell_free_list_size) % CELL_FREE_LIST_SIZE] = cell;
    ++heap->cell_free_list_size;
#if ARKHAM_STATS
    ++heap->cell_free_list_free;
#endif
  } else {
#endif
#if !ARKHAM_URC && !ALLOC_DEBUG
    free(cell);
#endif /* #if !ARKHAM_URC && !ALLOC_DEBUG */
#if ARKHAM_STATS
    ASSERT0(heap->cell_free < heap->cell_alloc);
    ++heap->cell_free;
#endif
#if CELL_FREE_LIST
  }
#endif
}

static void
heap_free_batom(heap_t *heap, batom_t *batom) {
#if ARKHAM_STATS
  ASSERT0(heap->batom_free < heap->batom_alloc);
  ++heap->batom_free;
#endif
  ASSERT0(batom->metainfo.refs != ALLOC_FREE_MARKER);
  batom->metainfo.refs = ALLOC_FREE_MARKER;
#if !ARKHAM_URC && !ALLOC_DEBUG
    free(batom);
#endif /* #if !ARKHAM_URC && !ALLOC_DEBUG */
}

bool
noun_is_freed(noun_t noun, heap_t *heap) {
  switch (noun_get_type(noun)) {
  case satom_type: return false;
  case batom_type:
  case cell_type: {
    noun_metainfo_t *noun_metainfo = NOUN_AS_NOUN_METAINFO(noun);
    return noun_metainfo_get_refs(noun_metainfo) == ALLOC_FREE_MARKER;
  }
  }
}

bool
noun_is_valid_atom(noun_t noun, heap_t *heap) {
  return !noun_is_freed(noun, heap) && noun_get_type(noun) != cell_type;
}

static bool
noun_is_shared(noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  switch (noun_get_type(noun)) {
  case satom_type: return true;
  case batom_type:
  case cell_type: {
    noun_metainfo_t *noun_metainfo = NOUN_AS_NOUN_METAINFO(noun);
    return noun_metainfo_get_refs(noun_metainfo) > 1;
  }
  }
}

#if ALLOC_DEBUG
static unsigned long
noun_get_id(noun_t noun) {
  switch (noun_get_type(noun)) {
  case satom_type: ASSERT0(noun_get_type(noun) != satom_type);
  case batom_type:
  case cell_type: {
    noun_metainfo_t *noun_metainfo = NOUN_AS_NOUN_METAINFO(noun);
    return noun_metainfo->id;
  }
  }
}
#endif

#if ALLOC_DEBUG
noun_t
noun_share(noun_t noun, heap_t *heap, noun_metainfo_t *owner) {
#else
noun_t
noun_share(noun_t noun, heap_t *heap) {
#endif
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return noun;
  case batom_type:
  case cell_type: {
    noun_metainfo_t *noun_metainfo = NOUN_AS_NOUN_METAINFO(noun);
#if ALLOC_DEBUG
    noun_metainfo_add_owner(noun_metainfo, owner);
#endif
    satom_t refs = noun_metainfo_get_refs(noun_metainfo);
    ASSERT0(refs != ALLOC_FREE_MARKER);
    if (refs == 1) {
      if (type == cell_type) {
#if SHARED_CELL_LIST
        if (heap->shared_cell_list_size < SHARED_CELL_LIST_SIZE) {
          // Defer the expense of reference counting.
          // See "noun_unshare".
          heap->shared_cell_list[heap->shared_cell_list_size++] =
            (cell_t *)noun_metainfo;
          // Return early (avoid the reference counting cost):
          return noun;
        }
#if ARKHAM_STATS
        else
          ++heap->cell_overflow_to_shared;
#endif // ARKHAM_STATS
#endif // SHARED_CELL_LIST
#if ARKHAM_STATS
        ++heap->cell_shared;
        ++heap->cell_to_shared;
        if (heap->cell_shared > heap->cells_max_shared)
          heap->cells_max_shared = heap->cell_shared;
#endif
      } else {
#if ARKHAM_STATS
        ++heap->batom_shared;
        ++heap->batom_to_shared;
        if (heap->batom_shared > heap->batoms_max_shared)
          heap->batoms_max_shared = heap->batom_shared;
#endif
      }
    }
#if ARKHAM_STATS
    if (NOUN_IS_CELL(noun) && refs + 1 > heap->cell_max_refs) {
      heap->cell_max_refs = refs + 1;
    }
    if (NOUN_IS_BATOM(noun) && refs + 1 > heap->batom_max_refs) {
      heap->batom_max_refs = refs + 1;
    }
#endif
    noun_metainfo_inc_refs(noun_metainfo);
    return noun;
  }
  }
}

#if ALLOC_DEBUG
void
noun_unshare(noun_t noun, heap_t *heap, bool toplevel, noun_metainfo_t *owner) {
#else
void
noun_unshare(noun_t noun, heap_t *heap, bool toplevel) {
#endif
  ASSERT0(!noun_is_freed(noun, heap));
  enum noun_type type = noun_get_type(noun);
  switch (type) {
  case satom_type: return;
  case batom_type:
  case cell_type: {
    noun_metainfo_t *noun_metainfo = NOUN_AS_NOUN_METAINFO(noun);
#if ALLOC_DEBUG
    noun_metainfo_remove_owner(noun_metainfo, owner);
#endif
    satom_t refs = noun_metainfo_get_refs(noun_metainfo);
#if SHARED_CELL_LIST
    if (type == cell_type) {
      unsigned int sz = heap->shared_cell_list_size;
      for (int i = 0; i < sz; ++i)
        if (heap->shared_cell_list[i] == (cell_t *)noun_metainfo) {
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
        UNSHARE_CHILD(noun_get_left(noun), noun_metainfo);
        UNSHARE_CHILD(noun_get_right(noun), noun_metainfo);
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
#if ARKHAM_STATS
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
      noun_metainfo_dec_refs(noun_metainfo);
    }
  }
  }
}

noun_t
cell_set_left(noun_t noun, noun_t left, heap_t *heap) {
  ASSERT0(noun_get_type(noun) == cell_type);
  cell_t *cell = noun_as_cell(noun);
  // ZZZ: if !logged then log
  SHARE(left, &(cell->metainfo));
  UNSHARE(noun_get_left(noun), &(cell->metainfo));
  cell->base.left = left;
  return CELL_AS_NOUN(cell);
}

noun_t
cell_set_right(noun_t noun, noun_t right, heap_t *heap) {
  ASSERT0(noun_get_type(noun) == cell_type);
  cell_t *cell = noun_as_cell(noun);
  // ZZZ: if !logged then log
  SHARE(right, &(cell->metainfo));
  UNSHARE(noun_get_right(noun), &(cell->metainfo));
  cell->base.right = right;
  return CELL_AS_NOUN(cell);
}

//XXX: alloc without inline refs & metainfo
#if ARKHAM_URC
URC_INLINE cell_t *
cell_new_nursery(cell_t **cellp, noun_t left, noun_t right) {
  cell_t *cell = (*cellp)++;
  cell->base.left = left;
  cell->base.right = right;
  return cell;
}
#endif /* #if ARKHAM_URC */

static URC_INLINE cell_t *
heap_alloc_cell(heap_t *heap) {
  cell_t *cell;

#if CELL_FREE_LIST
  if (heap->cell_free_list_size > 0) {
    cell = (cell_t *)heap->cell_free_list[heap->cell_free_list_start];
    if (++heap->cell_free_list_start == CELL_FREE_LIST_SIZE)
      heap->cell_free_list_start = 0;
    --heap->cell_free_list_size;
#if ARKHAM_STATS
    ++heap->cell_free_list_alloc;
#endif
  } else {
#endif
    cell = (cell_t *)calloc(1, sizeof(cell_t));
#if ARKHAM_STATS
    heap_alloc_cells_stats(heap, 1);
#endif
#if CELL_FREE_LIST
  }
#endif

#if INLINE_REFS
  (&(cell->metainfo))->refs = 0;
#endif

#if INLINE_REFS && ARKHAM_PADDING && ARKHAM_ASSERT
  (&(cell->metainfo))->_padding = 0;
#endif

#if ALLOC_DEBUG
  heap_register_debug(heap, &(cell->metainfo), cell_type);
#endif

  return cell;
}

URC_INLINE cell_t *
cell_new(heap_t *heap, noun_t left, noun_t right) {
  cell_t *cell = heap_alloc_cell(heap);
  cell->base.left = left;
  cell->base.right = right;
  SHARE(left, &(cell->metainfo));
  SHARE(right, &(cell->metainfo));
  return cell;
}

noun_t URC_INLINE
batom_new(heap_t *heap, mpz_t val, bool clear) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init(batom->val); // TODO: Use custom mpz allocator (portable image)
  mpz_set(batom->val, val);
  if (clear)
    mpz_clear(val);
  return BATOM_AS_NOUN(batom);
}

noun_t
batom_new_ui(heap_t *heap, unsigned long val) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init_set_ui(batom->val, val);
  return BATOM_AS_NOUN(batom);
}

static noun_t
batom_copy(noun_t noun, heap_t *heap) {
  ASSERT0(!noun_is_freed(noun, heap));
  ASSERT0(noun_get_type(noun) == batom_type);
  batom_t *batom = (batom_t *)NOUN_AS_NOUN_METAINFO(noun);
  return batom_new(heap, batom->val, false);
}

static noun_t
atom_new(heap_t *heap, const char *str) {
  mpz_t val;
  mpz_init_set_str(val, str, 10);
  if (!NO_SATOMS && mpz_cmp(val, SATOM_MAX_MPZ) <= 0)
    return satom_as_noun((satom_t)mpz_get_ui(val));
  else
    return batom_new(heap, val, true);
}

noun_t
atom_increment(noun_t noun) {
  ASSERT0(!noun_is_freed(noun, machine_get()->heap));
  ASSERT0(noun_get_type(noun) != cell_type);

  if (noun_get_type(noun) == satom_type) {
    satom_t satom = noun_as_satom(noun);
    if (satom != SATOM_MAX)
      return satom_as_noun(satom + 1);
    else {
      heap_t *heap = machine_get()->heap;
      noun = batom_new_ui(heap, SATOM_MAX);
    }
  } else {
    heap_t *heap = machine_get()->heap;
    if (noun_is_shared(noun, heap))
      noun = batom_copy(noun, heap);
  }

  batom_t *batom = noun_as_batom(noun);
  mpz_add_ui(batom->val, batom->val, 1);
  return noun;
}

noun_t
atom_equals(noun_t a, noun_t b) {
  enum noun_type a_type = noun_get_type(a);
  enum noun_type b_type = noun_get_type(b);

  ASSERT0(a_type != cell_type);
  ASSERT0(b_type != cell_type);

  // Assume that atoms are normalized:
  if (a_type != b_type) return _NO;
  if (a_type == satom_type)
    return (NOUN_AS_SATOM(a) == NOUN_AS_SATOM(b)) ? _YES : _NO;
  else
    return (mpz_cmp(NOUN_AS_BATOM(a)->val, NOUN_AS_BATOM(b)->val) == 0) ? 
      _YES : _NO;
}

noun_t
atom_add(noun_t n1, noun_t n2) {
  ASSERT0(noun_is_valid_atom(n1, machine_get()->heap));
  ASSERT0(noun_is_valid_atom(n2, machine_get()->heap));

  if (NOUN_IS_SATOM(n1) && NOUN_IS_SATOM(n2)) {
    satom_t sn1 = noun_as_satom(n1);
    satom_t sn2 = noun_as_satom(n2);
    satom_t sum = sn1 + sn2;
    if ((sum & SATOM_OVERFLOW_BIT) == 0)
      return satom_as_noun(sum);
  }

  noun_t sum;
  heap_t *heap = machine_get()->heap;

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
atom_is_even(noun_t noun) {
  enum noun_type type = noun_get_type(noun);
  ASSERT0(type != cell_type);
  if (type == satom_type)
    return (NOUN_AS_SATOM(noun) & 1) == 0;
  else {
    return mpz_tstbit(noun_as_batom(noun)->val, 0) == 0;
  }
}

static noun_t
batom_normalize(noun_t noun, heap_t *heap) {
  batom_t *batom = noun_as_batom(noun);
  if (!NO_SATOMS && mpz_cmp(batom->val, SATOM_MAX_MPZ) <= 0) {
    noun_t result = satom_as_noun((satom_t)mpz_get_ui(batom->val));
    UNSHARE(noun, NULL);
    return result;
  } else {
    return noun;
  }
}

static satom_t
atom_get_satom(noun_t noun, bool *fits) {
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

static noun_t
atom_div2(noun_t noun, heap_t *heap) {
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

static noun_t
atom_dec_div2(noun_t noun, heap_t *heap) {
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
    noun_t result = batom_normalize(noun, heap);
    return result;
  }
}

static void
batom_print(FILE *file, batom_t *atom) {
  char *str = mpz_get_str(NULL, 10, atom->val);
  fprintf(file, "%s", str);
  free(str);
}

static Fnv_t
batom_hash(batom_t *atom, Fnv_t hash) {
  char *str = mpz_get_str(NULL, 10, atom->val);
  Fnv_t result = FNV_STR(str, hash);
  free(str);
  return result;
}

static void
cell_print(FILE *file, noun_t cell, bool brackets, bool metainfo) {
  ASSERT0(noun_get_type(cell) == cell_type);
  if (brackets) fprintf(file, "[");
#if ALLOC_DEBUG_PRINT
  if (metainfo) {
    noun_metainfo_print_metainfo(file, "", &(noun_as_cell(cell)->metainfo), "");
    fprintf(file, " ");
  }
#endif
  noun_print(file, noun_get_left(cell), true, metainfo);
  fprintf(file, " ");
  noun_print(file, noun_get_right(cell), ALLOC_DEBUG_PRINT && metainfo ? 
             true : false, metainfo);
  if (brackets) fprintf(file, "]");
}

void
noun_print(FILE *file, noun_t noun, bool brackets, bool metainfo) {
  switch (noun_get_type(noun)) {
  case cell_type:
    {
      cell_print(file, noun, brackets, metainfo);
      break;
    }
  case batom_type:
    {
#if ALLOC_DEBUG_PRINT
      noun_metainfo_print_metainfo(file, "", &(noun_as_batom(noun)->metainfo),
        "");
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
cell_print_decl(FILE *file, noun_t cell) {
  ASSERT0(noun_get_type(cell) == cell_type);
  fprintf(file, "CELL(");
  noun_print_decl(file, noun_get_left(cell));
  fprintf(file, ", ");
  noun_print_decl(file, noun_get_right(cell));
  fprintf(file, ")");
}

static void
noun_print_decl(FILE *file, noun_t noun) {
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

static Fnv_t
cell_hash(noun_t cell, Fnv_t hash) {
  ASSERT0(noun_get_type(cell) == cell_type);
  hash = noun_hash(noun_get_left(cell), hash);
  return noun_hash(noun_get_right(cell), hash);
}

Fnv_t
noun_hash(noun_t noun, Fnv_t hash) {
  switch (noun_get_type(noun)) {
  case cell_type:
    return cell_hash(noun, hash);
  case batom_type:
    return batom_hash(noun_as_batom(noun), hash);
  case satom_type: {
    satom_t satom = noun_as_satom(noun);
    return FNV_BUF(&satom, sizeof(satom), hash);
  }
  }
}

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

void
arkham_crash(machine_t *machine, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    abort();
}

static void
stack_print_stats(fstack_t *stack, FILE *file) {
#if ARKHAM_STATS
  fprintf(file, "max_size=%lu\n", stack->max_size);
#endif
}

static fstack_t *
stack_new(int capacity) {
  fstack_t *stack = (fstack_t *)calloc(1, sizeof(fstack_t) + 
      capacity * sizeof(frame_t));
  stack->capacity = capacity;
  return stack;
}

static void
stack_free(fstack_t *stack) {
  free(stack);
}

static fstack_t *
stack_resize(fstack_t *stack) {
  stack->capacity = stack->capacity * 2;
  return (fstack_t *)realloc(stack, sizeof(fstack_t) +
      stack->capacity * sizeof(frame_t));
}

static inline fstack_t *
stack_push(fstack_t *stack, frame_t frame, bool share, heap_t *heap) {
  if (share)
    SHARE(frame.data, STACK_OWNER);
  if (stack->size >= stack->capacity)
    stack = stack_resize(stack);
  stack->frames[stack->size++] = frame;
#if ARKHAM_STATS
  if (stack->size > stack->max_size)
    stack->max_size = stack->size;
#endif
  return stack;
}

static inline bool
stack_is_empty(fstack_t *stack) {
  return stack->size == 0;
}

static inline size_t
stack_size(fstack_t *stack) {
  return stack->size;
}

static inline frame_t *
stack_current_frame(fstack_t *stack) {
  ASSERT0(!stack_is_empty(stack));
  return &(stack->frames[stack->size - 1]);
}

static inline fstack_t *
stack_pop(fstack_t *stack, bool unshare, heap_t *heap) {
  ASSERT0(!stack_is_empty(stack));
  if (unshare)
    UNSHARE(stack_current_frame(stack)->data, STACK_OWNER);
  --stack->size;
  return stack;
}

static noun_t parse(machine_t *machine, infile_t *input, bool *eof) {
  heap_t *heap = machine->heap;
  vec_t token;
  vec_init(&token, sizeof(char));
  vec_t stack;
  vec_init(&stack, sizeof(noun_t));
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
        noun_t atom = atom_new(heap, vec_get(&token, 0));
        vec_push(&stack, &atom);
        vec_clear(&token);
        if (vec_size(&count) == 0) {
          fprintf(stderr, "Parse error: raw atom\n");
          exit(4); // TODO: Recover from parser error instead of exit
        }
        int n = (*(int *)vec_get_top(&count)) + 1;
        vec_set_top(&count, &n);
      }
      if (!started) return _UNDEFINED;
      if (vec_size(&stack) != 1) {
        fprintf(stderr, "Parse error: unclosed '['\n");
        exit(4); // TODO: Recover from parser error instead of exit
      }
      if (vec_size(&count) > 0) {
        fprintf(stderr, "Parse error: unclosed '['\n");
        exit(4); // TODO: Recover from parser error instead of exit
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
          exit(4); // TODO: Recover from parser error instead of exit
        }
        if (vec_size(&stack) < 2) {
          fprintf(stderr, "Parse error: too few atoms (%d) in a cell "
              "at column %d\n", *(int *)vec_get_top(&count), column);
          exit(4); // TODO: Recover from parser error instead of exit
        }
        for (int i = 1; i < *(int*)vec_get_top(&count); ++i) {
          noun_t right = *(noun_t *)vec_pop(&stack);
          noun_t left = *(noun_t *)vec_pop(&stack);
          CELLS(1);
          noun_t cell = CELL(left, right);
          END_CELLS();
          vec_push(&stack, &cell);
        }
        vec_pop(&count);
        if (vec_size(&count) > 0)
          ++(*(int *)vec_get_top(&count));
        if (vec_size(&stack) == 1 && vec_size(&count) == 0) {
          return *(noun_t *)vec_get_top(&stack);
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
        fprintf(stderr, "Parse error: unexpected character '%c' "
            "at column %d\n", c, column);
        exit(4); // TODO: Recover from parser error instead of exit
      }
    } else {
      if (c == '[' || c == ']' || c == '\n' || c == '\r' || c == ' ' ||
          c == '\t') {
        if (c == '\n') {
          ++row;
          column = 1;
        }
        if (vec_size(&token) > 0) {
          char nul = 0;
          vec_push(&token, &nul);
          noun_t atom = atom_new(heap, vec_get(&token, 0));
          vec_clear(&token);
          vec_push(&stack, &atom);
          if (vec_size(&count) == 0) {
            fprintf(stderr, "Parse error: raw atom\n");
            exit(4); // TODO: Recover from parser error instead of exit
          }
          ++(*(int *)vec_get_top(&count));
        }
        goto redo;
      } else if (c >= '0' && c <= '9') {
        vec_push(&token, &c);
      } else {
        fprintf(stderr, "Parse error: unexpected character '%c' "
            "at column %d\n", c, column);
        exit(4); // TODO: Recover from parser error instead of exit
      }
    }

    ++column;
  }

  return *(noun_t *)vec_get_top(&stack);
}

static void cite(FILE *file, int line, const char *suffix) {
  fprintf(file, "  ::  #%d%s", line, suffix);
}

static void trace(machine_t *machine, enum op_t op, noun_t noun) {
  FILE *file = machine->trace_file;
  for (int i = 0; i < stack_size(machine->stack); ++i)
    fprintf(file, "__ ");
  fprintf(file, "%s", op_to_string(op));
  noun_print(file, noun, true, true);
}

#define TRACE(root) if (ARKHAM_TRACE && trace_flag) trace(machine, op, root)
#define CITE(line) if (ARKHAM_TRACE && trace_flag) cite(file, line, "\n")
#define CITE_INLINE(line) if (ARKHAM_TRACE && trace_flag) cite(file, line, "")
#define CITE_END(p) if (ARKHAM_TRACE && trace_flag && (p)) fprintf(file, "\n")
#define PR(noun) do { \
    fprintf(file, "%s: ", #noun); \
    noun_print(file, noun, true, true); \
    fprintf(file, "\n"); \
} while (false)
#define ASSIGN(l, r, o) do { \
    noun_t old = l; l = SHARE(r, o) ; UNSHARE(old, o); \
} while (false)
#define L(noun) noun_get_left(noun)
#define R(noun) noun_get_right(noun)
#define T(noun) noun_get_type(noun)
#define FRAME(cf, cd) (frame_t){ .fn = cf, .data = cd }
#define FN noun_t
#if NO_SATOMS
noun_t _UNDEFINED;
noun_t _0;
noun_t _1;
noun_t _2;
noun_t _3;
noun_t _4;
noun_t _5;
noun_t _6;
noun_t _7;
noun_t _8;
noun_t _9;
noun_t _10;
#endif

static void dump(machine_t *machine, frame_t *frame, root_t *root,
    const char *function) {
  FILE *file = machine->trace_file;

  fprintf(file, "root: ");
  noun_print(file, root->noun, true, true);
  fprintf(file, "\n");

  fprintf(file, "data: ");
  noun_print(file, frame->data, true, true);
  fprintf(file, "\n");

  ASSERT(false, "%s\n", function);
}

#define TF() if (ARKHAM_TRACE && machine->trace_flag) \
    fprintf(machine->trace_file, "function = %s\n", __FUNCTION__)

static fn_ret_t f13(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  machine->stack = stack_pop(machine->stack, /* unshare */ false,
      machine->heap);
  heap_t *heap = machine->heap;
  CELLS(1);
  fn_ret_t result = (fn_ret_t){ 
    .root = SHARE(CELL(_2, root->noun), ROOT_OWNER), 
    .op = slash_op
  };
  END_CELLS();
  return result;
}

static fn_ret_t f14(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  machine->stack = stack_pop(machine->stack, /* unshare */ false,
      machine->heap);
  heap_t *heap = machine->heap;
  CELLS(1);
  fn_ret_t result = (fn_ret_t){ 
    .root = SHARE(CELL(_3, root->noun), ROOT_OWNER),
    .op = slash_op
  };
  END_CELLS();
  return result;
}

static fn_ret_t f16p2(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  CELLS(1);
  noun_t next_root = SHARE(CELL(frame->data, root->noun), ROOT_OWNER);
  END_CELLS();
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = ret_op };
}

static fn_ret_t f16p1(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  noun_t next_root = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f16p2;
  ASSIGN(frame->data, root->noun, STACK_OWNER);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f20p2(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  CELLS(1);
  noun_t next_root = SHARE(CELL(frame->data, root->noun), ROOT_OWNER);
  END_CELLS();
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f20p1(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  FILE *file = machine->trace_file;
  noun_t next_root = SHARE(frame->data, ROOT_OWNER);
  frame->fn = f20p2;
  ASSIGN(frame->data, root->noun, STACK_OWNER);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f21(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root->noun, ROOT_OWNER), .op = cell_op };
}

static fn_ret_t f22(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root->noun, ROOT_OWNER), .op = inc_op };
}

static fn_ret_t f23(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  machine->stack = stack_pop(machine->stack, /* unshare */ false, heap);
  return (fn_ret_t){ .root = SHARE(root->noun, ROOT_OWNER), .op = equals_op };
}

static fn_ret_t f26(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  CELLS(1);
  noun_t next_root = SHARE(CELL(root->noun, frame->data), ROOT_OWNER);
  END_CELLS();
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t f27(machine_t *machine, frame_t *frame, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  CELLS(2);
  noun_t next_root = SHARE(CELL(CELL(root->noun, L(frame->data)),
      R(R(R(frame->data)))), ROOT_OWNER);
  END_CELLS();
  machine->stack = stack_pop(machine->stack, /* unshare */ true, heap);
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t cond2(machine_t *machine, frame_t *frame, root_t *root) {
  TF();

  if (T(root->noun) == cell_type) {
    CRASH(machine);
    // Make the compiler happy:
    return (fn_ret_t){ .root = root->noun, .op = crash_op };
  }

  heap_t *heap = machine->heap;
  CELLS(1);
  noun_t data = frame->data;
  SHARE(data, COND2_OWNER);
  machine->stack = stack_pop(machine->stack, /* unshare */ true,
      machine->heap);
  bool fits;
  satom_t satom = atom_get_satom(root->noun, &fits);
  if (!fits || (satom != 0 && satom != 1))
    CRASH(machine);
  noun_t r = R(data);
  noun_t next_root = SHARE(CELL(L(data), (satom == 0 ? L(r) : R(r))),
      ROOT_OWNER);
  END_CELLS();
  UNSHARE(data, COND2_OWNER);
  noun_t discard = (satom == 0 ? R(r) : L(r));
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static fn_ret_t cond1(machine_t *machine, root_t *root) {
  TF();
  heap_t *heap = machine->heap;
  bool implement_directly = true;
  CELLS(implement_directly ? 3 : 18);
  noun_t root_noun = root->noun;
  noun_t a = L(root_noun);
  noun_t r = R(root_noun);
  noun_t rr = R(r);
  noun_t b = L(rr);
  noun_t rrr = R(rr);
  noun_t c = L(rrr);
  noun_t d = R(rrr);
  noun_t next_root;
  if (implement_directly) {
    next_root = SHARE(CELL(a, b), ROOT_OWNER);
    stack_push(machine->stack, FRAME(cond2, CELL(a, CELL(c, d))),
               /* share */ true, heap);
    END_CELLS();
  } else {
    next_root = SHARE(CELL(a, CELL(_2, CELL(CELL(_0, _1), CELL(_2, CELL(
        CELL(_1, CELL(c, d)), CELL(CELL(_1, _0), CELL(_2, CELL(
        CELL(_1, CELL(_2, _3)), CELL(CELL(_1, _0), CELL(_4,
        CELL(_4, b))))))))))), ROOT_OWNER);
    END_CELLS();
  }
  return (fn_ret_t){ .root = next_root, .op = nock_op };
}

static inline void inc_ops(machine_t *machine) { 
#if ARKHAM_OP_TRACE
  Fnv_t hash = FNV1_INIT;
  do_roots(machine, roots_hash, &hash);
  fprintf(machine->trace_file, "op=%09lu hash=%016" SATOM_X_FMT "\n",
          machine->ops, hash);
#endif
  do_roots(machine, roots_sanity, NULL);//XXX
#if ARKHAM_STATS
  ++machine->ops;
#endif
}

static noun_t arkham_run_impl(machine_t *machine, enum op_t op,
                              noun_t root_noun) {
  heap_t *heap = machine->heap;
  FILE *file = machine->trace_file;
  bool trace_flag = machine->trace_flag;
  root_t *root = root_new(heap, root_noun);

#if ARKHAM_THREADED_INTERPRETER
  void *op_labels[] = { 
    &&slash_op,
    &&cell_op,
    &&inc_op,
    &&equals_op,
    &&nock_op,
    &&ret_op,
    &&crash_op,
    &&cond_op
  };
#define NEXT_OP(o) TRACE(root->noun); inc_ops(machine); goto *op_labels[o]
#define LABEL(l) l
#else /* #if !ARKHAM_THREADED_INTERPRETER */
#define NEXT_OP(o) TRACE(root->noun); inc_ops(machine); op = o; continue
#define LABEL(l) case l
#endif /* #if ARKHAM_THREADED_INTERPRETER */

#define CALL0(o, n, cf) machine->stack = stack_push(machine->stack, \
  FRAME(cf, _UNDEFINED), /* share */ false, heap); \
  ASSIGN(root->noun, n, ROOT_OWNER); NEXT_OP(o)
#define CALL1(o, n, cf, cd) machine->stack = stack_push(machine->stack, \
  FRAME(cf, cd), /* share */ true, heap); ASSIGN(root->noun, n, \
    ROOT_OWNER); NEXT_OP(o)
#define TAIL_CALL(o, n) ASSIGN(root->noun, n, ROOT_OWNER); op = o; \
  NEXT_OP(o)
#define RET(n) ASSIGN(root->noun, n, ROOT_OWNER); goto ret

  SHARE(root->noun, ROOT_OWNER);

  /* interpreter */
#if ARKHAM_THREADED_INTERPRETER
  NEXT_OP(op);
#else
  while (true) {
    switch (op) {
#endif
    LABEL(nock_op): {
      noun_t rt = root->noun;
      if (T(rt) == cell_type) {
        noun_t r = R(rt);
        if (T(r) == cell_type) {
          noun_t rl = L(r);
          if (T(rl) == cell_type) {
            CELLS(3);
            if (DATA_MOVED()) {
              rt = root->noun; r = R(rt); rl = L(r);
            }
            CITE(16);
            noun_t l = L(rt); 
            noun_t nxt1 = CELL(l, CELL(L(rl), R(rl))); 
            noun_t nxt2 = CELL(l, R(r)); 
            END_CELLS();
            CALL1(nock_op, nxt1, f16p1, nxt2); 
          } else /* if (T(rl) != cell_type) */ {
            bool fits;
            satom_t satom = atom_get_satom(rl, &fits);
            if (fits) {
              switch (satom) {
              case 0: { 
                CITE(18);
                CELLS(1);
                if (DATA_MOVED()) {
                  rt = root->noun; r = R(rt);
                }
                noun_t nxt = CELL(R(r), L(rt));
                END_CELLS();
                TAIL_CALL(slash_op, nxt);
              }
              case 1: { 
                CITE(19);
                noun_t nxt = R(r);
                RET(nxt);
              }
              case 2: {
                noun_t rr = R(r);
                if (T(rr) == cell_type) { 
                  CITE(20); 
                  CELLS(2);
                  if (DATA_MOVED()) {
                    rt = root->noun; r = R(rt); rr = R(r);
                  }
                  noun_t l = L(rt);
                  noun_t nxt1 = CELL(l, L(rr));
                  noun_t nxt2 = CELL(l, R(rr));
                  END_CELLS();
                  CALL1(nock_op, nxt1, f20p1, nxt2);
                } else CRASH(machine);
              }
              case 3: {
                CITE(21);
                CELLS(1);
                if (DATA_MOVED()) {
                  rt = root->noun; r = R(rt);
                }
                noun_t nxt = CELL(L(rt), R(r));
                END_CELLS();
                CALL0(nock_op, nxt, f21);
              }
              case 4: {
                CITE(22);
                CELLS(1);
                if (DATA_MOVED()) {
                  rt = root->noun; r = R(rt);
                }
                noun_t nxt = CELL(L(rt), R(r));
                END_CELLS();
                CALL0(nock_op, nxt, f22);
              }
              case 5: {
                CITE(23);
                CELLS(1);
                if (DATA_MOVED()) {
                  rt = root->noun; r = R(rt);
                }
                noun_t nxt = CELL(L(rt), R(r));
                END_CELLS();
                CALL0(nock_op, nxt, f23);
              }
              case 6: {
                CITE(25);
                fn_ret_t fn_ret = cond1(machine, root);
                op = fn_ret.op;
                UNSHARE(rt, ROOT_OWNER);
                root->noun = fn_ret.root;
                NEXT_OP(op);
              }
              case 7: { 
                noun_t rr = R(r);
                if (T(rr) == cell_type) { 
                  CITE(26); 
                  bool implement_directly = true;
                  if (implement_directly) {
                    // 7r ::     *[a 7 b c]         *[*[a b] c]
                    CELLS(1);
                    if (DATA_MOVED()) {
                      rt = root->noun; r = R(rt); rr = R(r);
                    }
                    noun_t nxt1 = CELL(L(rt), L(rr));
                    noun_t nxt2 = R(rr); 
                    END_CELLS(); 
                    CALL1(nock_op, nxt1, f26, nxt2);
                  } else {
                    CELLS(4);
                    if (DATA_MOVED()) {
                      rt = root->noun; rr = R(R(rt));
                    }
                    noun_t nxt = CELL(L(rt), CELL(_2, CELL(L(rr),
                        CELL(_1, R(rr)))));
                    END_CELLS(); 
                    TAIL_CALL(nock_op, nxt);
                  }
                } else CRASH(machine);
              }
              case 8: {
                noun_t rr = R(r);
                if (T(rr) == cell_type) { 
                  CITE(27); 
                  bool implement_directly = true;
                  if (implement_directly) {
                    // 8r ::     *[a 8 b c]        *[[*[a b] a] c]
                    CELLS(1);
                    if (DATA_MOVED()) {
                      rt = root->noun; rr = R(R(rt));
                    }
                    noun_t nxt1 = CELL(L(rt), L(rr));
                    END_CELLS(); 
                    CALL1(nock_op, nxt1, f27, rt);
                  } else {
                    CELLS(8);
                    if (DATA_MOVED()) {
                      rt = root->noun; rr = R(R(rt));
                    }
                    noun_t nxt = CELL(L(rt), CELL(_7, CELL(CELL(CELL(_7,
                        CELL(CELL(_0, _1), L(rr))), CELL(_0, _1)), R(rr))));
                    END_CELLS(); 
                    TAIL_CALL(nock_op, nxt);
                  }
                } else CRASH(machine);
              }
              case 9: {
                noun_t rr = R(r);
                if (T(rr) == cell_type) { 
                  CITE(28); 
                  // TODO: Implement direct reductions
                  CELLS(7);
                  if (DATA_MOVED()) {
                    rt = root->noun; rr = R(R(rt));
                  }
                  noun_t nxt = CELL(L(rt), CELL(_7, CELL(R(rr), CELL(_2,
                      CELL(CELL(_0, _1), CELL(_0, L(rr)))))));
                  END_CELLS(); 
                  TAIL_CALL(nock_op, nxt);
                } else CRASH(machine);
              }
              case 10: {
                noun_t rr = R(r);
                if (T(rr) == cell_type) { 
                  CITE(29); 
                  noun_t rrl = L(rr);
                  noun_t nxt;
                  if (T(rrl) == cell_type) { 
                    // TODO: Implement direct reductions
                    CELLS(6);
                    if (DATA_MOVED()) {
                      rt = root->noun; rr = R(R(rt)); rrl = L(rr);
                    }
                    nxt = CELL(L(rt), CELL(_8, CELL(R(rrl), CELL(_7,
                        CELL(CELL(_0, _2), R(rr))))));
                    END_CELLS();
                  } else {
                    CELLS(1);
                    if (DATA_MOVED()) {
                      rt = root->noun; rrl = L(R(R(rt)));
                    }
                    nxt = CELL(L(rt), rrl);
                    END_CELLS();
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
      } else /* if (T(rt) != cell_type) */ {
        CITE(35); CRASH(machine);
      }
    }

    LABEL(slash_op): {
      noun_t rt = root->noun;
      if (T(rt) == cell_type) {
        noun_t l = L(rt);
        if (T(l) == cell_type) CRASH(machine);
        else {
          bool fits;
          satom_t satom = atom_get_satom(l, &fits);
          if (fits) {
            if (satom == 1) { CITE(10); noun_t nxt = R(rt); RET(nxt); }
            else {
              noun_t r = R(rt);
              if (T(r) == cell_type) {
                bool implement_directly = true;
                if (implement_directly) {
                  // Run through the bits from left to right:
                  int msb = (sizeof(satom) * 8 - __builtin_clzl(satom) - 1);
                  satom_t mask = (1 << (msb - 1));
                  noun_t nxt = r;
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
                  if (satom == 2) { 
                    CITE(11);
                    noun_t nxt = L(r);
                    noun_t rr = R(r);
                    RET(nxt);
                  }
                  else if (satom == 3) {
                    CITE(12);
                    noun_t nxt = R(r);
                    noun_t lr = L(r);
                    RET(nxt);
                  }
                  /* else fall through to even/odd check */
                }
              } else /* if (T(r) != cell_type) */ {
                CITE(34); CRASH(machine);
              }
            }
          } /* else fall through to even/odd check */
          if (atom_is_even(l)) { 
            CITE(13);
            CELLS(1);
            if (DATA_MOVED()) {
              rt = root->noun; l = L(rt);
            }
            noun_t nxt = CELL(atom_div2(l, heap), R(rt));
            END_CELLS();
            CALL0(slash_op, nxt, f13);
          } else {
            CITE(14);
            CELLS(1);
            if (DATA_MOVED()) {
              rt = root->noun; l = L(rt);
            }
            noun_t nxt = CELL(atom_dec_div2(l, heap), R(rt));
            END_CELLS();
            CALL0(slash_op, nxt, f14);
          }
        }
      } else /* if (T(rt) != cell_type) */ {
        CITE(34); CRASH(machine);
      }
    }

    LABEL(cell_op): {
      if (T(root->noun) == cell_type) {
        CITE(4); RET(_0);
      } else {
        CITE(5); RET(_1);
      }
    }

    LABEL(inc_op): {
      if (T(root->noun) != cell_type) {
        CITE(6); RET(atom_increment(root->noun));
      } else {
        CRASH(machine);
      }
    }

    LABEL(equals_op): {
      noun_t rt = root->noun;
      if (T(rt) == cell_type) {
        noun_t l = L(rt);
        if (T(l) != cell_type) {
          noun_t r = R(rt);
          if (T(r) != cell_type && NOUN_EQUALS(atom_equals(l, r), _YES)) {
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

    LABEL(ret_op): { ASSERT0(op != ret_op); }
    LABEL(crash_op): { ASSERT0(op != crash_op); }
    LABEL(cond_op): { ASSERT0(op != cond_op); }
#if !ARKHAM_THREADED_INTERPRETER
    } /* switch (op) */
#endif

  ret:
    if (stack_is_empty(machine->stack)) {
      root_noun = root->noun;
#if ARKHAM_URC && ARKHAM_STATS
      collect_garbage(0);
#endif
      root_delete(heap, root);
      return root_noun;
    } else {
      frame_t *frame = stack_current_frame(machine->stack);
      fn_ret_t fn_ret = frame->fn(machine, frame, root);
      op = fn_ret.op;
      UNSHARE(root->noun, ROOT_OWNER);
      root->noun = fn_ret.root;
      if (op == ret_op)
        goto ret;
#if ARKHAM_THREADED_INTERPRETER
      else
        NEXT_OP(op);
#endif
    }
#if !ARKHAM_THREADED_INTERPRETER
  }
#endif /* while (true) */
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

static void arkham_run(int n_inputs, infile_t *inputs, bool trace_flag,
    bool interactive_flag, const char *module_name) {
  for (int i = 0; i < n_inputs; ++i) {
    machine_t machine;
#if ARKHAM_STATS
    machine.ops = 0;
#endif
    machine.heap = heap_new();
    alloc_atoms(machine.heap);
    machine.stack = stack_new(1);
#if ARKHAM_LLVM
    machine.llvm = llvm_new(module_name);
#endif
    machine.trace_file = fopen(ARKHAM_TRACE_FILE, "w");
    FAIL(machine.trace_file != NULL, "Could not create log file: '%s'\n",
         ARKHAM_TRACE_FILE);
    machine.log_file = fopen(ARKHAM_LOG_FILE, "w");
    FAIL(machine.log_file != NULL, "Could not create log file: '%s'\n",
         ARKHAM_LOG_FILE);
    machine.out_file = stdout;
    machine.trace_flag = trace_flag;

    machine_set(&machine);

    infile_t *input = inputs + i;
    if (input->name != NULL) 
      INFO("Input file: %s\n", input->name);
    else
      INFO0("Input file: standard input\n");

    if (false) { // ZZZ
      char *env = getenv("ARKHAM_ARG");
      int arg = (env != NULL ? atoi(env) : 10);
      test_jit(satom_as_noun(arg));
    } else {
      bool eof = false;
      do {
        // TODO: Use readline (or editline)
        if (interactive_flag) printf("> ");
        noun_t top = parse(&machine, input, &eof);
        if (NOUN_IS_DEFINED(top)) {
          noun_print(machine.out_file, arkham_run_impl(&machine, nock_op, top),
                     true, true);
          printf("\n");
        }
      } while (interactive_flag && !eof);
    }

    free_atoms(machine.heap);
    heap_free_free_list(machine.heap);
#if ARKHAM_STATS
    fprintf(machine.trace_file, "heap stats:\n");
    heap_print_stats(machine.heap, machine.trace_file);
    fprintf(machine.trace_file, "stack stats:\n");
    stack_print_stats(machine.stack, machine.trace_file);
    fprintf(machine.trace_file, "op stats:\n");
    fprintf(machine.trace_file, "ops=%lu\n", machine.ops);
#endif
#if ARKHAM_LLVM
    llvm_delete(machine.llvm);
#endif
    heap_free(machine.heap);
    stack_free(machine.stack);
    if (machine.log_file != stdout && machine.log_file != stderr)
      fclose(machine.log_file);
    if (machine.trace_file != stdout && machine.trace_file != stderr)
      fclose(machine.trace_file);
    if (machine.out_file != stdout && machine.out_file != stderr)
      fclose(machine.out_file);
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

#if ARKHAM_LLVM
  llvm_init_global();
#endif

  // REVISIT: use getopt?

  const char *trace_env = getenv("ARKHAM_TRACE");
  if (trace_env == NULL) trace_env = "false";
  bool trace_flag = !(strcasecmp(trace_env, "no") == 0 ||
      strcmp(trace_env, "0") == 0 || strcasecmp(trace_env, "false") == 0);
  bool interactive = false;
  infile_t *inputs = (infile_t *)calloc(1, argc * sizeof(infile_t));
  int n_inputs = 0;
  for (int i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    BEGIN_MATCH_STRING(arg);
    STRCMP_CASE("--help", arkham_usage(NULL));
    STRCMP_CASE("--interactive", interactive = true);
    STRCMP_CASE("-i", interactive = true);
    STRCMP_CASE("--enable-tracing", trace_flag = true);
    STRCMP_CASE("--disable-tracing", trace_flag = false);
    STRCMP_CASE("-", {
        inputs[n_inputs].name = NULL;
        inputs[n_inputs].file = stdin;
        ++n_inputs; });
    TRUE_CASE(file, {
        if (strncmp(file, "-", 1) == 0)
          arkham_usage("Unknown option: '%s'\n", file);
        else { 
          FILE *f = fopen(file, "r");
          if (f != NULL) {
            inputs[n_inputs].name = file;
            inputs[n_inputs].file = f;
            ++n_inputs;
          } else arkham_usage("File not found: %s\n", file);
        }
      });
    END_MATCH_STRING();
  }
  if (n_inputs == 0) {
    // Drop into REPL if there are no file specified:
    inputs[n_inputs].name = NULL;
    inputs[n_inputs].file = stdin;
    ++n_inputs;
    interactive = true;
  }
  FAIL(ARKHAM_TRACE || !trace_flag, "Call tracing disabled for this build");
  arkham_run(n_inputs, inputs, trace_flag, interactive, argv[0]);
}
