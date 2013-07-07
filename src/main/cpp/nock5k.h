#if !defined(NOCK5K_H)
#define NOCK5K_H

#include <inttypes.h>
#include <gmp.h>
#include <config.h>
#include <stdio.h>

#define ASSERT(p, ...) do { if (NOCK_ASSERT && !(p)) fail(__VA_ARGS__); } while(false)
#define CRASH(machine) crash(machine, "Crash: %s: %d\n", __FUNCTION__, __LINE__)
#define IS_DEBUG (NOCK_LOG >= NOCK_DEBUG)
#define DEBUG(f, ...) do { if (IS_DEBUG) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define DEBUG0(s) do { if (NOCK_LOG >= NOCK_DEBUG) printf(s); } while (false)
#define IS_INFO (NOCK_LOG >= NOCK_INFO)
#define INFO(f, ...) do { if (IS_INFO) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define INFO0(s) do { if (NOCK_LOG => NOCK_INFO) printf(s); } while (false)

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

#if NOCK_LLVM
typedef struct {
  LLVMModuleRef module;
  LLVMBuilderRef builder;
  LLVMExecutionEngineRef engine;
  LLVMPassManagerRef pass_manager;
} llvm_t;
#endif

struct fstack;

struct frame;

typedef struct machine {
  struct fstack *stack;
  struct heap *heap;
  FILE *file;
#if NOCK_LLVM
  llvm_t llvm;
#endif
  bool trace_flag;
#if NOCK_STATS
  unsigned long ops;
#endif  
} machine_t;

#if NO_SATOMS
extern fat_noun_t _NULL;
extern fat_noun_t _0;
extern fat_noun_t _1;
extern fat_noun_t _2;
extern fat_noun_t _3;
extern fat_noun_t _4;
extern fat_noun_t _5;
extern fat_noun_t _6;
extern fat_noun_t _7;
extern fat_noun_t _8;
extern fat_noun_t _9;
extern fat_noun_t _10;
#else
#define _NULL ((fat_noun_t){ .ptr = (noun_t *)0, .flags = 0 })
#define _0 ((fat_noun_t){ .ptr = (noun_t *)0, .flags = NOUN_SATOM_FLAG })
#define _1 ((fat_noun_t){ .ptr = (noun_t *)1, .flags = NOUN_SATOM_FLAG })
#define _2 ((fat_noun_t){ .ptr = (noun_t *)2, .flags = NOUN_SATOM_FLAG })
#define _3 ((fat_noun_t){ .ptr = (noun_t *)3, .flags = NOUN_SATOM_FLAG })
#define _4 ((fat_noun_t){ .ptr = (noun_t *)4, .flags = NOUN_SATOM_FLAG })
#define _5 ((fat_noun_t){ .ptr = (noun_t *)5, .flags = NOUN_SATOM_FLAG })
#define _6 ((fat_noun_t){ .ptr = (noun_t *)6, .flags = NOUN_SATOM_FLAG })
#define _7 ((fat_noun_t){ .ptr = (noun_t *)7, .flags = NOUN_SATOM_FLAG })
#define _8 ((fat_noun_t){ .ptr = (noun_t *)8, .flags = NOUN_SATOM_FLAG })
#define _9 ((fat_noun_t){ .ptr = (noun_t *)9, .flags = NOUN_SATOM_FLAG })
#define _10 ((fat_noun_t){ .ptr = (noun_t *)10, .flags = NOUN_SATOM_FLAG })
#endif

/* note: we use pointer tagging to distinguish types */
#define NOUN_SATOM_FLAG 1
#define NOUN_PTR_SATOM_LEFT_FLAG 1
#define NOUN_PTR_SATOM_RIGHT_FLAG 2
#define NOUN_PTR_FLAGS (NOUN_PTR_SATOM_LEFT_FLAG | NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_IS_LEFT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_LEFT_FLAG) == NOUN_PTR_SATOM_LEFT_FLAG)
#define NOUN_IS_RIGHT_SATOM(noun_ptr) ((((satom_t)noun_ptr) & NOUN_PTR_SATOM_RIGHT_FLAG) == NOUN_PTR_SATOM_RIGHT_FLAG)
#define NOUN_RAW_PTR(noun_ptr) ((void *)(((satom_t)noun_ptr) & ~(satom_t)NOUN_PTR_FLAGS))

#define NOUN_EQUALS(n1, n2) (n1.ptr == n2.ptr && n1.flags == n2.flags)
#define IS_NULL(noun) NOUN_EQUALS(noun, _NULL)
#define CELL(left, right) cell_new(heap, left, right)

#if ALLOC_DEBUG
#define STACK_OWNER ((base_t *)1)
#define ROOT_OWNER ((base_t *)2)
#define COND2_OWNER ((base_t *)3)
#define HEAP_OWNER ((base_t *)4)
#define LAST_OWNER HEAP_OWNER
#endif

extern "C" {
void machine_set(machine_t *m);

void crash(machine_t *machine, const char *format, ...);

void fail(const char *format, ...);

static inline enum noun_type
noun_get_type(fat_noun_t noun) {
  if ((noun.flags & NOUN_SATOM_FLAG) == NOUN_SATOM_FLAG)
    return satom_type;
  else {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    // A cell can't point to itself. This distinguishes a batom from a cell.
    return ((base_t *)base->left) == base ? batom_type : cell_type;
  }
}

static inline satom_t
noun_as_satom(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == satom_type, "noun_get_type(noun) == satom_type\n");
  return (satom_t)noun.ptr;
}

static inline fat_noun_t
satom_as_noun(satom_t satom) {
  return (fat_noun_t){ .ptr = (noun_t *)satom, .flags = NOUN_SATOM_FLAG };
}

static inline batom_t *
noun_as_batom(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == batom_type, "noun_get_type(noun) == batom_type\n");
  return (batom_t *)NOUN_RAW_PTR(noun.ptr);
}

static inline cell_t *
noun_as_cell(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (cell_t *)NOUN_RAW_PTR(noun.ptr);
}

static inline fat_noun_t
noun_get_left(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t){ .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->base.left,
      .flags = NOUN_IS_LEFT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

static inline fat_noun_t
noun_get_right(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t){ 
    .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->right,
      .flags = NOUN_IS_RIGHT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

void noun_print(FILE *file, fat_noun_t noun, bool brackets);

const char *noun_type_to_string(enum noun_type noun_type);

fat_noun_t cell_new(struct heap *heap, fat_noun_t left, fat_noun_t right);

bool noun_is_valid_atom(fat_noun_t noun, struct heap *heap);

fat_noun_t atom_add(fat_noun_t n1, fat_noun_t n2, struct heap *heap);

bool atom_equals(fat_noun_t a, fat_noun_t b);

fat_noun_t atom_increment(fat_noun_t noun, struct heap *heap);

fat_noun_t batom_new(struct heap *heap, mpz_t val, bool clear);

fat_noun_t batom_new_ui(struct heap *heap, unsigned long val);

#if ALLOC_DEBUG
fat_noun_t noun_share(fat_noun_t noun, struct heap *heap, base_t *owner);

void noun_unshare(fat_noun_t noun, struct heap *heap, bool toplevel, base_t *owner);
#else
fat_noun_t noun_share(fat_noun_t noun, struct heap *heap);

void noun_unshare(fat_noun_t noun, struct heap *heap, bool toplevel);
#endif

} /* extern "C" */

#endif /* #if !defined(NOCK5K_H) */
