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

#define _ASSERT true
#define _DEBUG 4
#define _INFO 3
#define _WARN 2
#define _ERROR 1
#define _LOG 3
#define _STATS _ASSERT

#define ASSERT(p, ...) do { if (_ASSERT && !(p)) fail(__VA_ARGS__); } while(false)
#define DEBUG(f, ...) do { if (_LOG >= _DEBUG) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
#define DEBUG0(s) do { if (_LOG >= _DEBUG) printf(s); } while (false)
#define INFO(f, ...) do { if (_LOG >= _INFO) printf("%s %d:" f, __FUNCTION__, __LINE__, __VA_ARGS__); } while (false)
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

typedef struct base { 
#if _STATS
  struct cell *owner;
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

enum noun_type {
  cell_type,
  batom_type,
  satom_type
};

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
    return (base_t *)base->left == base ? batom_type : cell_type;
  }
}

static bool
noun_has_owner(fat_noun_t noun) {
  if ((noun.flags & NOUN_SATOM_FLAG) == NOUN_SATOM_FLAG)
    return false;
  else {
    base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
    return base->owner != NULL;
  }
}

static void
noun_set_owner(fat_noun_t noun, cell_t *owner) {
  switch (noun_get_type(noun)) {
  case cell_type:
  case batom_type:
    {
      base_t *base = (base_t *)NOUN_RAW_PTR(noun.ptr);
      if (owner != NULL)
	ASSERT(base->owner == NULL, "base->owner == NULL\n");
      else
	ASSERT(base->owner != NULL, "base->owner != NULL\n");
      base->owner = owner;
      break;
    }
  case satom_type:
    {
      // Do nothing.
      break;
    }
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

static fat_noun_t
noun_get_left(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t) { .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->base.left,
      .flags = NOUN_IS_LEFT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

static fat_noun_t
noun_get_right(fat_noun_t noun) {
  ASSERT(noun_get_type(noun) == cell_type, "noun_get_type(noun) == cell_type\n");
  return (fat_noun_t) { 
    .ptr = ((cell_t *)NOUN_RAW_PTR(noun.ptr))->right,
      .flags = NOUN_IS_RIGHT_SATOM(noun.ptr) ? NOUN_SATOM_FLAG : 0
      };
}

typedef struct {
#if _STATS
  unsigned long cell_alloc_count;
  unsigned long cell_free_count;
  unsigned long cell_max_count;
  unsigned long batom_alloc_count;
  unsigned long batom_free_count;
  unsigned long batom_max_count;
#endif
} heap_t;

static void
heap_print_stats(heap_t *heap, FILE *file) {
#if _STATS
  fprintf(file, "cell_alloc_count=%lu\n", heap->cell_alloc_count);
  fprintf(file, "cell_free_count=%lu\n", heap->cell_free_count);
  fprintf(file, "cell_max_count=%lu\n", heap->cell_max_count);
  fprintf(file, "batom_alloc_count=%lu\n", heap->batom_alloc_count);
  fprintf(file, "batom_free_count=%lu\n", heap->batom_free_count);
  fprintf(file, "batom_max_count=%lu\n", heap->batom_max_count);
#endif
}

static heap_t *
heap_new() {
  heap_t *heap = (heap_t *)calloc(1, sizeof(heap_t));
  return heap;
}

static cell_t *
heap_alloc_cell(heap_t *heap) {
#if _STATS
  ++heap->cell_alloc_count;
  int active_cell_count = heap->cell_alloc_count - heap->cell_free_count;
  if (active_cell_count > heap->cell_max_count) {
    heap->cell_max_count = active_cell_count;
  }
#endif
  return (cell_t *)calloc(1, sizeof(cell_t));
}

static void
heap_free_cell(heap_t *heap, cell_t *cell) {
#if _STATS
  ASSERT(heap->cell_free_count < heap->cell_alloc_count, "heap->cell_free_count < heap->cell_alloc_count\n");
  ++heap->cell_free_count;
#endif
  free(cell);
}

static batom_t *
heap_alloc_batom(heap_t *heap) {
#if _STATS
  ++heap->batom_alloc_count;
  int active_batom_count = heap->batom_alloc_count - heap->batom_free_count;
  if (active_batom_count > heap->batom_max_count) {
    heap->batom_max_count = active_batom_count;
  }
#endif
  return (batom_t *)calloc(1, sizeof(batom_t));
}

static void
heap_free_batom(heap_t *heap, batom_t *batom) {
#if _STATS
  ASSERT(heap->batom_free_count < heap->batom_alloc_count, "heap->batom_free_count < heap->batom_alloc_count\n");
  ++heap->batom_free_count;
#endif
  free(batom);
}

static fat_noun_t
heap_new_cell(heap_t *heap, fat_noun_t left, fat_noun_t right) {
  cell_t *cell = heap_alloc_cell(heap);
#if _STATS
  noun_set_owner(left, cell);
  noun_set_owner(right, cell);
#endif
  cell->base.left = left.ptr;
  cell->right = right.ptr;
  return (fat_noun_t) {
    .ptr = (noun_t *)
      (((satom_t)cell) |
       ((noun_get_type(left) == satom_type) ? NOUN_PTR_SATOM_LEFT_FLAG : 0) |
       ((noun_get_type(right) == satom_type) ? NOUN_PTR_SATOM_RIGHT_FLAG : 0)),
      .flags = 0
      };
}

static void
heap_delete_cell(heap_t *heap, fat_noun_t cell) {
  ASSERT(noun_get_type(cell) == cell_type, "noun_get_type(cell) == cell_type\n");
#if _STATS
  noun_set_owner(noun_get_left(cell), NULL);
  noun_set_owner(noun_get_right(cell), NULL);
#endif
  heap_free_cell(heap, (cell_t *)NOUN_RAW_PTR(cell.ptr));
}

static fat_noun_t
heap_new_batom(heap_t *heap, mpz_t val) {
  batom_t *batom = heap_alloc_batom(heap);
  mpz_init(batom->val);
  mpz_set(batom->val, val);
  mpz_clear(val);
  return (fat_noun_t) { .ptr = (noun_t *)batom, .flags = 0 };
}

static fat_noun_t
heap_new_atom(heap_t *heap, const char *str) {
  mpz_t val;
  mpz_init_set_str(val, str, 10);
  if (mpz_cmp(val, SATOM_MAX_MPZ) <= 0)
    return satom_as_noun((satom_t)mpz_get_ui(val));
  else
    return heap_new_batom(heap, val);
}

static void
heap_delete_batom(heap_t *heap, fat_noun_t batom) {
  ASSERT(noun_get_type(batom) == batom_type, "noun_get_type(batom) == batom_type\n");
  batom_t *batom_ptr = (batom_t *)NOUN_RAW_PTR(batom.ptr);
  mpz_clear(batom_ptr->val);
  heap_free_batom(heap, batom_ptr);
}

static bool
noun_atoms_equal(fat_noun_t a, fat_noun_t b) {
  enum noun_type a_type = noun_get_type(a);
  enum noun_type b_type = noun_get_type(b);
  ASSERT(a_type != cell_type, "a_type != cell_type\n");
  ASSERT(b_type != cell_type, "b_type != cell_type\n");
  if (a_type != b_type) return false;
  if (a_type == satom_type)
    return ((satom_t)a.ptr) == ((satom_t)b.ptr);
  else
    return mpz_cmp(((batom_t *)a.ptr)->val, ((batom_t *)a.ptr)->val) == 0;
}

static void noun_print(FILE *file, fat_noun_t noun, bool brackets);

static void
batom_print(FILE *file, batom_t *atom) {
  char *str = mpz_get_str(NULL, 10, atom->val);
  fprintf(file, "%s", str);
  free(str);
}

static void
cell_print(FILE *file, fat_noun_t cell, bool brackets) {
  if (brackets) fprintf(file, "[");
  noun_print(file, noun_get_left(cell), false);
  fprintf(file, " ");
  noun_print(file, noun_get_right(cell), false);
  if (brackets) fprintf(file, "]");
}

static void
cell_drop(FILE *file, fat_noun_t cell, bool brackets) {
  if (brackets) fprintf(file, "[");
  noun_print(file, noun_get_left(cell), false);
  fprintf(file, " ");
  noun_print(file, noun_get_right(cell), false);
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

static void
noun_drop(fat_noun_t noun, heap_t *heap) {
  switch (noun_get_type(noun)) {
  case cell_type:
    {
      heap_delete_cell(heap, noun);
      noun_drop(noun_get_left(noun), heap);
      noun_drop(noun_get_right(noun), heap);
      break;
    }
  case batom_type:
    {
      heap_delete_batom(heap, noun);
      break;
    }
  case satom_type:
    {
      break;
    }
  }
}

enum op_t { crash_op, slash_op, cell_op, inc_op, equals_op, cond_op, nock_op };

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
typedef void (*fn_t)(struct fstack *stack, fat_noun_t data, bool trace);
typedef struct { enum op_t op; fn_t fn; fat_noun_t data; } frame_t;
typedef struct fstack { 
  int capacity; 
  int size; 
#if _STATS
  unsigned long max_size;
#endif
  frame_t frames[0];
} fstack_t;

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

static fstack_t *
stack_push(fstack_t *stack, frame_t frame) {
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

static fstack_t *
stack_pop(fstack_t *stack) {
  ASSERT(!stack_is_empty(stack), "!stack_is_empty(stack)\n");
  --stack->size;
  return stack;
}

static frame_t *
stack_current_frame(fstack_t *stack) {
  ASSERT(!stack_is_empty(stack), "!stack_is_empty(stack)\n");
  return &(stack->frames[stack->size - 1]);
}

static fat_noun_t parse(heap_t *heap, infile_t *input) {
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
	  stack.push(heap_new_cell(heap, left, right));
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
	  stack.push(heap_new_atom(heap, token.c_str()));
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
  fprintf(file, "  ::  #%d", line);
}

static void trace(FILE *file, int *indent, enum op_t op, fat_noun_t noun, bool in) {
  bool out = !in;
  bool print = in;
  if (out || *indent > 0)
    fprintf(file, "\n");
  if (out) *indent -= 1;
  if (out) return;
  for (int i = 0; i < *indent; ++i) fprintf(file, "    ");
  fprintf(file, "%s %s", (in ? "->" : "<-"), op_to_string(op));
  noun_print(file, noun, true);
  if (in) *indent += 1;
  if (out && *indent == 0)
    fprintf(file, "\n");
}

static void finish_20_p1(struct fstack *stack, fat_noun_t data, bool trace) {
  ASSERT(false, "%s\n", __FUNCTION__);
}

static fat_noun_t nock5k_run_impl(heap_t *heap, fstack_t **stackp, bool trace_flag) {
  FILE *file = stdout;

  /* tracing/debugging */
  int indent = 0;

#define TRACE_IN() if (trace_flag) trace(file, &indent, op, root, true)
#define TRACE_OUT() if (trace_flag) trace(file, &indent, op, root, false)
#define CITE(line) if (trace_flag) cite(file, line)
#define NC(left, right) heap_new_cell(heap, left, right)
#define DC(noun) heap_delete_cell(heap, noun)
#define DC2(n1, n2) DC(n1); DC(n2)
#define DC3(n1, n2, n3) DC(n1); DC(n2); DC(n3)
#define L(noun) noun_get_left(noun)
#define R(noun) noun_get_right(noun)
#define T(noun) noun_get_type(noun)
#define FRAME(o, f, d) (frame_t){ .op = o, .fn = f, .data = d }
#define CALL(o, f, d) stack = stack_push(stack, FRAME(o, f, d)); goto call
#define RET(noun) root = noun; TRACE_OUT(); goto ret
#define DR(noun) noun_drop(noun, heap)
#define FN fat_noun_t

  /* interpreter */
  fat_noun_t root;
  enum op_t op;
  fstack_t *stack = *stackp;
  while (true) {
  call:
    frame_t *frame = stack_current_frame(stack);
    root = frame->data;
    op = frame->op;
    ASSERT(!noun_has_owner(root), "!noun_has_owner(root)\n");

  tail_call:
    TRACE_IN();

    DEBUG("op=%s\n", op_to_string(op));
    switch (op) {
    case nock_op: 
      {
	DEBUG("T(root)=%s\n", noun_type_to_string(T(root)));
	switch (T(root)) {
	case cell_type:
	  {
	    fat_noun_t r = R(root);
	    DEBUG("T(r)=%s\n", noun_type_to_string(T(r)));
	    switch (T(r)) {
	    case cell_type:
	      {
		fat_noun_t rl = L(r);
		DEBUG("T(rl)=%s\n", noun_type_to_string(T(rl)));
		switch (T(rl)) {
		case satom_type:
		  {
		    DEBUG("rl=%" SATOM_FMT "\n", noun_as_satom(rl));
		    switch (noun_as_satom(rl)) {
		    // case Cell(a, Cell(Zero, b)) => { cite(18) ; slash(Cell(b, a)) }
		      //ZZZ: this is a tail call: implement it as such
		    case 0: { CITE(18); FN nxt = NC(R(r), L(root)); DC2(root, r); CALL(slash_op, NULL, nxt); }
		    // case Cell(a, Cell(One, b)) => { cite(19) ; b }
		    case 1: { CITE(19); FN nxt = R(r); DC2(root, r); RET(nxt); }
		    // case Cell(a, Cell(Two, Cell(b, c))) => { cite(20) ; nock(Cell(nock(Cell(a, b)), nock(Cell(a, c)))) }
		    case 2: { fat_noun_t rr = R(r);
		    	if (T(rr) == cell_type) { CITE(20); DC3(root, r, rr); CALL(nock_op, finish_20_p1, NC(L(root), L(rr))); } }
		    }
		  }
		case cell_type:
		  {
		    //ZZZ
		  // case Cell(a, Cell(Cell(b, c), d)) => { cite(16) ; Cell(nock(Cell(a, Cell(b, c))), nock(Cell(a, d))) }
		  }
		default: ;
		}
	      }
	    default: ;
	    }
	  }
	default: { CITE(35); goto crash; }
	}

	goto crash;
      }

    case crash_op: { goto crash; }

    case slash_op: 
      {
	//ZZZ
	DEBUG("T(root)=%s\n", noun_type_to_string(T(root)));
	switch (T(root)) {
	case cell_type:
	  {
	    fat_noun_t l = L(root);
	    DEBUG("T(l)=%s\n", noun_type_to_string(T(l)));
	    switch (T(l)) {
	    case satom_type:
	      {
		DEBUG("l=%" SATOM_FMT "\n", noun_as_satom(l));
		switch (noun_as_satom(l)) {
		// case Cell(One, a) => { cite(10) ; a }
		case 1: { CITE(10); FN nxt = R(root); DC(root); RET(nxt); }
		// case Cell(Two, Cell(a, _)) => { cite(11) ; a }
		case 2: { fat_noun_t r = R(root);
		    if (T(r) == cell_type) { CITE(11); FN nxt = L(r); DC2(root, r); DR(R(r)); RET(nxt); } }
		// case Cell(Three, Cell(_, b)) => { cite(12) ; b }
		case 3: { fat_noun_t r = R(root);
		    if (T(r) == cell_type) { CITE(12); FN nxt = R(r); DC2(root, r); DR(L(r)); RET(nxt); } }
		}
	      }
	    case cell_type:
	      {
		//ZZZ
		// case Cell(a, Cell(Cell(b, c), d)) => { cite(16) ; Cell(nock(Cell(a, Cell(b, c))), nock(Cell(a, d))) }
	      }
	    default: ;
	    }
	  }
	default: { CITE(34); goto crash; }
	}

	goto crash;
      }

    case cell_op: 
      {
	//ZZZ
	goto crash;
      }

    case inc_op: 
      {
	//ZZZ
	goto crash;
      }

    case equals_op: 
      {
	//ZZZ
	goto crash;
      }

    case cond_op: 
      {
	//ZZZ
	goto crash;
      }
    }

  ret:
    while (true) {
      stack = stack_pop(stack);
      if (stack_is_empty(stack)) {
	*stackp = stack;
	return root;
      }
      TRACE_OUT(); 
      frame_t *frame = stack_current_frame(stack);
      if (frame->fn != NULL) {
	ASSERT(false, "Call continuation\n");
      }
    }
  }

 crash:

  fprintf(file, "\nCrash: %s", op_to_string(op)); noun_print(file, root, true); fprintf(file, "\n");
  exit(2);
}

static void nock5k_run(int n_inputs, infile_t *inputs, bool trace) {
  for (int i = 0; i < n_inputs; ++i) {
    infile_t *input = inputs + i;
    if (input->name != NULL) 
      printf("file: %s\n", input->name);
    else
      printf("file: standard input\n");

    heap_t *heap = heap_new();
    fstack_t *stack = stack_new(1);
    stack = stack_push(stack, (frame_t) { .op = nock_op, .fn = NULL, .data = parse(heap, input) } );
    noun_print(stdout, nock5k_run_impl(heap, &stack, trace), true);
    printf("\n");
#if _STATS
    printf("heap stats:\n");
    heap_print_stats(heap, stdout);
    printf("stack stats:\n");
    stack_print_stats(stack, stdout);
#endif
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
  bool trace = !(strcasecmp(trace_env, "no") == 0 || strcmp(trace_env, "0") || strcasecmp(trace_env, "false"));
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
	fprintf(stderr, "***** '%s' %d\n", file, (strncmp(file, "-", 1)));
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
