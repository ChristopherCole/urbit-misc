#include <gmp.h>

#include "nock5k.h"

//ZZZ: split functions into inline/outline (fast/slow) portions

__thread machine_t *machine;

extern "C" {

void machine_set(machine_t *m) {
  machine = m;
}

static __attribute__((noinline)) fat_noun_t
add_slow(fat_noun_t n1, fat_noun_t n2) {
  ASSERT(!noun_is_freed(n1, machine->heap), "!noun_is_freed(noun, machine->heap)\n");
  ASSERT(noun_get_type(n1) != cell_type, "noun_get_type(noun) != cell_type\n");
  ASSERT(!noun_is_freed(n2, machine->heap), "!noun_is_freed(noun, machine->heap)\n");
  ASSERT(noun_get_type(n2) != cell_type, "noun_get_type(noun) != cell_type\n");

  fat_noun_t sum;

  if (n1.flags & NOUN_SATOM_FLAG)
    sum = batom_new_ui(machine->heap, noun_as_satom(n1));
  else
    sum = batom_new(machine->heap, noun_as_batom(n1)->val, /* clear */ false);

  batom_t *bsum = noun_as_batom(sum);

  if (n2.flags & NOUN_SATOM_FLAG)
    mpz_add_ui(bsum->val, bsum->val, noun_as_satom(n2));
  else
    mpz_add(bsum->val, bsum->val, noun_as_batom(n2)->val);
  
  // USH(n1);//ZZZ???
  // USH(n2);

  return sum;
}

static inline fat_noun_t
add(fat_noun_t n1, fat_noun_t n2) {
  ASSERT(!noun_is_freed(n1, machine->heap), "!noun_is_freed(noun, machine->heap)\n");
  ASSERT(noun_get_type(n1) != cell_type, "noun_get_type(noun) != cell_type\n");
  ASSERT(!noun_is_freed(n2, machine->heap), "!noun_is_freed(noun, machine->heap)\n");
  ASSERT(noun_get_type(n2) != cell_type, "noun_get_type(noun) != cell_type\n");

  if (n1.flags & n2.flags & NOUN_SATOM_FLAG) {
    satom_t sn1 = noun_as_satom(n1);
    satom_t sn2 = noun_as_satom(n2);
    satom_t sum = sn1 + sn2;
    if (sum > sn1 && sum > sn2)
      return satom_as_noun(sum);
  }

  return add_slow(n1, n2);
}

static __attribute__((noinline)) fat_noun_t
inc_slow(fat_noun_t n) {
  //ZZZ
  return _NULL;
}

static inline fat_noun_t
inc(fat_noun_t n) {
  //ZZZ
  return _NULL;
}

static __attribute__((noinline)) bool
eq_slow(fat_noun_t n1, fat_noun_t n2) {
  //ZZZ
  return false;
}

static inline bool
eq(fat_noun_t n1, fat_noun_t n2) {
  //ZZZ
  return false;
}

extern fat_noun_t
fib(fat_noun_t n) {
  ASSERT(!noun_is_freed(n, machine->heap), "!noun_is_freed(n, machine->heap)\n");
  ASSERT(noun_get_type(n) != cell_type, "noun_get_type(n) != cell_type\n");

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

} /* extern "C" */
