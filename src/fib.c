#include <arkham.h>

extern noun_t
singleton(noun_t n) {
  ASSERT(noun_is_valid_atom(n, machine_get()->heap), "noun_is_valid_atom(n, "
         "machine->heap)\n");

  noun_t f0 = _0;
  noun_t f1 = _1;
  noun_t counter = _0;
  while (true) {
    if (NOUN_EQUALS(atom_equals(n, counter), _YES))
      return f0;
    else {
      counter = atom_increment(counter);
      noun_t sum = atom_add(f0, f1);
      f0 = f1;
      f1 = sum;
    }
  }
}
