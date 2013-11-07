* Bitcode to human-readable:
    llvm-dis foo.bc -o -

// Node *fib_rlyeh(Environment *env) {
//   heap_t *heap = machine->heap;
//   CELLS(1);

//   Declaration *decl_f0_f1 = new Declaration(CELL(_0, _1)); {
//     Declaration *decl_counter = new Declaration(_0);
//     /**/ decl_f0_f1->set_inner(decl_counter); {
//       Loop *loop = new Loop();
//       /**/ decl_counter->set_inner(loop); {
//         BinaryExpression *eq = new BinaryExpression(binop_eq_type);
//         /**/ loop->set_test(eq); {
//           Load *eq_left = new Load(15);
//           /**/ eq->set_left(eq_left);
//         } {
//           Load *eq_right = new Load(6);
//           /**/ eq->set_right(eq_right);
//         } 
//       } {
//         Load *result = new Load(28);
//         /**/ loop->set_result(result);
//       } {
//         Iteration *iteration = new Iteration();
//         /**/ loop->set_iteration(iteration); {
//           Store *store_6 = new Store(6);
//           /**/ iteration->add_store(store_6);
//           IncrementExpression *inc_6 = new IncrementExpression();
//           /**/ store_6->set_subexpr(inc_6);
//           Load *load_6 = new Load(6);
//           /**/ inc_6->set_subexpr(load_6);
//         } {
//           Store *store_28 = new Store(28);
//           /**/ iteration->add_store(store_28);
//           Load *load_29 = new Load(29);
//           /**/ store_28->set_subexpr(load_29);
//         } {
//           Store *store_29 = new Store(29);
//           /**/ iteration->add_store(store_29);
//           BinaryExpression *add = new BinaryExpression(binop_add_type);
//           /**/ store_29->set_subexpr(add);
//           Load *add_left = new Load(28);
//           /**/ add->set_left(add_left);
//           Load *add_right = new Load(29);
//           /**/ add->set_right(add_right);
//         } {
//           Store *store_15 = new Store(15);
//           /**/ iteration->add_store(store_15);
//           Load *load_15 = new Load(15);
//           /**/ store_15->set_subexpr(load_15);
//         }
//       }
//     }
//   }

//   return decl_f0_f1;
// }


#if 0
PUSH going into DECL and pop coming out

         1
    2          3
 4    5     6     7
8 9 10 11 12 13 14 15
               2829

dec:

         *
    CORE       *
            0     N


fib (outer):
        *
    CORE       *
            0     *
                *  N
               1a 1b

fib (inner):
        *
    CORE       *
            0     *
                1a  1b


#endif

# -lprofiler 
