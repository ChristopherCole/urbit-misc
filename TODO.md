High:
* Remove ARKHAM_LLVM (assume TRUE)
* Recover from parser error instead of exit
Medium:
* Output Rlyeh when saving bitcode
* Snapshot (and jemalloc integration)
* Exact GC (interpret stack)
* Integrate log and trace
Low:
* Inflate cells when refs > 1
* Use custom mpz allocator (portable image)
* Use readline (or editline)
* Adjustable owners array size
* Include satoms in graph output
* Add timing and logging to garbage collection
