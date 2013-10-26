#if !defined(CONFIG_H)
#define CONFIG_H

#define INLINE_REFS true // TODO: Inflate cells when refs > 1
#define ARKHAM_USE_NURSERY true
#define ARKHAM_THREADED_INTERPRETER true

#ifndef ARKHAM_PRODUCTION
#define ARKHAM_PRODUCTION false
#endif
#ifndef ARKHAM_LLVM
#define ARKHAM_LLVM true
#endif
#ifndef ARKHAM_LOG_FILE
#define ARKHAM_LOG_FILE "/var/tmp/arkham.log"
#endif
#ifndef ARKHAM_TRACE_FILE
#define ARKHAM_TRACE_FILE "/var/tmp/arkham.trace"
#endif

#define ALLOC_DEBUG (!ARKHAM_PRODUCTION)
#define ARKHAM_TRACE (!ARKHAM_PRODUCTION)
#define ARKHAM_ASSERT (!ARKHAM_PRODUCTION)
#define ARKHAM_STATS (!ARKHAM_PRODUCTION)
#define ARKHAM_OP_TRACE false

#define ALLOC_DEBUG_PRINT ALLOC_DEBUG
#define SHARED_CELL_LIST_SIZE 0
#define SHARED_CELL_LIST SHARED_CELL_LIST_SIZE > 0
#define CELL_FREE_LIST_SIZE (ARKHAM_USE_NURSERY && ALLOC_DEBUG ? 0 : 16)
#define CELL_FREE_LIST CELL_FREE_LIST_SIZE > 0
#define NO_SATOMS false
#define ALLOC_FREE_MARKER 0xfeef1ef0 /* Fee Fie Fo (Fum) */
#define ARKHAM_DEBUG 4
#define ARKHAM_INFO 3
#define ARKHAM_WARN 2
#define ARKHAM_ERROR 1
#if ARKHAM_PRODUCTION
#define ARKHAM_LOG ARKHAM_INFO
#else
#define ARKHAM_LOG ARKHAM_DEBUG
#endif

#endif /* #if !defined(CONFIG_H) */
