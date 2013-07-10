#if !defined(CONFIG_H)
#define CONFIG_H

#define INLINE_REFS true // TODO
#ifndef PRODUCTION
#define PRODUCTION false
#endif
#define ALLOC_DEBUG (true && !PRODUCTION)
#define ALLOC_DEBUG_PRINT (false/*QQQ*/ && ALLOC_DEBUG)
#define SHARED_CELL_LIST_SIZE 0
#define SHARED_CELL_LIST SHARED_CELL_LIST_SIZE > 0
#define CELL_FREE_LIST_SIZE (ALLOC_DEBUG ? 0 : 16)
#define CELL_FREE_LIST CELL_FREE_LIST_SIZE > 0
#define NO_SATOMS false
#define ALLOC_FREE_MARKER 0xfeef1ef0 /* Fee Fie Fo (Fum) */
#define TRACE_FUNCTIONS (false && !PRODUCTION)
#define NOCK_ASSERT (true && !PRODUCTION)
#define NOCK_DEBUG 4
#define NOCK_INFO 3
#define NOCK_WARN 2
#define NOCK_ERROR 1
#if PRODUCTION
#define NOCK_LOG NOCK_INFO
#else
#define NOCK_LOG NOCK_DEBUG
#endif
#define NOCK_STATS true
#ifndef NOCK_LLVM
#define NOCK_LLVM false
#endif

#endif /* #if !defined(CONFIG_H) */
