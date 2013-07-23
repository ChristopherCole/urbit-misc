#if !defined(CONFIG_H)
#define CONFIG_H

#define INLINE_REFS true // TODO
#ifndef ARKHAM_PRODUCTION
#define ARKHAM_PRODUCTION false
#endif
#define ALLOC_DEBUG (true && !ARKHAM_PRODUCTION)
#define ALLOC_DEBUG_PRINT (true && ALLOC_DEBUG)
#define SHARED_CELL_LIST_SIZE 0
#define SHARED_CELL_LIST SHARED_CELL_LIST_SIZE > 0
#define CELL_FREE_LIST_SIZE (ALLOC_DEBUG ? 0 : 16)
#define CELL_FREE_LIST CELL_FREE_LIST_SIZE > 0
#define NO_SATOMS false
#define ALLOC_FREE_MARKER 0xfeef1ef0 /* Fee Fie Fo (Fum) */
#define TRACE_FUNCTIONS (false && !ARKHAM_PRODUCTION)
#define ARKHAM_ASSERT (true && !ARKHAM_PRODUCTION)
#define ARKHAM_DEBUG 4
#define ARKHAM_INFO 3
#define ARKHAM_WARN 2
#define ARKHAM_ERROR 1
#if ARKHAM_PRODUCTION
#define ARKHAM_LOG ARKHAM_INFO
#else
#define ARKHAM_LOG ARKHAM_DEBUG
#endif
#define ARKHAM_STATS true
#ifndef ARKHAM_LLVM
#define ARKHAM_LLVM true
#endif
#ifndef FAT_NOUNS
#define FAT_NOUNS false
#endif

#endif /* #if !defined(CONFIG_H) */
