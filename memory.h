//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_MEMORY_H
#define WOLFSSL_RSAPSS_MEMORY_H

#include "types.h"
#include <memory.h>
#include "port.h"
#include "error.h"

#define WOLFSSL_NO_MALLOC
typedef unsigned int        word32;
typedef unsigned char       byte;
typedef int                 wolfSSL_Mutex;

//////typedef void *(*wolfSSL_Malloc_cb)(size_t size);
//typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);
//typedef void (*wolfSSL_Free_cb)(void *ptr);
//////void* wolfSSL_Malloc(size_t size, void* heap, int type);
////
//void wolfSSL_Free(void *ptr);
//////void* wolfSSL_Malloc(size_t size);
//void* wolfSSL_Realloc(void *ptr, size_t size);

typedef void *(*wolfSSL_Malloc_cb)(size_t size, void* heap, int type);
typedef void (*wolfSSL_Free_cb)(void *ptr, void* heap, int type);
typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size, void* heap, int type);
void* wolfSSL_Malloc(size_t size, void* heap, int type);
void  wolfSSL_Free(void *ptr, void* heap, int type);
void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type);

/* flags for loading static memory (one hot bit) */
#define WOLFMEM_GENERAL       0x01
#define WOLFMEM_IO_POOL       0x02
#define WOLFMEM_IO_POOL_FIXED 0x04
#define WOLFMEM_TRACK_STATS   0x08

#define WOLFMEM_MAX_BUCKETS  9
#define WOLFSSL_STATIC_ALIGN 16
#define WOLFMEM_IO_SZ        16992 /* 16 byte aligned */

typedef struct WOLFSSL_MEM_STATS      WOLFSSL_MEM_STATS;
typedef struct WOLFSSL_MEM_CONN_STATS WOLFSSL_MEM_CONN_STATS;

struct WOLFSSL_MEM_CONN_STATS {
    word32 peakMem;   /* peak memory usage    */
    word32 curMem;    /* current memory usage */
    word32 peakAlloc; /* peak memory allocations */
    word32 curAlloc;  /* current memory allocations */
    word32 totalAlloc;/* total memory allocations for lifetime */
    word32 totalFr;   /* total frees for lifetime */
};

struct WOLFSSL_MEM_STATS {
    word32 curAlloc;  /* current memory allocations */
    word32 totalAlloc;/* total memory allocations for lifetime */
    word32 totalFr;   /* total frees for lifetime */
    word32 totalUse;  /* total amount of memory used in blocks */
    word32 avaIO;     /* available IO specific pools */
    word32 maxHa;     /* max number of concurent handshakes allowed */
    word32 maxIO;     /* max number of concurent IO connections allowed */
    word32 blockSz[WOLFMEM_MAX_BUCKETS]; /* block sizes in stacks */
    word32 avaBlock[WOLFMEM_MAX_BUCKETS];/* ava block sizes */
    word32 usedBlock[WOLFMEM_MAX_BUCKETS];
    int    flag; /* flag used */
};

typedef struct wc_Memory wc_Memory; /* internal structure for mem bucket */
typedef struct WOLFSSL_HEAP {
    wc_Memory* ava[WOLFMEM_MAX_BUCKETS];
    wc_Memory* io;                  /* list of buffers to use for IO */
    word32     maxHa;               /* max concurent handshakes */
    word32     curHa;
    word32     maxIO;               /* max concurrent IO connections */
    word32     curIO;
    word32     sizeList[WOLFMEM_MAX_BUCKETS];/* memory sizes in ava list */
    word32     distList[WOLFMEM_MAX_BUCKETS];/* general distribution */
    word32     inUse; /* amount of memory currently in use */
    word32     ioUse;
    word32     alloc; /* total number of allocs */
    word32     frAlc; /* total number of frees  */
    int        flag;
    wolfSSL_Mutex memory_mutex;
} WOLFSSL_HEAP;

/* structure passed into XMALLOC as heap hint
 * having this abstraction allows tracking statistics of individual ssl's
 */
typedef struct WOLFSSL_HEAP_HINT {
    WOLFSSL_HEAP*           memory;
    WOLFSSL_MEM_CONN_STATS* stats;  /* hold individual connection stats */
    wc_Memory*              outBuf; /* set if using fixed io buffers */
    wc_Memory*              inBuf;
    byte                    haFlag; /* flag used for checking handshake count */
} WOLFSSL_HEAP_HINT;

#define WOLFSSL_STATIC_TIMEOUT 1




#define WOLFMEM_DEF_BUCKETS  9     /* number of default memory blocks */
#define WOLFMEM_BUCKETS 64,128,256,512,1024,2432,3456,4544,16128
#define WOLFMEM_DIST    49,10,6,14,5,6,9,1,1



int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT** pHint, unsigned char* buf, unsigned int sz, int flag, int max);
int wolfSSL_init_memory_heap(WOLFSSL_HEAP* heap);
int wolfSSL_load_static_memory(byte* buffer, word32 sz,
                               int flag, WOLFSSL_HEAP* heap);
int SetFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io);
int FreeFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io);
int wolfSSL_StaticBufferSz(byte* buffer, word32 sz, int flag);
int wolfSSL_MemoryPaddingSz(void);
int wolfSSL_GetMemStats(WOLFSSL_HEAP* heap, WOLFSSL_MEM_STATS* stats);


#endif //WOLFSSL_RSAPSS_MEMORY_H
