//
// Created by Administrator on 2019/3/8.
//

#include "memory.h"
#include <stdlib.h>
#include "types.h"

static wolfSSL_Malloc_cb  malloc_function = NULL;
static wolfSSL_Realloc_cb realloc_function = NULL;
static wolfSSL_Free_cb    free_function = NULL;

//void* wolfSSL_Malloc(size_t size)
//{
//    void* res = 0;
//    if (malloc_function) {
//        res = malloc_function(size);
//    } else {
//        res = malloc(size);
//    }
//    return res;
//}

struct wc_Memory {
    byte*  buffer;
    struct wc_Memory* next;
    word32 sz;
};

/* returns amount of memory used on success. On error returns negative value
   wc_Memory** list is the list that new buckets are prepended to
 */
static int create_memory_buckets(byte* buffer, word32 bufSz, word32 buckSz, word32 buckNum, wc_Memory** list) {
    word32 i;
    byte*  pt  = buffer;
    int    ret = 0;
    word32 memSz = (word32)sizeof(wc_Memory);
    word32 padSz = -(int)memSz & (WOLFSSL_STATIC_ALIGN - 1);

    /* if not enough space available for bucket size then do not try */
    if (buckSz + memSz + padSz > bufSz) {
        return ret;
    }

    for (i = 0; i < buckNum; i++) {
        if ((buckSz + memSz + padSz) <= (bufSz - ret)) {
            /* create a new struct and set its values */
            wc_Memory* mem = (struct wc_Memory*)(pt);
            mem->sz = buckSz;
            mem->buffer = (byte*)pt + padSz + memSz;
            mem->next = NULL;

            /* add the newly created struct to front of list */
            if (*list == NULL) {
                *list = mem;
            } else {
                mem->next = *list;
                *list = mem;
            }

            /* advance pointer and keep track of memory used */
            ret += buckSz + padSz + memSz;
            pt  += buckSz + padSz + memSz;
        }
        else {
            break; /* not enough space left for more buckets of this size */
        }
    }

    return ret;
}

int wolfSSL_init_memory_heap(WOLFSSL_HEAP* heap)
{
    word32 wc_MemSz[WOLFMEM_DEF_BUCKETS] = { WOLFMEM_BUCKETS };
    word32 wc_Dist[WOLFMEM_DEF_BUCKETS]  = { WOLFMEM_DIST };

    if (heap == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(heap, 0, sizeof(WOLFSSL_HEAP));

    XMEMCPY(heap->sizeList, wc_MemSz, sizeof(wc_MemSz));
    XMEMCPY(heap->distList, wc_Dist,  sizeof(wc_Dist));

    if (wc_InitMutex(&(heap->memory_mutex)) != 0) {
        return BAD_MUTEX_E;
    }

    return 0;
}

int wc_LoadStaticMemory(WOLFSSL_HEAP_HINT** pHint, unsigned char* buf, unsigned int sz, int flag, int max)
{
    int ret;
    WOLFSSL_HEAP*      heap;
    WOLFSSL_HEAP_HINT* hint;
    word32 idx = 0;

    if (pHint == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((sizeof(WOLFSSL_HEAP) + sizeof(WOLFSSL_HEAP_HINT)) > sz - idx) {
        return BUFFER_E; /* not enough memory for structures */
    }

    /* check if hint has already been assigned */
    if (*pHint == NULL) {
        heap = (WOLFSSL_HEAP*)buf;
        idx += sizeof(WOLFSSL_HEAP);
        hint = (WOLFSSL_HEAP_HINT*)(buf + idx);
        idx += sizeof(WOLFSSL_HEAP_HINT);

        ret = wolfSSL_init_memory_heap(heap);
        if (ret != 0) {
            return ret;
        }

        XMEMSET(hint, 0, sizeof(WOLFSSL_HEAP_HINT));
        hint->memory = heap;
    }
    else {
        hint = (WOLFSSL_HEAP_HINT*)(*pHint);
        heap = hint->memory;
    }

    ret = wolfSSL_load_static_memory(buf + idx, sz - idx, flag, heap);
    if (ret != 1) {
        return -1;
    }

    /* determine what max applies too */
    if ((flag & WOLFMEM_IO_POOL) || (flag & WOLFMEM_IO_POOL_FIXED)) {
        heap->maxIO = max;
    }
    else { /* general memory used in handshakes */
        heap->maxHa = max;
    }
    heap->flag |= flag;
    *pHint = hint;
    (void)max;
    return 0;
}

int wolfSSL_load_static_memory(byte* buffer, word32 sz, int flag,
                               WOLFSSL_HEAP* heap)
{
    word32 ava = sz;
    byte*  pt  = buffer;
    int    ret = 0;
    word32 memSz = (word32)sizeof(wc_Memory);
    word32 padSz = -(int)memSz & (WOLFSSL_STATIC_ALIGN - 1);

    if (buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    /* align pt */
    while ((wolfssl_word)pt % WOLFSSL_STATIC_ALIGN && pt < (buffer + sz)) {
        *pt = 0x00;
        pt++;
        ava--;
    }
    /* devide into chunks of memory and add them to available list */
    while (ava >= (heap->sizeList[0] + padSz + memSz)) {
        int i;
        /* creating only IO buffers from memory passed in, max TLS is 16k */
        if (flag & WOLFMEM_IO_POOL || flag & WOLFMEM_IO_POOL_FIXED) {
            if ((ret = create_memory_buckets(pt, ava, WOLFMEM_IO_SZ, 1, &(heap->io))) < 0) {
                return ret;
            }

            /* check if no more room left for creating IO buffers */
            if (ret == 0) {
                break;
            }

            /* advance pointer in buffer for next buckets and keep track
               of how much memory is left available */
            pt  += ret;
            ava -= ret;
        }
        else {
            /* start at largest and move to smaller buckets */
            for (i = (WOLFMEM_MAX_BUCKETS - 1); i >= 0; i--) {
                if ((heap->sizeList[i] + padSz + memSz) <= ava) {
                    if ((ret = create_memory_buckets(pt, ava, heap->sizeList[i], heap->distList[i], &(heap->ava[i]))) < 0) {
                        return ret;
                    }

                    /* advance pointer in buffer for next buckets and keep track
                       of how much memory is left available */
                    pt  += ret;
                    ava -= ret;
                }
            }
        }
    }
    return 1;
}


/* returns the size of management memory needed for each bucket.
 * This is memory that is used to keep track of and align memory buckets. */
int wolfSSL_MemoryPaddingSz(void)
{
    word32 memSz = (word32)sizeof(wc_Memory);
    word32 padSz = -(int)memSz & (WOLFSSL_STATIC_ALIGN - 1);
    return memSz + padSz;
}


/* Used to calculate memory size for optimum use with buckets.
   returns the suggested size rounded down to the nearest bucket. */
int wolfSSL_StaticBufferSz(byte* buffer, word32 sz, int flag)
{
    word32 bucketSz[WOLFMEM_MAX_BUCKETS] = {WOLFMEM_BUCKETS};
    word32 distList[WOLFMEM_MAX_BUCKETS] = {WOLFMEM_DIST};

    word32 ava = sz;
    byte*  pt  = buffer;
    word32 memSz = (word32)sizeof(wc_Memory);
    word32 padSz = -(int)memSz & (WOLFSSL_STATIC_ALIGN - 1);

    if (buffer == NULL) {
        return BAD_FUNC_ARG;
    }

    /* align pt */
    while ((wolfssl_word)pt % WOLFSSL_STATIC_ALIGN && pt < (buffer + sz)) {
        pt++;
        ava--;
    }

    /* creating only IO buffers from memory passed in, max TLS is 16k */
    if (flag & WOLFMEM_IO_POOL || flag & WOLFMEM_IO_POOL_FIXED) {
        if (ava < (memSz + padSz + WOLFMEM_IO_SZ)) {
            return 0; /* not enough room for even one bucket */
        }

        ava = ava % (memSz + padSz + WOLFMEM_IO_SZ);
    }
    else {
        int i, k;

        if (ava < (bucketSz[0] + padSz + memSz)) {
            return 0; /* not enough room for even one bucket */
        }

        while ((ava >= (bucketSz[0] + padSz + memSz)) && (ava > 0)) {
            /* start at largest and move to smaller buckets */
            for (i = (WOLFMEM_MAX_BUCKETS - 1); i >= 0; i--) {
                for (k = distList[i]; k > 0; k--) {
                    if ((bucketSz[i] + padSz + memSz) <= ava) {
                        ava -= bucketSz[i] + padSz + memSz;
                    }
                }
            }
        }
    }

    return sz - ava; /* round down */
}


int FreeFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io)
{

    /* check if fixed buffer was set */
    if (*io == NULL) {
        return 1;
    }

    if (heap == NULL) {
    }
    else {
        /* put IO buffer back into IO pool */
        (*io)->next = heap->io;
        heap->io    = *io;
        *io         = NULL;
    }

    return 1;
}


int SetFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io)
{
    if (heap == NULL) {
        return MEMORY_E;
    }

    *io = heap->io;

    if (*io != NULL) {
        heap->io = (*io)->next;
        (*io)->next = NULL;
    }
    else { /* failed to grab an IO buffer */
        return 0;
    }

    return 1;
}


int wolfSSL_GetMemStats(WOLFSSL_HEAP* heap, WOLFSSL_MEM_STATS* stats)
{
    word32     i;
    wc_Memory* pt;

    XMEMSET(stats, 0, sizeof(WOLFSSL_MEM_STATS));

    stats->totalAlloc = heap->alloc;
    stats->totalFr    = heap->frAlc;
    stats->curAlloc   = stats->totalAlloc - stats->totalFr;
    stats->maxHa      = heap->maxHa;
    stats->maxIO      = heap->maxIO;
    for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
        stats->blockSz[i] = heap->sizeList[i];
        for (pt = heap->ava[i]; pt != NULL; pt = pt->next) {
            stats->avaBlock[i] += 1;
        }
    }

    for (pt = heap->io; pt != NULL; pt = pt->next) {
        stats->avaIO++;
    }

    stats->flag       = heap->flag; /* flag used */

    return 1;
}


void* wolfSSL_Malloc(size_t size, void* heap, int type)
{
    void* res = 0;
    wc_Memory* pt = NULL;
    int   i;

    /* if no heap hint then use dynamic memory*/
    if (heap == NULL) {
    } else {
        WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;
        WOLFSSL_HEAP*      mem  = hint->memory;

        if (wc_LockMutex(&(mem->memory_mutex)) != 0) {
            return NULL;
        }

        /* case of using fixed IO buffers */
        if (mem->flag & WOLFMEM_IO_POOL_FIXED && (type == DYNAMIC_TYPE_OUT_BUFFER || type == DYNAMIC_TYPE_IN_BUFFER)) {
            if (type == DYNAMIC_TYPE_OUT_BUFFER) {
                pt = hint->outBuf;
            }
            if (type == DYNAMIC_TYPE_IN_BUFFER) {
                pt = hint->inBuf;
            }
        } else {
            /* check if using IO pool flag */
            if (mem->flag & WOLFMEM_IO_POOL &&
                (type == DYNAMIC_TYPE_OUT_BUFFER ||
                 type == DYNAMIC_TYPE_IN_BUFFER)) {
                if (mem->io != NULL) {
                    pt      = mem->io;
                    mem->io = pt->next;
                }
            }

            /* general static memory */
            if (pt == NULL) {
                for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
                    if ((word32)size < mem->sizeList[i]) {
                        if (mem->ava[i] != NULL) {
                            pt = mem->ava[i];
                            mem->ava[i] = pt->next;
                            break;
                        }
                    }
                }
            }
        }

        if (pt != NULL) {
            mem->inUse += pt->sz;
            mem->alloc += 1;
            res = pt->buffer;

            /* keep track of connection statistics if flag is set */
            if (mem->flag & WOLFMEM_TRACK_STATS) {
                WOLFSSL_MEM_CONN_STATS* stats = hint->stats;
                if (stats != NULL) {
                    stats->curMem += pt->sz;
                    if (stats->peakMem < stats->curMem) {
                        stats->peakMem = stats->curMem;
                    }
                    stats->curAlloc++;
                    if (stats->peakAlloc < stats->curAlloc) {
                        stats->peakAlloc = stats->curAlloc;
                    }
                    stats->totalAlloc++;
                }
            }
        } else {
        }
        wc_UnLockMutex(&(mem->memory_mutex));
    }

    (void)i;
    (void)pt;
    (void)type;
    return res;
}

void wolfSSL_Free(void *ptr, void* heap, int type)
{
    int i;
    wc_Memory* pt;

    if (ptr) {
        if (heap == NULL) {
        }
        else {
            WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;
            WOLFSSL_HEAP*      mem  = hint->memory;
            word32 padSz = -(int)sizeof(wc_Memory) & (WOLFSSL_STATIC_ALIGN - 1);

            /* get memory struct and add it to available list */
            pt = (wc_Memory*)((byte*)ptr - sizeof(wc_Memory) - padSz);
            if (wc_LockMutex(&(mem->memory_mutex)) != 0) {
                return;
            }

            /* case of using fixed IO buffers */
            if (mem->flag & WOLFMEM_IO_POOL_FIXED &&
                (type == DYNAMIC_TYPE_OUT_BUFFER ||
                 type == DYNAMIC_TYPE_IN_BUFFER)) {
                /* fixed IO pools are free'd at the end of SSL lifetime
                   using FreeFixedIO(WOLFSSL_HEAP* heap, wc_Memory** io) */
            }
            else if (mem->flag & WOLFMEM_IO_POOL && pt->sz == WOLFMEM_IO_SZ &&
                     (type == DYNAMIC_TYPE_OUT_BUFFER ||
                      type == DYNAMIC_TYPE_IN_BUFFER)) {
                pt->next = mem->io;
                mem->io  = pt;
            }
            else { /* general memory free */
                for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
                    if (pt->sz == mem->sizeList[i]) {
                        pt->next = mem->ava[i];
                        mem->ava[i] = pt;
                        break;
                    }
                }
            }
            mem->inUse -= pt->sz;
            mem->frAlc += 1;

            /* keep track of connection statistics if flag is set */
            if (mem->flag & WOLFMEM_TRACK_STATS) {
                WOLFSSL_MEM_CONN_STATS* stats = hint->stats;
                if (stats != NULL) {
                    /* avoid under flow */
                    if (stats->curMem > pt->sz) {
                        stats->curMem -= pt->sz;
                    }
                    else {
                        stats->curMem = 0;
                    }

                    if (stats->curAlloc > 0) {
                        stats->curAlloc--;
                    }
                    stats->totalFr++;
                }
            }
            wc_UnLockMutex(&(mem->memory_mutex));
        }
    }

    (void)i;
    (void)pt;
    (void)type;
}

void* wolfSSL_Realloc(void *ptr, size_t size, void* heap, int type)
{
    void* res = 0;
    wc_Memory* pt = NULL;
    word32 prvSz;
    int    i;

    if (heap == NULL) {

    } else {
        WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;
        WOLFSSL_HEAP*      mem  = hint->memory;
        word32 padSz = -(int)sizeof(wc_Memory) & (WOLFSSL_STATIC_ALIGN - 1);

        if (wc_LockMutex(&(mem->memory_mutex)) != 0) {
            return NULL;
        }

        /* case of using fixed IO buffers or IO pool */
        if (((mem->flag & WOLFMEM_IO_POOL)||(mem->flag & WOLFMEM_IO_POOL_FIXED)) && (type == DYNAMIC_TYPE_OUT_BUFFER || type == DYNAMIC_TYPE_IN_BUFFER)) {
            /* no realloc, is fixed size */
            pt = (wc_Memory*)((byte*)ptr - padSz - sizeof(wc_Memory));
            if (pt->sz < size) {
                res = NULL; /* return NULL in error case */
            }
            res = pt->buffer;
        }
        else {
            /* general memory */
            for (i = 0; i < WOLFMEM_MAX_BUCKETS; i++) {
                if ((word32)size < mem->sizeList[i]) {
                    if (mem->ava[i] != NULL) {
                        pt = mem->ava[i];
                        mem->ava[i] = pt->next;
                        break;
                    }
                }
            }

            if (pt != NULL && res == NULL) {
                res = pt->buffer;

                /* copy over original information and free ptr */
                prvSz = ((wc_Memory*)((byte*)ptr - padSz -
                                      sizeof(wc_Memory)))->sz;
                prvSz = (prvSz > pt->sz)? pt->sz: prvSz;
                XMEMCPY(pt->buffer, ptr, prvSz);
                mem->inUse += pt->sz;
                mem->alloc += 1;

                /* free memory that was previously being used */
                wc_UnLockMutex(&(mem->memory_mutex));
                wolfSSL_Free(ptr, heap, type);
                if (wc_LockMutex(&(mem->memory_mutex)) != 0) {
                    return NULL;
                }
            }
        }
        wc_UnLockMutex(&(mem->memory_mutex));
    }

    (void)i;
    (void)pt;
    (void)type;

    return res;
}


//void* wolfSSL_Realloc(void *ptr, size_t size)
//{
//    void* res = 0;
//
//    if (realloc_function) {
//        res = realloc_function(ptr, size);
//    }
//    else {
//        res = realloc(ptr, size);
//    }
//
//    return res;
//}
//
//void wolfSSL_Free(void *ptr)
//{
//
//    if (free_function) {
//        free_function(ptr);
//    } else {
//        free(ptr);
//    }
//}
