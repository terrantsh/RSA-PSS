//
// Created by Administrator on 2019/3/8.
//

#include "memory.h"
#include <stdlib.h>
#include "types.h"

static wolfSSL_Malloc_cb  malloc_function = NULL;
static wolfSSL_Realloc_cb realloc_function = NULL;

void* wolfSSL_Malloc(size_t size)
{
    void* res = 0;
    if (malloc_function) {
        res = malloc_function(size);
    } else {
        res = malloc(size);
    }
    return res;
}

void* wolfSSL_Realloc(void *ptr, size_t size)
{
    void* res = 0;

    if (realloc_function) {
        res = realloc_function(ptr, size);
    }
    else {
        res = realloc(ptr, size);
    }

    return res;
}
