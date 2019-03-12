//
// Created by Administrator on 2019/3/8.
//

#ifndef WOLFSSL_RSAPSS_MEMORY_H
#define WOLFSSL_RSAPSS_MEMORY_H

#include "types.h"
#include <memory.h>

void* wolfSSL_Malloc(size_t size);
void* wolfSSL_Realloc(void *ptr, size_t size);
typedef void *(*wolfSSL_Malloc_cb)(size_t size);
typedef void *(*wolfSSL_Realloc_cb)(void *ptr, size_t size);

#endif //WOLFSSL_RSAPSS_MEMORY_H
