//
// Created by Administrator on 2019/3/14.
//

#ifndef WOLFSSL_RSAPSS_PORT_H
#define WOLFSSL_RSAPSS_PORT_H

#include "types.h"


typedef int wolfSSL_Mutex;
int wc_LockMutex(wolfSSL_Mutex*);
int wc_UnLockMutex(wolfSSL_Mutex*);
int wc_InitMutex(wolfSSL_Mutex* );
int wc_FreeMutex(wolfSSL_Mutex *);

#endif //WOLFSSL_RSAPSS_PORT_H
