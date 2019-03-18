cmake_minimum_required(VERSION 3.13)
project(wolfssl_rsapss C)

set(CMAKE_C_STANDARD 99)

add_executable(wolfssl_rsapss main.c types.h rsa.c rsa.h error.h memory.c memory.h random.c random.h sha256.c sha256.h misc.c misc.h hash.c hash.h wolfmath.c wolfmath.h port.c port.h Tfm.c Tfm.h asm.c)