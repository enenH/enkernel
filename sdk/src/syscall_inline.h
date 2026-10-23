//
// Created by ITEK on 2022/10/11.
//

#ifndef NATIVE_HOOK_SYSCALL_INLINE_H
#define NATIVE_HOOK_SYSCALL_INLINE_H

#include <sys/syscall.h>
#include <cstdio>


#define __asm_syscall(...) do { \
    __asm__ __volatile__ ( "svc 0" \
    : "=r"(x0) : __VA_ARGS__ : "memory", "cc"); \
    return x0; \
    } while (0)

__attribute__((always_inline))
static inline long __syscall0(long n) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0");
    __asm_syscall("r"(x8));
}

__attribute__((always_inline))
static inline long __syscall1(long n, long a) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    __asm_syscall("r"(x8), "0"(x0));
}

__attribute__((always_inline))
static inline long __syscall2(long n, long a, long b) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    __asm_syscall("r"(x8), "0"(x0), "r"(x1));
}

__attribute__((always_inline))
static inline long __syscall3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm_syscall("r"(x8), "0"(x0), "r"(x1), "r"(x2));
}

__attribute__((always_inline))
static inline long __syscall4(long n, long a, long b, long c, long d) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm_syscall("r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3));
}

__attribute__((always_inline))
static inline long __syscall5(long n, long a, long b, long c, long d, long e) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    __asm_syscall("r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4));
}

__attribute__((always_inline))
static inline long __syscall6(long n, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm_syscall("r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5));
}

#endif //NATIVE_HOOK_SYSCALL_INLINE_H
