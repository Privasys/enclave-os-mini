/*
 * Copyright (c) Privasys. All rights reserved.
 * Licensed under the GNU Affero General Public License v3.0.
 *
 * getrandom_shim.c — Satisfy the getrandom crate's Linux backend inside SGX.
 *
 * The `getrandom` crate selects its Linux backend (via target_os = "linux")
 * for the Teaclave SGX target.  That backend calls libc::syscall(SYS_getrandom)
 * and has a /dev/urandom fallback path.  Neither works inside an SGX enclave.
 *
 * This shim provides the missing POSIX symbols:
 *   - syscall(): when called with SYS_getrandom (318), delegates to the SGX
 *     SDK's sgx_read_rand() — the enclave's only trustable entropy source
 *     (internally uses RDRAND with proper retry logic).
 *   - open, read, close, poll, pthread_mutex_{lock,unlock}, etc.: dead-code stubs
 *     that the linker requires but are never reached at runtime, because
 *     syscall(SYS_getrandom) always succeeds.
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <sgx_trts.h>    /* sgx_read_rand() — trusted RDRAND from the SGX SDK */

/* x86-64 syscall numbers */
#define SYS_getrandom 318

/* errno values */
#define ENOSYS 38
#define EINVAL 22

/* Thread-local errno (getrandom reads this via libc::*__errno_location) */
static __thread int shim_errno;

int *__errno_location(void) {
    return &shim_errno;
}

/*
 * Minimal syscall() — only SYS_getrandom is implemented.
 * Signature: long syscall(long number, ...)
 *
 * For SYS_getrandom the kernel prototype is:
 *   ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
 *
 * Delegates to sgx_read_rand(), the SGX SDK's audited entropy function
 * that wraps RDRAND with proper retry logic inside the trusted runtime.
 */
long syscall(long number, ...) {
    if (number == SYS_getrandom) {
        va_list ap;
        va_start(ap, number);
        void  *buf  = va_arg(ap, void *);
        size_t len  = va_arg(ap, size_t);
        /* unsigned int flags = */ va_arg(ap, unsigned int);
        va_end(ap);

        if (!buf || len == 0) {
            shim_errno = EINVAL;
            return -1;
        }

        if (sgx_read_rand((unsigned char *)buf, len) != 0 /*SGX_SUCCESS*/) {
            shim_errno = ENOSYS;
            return -1;
        }

        return (long)len;
    }

    /* All other syscalls: not supported inside SGX */
    shim_errno = ENOSYS;
    return -1;
}

/* ---- Dead-code stubs required by the linker but never called ---- */

int open(const char *path, int flags, ...) {
    (void)path; (void)flags;
    shim_errno = ENOSYS;
    return -1;
}

long read(int fd, void *buf, size_t count) {
    (void)fd; (void)buf; (void)count;
    shim_errno = ENOSYS;
    return -1;
}

int close(int fd) {
    (void)fd;
    return 0;
}

int poll(void *fds, unsigned long nfds, int timeout) {
    (void)fds; (void)nfds; (void)timeout;
    shim_errno = ENOSYS;
    return -1;
}

int pthread_mutex_lock(void *mutex) {
    (void)mutex;
    return 0;
}

int pthread_mutex_unlock(void *mutex) {
    (void)mutex;
    return 0;
}

int __xpg_strerror_r(int errnum, char *buf, size_t buflen) {
    (void)errnum;
    if (buf && buflen > 0) {
        buf[0] = '\0';
    }
    return 0;
}
