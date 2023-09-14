/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <string.h>
#include <stdio.h>
#include "pthread.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include "sgx_trts.h"
#include "sgx_edger8r.h"
#include <sys/mman.h>
#include <link.h>
#include <sys/types.h>
#include <unistd.h>
#include <unwind.h>
#include <sys/shm.h>


/* Defines for forward declarations */
unsigned long long srusage = sizeof(struct rusage);
unsigned long long sstat   = sizeof(struct stat);


/* Defines for proxy */
typedef struct ms_libsfuzz_ocall_print_string_t {
        const char* ms_str;
} ms_libsfuzz_ocall_print_string_t;
typedef struct ms_libsfuzz_ocall_getenv_t {
        char* ms_retval;
        const char* ms_name;
} ms_libsfuzz_ocall_getenv_t;
typedef struct ms_libsfuzz_ocall_write_t {
        size_t ms_retval;
        int ms_fd;
        const void* ms_buf;
        size_t ms_count;
} ms_libsfuzz_ocall_write_t;


/* Edger generated code */
#define CHECK_ENCLAVE_POINTER(ptr, siz) do {    \
        if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))     \
                return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (     \
        ((a) += (b)) < (b)      \
)

static inline sgx_status_t SGX_CDECL libsfuzz_ocall_getenv(char** retval, const char* name)
{
	        sgx_status_t status = SGX_SUCCESS;
        size_t _len_name = name ? strlen(name) + 1 : 0;

        ms_libsfuzz_ocall_getenv_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_getenv_t);
        void *__tmp = NULL;


        CHECK_ENCLAVE_POINTER(name, _len_name);

        if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
                return SGX_ERROR_INVALID_PARAMETER;

        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_getenv_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_getenv_t));
        ocalloc_size -= sizeof(ms_libsfuzz_ocall_getenv_t);

        if (name != NULL) {
                ms->ms_name = (const char*)__tmp;
                if (_len_name % sizeof(*name) != 0) {
                        sgx_ocfree();
                        return SGX_ERROR_INVALID_PARAMETER;
                }
                if (memcpy_s(__tmp, ocalloc_size, name, _len_name)) {
                        sgx_ocfree();
                        return SGX_ERROR_UNEXPECTED;
                }
		                __tmp = (void *)((size_t)__tmp + _len_name);
                ocalloc_size -= _len_name;
        } else {
                ms->ms_name = NULL;
        }

        status = sgx_ocall(5, ms);

        if (status == SGX_SUCCESS) {
                if (retval) *retval = ms->ms_retval;
        }
        sgx_ocfree();
        return status;
}
static inline inline sgx_status_t SGX_CDECL libsfuzz_ocall_print_string(const char* str)
{
#ifdef DEBUG
        sgx_status_t status = SGX_SUCCESS;
        size_t _len_str = str ? strlen(str) + 1 : 0;

        ms_libsfuzz_ocall_print_string_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_print_string_t);
        void *__tmp = NULL;


        CHECK_ENCLAVE_POINTER(str, _len_str);

        if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
                return SGX_ERROR_INVALID_PARAMETER;

        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_print_string_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_print_string_t));
        ocalloc_size -= sizeof(ms_libsfuzz_ocall_print_string_t);

        if (str != NULL) {
                ms->ms_str = (const char*)__tmp;
                if (_len_str % sizeof(*str) != 0) {
                        sgx_ocfree();
                        return SGX_ERROR_INVALID_PARAMETER;
                }
                if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
                        sgx_ocfree();
                        return SGX_ERROR_UNEXPECTED;
                }
                __tmp = (void *)((size_t)__tmp + _len_str);
                ocalloc_size -= _len_str;
        } else {
                ms->ms_str = NULL;
        }

        status = sgx_ocall(1, ms);

        if (status == SGX_SUCCESS) {
        }
        sgx_ocfree();
        return status;
#else 
	return SGX_SUCCESS;
#endif
}


ssize_t readlink (const char *__restrict __path,
		char *__restrict __buf, size_t __len) __THROW __nonnull ((1, 2)) __wur;
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
	libsfuzz_ocall_print_string("ARK:readlink \n");
	size_t ret_val;
	sgx_status_t stat;
	stat = libsfuzz_libsfuzz_ocall_readlink(&ret_val, pathname, buf, bufsiz);
	if (stat != SGX_SUCCESS) {
		char tbuf[100];
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
char * cache = 0xdeadbeef;
char *getenv(const char *name) __attribute__((no_sanitize_address));
char *getenv(const char *name) {
	char * ret_val;
	char tbuf[100];
	sgx_status_t stat;
	if (get_thread_data() == NULL) {
		return NULL;
	}
	if (cache != 0xdeadbeef && strcmp(name, "__AFL_SHM_ID") == 0) {
		return cache;
	}
	stat = libsfuzz_ocall_getenv(&ret_val, name);
	libsfuzz_ocall_print_string("ARK:getenv");
        libsfuzz_ocall_print_string(name);
        libsfuzz_ocall_print_string("\n");
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	if (strcmp(name, "__AFL_SHM_ID") == 0) {
		cache = ret_val;
	}
	return ret_val;
}

void *calloc(size_t nitems, size_t size) __attribute__((no_sanitize_address));
void *calloc(size_t nitems, size_t size) {
	libsfuzz_ocall_print_string("ARK:calloc\n");
	void * ret_val;
	sgx_status_t stat;
#if 0
	stat = libsfuzz_ocall_calloc(&ret_val,nitems,size);
	if (stat != SGX_SUCCESS) {
		libsfuzz_ocall_print_string("calloc failed \n");
	}
#endif 
	void * p= malloc(nitems * size);
	memset(p,0,nitems * size);
	return p;
}
pthread_t pthread_self(void) __attribute__((weak));
pthread_t pthread_self(void) {
	libsfuzz_ocall_print_string("ARK:pthread_self \n");
	pthread_t ret_val; 
	char tbuf[100];
	sgx_status_t stat;
	stat = libsfuzz_ocall_pthread_self(&ret_val);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int msync( void *addr,size_t  len,int  flags) __attribute__((weak));
int  msync( void *addr,
		size_t  len,
		int     flags ) {
		libsfuzz_ocall_print_string("ARK:msync \n");
	int ret;
	register int arg3 asm ("rdx") = flags;
        register size_t arg2 asm ("rsi") = len;
        register void * arg1 asm ("rdi") = addr;
	asm volatile(
			"syscall"
			: "=a" (ret)
			: "0" (26), "r" (arg1), "r" (arg2), "r" (arg3)
			:"memory", "cc", "r11", "cx");
	return ret;
}

pid_t getpid(void) {
	 pid_t ret;
          asm volatile (
                          "syscall"
                          : "=a" (ret)
                          : "0" (39)
                          : "memory", "cc", "r11", "cx");
          return ret;
}

void *mmap(void *addr, size_t length, int prot, int flags,
		int fd, off_t offset) {
	libsfuzz_ocall_print_string("ARK:mmap \n");
	void *  ret;
	register off_t arg6 asm ("r9") = offset;                    
	register int arg5  asm ("r8") = fd;
	register int arg4 asm ("r10") = flags;                   
	register int arg3 asm ("rdx") = prot;                   
	register size_t arg2 asm ("rsi") = length;                   
	register void * arg1 asm ("rdi") = addr;
	asm volatile (                                                     
			"syscall"                                                           
			: "=a" (ret)                                                  
			: "0" (9), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4),         
			"r" (arg5), "r" (arg6)                                              
			: "memory", "cc", "r11", "cx");                        
	return  ret;
}

int fork() {
	int ret;
	asm volatile (
			"syscall"
			: "=a" (ret)
			: "0" (57) 
			: "memory", "cc", "r11", "cx");
	return ret;
}

int waitpid(int pid, int *stat_loc, int options) {
	libsfuzz_ocall_print_string("ARK:waitpid \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	libsfuzz_ocall_waitpid(&ret_val,pid,stat_loc,options);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
static inline sgx_status_t SGX_CDECL libsfuzz_ocall_write(size_t* retval, int fd, const void* buf, size_t count)
{
        sgx_status_t status = SGX_SUCCESS;
        size_t _len_buf = count;

        ms_libsfuzz_ocall_write_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_write_t);
        void *__tmp = NULL;

        ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_write_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_write_t));

        ms->ms_fd = fd;
        if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
                ms->ms_buf = (void*)__tmp;
                memcpy(__tmp, buf, _len_buf);
                __tmp = (void *)((size_t)__tmp + _len_buf);
        } else if (buf == NULL) {
                ms->ms_buf = NULL;
        } else {
                sgx_ocfree();
                return SGX_ERROR_INVALID_PARAMETER;
        }

        ms->ms_count = count;
        status = sgx_ocall(37, ms);

        if (status == SGX_SUCCESS) {
                if (retval) *retval = ms->ms_retval;
        }
        sgx_ocfree();
        return status;
}
ssize_t write (int __fd, const void *__buf, size_t __n) __wur;
ssize_t write (int __fd, const void *__buf, size_t __n) {
	libsfuzz_ocall_print_string("ARK:write \n");
	char tbuf[100];
	sgx_status_t stat;
	ssize_t ret_val;
	libsfuzz_ocall_write(&ret_val, __fd, __buf, __n);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
ssize_t read (int __fd, void *__buf, size_t __nbytes) __wur;
ssize_t read (int __fd, void *__buf, size_t __nbytes) {
	libsfuzz_ocall_print_string("ARK:read \n");
	char tbuf[100];
	sgx_status_t stat;
	ssize_t ret_val;
	libsfuzz_ocall_read(&ret_val, __fd, __buf, __nbytes);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

void *shmat(int shmid, const void *shmaddr, int shmflg) {
	libsfuzz_ocall_print_string("ARK:shmat \n");
#if 1
	void *   ret;
	register const void * arg2 asm ("rsi") = shmaddr;
	register int arg1 asm ("rdi") = shmid;
	register int arg3 asm ("rdx") = shmflg;
	asm volatile (
			"syscall"
			: "=a" (ret)
			: "0" (30), "r" (arg1), "r" (arg2)
			: "memory", "cc", "r11", "cx");
	return  ret;
#endif 
	libsfuzz_ocall_print_string("ARK:read \n");
        char tbuf[100];
        sgx_status_t stat;
        void* ret_val;
        libsfuzz_ocall_shmat(&ret_val, shmid, shmaddr, shmflg);
        if (stat != SGX_SUCCESS) {
                snprintf(tbuf,100, "%d", ret_val);
                libsfuzz_ocall_print_string(tbuf);
        }
        return ret_val;
}
int munmap(void *addr, size_t length) __attribute__((weak));
int munmap(void *addr, size_t length) {
	libsfuzz_ocall_print_string("ARK:munmap \n");
	int   ret;
	register size_t arg2 asm ("rsi") = length;
	register void * arg1 asm ("rdi") = addr;
	asm volatile (
			"syscall"
			: "=a" (ret)
			: "0" (11), "r" (arg1), "r" (arg2)
			: "memory", "cc", "r11", "cx");
	return  ret;

}

int madvise(void *addr, size_t length, int advice) {
	libsfuzz_ocall_print_string("ARK:madvise \n");
	int   ret;
	register size_t arg2 asm ("rsi") = length;
	register void * arg1 asm ("rdi") = addr;
	register int arg3 asm ("rdx") = advice;
	asm volatile (
			"syscall"
			: "=a" (ret)
			: "0" (28), "r" (arg1), "r" (arg2)
			: "memory", "cc", "r11", "cx");
	return  ret;
}
int
__fxstat (int vers, int fd, struct stat *buf) {
	libsfuzz_ocall_print_string("ARK:__fxstat \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	libsfuzz_ocall_fxstat(&ret_val,vers,fd,buf);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int sigaltstack(const stack_t *ss, stack_t *old_ss) {
	libsfuzz_ocall_print_string("ARK:sigaltstack \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_sigaltstack(&ret_val,(unsigned long long)ss, (unsigned long long)old_ss);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf,100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int getrlimit(int resource, struct rlimit *rlim) { 
	libsfuzz_ocall_print_string("ARK:getrlimit \n");
	char tbuf[100];
	int ret_val;
	sgx_status_t stat;
	stat =  libsfuzz_ocall_getrlimit(&ret_val, resource, rlim);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
typedef struct ms_libsfuzz_ocall_setrlimit_t {
        int ms_retval;
        int ms_resource;
        const struct rlimit* ms_rlim;
} ms_libsfuzz_ocall_setrlimit_t;

static inline sgx_status_t SGX_CDECL libsfuzz_ocall_setrlimit(int* retval, int resource, const struct rlimit* rlim)
{
	        sgx_status_t status = SGX_SUCCESS;
        size_t _len_rlim = 16;

        ms_libsfuzz_ocall_setrlimit_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_setrlimit_t);
        void *__tmp = NULL;

        ocalloc_size += (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) ? _len_rlim : 0;

        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_setrlimit_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_setrlimit_t));

        ms->ms_resource = resource;
        if (rlim != NULL && sgx_is_within_enclave(rlim, _len_rlim)) {
                ms->ms_rlim = (struct rlimit*)__tmp;
                memcpy(__tmp, rlim, _len_rlim);
                __tmp = (void *)((size_t)__tmp + _len_rlim);
        } else if (rlim == NULL) {
                ms->ms_rlim = NULL;
        } else {
                sgx_ocfree();
                return SGX_ERROR_INVALID_PARAMETER;
        }

        status = sgx_ocall(34, ms);

        if (status == SGX_SUCCESS) {
                if (retval) *retval = ms->ms_retval;
        }
        sgx_ocfree();
        return status;
}
int setrlimit(int resource, const struct rlimit *rlim) __attribute__((no_sanitize_address));
int setrlimit(int resource, const struct rlimit *rlim) {
	libsfuzz_ocall_print_string("ARK:setrlimit \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_setrlimit(&ret_val, resource, rlim);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int pthread_attr_init(pthread_attr_t *attr) {
	libsfuzz_ocall_print_string("ARK:pthread_attr_init \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_attr_init(&ret_val, attr);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pthread_attr_destroy(pthread_attr_t *attr) {
	libsfuzz_ocall_print_string("ARK:pthread_attr_destroy \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_attr_destroy(&ret_val, attr);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int __sprintf_chk (char *__restrict __s, int __flag, size_t __slen,
                          const char *__restrict __format, ...) {
	libsfuzz_ocall_print_string("ARK:UNIMPLEMENTED __sprintf_chk \n");
	return 0;
}

int __snprintf_chk (char *__restrict __s, size_t __n, int __flag,
                           size_t __slen, const char *__restrict __format,
                           ...) {
	libsfuzz_ocall_print_string("ARK:__snprintf_chk \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_snprintf_chk(&ret_val, __s, __n, __flag, __slen, __format);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
#if 1
typedef struct ms_libsfuzz_ocall_dlsym_t {
        void* ms_retval;
        unsigned long long ms_handle;
        const char* ms_symbol;
} ms_libsfuzz_ocall_dlsym_t;

static inline inline sgx_status_t SGX_CDECL libsfuzz_ocall_dlsym(void** retval, unsigned long long handle, const char* symbol)
{
	sgx_status_t status = SGX_SUCCESS;
        size_t _len_symbol = symbol ? strlen(symbol) + 1 : 0;

        ms_libsfuzz_ocall_dlsym_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_dlsym_t);
        void *__tmp = NULL;

        ocalloc_size += (symbol != NULL && sgx_is_within_enclave(symbol, _len_symbol)) ? _len_symbol : 0;

        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_dlsym_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_dlsym_t));

        ms->ms_handle = handle;
        if (symbol != NULL && sgx_is_within_enclave(symbol, _len_symbol)) {
                ms->ms_symbol = (char*)__tmp;
                memcpy(__tmp, symbol, _len_symbol);
                __tmp = (void *)((size_t)__tmp + _len_symbol);
        } else if (symbol == NULL) {
                ms->ms_symbol = NULL;
        } else {
                sgx_ocfree();
                return SGX_ERROR_INVALID_PARAMETER;
        }

        status = sgx_ocall(35, ms);

        if (status == SGX_SUCCESS) {
                if (retval) *retval = ms->ms_retval;
        }
        sgx_ocfree();
        return status;
}
void *dlsym(void *handle, const char *symbol) __attribute__((no_sanitize_address)) __attribute__((weak));;
void *dlsym(void *handle, const char *symbol) { 
	char tbuf[100];
	sgx_status_t stat;
	void * ret_val;
	libsfuzz_ocall_print_string("ARK:dlsym:");
	libsfuzz_ocall_print_string(symbol);
	libsfuzz_ocall_print_string("\n");
	stat = libsfuzz_ocall_dlsym(&ret_val, (unsigned long long) handle, symbol);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
void *dlvsym(void *handle, char *symbol, char *version) {
	//char tbuf[400];
	//snprintf(tbuf, 400, "ARK:dlvsym %s", symbol);
	//libsfuzz_ocall_print_string("ARK:MYOCALL \n");
	libsfuzz_ocall_print_string("ARK:dlvsym\n");
	libsfuzz_ocall_print_string("dlvsym");
	libsfuzz_ocall_print_string(symbol);
	return NULL;
}
#endif
int open (const char *__file, int __oflag, ...) __nonnull ((1));
int open(const char *pathname, int flags, ...) {
	libsfuzz_ocall_print_string("ARK:open \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_open(&ret_val, pathname, flags);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
	libsfuzz_ocall_print_string("ARK:pthread_getattr_np \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat= libsfuzz_ocall_pthread_getattr_np(&ret_val,thread, attr);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
void * scache[100]; 
void *pthread_getspecific(pthread_key_t key) {
	if (scache[key] != 0)
		return scache[key];
	libsfuzz_ocall_print_string("ARK:pthread_getspecific");

	char tbuf[100];
#ifdef DEBUG
	snprintf(tbuf, 100, "%d \n", key);
	libsfuzz_ocall_print_string(tbuf);
#endif

	sgx_status_t stat;
	void * ret_val;
	stat = libsfuzz_ocall_pthread_getspecific(&ret_val, key);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	if (key < 100)
		scache[key] = ret_val;
	return ret_val;
}
int pthread_setspecific(pthread_key_t key, const void *value) {
	libsfuzz_ocall_print_string("ARK:pthread_setspecific \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_setspecific(&ret_val,key,value);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
typedef struct ms_libsfuzz_ocall_close_t {
        int ms_retval;
        int ms_fd;
} ms_libsfuzz_ocall_close_t;
static inline sgx_status_t SGX_CDECL libsfuzz_ocall_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

        ms_libsfuzz_ocall_close_t* ms = NULL;
        size_t ocalloc_size = sizeof(ms_libsfuzz_ocall_close_t);
        void *__tmp = NULL;


        __tmp = sgx_ocalloc(ocalloc_size);
        if (__tmp == NULL) {
                sgx_ocfree();
                return SGX_ERROR_UNEXPECTED;
        }
        ms = (ms_libsfuzz_ocall_close_t*)__tmp;
        __tmp = (void *)((size_t)__tmp + sizeof(ms_libsfuzz_ocall_close_t));

        ms->ms_fd = fd;
        status = sgx_ocall(7, ms);

        if (status == SGX_SUCCESS) {
                if (retval) *retval = ms->ms_retval;
        }
        sgx_ocfree();
        return status;
}
int close(int fd) __attribute__((weak));
int close(int fd) {
	libsfuzz_ocall_print_string("ARK:close \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_close(&ret_val, fd);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pthread_key_create(pthread_key_t *key, void (*destructor)(void*)) {
	libsfuzz_ocall_print_string("ARK:pthread_key_create \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_key_create(&ret_val, key, NULL);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int getrusage(int who, struct rusage *usage) {
	libsfuzz_ocall_print_string("ARK:getrusage \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_getrusage(&ret_val, who, usage);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int sched_yield(void) {
	libsfuzz_ocall_print_string("ARK:sched_yield \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_sched_yield(&ret_val);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int fcntl(int fd, int cmd, ... /* arg */ ) __attribute__((weak));
int fcntl(int fd, int cmd, ... /* arg */ ) {
	libsfuzz_ocall_print_string("ARK:UNIMPLEMENTED FCNTL \n");
}
void __syslog_chk(int priority, int flag, const char * format, ... ) {
	libsfuzz_ocall_print_string("ARK:UNIMPLEMENTED SYSLG \n");
}


int isatty(int fd) {
	if (fd == 0 || fd ==1 || fd ==2)
                return 1;
	libsfuzz_ocall_print_string("ARK:isatty \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_isatty(&ret_val, fd); 
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pipe(int pipefd[2]) {
	libsfuzz_ocall_print_string("ARK:pipe \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pipe(&ret_val, pipefd);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int usleep(useconds_t usec) {
	libsfuzz_ocall_print_string("ARK:usleep \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_usleep(&ret_val, usec);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
unsigned int sleep(unsigned int seconds) __attribute__((weak));
unsigned int sleep(unsigned int seconds) {
	libsfuzz_ocall_print_string("ARK:sleep \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_sleep(&ret_val, seconds);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}	
int execv(const char *path, char *const argv[]) {
	libsfuzz_ocall_print_string("ARK:execv \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	char *argv1 = argv[0];
	int i = 1;
	char * argv2 = NULL;
	char * argv3 = NULL;
	if (argv[1] != NULL) {
		argv2 = argv[1];
		i++;
		if (argv[2] != NULL) {
			argv3 = argv[2];
			i++;
		}
	}

	if (i == 3) {
		if (argv[3] != NULL)
			libsfuzz_ocall_print_string("execv ran out of params");
	}

	stat = libsfuzz_ocall_execv(&ret_val, path, 0, argv1, argv2, argv3);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int shm_open(const char *name, int oflag, mode_t mode) {
	libsfuzz_ocall_print_string("ARK:shm_open \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_shm_open(&ret_val, name,oflag,mode);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

int shm_unlink(const char *name) {
	libsfuzz_ocall_print_string("ARK:shm_unlink \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_shm_unlink(&ret_val, name);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
uid_t getuid(void) {
	libsfuzz_ocall_print_string("ARK:getuid \n");
	char tbuf[100];
	sgx_status_t stat;
	long long unsigned int  ret_val;
	stat = libsfuzz_ocall_getuid(&ret_val);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
long sysconf(int name) __attribute__((weak));
long sysconf(int name) {
	libsfuzz_ocall_print_string("ARK:sysconf \n");
	char tbuf[100];
	sgx_status_t stat;
	long ret_val;
	stat = libsfuzz_ocall_sysconf(&ret_val, name);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
	libsfuzz_ocall_print_string("ARK:pthread_attr_setstacksize \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_attr_setstacksize(&ret_val, attr, stacksize);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
	libsfuzz_ocall_print_string("ARK:pthread_attr_getstacksize \n");
	char tbuf[100];
	sgx_status_t stat;
	int ret_val;
	stat = libsfuzz_ocall_pthread_attr_getstacksize(&ret_val, (pthread_attr_t *) attr,stacksize);
	if (stat != SGX_SUCCESS) {
		snprintf(tbuf, 100, "%d", ret_val);
		libsfuzz_ocall_print_string(tbuf);
	}
	return ret_val;
}

void _exit(int status) {
	libsfuzz_ocall_print_string("ARK:_exit \n");
        char tbuf[100];
        sgx_status_t stat;
        stat = libsfuzz_ocall_exit(status);
        if (stat != SGX_SUCCESS) {
                snprintf(tbuf, 100, "%d", stat);
                libsfuzz_ocall_print_string(tbuf);
        }
}

void __wrap_abort(void)
{
    libsfuzz_ocall_print_string("=== Abort called !=== \n");
}

void libsfuzz_abort() {
	//libsfuzz_ocall_print_string("ARK:Abort \n");
	char tbuf[100];
        sgx_status_t stat;
	stat = libsfuzz_ocall_abort();
	if (stat != SGX_SUCCESS) {
                snprintf(tbuf, 100, "%d", stat);
                libsfuzz_ocall_print_string(tbuf);
        }
}
#define TEST_BUILD
#ifdef TEST_BUILD
int testGetEnv()
{
  char* pPath;
  pPath = getenv ("PATH");
  //if (pPath!=NULL)
  //  printf ("The current path is: %s",pPath);
  return 0;
}

int testUsleep() {
	libsfuzz_ocall_print_string("TestUsleep:Next print should be 1 seconds apart \n");
	
	for (int i = 0; i < 10; i++) 
		usleep(100000);
	libsfuzz_ocall_print_string("Was it 1 second apart? \n");
}

void testSleep() {
	libsfuzz_ocall_print_string("TestSleep:Next print should be 2 seconds apart \n");
	for (int i =0; i< 2; i++)
		sleep(1);
	libsfuzz_ocall_print_string("Was it 2 seconds apart? \n");
}

void testFork() {
	libsfuzz_ocall_print_string("TestFork:");
	// child process because return value zero
  	if (fork() == 0)
        	libsfuzz_ocall_print_string("Hello from Child!\n");
	// parent process because return value non-zero.
   	else
        	libsfuzz_ocall_print_string("Hello from Parent!\n");
}

void testShmat(int shmid) {
	 char * data = (char *) shmat(shmid, NULL, 0);
	 char * temp = "This is from the test side \n";
	 memcpy(data, temp, strlen(temp));
}

void testFuzzSGX (int shmid) {
	testUsleep();
	testSleep();
//	testFork();		
        testShmat(shmid);
}
#endif 


