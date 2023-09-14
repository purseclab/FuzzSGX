#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <syslog.h>
#include <stdlib.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#include <sys/stat.h>
#include "pthread.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/shm.h>

int libsfuzz_ocall_pthread_attr_init(pthread_attr_t *attr)
{
        printf("libsfuzz_ocall_pthread_attr_init \n");
        return pthread_attr_init(attr);

}
int libsfuzz_ocall_pthread_attr_destroy(pthread_attr_t *attr) {
        return pthread_attr_destroy(attr);
}
int libsfuzz_ocall_isatty(int fd) {
        printf("libsfuzz_ocall_isatty \n");
        return isatty(fd);
}
int libsfuzz_ocall_pipe(int pipefd[2]) {
        return pipe(pipefd);
}

int libsfuzz_ocall_usleep(unsigned long long usec) {
        return usleep(usec);
}

int libsfuzz_ocall_sleep(unsigned int seconds){
        return sleep(seconds);
}

int libsfuzz_ocall_execv(const char *pathname, int argv_num, char * argv1, char * argv2, char * argv3) {
        char * argv[3];
        argv[0] = argv1;
        argv[1] = argv2;
        argv[2] = argv3;
        return execv(pathname,argv);
}
int libsfuzz_ocall_pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
     return pthread_attr_setstacksize(attr,stacksize);
}
int libsfuzz_ocall_pthread_attr_getstacksize(pthread_attr_t *attr, size_t *stacksize) {
     return pthread_attr_getstacksize(attr,stacksize);
}

unsigned long long libsfuzz_ocall_getuid(void) {
        return getuid();
}
long libsfuzz_ocall_sysconf(int name) {
        return sysconf(name);
}

int libsfuzz_ocall_shm_open(const char *name, int oflag, unsigned long long  mode) {
        return shm_open(name,oflag,mode);
}

int libsfuzz_ocall_shm_unlink(const char *name) {
        return shm_unlink(name);
}

void libsfuzz_ocall_syslog_chk(int priority, int flag, const char * format) {
	/* TODO: This needs to be fixed */
        syslog(priority,format);
}

int libsfuzz_ocall_open(const char *pathname, int flags) {
        return open(pathname, flags);
}

int libsfuzz_ocall_close(int fd) {
        return close(fd);
}
int libsfuzz_ocall_getrusage(int who, struct rusage *usage) {
        return getrusage(who,usage);
}

int libsfuzz_ocall_sched_yield(void) {
        return sched_yield();
}

void * libsfuzz_ocall_dlsym(unsigned long long handle, const char * name) {
        return dlsym((void *)handle, name);
}

int libsfuzz_ocall_snprintf_chk(char * str, size_t maxlen, int flag, size_t strlen, const char * format) {
        //return sprintf(str,maxlen,flag,strlen,format);
        //snprintf(str,maxlen,flag,strlen,format);
        printf("ocall_sprintf_chk");
        return 0;
}

int ocall_sprintf_chk(char * str, size_t maxlen, int flag, size_t strlen, const char * format) {
        //return sprintf(str,maxlen,flag,strlen,format);
        //snprintf(str,maxlen,flag,strlen,format);
        printf("ocall_sprintf_chk");
        return 0;
}
int libsfuzz_ocall_pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
        return pthread_getattr_np(thread, attr);
}
void * libsfuzz_ocall_pthread_getspecific(pthread_key_t key) {
        return pthread_getspecific(key);
}
int libsfuzz_ocall_pthread_setspecific(pthread_key_t key, const void *value) {
        return pthread_setspecific(key,value);
}
int libsfuzz_ocall_pthread_key_create(pthread_key_t *key, int nodest) {
        if (nodest) perror("Destructor supplied, wasn't expecting");
        return pthread_key_create(key, NULL);
}
size_t libsfuzz_libsfuzz_ocall_readlink(const char *pathname, char *buf, size_t bufsiz) {
        return readlink(pathname,buf, bufsiz);
}

pthread_t libsfuzz_ocall_pthread_self() {
        return pthread_self();
}

int libsfuzz_ocall_getrlimit(int resource, struct rlimit *rlim) {
        return getrlimit(resource, rlim);
}
int libsfuzz_ocall_setrlimit(int resource, const struct rlimit *rlim) {
        return setrlimit(resource, rlim);
}

int libsfuzz_ocall_waitpid(int pid, int *stat_loc, int options) {
        return waitpid(pid,stat_loc,options);
}
size_t libsfuzz_ocall_write(int fd, const void *buf, size_t count) {
        return write(fd,buf,count);
}
size_t libsfuzz_ocall_read(int fd,  void *buf, size_t count) {
        return read(fd,buf,count);
}
int libsfuzz_ocall_fxstat (int vers, int fd, struct stat *buf) {
        return __fxstat(vers,fd,buf);
}

int libsfuzz_ocall_sigaltstack(unsigned long long ss, unsigned long long  old_ss) {
        const stack_t * ssc = (const stack_t *) ss;
        stack_t * oldsc = (stack_t *) old_ss;
        return sigaltstack(ssc,oldsc);
}

void * libsfuzz_ocall_calloc(size_t nitems, size_t size) {
	return calloc(nitems,size);
}

unsigned long long libsfuzz_ocall_shmat(int shmid, unsigned long long shmaddr, int shmflg) {
	return (unsigned long long) shmat(shmid, (const void *)shmaddr, shmflg);
}

#if 01
char * libsfuzz_ocall_getenv(const char *name) {
	//volatile char * ret_val;
	return getenv(name);
        //ret_val = getenv(name);
	//return ret_val;
}
#endif 
/* OCall functions */
void ocall_print_string(const char *str) __attribute__((weak));
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void libsfuzz_ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void libsfuzz_ocall_exit(int status) {
	_exit(status);
}

void libsfuzz_ocall_abort() {
	abort();
}
