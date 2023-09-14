/* App.c
*
* Copyright (C) 2006-2020 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#define __USE_GNU
#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "client-tls.h"
#include "server-tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ucontext.h>

#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/mount.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <linux/version.h>
#include <linux/loop.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define READ_END 0
#define WRITE_END 1

#include "nyx_api.h"
#include "nyx_agent.h"

enum
{
  REG_R8 = 0,
# define REG_R8         REG_R8
  REG_R9,
# define REG_R9         REG_R9
  REG_R10,
# define REG_R10        REG_R10
  REG_R11,
# define REG_R11        REG_R11
  REG_R12,
# define REG_R12        REG_R12
  REG_R13,
# define REG_R13        REG_R13
  REG_R14,
# define REG_R14        REG_R14
  REG_R15,
# define REG_R15        REG_R15
  REG_RDI,
# define REG_RDI        REG_RDI
  REG_RSI,
# define REG_RSI        REG_RSI
  REG_RBP,
# define REG_RBP        REG_RBP
  REG_RBX,
# define REG_RBX        REG_RBX
  REG_RDX,
# define REG_RDX        REG_RDX
  REG_RAX,
# define REG_RAX        REG_RAX
  REG_RCX,
# define REG_RCX        REG_RCX
  REG_RSP,
# define REG_RSP        REG_RSP
  REG_RIP,
# define REG_RIP        REG_RIP
  REG_EFL,
# define REG_EFL        REG_EFL
  REG_CSGSFS,           /* Actually short cs, gs, fs, __pad0.  */
# define REG_CSGSFS     REG_CSGSFS
  REG_ERR,
# define REG_ERR        REG_ERR
  REG_TRAPNO,
# define REG_TRAPNO     REG_TRAPNO
  REG_OLDMASK,
# define REG_OLDMASK    REG_OLDMASK
  REG_CR2
# define REG_CR2        REG_CR2
};

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;
int idx =0;
#define PAGE_SIZE 4096
#define KAFL_TMP_FILE "/tmp/trash"
#define PAYLOAD_MAX_SIZE (1 * 1024 * 1024)

#define CHECK_ERRNO(x, msg)                                                \
	do {                                                               \
		if (!(x)) {                                                \
			fprintf(stderr, "%s: %s\n", msg, strerror(errno)); \
			habort(msg);                                       \
			exit(1);                                           \
		}                                                          \
	} while (0)

static inline void kill_systemd(void)
{
	system("systemctl disable systemd-udevd");
	system("systemctl stop systemd-udevd");
	system("systemctl stop systemd-udevd-kernel.socket");
	system("systemctl stop systemd-udevd-control.socket");

	system("/lib/systemd/systemctl disable systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd-kernel.socket");
	system("/lib/systemd/systemctl stop systemd-udevd-control.socket");
}
void sigabrt_sigaction(int signal, siginfo_t* info, void* arg) {
    ucontext_t* context = (ucontext_t*) arg;

    hprintf("Signal Handler Called \n");
    hprintf("Signal Type: %s\n", strsignal(info->si_signo));


    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ((uint64_t) info->si_signo << 47);
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
    //exit(1);
    _exit(1);
}
void sigill_sigaction(int signal, siginfo_t* si, void* arg) {
//    assert(signal == SIGILL);
    ucontext_t* uc = (ucontext_t*) arg;

    hprintf("SIGILL Handler Called \n");

    const uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    greg_t* const rip_s = &uc->uc_mcontext.gregs[REG_RIP];

    if (*(uint32_t*) rip == 0x29ae0f48) // 480fae29 xrstor64 [rcx]
    {
	hprintf("Emulating XRSTOR \n");
        puts("WARNING: xrstor64 skipped");
        *rip_s += 4;
        return;
    }
    if ((*(uint32_t*) rip & 0xFFFFFF) == 0xf0c70f) // RDRAND EAX
    {
	hprintf("Emulating RDRAND EAX \n");
        uc->uc_mcontext.gregs[REG_RAX] = 0x45454545;
        uc->uc_mcontext.gregs[REG_EFL] = 1; // CF
        *rip_s += 3;
        return;
    }
    if ((*(uint32_t*) rip & 0xFFFFFF) == 0xf6c70f) // RDRAND ESI
    {
	hprintf("Emulating RDRAND ESI \n");
        uc->uc_mcontext.gregs[REG_RSI] = 0x45454545;
        uc->uc_mcontext.gregs[REG_EFL] = 1; // CF
        *rip_s += 3;
        return;
    }

    hprintf("Unknown instruction \n");
    hprintf("%d\n", *(uint32_t*) rip);
}
uint64_t  trace_start;
uint64_t  trace_end;
int agent_init(int verbose)
{
	host_config_t host_config;
	
	/* configure range_a */
        kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (const uintptr_t) (const uint64_t[])
            { trace_start, trace_end , 0 }
        );
        /* disable range_b */
        kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (const uintptr_t) (const uint64_t[])
            { 0xFFFFFFFFFFFFF001L, 0XFFFFFFFFFFFFF002L, 1 }
        );

	hprintf("Changed range \n");
	// set ready state
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		hprintf(stderr, "GET_HOST_CONFIG\n");
		hprintf(stderr, "\thost magic:  0x%x, version: 0x%x\n",
			host_config.host_magic, host_config.host_version);
		hprintf(stderr, "\tbitmap size: 0x%x, ijon:    0x%x\n",
			host_config.bitmap_size, host_config.ijon_bitmap_size);
		hprintf(stderr, "\tpayload size: %u KB\n",
			host_config.payload_buffer_size / 1024);
		hprintf(stderr, "\tworker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		hprintf("HOST_MAGIC mismatch: %08x != %08x\n",
			host_config.host_magic, NYX_HOST_MAGIC);
		habort("HOST_MAGIC mismatch!");
		return -1;
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		hprintf("HOST_VERSION mismatch: %08x != %08x\n",
			host_config.host_version, NYX_HOST_VERSION);
		habort("HOST_VERSION mismatch!");
		return -1;
	}

	if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
		hprintf("Fuzzer payload size too large: %lu > %lu\n",
			host_config.payload_buffer_size, PAYLOAD_MAX_SIZE);
		habort("Host payload size too large!");
		return -1;
	}

	agent_config_t agent_config = { 0 };
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	//agent_config.agent_timeout_detection = 0; // timeout by host
	//agent_config.agent_tracing = 0; // trace by host
	//agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 0; // no persistent mode
	//agent_config.trace_buffer_vaddr = 0xdeadbeef;
	//agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
	agent_config.coverage_bitmap_size = host_config.bitmap_size;
	//agent_config.input_buffer_size;
	//agent_config.dump_payloads; // set by hypervisor (??)

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG,
		       (uintptr_t)&agent_config);

	return 0;
}
void register_handlers() {
	 struct sigaction sa = {};
         sigemptyset(&sa.sa_mask);
         sa.sa_sigaction = sigill_sigaction;
         sa.sa_flags = SA_SIGINFO;
         sigaction(SIGILL, &sa, NULL);

         sigemptyset(&sa.sa_mask);
         sa.sa_sigaction = sigabrt_sigaction;
         sa.sa_flags = SA_SIGINFO;
         sigaction(SIGABRT, &sa, NULL);
         sigaction(SIGSEGV, &sa, NULL);
         sigaction(SIGFPE, &sa, NULL);
}
sgx_status_t SGXAPI sgx_create_enclave_addr(const char *file_name,
                                       const int debug,
                                       sgx_launch_token_t *launch_token,
                                       int *launch_token_updated,
                                       sgx_enclave_id_t *enclave_id,
                                       sgx_misc_attribute_t *misc_attr) {
	sgx_status_t ret = -1;
	if (access(file_name, F_OK) == 0) {
            hprintf("file exists \n");
        } else {
            hprintf("file doesn't exist \n");
        }

        char cmd[512] = "cat /proc/";
        pid_t pid = getpid();
        char pid_str[10];
        sprintf(pid_str, "%d", pid);
        strcat(strcat(cmd, pid_str), "/maps | grep \"\\-x\"  > .savestate");
        system(cmd);

        /* only print off if no command line arguments were passed in */
        ret = sgx_create_enclave(file_name, debug, launch_token, launch_token_updated, enclave_id, misc_attr);
        if (ret != SGX_SUCCESS) {
                hprintf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
                return ret;
        }
        strcat(cmd, "1");

        system(cmd);
        system("diff .savestate .savestate1 | grep ^+ | grep xp > temp");
        system("awk '{print $1}' temp > enclave_addr");


        FILE *fp;
        char line[100];

        fp = fopen("enclave_addr", "r");
        if (fp == NULL) {
                hprintf("Failed to open file.\n");
                return 1;
        }

	int lines =0;
        void * enclave_start;
        void * enclave_end;
        char * enclave_start_string;
        char * enclave_end_string;
        while (fgets(line, sizeof(line), fp)) {
                hprintf("%s", line);
                char * addr = &line[1];
                enclave_start_string = strtok(addr, "-");
                enclave_end_string = strtok(NULL, "-");
        }
        if (lines != 1) {
                hprintf("Couldn't get enclave range \n");
        }
        unsigned long long  start = strtoull(enclave_start_string, NULL, 16);
        unsigned long long  end = strtoull(enclave_end_string, NULL, 16);
        fclose(fp);

        hprintf("Enclaves starts at 0x%s\n", enclave_start_string);
        hprintf("Enclaves starts at 0x%llx\n", start);
        hprintf("Enclaves ends at 0x%s", enclave_end_string);
        hprintf("Enclaves ends at 0x%llx\n", end);

	trace_start = start;
	trace_end = end;

	return ret;
}

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;
	int ret;
	char loopname[4096];
	int loopctlfd, loopfd, backingfile;
	long devnr;
	char *filesystemtype = NULL;
	int sgxStatus = 0;
	int updated = 0;
        func_args args = { 0 };
	pid_t pid;

	register_handlers();

	/* only print off if no command line arguments were passed in */
	ret = sgx_create_enclave_addr(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		hprintf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}
	hprintf("Entered Program");	

	sgx_enclave_id_t global_eid = id;


	system("mkdir -p /tmp/a/");

	hprintf("Made dir");

	//kill_systemd();

	kAFL_payload *pbuf = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);
	assert(pbuf);

	hprintf("malloc");

	loopctlfd = open("/dev/loop-control", O_RDWR);
	CHECK_ERRNO(loopctlfd != -1, "Failed to open /dev/loop-control");


	hprintf("opened loop ctrol");
	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	CHECK_ERRNO(devnr != -1, "Failed to get free loop device");

	sprintf(loopname, "/dev/loop%ld", devnr);
	close(loopctlfd);

	agent_init(1);

	hprintf("Initialized agent");

	//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0); // need kernel CR3!
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)pbuf);

	loopfd = open(loopname, O_RDWR);
	CHECK_ERRNO(loopfd != -1, "Failed to open loop device");

	backingfile = open(KAFL_TMP_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	CHECK_ERRNO(backingfile != -1, "Failed to open backing file");

	ret = ioctl(loopfd, LOOP_SET_FD, backingfile);
	CHECK_ERRNO(ret != -1, "Failed to ioctl(LOOP_SET_FD)");

	pbuf->size = 20;

	char * temp = NULL;
	int MJgHvXAcEJ_1;

	int* MkQxzPqMYr_1 = &MJgHvXAcEJ_1;
	hprintf("About to ecall\n");
	ret = enc_wolfSSL_Cleanup(global_eid, MkQxzPqMYr_1);

	if (ret != SGX_SUCCESS) {
		hprintf("Failure Code: %d",ret);
		return 0;
	}

	long int* KEVOXsFkNs_1 = NULL;
	long int KBupqhzwqm_2;
	temp = (char *)&KBupqhzwqm_2;
	memcpy(temp, pbuf->data, 8);

	ret = enc_wolfSSL_CTX_new(global_eid, KEVOXsFkNs_1, KBupqhzwqm_2);

	if (ret != SGX_SUCCESS)
		hprintf("Failure Code: %d",ret);

	int ptr =0;
	int max_buff = PAYLOAD_MAX_SIZE/20;
	int ret_val;
	long ret_long;


	int fd[2];
	int status;

	hprintf("Abot to enter \n");
	while(1) {
		hprintf("About to spawn one more \n");
		pid = fork();
		if (pid == -1) {
			// error occurred
			hprintf("Fork failed\n");
			return 1;
		} else if (pid == 0) {
#define RAND_BUF_SIZE 10
			while (1) {
				idx++;
				hprintf("Inside child Counter:%d \n", idx);
				if (idx>100) {
					char *p =(char *)NULL;
					*p=100;
				}
				long int* KEVOXsFkNs_1 = NULL;
				long int KBupqhzwqm_2;
				temp = (char *)&KBupqhzwqm_2;
				memcpy(temp, pbuf->data, 8);
				ptr += 8;

				hprintf("enc_wolfSSL_CTX_new\n");
				ret = enc_wolfSSL_CTX_new(global_eid, KEVOXsFkNs_1, KBupqhzwqm_2);

				hprintf("enc_wolfSSL_Init\n");
				enc_wolfSSL_Init(global_eid, &ret_val);
				hprintf("enc_wolfSSL_Debugging_ON\n");
				enc_wolfSSL_Debugging_ON(global_eid);

				hprintf("enc_wolfSSL_Debugging_OFF\n");
				enc_wolfSSL_Debugging_OFF(global_eid);

				hprintf("enc_wolfTLSv1_2_client_method\n");
				enc_wolfTLSv1_2_client_method(global_eid, &ret_long);
				hprintf("enc_wolfTLSv1_2_server_method\n");
				enc_wolfTLSv1_2_server_method(global_eid, &ret_long);


				long ctxId;
				temp = (char *)&ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				const unsigned char* buf = pbuf->data + ptr;
				int sz = max_buff;
				ptr += max_buff;
				int type;
				temp = (char *)&type;
				memcpy(temp, pbuf->data + ptr, sizeof(int));
				hprintf("enc_wolfSSL_CTX_use_PrivateKey_buffer\n");
				enc_wolfSSL_CTX_use_PrivateKey_buffer(global_eid, &ret_val, ctxId, buf, sz, type);


				if (ret != SGX_SUCCESS)
					hprintf("Failure Code: %d",ret);

				temp = (char *)&ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				buf = pbuf->data + ptr;
				sz = max_buff;
				ptr += max_buff;
				type;
				temp = (char *)&type;
				memcpy(temp, pbuf->data + ptr, sizeof(int));
				hprintf("enc_wolfSSL_CTX_load_verify_buffer\n");
				enc_wolfSSL_CTX_load_verify_buffer(global_eid, &ret_val, ctxId, buf, sz, type);

				temp = (char *)&ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				buf = pbuf->data + ptr;
				sz = max_buff;
				ptr += max_buff;
				type;
				temp = (char *)&type;
				memcpy(temp, pbuf->data + ptr, sizeof(int));
				hprintf("enc_wolfSSL_CTX_use_certificate_chain_buffer_format\n");
				enc_wolfSSL_CTX_use_certificate_chain_buffer_format(global_eid, &ret_val, ctxId, buf, sz, type);


				temp = (char *)&ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				buf = pbuf->data + ptr;
				sz = max_buff;
				ptr += max_buff;
				type;
				temp = (char *)&type;
				memcpy(temp, pbuf->data + ptr, sizeof(int));
				hprintf("enc_wolfSSL_CTX_use_certificate_buffer\n");
				enc_wolfSSL_CTX_use_certificate_buffer(global_eid, &ret_val, ctxId, buf, sz, type);
#if 1 
				temp = (char *)&ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				char * list = (pbuf->data + ptr);
				list[max_buff - 1] = 0;
				list [1] = "\0";
				ptr += max_buff;
				hprintf("enc_wolfSSL_CTX_set_cipher_list\n");
				enc_wolfSSL_CTX_set_cipher_list(global_eid, &ret_val, ctxId,  list);

#endif
#if 1
				long sslId;
				temp = (char*) &sslId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				hprintf("enc_wolfSSL_connect\n");
				enc_wolfSSL_connect(global_eid, &ret_val,  sslId);


				temp = (char*) &sslId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);

				char * in = pbuf->data + ptr;
				ptr += max_buff;
				hprintf("enc_wolfSSL_write\n");
				enc_wolfSSL_write(global_eid, &ret_val, sslId, in,
						max_buff);

				temp = (char*) &sslId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				int ret;
				temp = (char *) &ret;
				memcpy(temp, pbuf->data + ptr, sizeof(int));
				ptr += sizeof(int);
				hprintf("enc_wolfSSL_get_error\n");
				enc_wolfSSL_get_error(global_eid, &ret_val, sslId, ret);

				temp = (char*) &sslId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				char out[RAND_BUF_SIZE];
				hprintf("enc_wolfSSL_read\n");
				enc_wolfSSL_read(global_eid, &ret_val, sslId, out,
						RAND_BUF_SIZE);

				temp = (char*) &sslId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				hprintf("enc_wolfSSL_free\n");
				enc_wolfSSL_free(global_eid, sslId);

				temp = (char*) &ctxId;
				memcpy(temp, pbuf->data + ptr, sizeof(long));
				ptr += sizeof(long);
				hprintf("enc_wolfSSL_CTX_free\n");
				enc_wolfSSL_CTX_free(global_eid, ctxId);


				hprintf("enc_wolfSSL_Cleanup\n");
				enc_wolfSSL_Cleanup(global_eid, &ret_val);


#endif 
				// first round for warmup - real start now
				printf("%.*s",pbuf->size, pbuf->data);
				hprintf("Loop after 5 \n");
				kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
				//sleep(5);
				hprintf("After release \n");
				idx++;
				kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
				//sleep(5);
				hprintf("After Next payload \n");
				kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
				hprintf("%d\n", idx);
				//sleep(5);
				hprintf("After Acquire \n");
			}

		}
		else {
			while(1);
			// parent process
			hprintf("Child process ID is %d\n", pid);
			waitpid(pid, &status, 0);
			hprintf("Child process exited with status %d\n", status);
			hprintf("Will run next program\n");
		}
	}

	/*[[[cog
	  import cog
	  filename = "./temp"
	  with open(filename) as f:
	  for line in  f.readlines():
	  cog.outl(line)
	  ]]]*/

	//[[[end]]]

	return 0;
}

static double current_time()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);

	return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow. 
	 */ printf("%s", str);
}

void ocall_current_time(double* time)
{
	if(!time) return;
	*time = current_time();
	return;
}

void ocall_low_res_time(int* time)
{
	struct timeval tv;
	if(!time) return;
	*time = tv.tv_sec;
	return;
}

size_t ocall_recv(int sockfd, void *buf, size_t length, int flags)
{
	return recv(sockfd, buf, length, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}

