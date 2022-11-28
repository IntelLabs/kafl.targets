/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <sys/stat.h>
#include <assert.h>

#include "nyx_api.h"
#include "nyx_agent.h"

#define ASAN_EXIT_CODE 101
//#define REDIRECT_STDERR_TO_HPRINTF
//#define REDIRECT_STDOUT_TO_HPRINTF

#define PAYLOAD_MAX_SIZE (128 * 1024)

char output_filename[] = "/tmp/payload"; // = getenv()
uint8_t stdin_mode = 0;

const bool allow_persistent = false; // = getenv()

//extern uint32_t memlimit;

long int random(void)
{
	return 0;
}
int rand(void)
{
	return 0;
}

// TODO - refactor into reusable lib component
int agent_init(int verbose)
{
	static host_config_t host_config __attribute__((aligned(PAGE_SIZE)));
	memset(&host_config, 0, sizeof(host_config));

	get_nyx_cpu_type();

	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		fprintf(stderr, "GET_HOST_CONFIG\n");
		fprintf(stderr,
		        "\thost magic:  0x%x, version: 0x%x\n",
		        host_config.host_magic,
		        host_config.host_version);
		fprintf(stderr,
		        "\tbitmap size: 0x%x, ijon:    0x%x\n",
		        host_config.bitmap_size,
		        host_config.ijon_bitmap_size);
		fprintf(stderr, "\tpayload size: %u KB\n", host_config.payload_buffer_size / 1024);
		fprintf(stderr, "\tworker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		hprintf("HOST_MAGIC mismatch: %08x != %08x\n", host_config.host_magic, NYX_HOST_MAGIC);
		habort("HOST_MAGIC mismatch!");
		return -1;
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		hprintf("HOST_VERSION mismatch: %08x != %08x\n",
		        host_config.host_version,
		        NYX_HOST_VERSION);
		habort("HOST_VERSION mismatch!");
		return -1;
	}

	if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
		hprintf("Fuzzer payload size too large: %lu > %lu\n",
		        host_config.payload_buffer_size,
		        PAYLOAD_MAX_SIZE);
		habort("Host payload size too large!");
		return -1;
	}

	static agent_config_t agent_config __attribute__((aligned(PAGE_SIZE)));
	memset(&agent_config, 0, sizeof(agent_config));
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	agent_config.agent_timeout_detection = 0;              // timeout by host
	agent_config.agent_tracing = 0;                        // trace by host
	agent_config.agent_ijon_tracing = 0;                   // no IJON
	agent_config.agent_non_reload_mode = allow_persistent; // allow persistent?
	agent_config.trace_buffer_vaddr = 0xdeadbeef;
	agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
	agent_config.coverage_bitmap_size = host_config.bitmap_size;
	//agent_config.input_buffer_size;
	//agent_config.dump_payloads; // set by hypervisor (??)

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

	// set ready state
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	return 0;
}

#define ERRNO_FAIL_ON(cond, msg)                     \
	do {                                             \
		if ((cond)) {                                \
			hprintf("Error: %s\n", strerror(errno)); \
			habort(msg);                             \
		}                                            \
	} while (0)

static int detectranges(char *mapfile, char *pattern)
{
	int ret = 0;
	unsigned region = 0;
	char line[4096];

	if (!mapfile || !pattern) {
		return -1;
	}

	FILE *fp = fopen(mapfile, "r");
	ERRNO_FAIL_ON(fp == NULL, "fopen() failure");

	while ((fgets(line, sizeof(line), fp) == line)) {
		unsigned long start = 0;
		unsigned long end = 0;
		char *file;

		ret = sscanf(line, "%lx-%lx %*2cxp %*x %*2d:%*2d %*d %ms", &start, &end, &file);
		//hprintf("Got %d args out of line %s", ret, line);

		if (ret == 3) {
			if (strstr(file, pattern)) {
				hprintf(" => matched range %u: %lx-%lx (%s)\n", region, start, end, file);
				hrange_submit(region, start, end);
				region++;
				free(file);
			}
		}
	}
	return region;
}

void snapshot_reload()
{
	if (!allow_persistent) {
		hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
}

/* Trampoline for the real main() */
int (*main_orig)(int, char **, char **);

int forkserver(int argc, char **argv, char **envp)
{
	struct rlimit r;
	int fd = 0;
	int pipefd[2];

	struct iovec iov;
	int pid;
	int status = 0;
	int ret = 0;

	ret = pipe(pipefd);
	ERRNO_FAIL_ON(ret == -1, "pipe");

#ifdef REDIRECT_STDERR_TO_HPRINTF
	int pipe_stderr_hprintf[2];
	ret = pipe(pipe_stderr_hprintf);
	ERRNO_FAIL_ON(ret == -1, "pipe");
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
	int pipe_stdout_hprintf[2];
	ret = pipe(pipe_stdout_hprintf);
	ERRNO_FAIL_ON(ret == -1, "pipe");
#endif

	//r.rlim_max = (rlim_t)(memlimit << 20);
	//r.rlim_cur = (rlim_t)(memlimit << 20);

	ret = dup2(open("/dev/null", O_WRONLY), STDOUT_FILENO);
	ERRNO_FAIL_ON(ret == -1, "dup2(STDOUT)");
	ret = dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);
	ERRNO_FAIL_ON(ret == -1, "dup2(STDERR)");

	if (!stdin_mode) {
		ret = dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);
		ERRNO_FAIL_ON(ret == -1, "dup2(STDIN)");
	}

	agent_init(1);

	kAFL_payload *payload_buffer = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

	//hpush_file("/proc/self/maps", "proc_map.txt", 0);
	//agent_setrange(0,0x555555550000,0x555555567000);
	ret = detectranges("/proc/self/maps", "bison");
	if (ret < 1) {
		habort("No IP ranges registered?!");
	}

	hprintf("main() => 0x%lx\n", main_orig);

	while (1) {
#if defined(REDIRECT_STDERR_TO_HPRINTF) || defined(REDIRECT_STDOUT_TO_HPRINTF)
		char stdio_buf[HPRINTF_MAX_SIZE];
#endif

		pid = fork();
		assert(pid != -1);

		if (!pid) {
			// on normal exit, directly skip to snapshot reload
			atexit(snapshot_reload);

			//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
			//kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
			//kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
			kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

			if (stdin_mode) {
				ret = pipe(pipefd);
				ERRNO_FAIL_ON(ret == -1, "pipe");
			} else {
				fd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
				ERRNO_FAIL_ON(fd == -1, "open");
			}

			if (stdin_mode) {
				iov.iov_base = payload_buffer->data;
				iov.iov_len = payload_buffer->size;

				vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);
				dup2(pipefd[0], STDIN_FILENO);
				close(pipefd[1]);
			} else {
				ret = write(fd, payload_buffer->data, payload_buffer->size);
				ERRNO_FAIL_ON(ret != payload_buffer->size, "write");
				close(fd);
			}

#ifdef REDIRECT_STDERR_TO_HPRINTF
			dup2(pipe_stderr_hprintf[1], STDERR_FILENO);
			close(pipe_stderr_hprintf[0]);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			dup2(pipe_stdout_hprintf[1], STDOUT_FILENO);
			close(pipe_stdout_hprintf[0]);
#endif

#ifndef ASAN_BUILD
			/* disable setrlimtit in case of ASAN builds... */
			setrlimit(RLIMIT_AS, &r);
#endif
			struct itimerval timer;
			//if (payload_buffer->redqueen_mode) {
			//	timer.it_value.tv_sec = 10;
			//	timer.it_value.tv_usec = 0;
			//} else {
			timer.it_value.tv_sec = 1;
			timer.it_value.tv_usec = 200;
			//}
			timer.it_interval.tv_sec = 0;
			timer.it_interval.tv_usec = 0;
			setitimer(ITIMER_VIRTUAL, &timer, NULL);

			return main_orig(argc, argv, envp);

		} else if (pid > 0) {
#ifdef REDIRECT_STDERR_TO_HPRINTF
			close(pipe_stderr_hprintf[1]);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			close(pipe_stdout_hprintf[1]);
#endif
			waitpid(pid, &status, WUNTRACED);

#ifdef REDIRECT_STDERR_TO_HPRINTF
			while ((ret = read(pipe_stderr_hprintf[0], stdio_buf, HPRINTF_MAX_SIZE - 1))) {
				if (ret > 0) {
					hprintf("%s\n", stdio_buf);
				}
			}
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			while ((ret = read(pipe_stdout_hprintf[0], stdio_buf, HPRINTF_MAX_SIZE - 1))) {
				if (ret > 0) {
					hprintf(" => %s\n", stdio_buf);
				}
			}
#endif

			if (WIFSIGNALED(status)) {
				if (WTERMSIG(status) == SIGVTALRM) {
					hprintf("TIMEOUT found\n");
					//kAFL_hypercall(HYPERCALL_KAFL_TIMEOUT, 1);
				} else {
					kAFL_hypercall(HYPERCALL_KAFL_PANIC, 1);
				}
			} else if (WEXITSTATUS(status) == ASAN_EXIT_CODE) {
				kAFL_hypercall(HYPERCALL_KAFL_KASAN, 1);
			}
			//hprintf("EXIT OK\n");
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		}
	}
}

int __libc_start_main(int (*main)(int, char **, char **),
                      int argc,
                      char **argv,
                      void (*init)(void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void(*stack_end))
{
	/* Save the real main function address */
	main_orig = main;

	/* Find the real __libc_start_main()... */
	typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

	/* ... and call it with our custom main function */
	return orig(forkserver, argc, argv, init, fini, rtld_fini, stack_end);
}
