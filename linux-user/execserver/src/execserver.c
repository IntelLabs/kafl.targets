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
			hprintf("Error on %s: %s\n", msg, strerror(errno));  \
			habort("msg"); \
		}                                            \
	} while (0)

int main(int argc, char **argv)
{
	int fd = 0;
	int pid;
	int status = 0;
	int ret = 0;
	int opt = 0;
	long int num_execs = -1;

	while ((opt = getopt(argc, argv, "+n:")) != -1) {
		switch (opt) {
			case 'n':
				num_execs = strtoul(optarg, NULL, 0);
				ERRNO_FAIL_ON(errno, "strtoul");
				break;
			default:
				fprintf(stderr, "Usage: execserver [-n <int>] <command> [command-args]");
				exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing <command> argument. Exit.");
		exit(EXIT_FAILURE);
	}

	agent_init(1);

	kAFL_payload *payload_buffer = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

	while (num_execs > 0 || num_execs == -1) {

		pid = fork();
		assert(pid != -1);

		if (!pid) {
			// on normal exit, directly skip to snapshot reload
			//atexit(snapshot_reload);

			//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
			kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
			//kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
			//kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

			fd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, 0666);
			ERRNO_FAIL_ON(fd == -1, "open");

			ret = write(fd, payload_buffer->data, payload_buffer->size);
			ERRNO_FAIL_ON(ret != payload_buffer->size, "write");
			close(fd);

			hprintf("exec: %s, %s, %s\n", argv[optind], argv[optind+1], argv[optind+2]);
			ret = execvp(argv[optind], &argv[optind]);
			ERRNO_FAIL_ON(ret != -1, "execvp");

		} else if (pid > 0) {
			waitpid(pid, &status, WUNTRACED);

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
			hprintf("EXIT OK\n");
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		}

		if (num_execs > 0)
			num_execs--;

	}
}
