/*
 * Copyright (C)  2022  Intel Corporation. 
 *
 * This software and the related documents are Intel copyrighted materials, and
 * your use of them is governed by the express license under which they were
 * provided to you ("License"). Unless the License provides otherwise, you may
 * not use, modify, copy, publish, distribute, disclose or transmit this software
 * or the related documents without Intel's prior written permission. This
 * software and the related documents are provided as is, with no express or
 * implied warranties, other than those that are expressly stated in the License.
 *
 * SPDX-License-Identifier: MIT
 *
 */

/*
 * vmcall.c - a helper tool for placing kAFL/Nyx hypercalls
 */


#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/select.h>
#include <libgen.h>

#include <nyx_api.h>

char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));

bool enable_vmcall = false;

#ifdef DEBUG
#define debug_printf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define debug_printf(fmt, ...)
#endif

#define cpuid(in,a,b,c,d)\
	asm("cpuid": "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY)/sizeof((ARRAY)[0]))

enum nyx_cpu_type {
	nyx_cpu_none = 0,
	nyx_cpu_v1, /* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
};

struct cmd_table {
	char *name;
	int (*handler)(int, char**);
};

static int cmd_vmcall(int argc, char **argv);
static int cmd_hcat(int argc, char **argv);
static int cmd_habort(int argc, char **argv);
	
struct cmd_table cmds[] = {
	{ "vmcall", cmd_vmcall },
	{ "hcat",   cmd_hcat   },
	{ "habort", cmd_habort }
};

static enum nyx_cpu_type get_nyx_cpu_type(void)
{
	uint32_t regs[4];
	char str[17];

	cpuid(0x80000004, regs[0], regs[1], regs[2], regs[3]);

	memcpy(str, regs, sizeof(regs));
	str[16] = '\0';
	
	debug_printf("CPUID info: >>%s<<\n", str);

	if (0 == strncmp(str, "NYX vCPU (PT)", sizeof(str))) {
		return nyx_cpu_v1;
	} else if (0 == strncmp(str, "NYX vCPU (NO-PT)", sizeof(str))) {
		return nyx_cpu_v2;
	} else {
		return nyx_cpu_none;
	}
}

static void hypercall(unsigned id, uintptr_t arg)
{
	if (enable_vmcall) {
		kAFL_hypercall(id, arg);
	} else {
		debug_printf("Skipping vmcall(0x%x,0x%lx) ..\n", id, arg);
	}
}

static bool file_is_ready(int fd)
{
	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = 10,
	};

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (!select(fd+1, &fds, NULL, NULL, &tv))
		return false;

	return true;
}

static size_t file_to_hprintf(FILE *f)
{
	size_t written = 0;
	size_t read = 0;

	while (!feof(f)) {
		read = fread(hprintf_buffer, 1, sizeof(hprintf_buffer), f);
		if (read <= 0) {
			fprintf(stderr, "Error reading from file descriptor %d", fileno(f));
			return written;
		}

		hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
		written += read;
	}
	return written;
}

/**
 * Read stdin or file argument and output to hprintf buffer.
 *
 * Unlike cat, we first check and print <stdin> and then also
 * print any given file arguments up until first error.
 */
static int cmd_hcat(int argc, char **argv)
{
	FILE *f;
	size_t read = 0;
	size_t written = 0;
	
	debug_printf("[hcat] start...\n");

	if (file_is_ready(fileno(stdin))) {
		written += file_to_hprintf(stdin);
	}

	for (int i=0; i<argc; i++) {
		f = fopen(argv[i], "r");
		if (!f) {
			fprintf(stderr, "Error opening file %s: %s\n", argv[i], strerror(errno));
			return written;
		} else {
			written += file_to_hprintf(f);
		}
	}

	debug_printf("[hcat] %zd bytes written.\n", written);
	return (written > 0);
}

static int cmd_habort(int argc, char **argv)
{
	debug_printf("[habort] start...\n");

	if (argc > 0) {
		debug_printf("[habort] abort with '%s'\n", argv[0]);
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)argv[0]);
	} else {
		debug_printf("[habort] abort with '%s'\n", "vmcall/habort called.");
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"vmcall/habort called.");
	}

	return 0;
}

static int cmd_vmcall(int argc, char **argv)
{
	debug_printf("[vmcall] start...\n");

	// check if actual command is in argv[1]
	for (int i=0; i<ARRAY_SIZE(cmds); i++) {
		if (0 == strncmp(basename(argv[0]), cmds[i].name, strlen(cmds[i].name))) {
			return cmds[i].handler(argc-1, argv+1);
		}
	}

	// default vmcall action
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (nyx_cpu_v1 == get_nyx_cpu_type()) {
		fprintf(stderr, "VMCALL enabled.\n");
		enable_vmcall = true;
	} else {
		fprintf(stderr, "VMCALL disabled.\n");
	}

	for (int i=0; i< ARRAY_SIZE(cmds); i++) {
		if (0 == strncmp(basename(argv[0]), cmds[i].name, strlen(cmds[i].name))) {
			return cmds[i].handler(argc-1, argv+1);
		}
	}

	return ret;
}
