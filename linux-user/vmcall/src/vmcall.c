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

#include <sys/select.h>

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

enum nyx_cpu_type {
	nyx_cpu_none = 0,
	nyx_cpu_v1, /* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
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

/**
 * read stdin or file argument and output with hprintf
 */
static size_t hcat()
{
	FILE *f;
	size_t read = 0;
	size_t written = 0;

	if (!file_is_ready(fileno(stdin)))
		return 0;

	while (!feof(stdin)) {
		read = fread(hprintf_buffer, 1, sizeof(hprintf_buffer), stdin);
		if (read <= 0) {
			fprintf(stderr, "Error reading from file descriptor %d", fileno(stdin));
			return written;
		}

		hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
		written += read;
	}
	return written;
}

int main(char **argv, int argc) {

	int ret = 0;

	if (nyx_cpu_v1 == get_nyx_cpu_type()) {
		fprintf(stderr, "VMCALL enabled.\n");
		enable_vmcall = true;
	} else {
		fprintf(stderr, "VMCALL disabled.\n");
	}

	ret = hcat();

	return ret;
}
