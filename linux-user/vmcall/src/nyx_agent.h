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
 */

/*
 * kafl_agent.h - common helpers for Linux kAFL agents
 */

#include <nyx_api.h>

#define KAFL_CPUID_IDENTIFIER 0x80000004
#define PAGE_SIZE 4096

#define cpuid(in, a, b, c, d) \
	asm("cpuid" : "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))

#ifdef DEBUG
#define debug_printf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define debug_printf(fmt, ...)
#endif

typedef enum {
	nyx_cpu_invalid = -1,
	nyx_cpu_none = 0,
	nyx_cpu_v1, /* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
} nyx_cpu_type_t;

extern nyx_cpu_type_t nyx_cpu_type;

void *malloc_resident_pages(size_t num_pages);
void free_resident_pages(void *buf, size_t num_pages);
nyx_cpu_type_t get_nyx_cpu_type(void);
unsigned long hypercall(unsigned id, uintptr_t arg);
ssize_t hprintf_from_file(FILE *f);
int hget_file(char *src_path, mode_t flags);
int hpush_file(char *src_path, char *dst_name, int append);
int check_host_magic(int verbose);
void habort_msg(const char *msg);
void hrange_submit(unsigned id, uintptr_t start, uintptr_t end);
