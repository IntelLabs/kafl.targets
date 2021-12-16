/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>
#include <fatal.h>
#include <sys/check.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define _GNU_SOURCE
#include "kafl_user.h"
#include "target.h"

static void agent_init(void *panic_handler, void *kasan_handler)
{
	hprintf("Initiate fuzzer handshake...\n");

	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	/* submit panic and optionally kasan handlers for qemu override */
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uintptr_t)panic_handler);

	if (kasan_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uintptr_t)kasan_handler);
	}
}

//#define PAYLOAD_ON_HEAP
static void agent_run(void)
{
#ifdef PAYLOAD_ON_HEAP
	/* fixme: GET_PAYLOAD requires page-aligned buffer! */
	kAFL_payload* payload_buffer = k_malloc(PAYLOAD_SIZE);
	if (!payload_buffer)
		return;
#else
	uint8_t buffer[PAYLOAD_SIZE] __attribute__((aligned(4096)));
	kAFL_payload* payload_buffer = (kAFL_payload*)buffer;
#endif

	///* touch the memory to ensure all pages are present in memory */
	//memset(payload_buffer, 0, PAYLOAD_SIZE);
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);

	target_init();

	while (1) {
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
		target_entry(payload_buffer->data, payload_buffer->size);

		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
}

/*
 * That function is weak symbol on Zephyr, just override it with our
 * function to notify KVM through hypercall.
 */
void k_sys_fatal_error_handler(unsigned int reason, const z_arch_esf_t *esf)
{
	switch (reason) {
		case K_ERR_KERNEL_OOPS:
			kAFL_hypercall(HYPERCALL_KAFL_KASAN, 0);
			break;
		case K_ERR_CPU_EXCEPTION:
		case K_ERR_KERNEL_PANIC:
		default:
			kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
			break;
	}

	k_fatal_halt(reason);
}

void main(void)
{
	hprintf("kAFL Hello World! %s\n\n", CONFIG_BOARD);
	
	// skip rewrite in favor of custom k_sys_fatal_error_handler()
	void* panic_handler = NULL;
	void* kasan_handler = NULL;

	hprintf("Kernel Panic Handler Address:\t%p\n", panic_handler);

	if (kasan_handler){
		hprintf("Kernel KASAN Handler Address:\t%p\n", kasan_handler);
	}

	agent_init(panic_handler, kasan_handler);
	agent_run();
}
