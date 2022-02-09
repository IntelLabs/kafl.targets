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
#include "../../nyx_api.h"
#include "target.h"

#define PAYLOAD_MAX_SIZE (128*1024)

#ifndef PAYLOAD_ON_HEAP
static uint8_t bss_buffer[PAYLOAD_MAX_SIZE] __attribute__((aligned(4096)));
#endif

static void agent_init(void *panic_handler, void *kasan_handler)
{
	hprintf("Initiate fuzzer handshake...\n");

	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);

	/* submit panic and optionally kasan handlers for qemu override */
	if (panic_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uintptr_t)panic_handler);
	}

	if (kasan_handler) {
		kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uintptr_t)kasan_handler);
	}

	/* Request information on available (host) capabilites (not optional) */
	volatile host_config_t host_config;
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
	if (host_config.host_magic != NYX_HOST_MAGIC ||
	    host_config.host_version != NYX_HOST_VERSION) {
		hprintf("host_config magic/version mismatch!\n");
		habort("GET_HOST_CNOFIG magic/version mismatch!\n");
	}
	hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
	hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
	hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

	//uint8_t *trace_buffer = mmap(NULL, MMAP_SIZE(TRACE_BUFFER_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	//memset(trace_buffer, 0, TRACE_BUFFER_SIZE);  // makes sure that the bitmap buffer is already

	/* reserved guest memory must be at least as large as host SHM view */
	if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
		habort("Insufficient guest payload buffer!\n");
	}

	/* submit agent configuration */
	volatile agent_config_t agent_config = {0};
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;

	agent_config.agent_tracing = 0; // trace by host!
	agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 1; // allow persistent
	agent_config.coverage_bitmap_size = host_config.bitmap_size;

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
}

//#define PAYLOAD_ON_HEAP
static void agent_run(void)
{
	kAFL_payload* payload_buffer;

#ifndef PAYLOAD_ON_HEAP
	payload_buffer = (kAFL_payload*)bss_buffer;
#else
	/* fixme: GET_PAYLOAD requires page-aligned buffer! */
	payload_buffer = k_malloc(PAYLOAD_MAX_SIZE);
	if (!payload_buffer) {
		habort("Failed to allocate payload_buffer!");
		return;
	}
#endif

	/* touch the memory to ensure all pages are present in memory */
	memset(payload_buffer, 0, PAYLOAD_MAX_SIZE);

	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

	target_init();
	hprintf("Target init done...\n");

	while (1) {
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
		//hprintf("target_entry()...\n");
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
