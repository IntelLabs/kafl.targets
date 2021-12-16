/*
 * This file is part of kAFL.
 *
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 * Copyright 2021 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef KAFL_USER_H
#define KAFL_USER_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else 
#include <stdint.h>
#endif

#define HYPERCALL_KAFL_RAX_ID				0x01f
#define HYPERCALL_KAFL_ACQUIRE				0
#define HYPERCALL_KAFL_GET_PAYLOAD			1
#define HYPERCALL_KAFL_GET_PROGRAM			2
#define HYPERCALL_KAFL_GET_ARGV				3
#define HYPERCALL_KAFL_RELEASE				4
#define HYPERCALL_KAFL_SUBMIT_CR3			5
#define HYPERCALL_KAFL_SUBMIT_PANIC			6
#define HYPERCALL_KAFL_SUBMIT_KASAN			7
#define HYPERCALL_KAFL_PANIC				8
#define HYPERCALL_KAFL_KASAN				9
#define HYPERCALL_KAFL_LOCK					10
#define HYPERCALL_KAFL_INFO					11
#define HYPERCALL_KAFL_NEXT_PAYLOAD			12
#define HYPERCALL_KAFL_PRINTF				13
#define HYPERCALL_KAFL_PRINTK_ADDR			14
#define HYPERCALL_KAFL_PRINTK				15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE	16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE		17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE	18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT			20
#define HYPERCALL_KAFL_TIMEOUT				21

#define PAYLOAD_SIZE						(128 << 10)				/* up to 128KB payloads */
#define INFO_SIZE        					(128 << 10)				/* 128KB info string */

#define HPRINTF_MAX_SIZE					0x1000					/* up to 4KB hprintf strings */


typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-sizeof(int32_t)];
} kAFL_payload;

typedef struct{
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges; 

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

#if defined(__i386__)
static inline void kAFL_hypercall(uint32_t p1, uint32_t p2)
{
	uint32_t nr = HYPERCALL_KAFL_RAX_ID;
	asm ("vmcall"
			: : "a"(nr), "b"(p1), "c"(p2));
}
#elif defined(__x86_64__)
static inline void kAFL_hypercall(uint64_t p1, uint64_t p2)
{
	uint64_t nr = HYPERCALL_KAFL_RAX_ID;
	asm ("vmcall"
			: : "a"(nr), "b"(p1), "c"(p2));
}
#endif

static void hprintf(const char * format, ...)  __attribute__ ((unused));
static void hprintf(const char * format, ...){
	static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(4096)));

	va_list args;
	va_start(args, format);
	vsnprintk((char*)hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
	//printf("%s", hprintf_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
	va_end(args);
}
#endif /* KAFL_USER_H */
