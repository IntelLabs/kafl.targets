/*
 * Target-specific helpers for Nyx Agent
 *
 * based on Nyx/packer: https://github.com/nyx-fuzz/packer/nyx.h
 *
 * Copyright 2021 Sergej Schumilo, Cornelius Aschermann
 * Copyright 2022 Intel Corporation
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef NYX_AGENT_H
#define NYX_AGENT_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>


enum nyx_cpu_type {
	unkown = 0, 
	nyx_cpu_v1,	/* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
};

#define cpuid(in,a,b,c,d)\
	asm("cpuid": "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));

static int is_nyx_vcpu(void)
{
	unsigned long eax,ebx,ecx,edx;
	char str[8];
	cpuid(0x80000004,eax,ebx,ecx,edx);	

	for(int j=0;j<4;j++){
		str[j] = eax >> (8*j);
		str[j+4] = ebx >> (8*j);
	}

	return !memcmp(&str, "NYX vCPU", 8);
}

static int get_nyx_cpu_type(void)
{
	unsigned long eax,ebx,ecx,edx;
	char str[8];
	cpuid(0x80000004,eax,ebx,ecx,edx);	

	for(int j=0;j<4;j++){
		str[j] = eax >> (8*j);
		str[j+4] = ebx >> (8*j);
	}

	if(memcmp(&str, "NYX vCPU", 8) != 0){
		return unkown;
	}

	for(int j=0;j<4;j++){
		str[j] = ecx >> (8*j);
		str[j+4] = edx >> (8*j);
	}

	if(memcmp(&str, " (NO-PT)", 8) != 0){
		return nyx_cpu_v1;
	}

	return nyx_cpu_v2;

	str[8] = 0;
	printf("ECX: %s\n", str);
}

#endif // NYX_AGENT_H
