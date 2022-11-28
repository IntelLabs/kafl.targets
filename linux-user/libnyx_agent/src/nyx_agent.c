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
 * agent_lib.c - common helper functions for Linux kAFL agents
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <errno.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/mman.h>

#include <nyx_api.h>

#include "nyx_agent.h"

nyx_cpu_type_t nyx_cpu_type = nyx_cpu_invalid;

/**
 * Allocate page-aligned memory
 */
void *malloc_resident_pages(size_t num_pages)
{
	size_t data_size = PAGE_SIZE * num_pages;
	void *ptr = NULL;

	if ((ptr = aligned_alloc(PAGE_SIZE, data_size)) == NULL) {
		fprintf(stderr, "Allocation failure: %s\n", strerror(errno));
		goto err_out;
	}

	// ensure pages are aligned and resident
	memset(ptr, 0x42, data_size);
	if (mlock(ptr, data_size) == -1) {
		fprintf(stderr, "Error locking scratch buffer: %s\n", strerror(errno));
		goto err_out;
	}

	assert(((uintptr_t)ptr % PAGE_SIZE) == 0);
	return ptr;
err_out:
	free(ptr);
	return NULL;
}

/**
 * Free memory allocated by malloc_resident_pages()
 */
void free_resident_pages(void *buf, size_t num_pages)
{
	if (buf) {
		munlock(buf, num_pages);
		free(buf);
	}
}

/**
 * Get Nyx VMM type from CPUID
 */
static nyx_cpu_type_t _get_nyx_cpu_type(void)
{
	uint32_t regs[4];
	char str[17];

	cpuid(KAFL_CPUID_IDENTIFIER, regs[0], regs[1], regs[2], regs[3]);

	memcpy(str, regs, sizeof(regs));
	str[16] = '\0';

	//debug_printf("CPUID string: >>%s<<\n", str);

	if (0 == strncmp(str, "NYX vCPU (PT)", sizeof(str))) {
		return nyx_cpu_v1;
	} else if (0 == strncmp(str, "NYX vCPU (NO-PT)", sizeof(str))) {
		return nyx_cpu_v2;
	} else {
		return nyx_cpu_none;
	}
}

nyx_cpu_type_t get_nyx_cpu_type(void)
{
	if (nyx_cpu_type == nyx_cpu_invalid) {
		nyx_cpu_type = _get_nyx_cpu_type();
	}
	return nyx_cpu_type;
}

/**
 * Execute hypercall depending on Nyx CPU type
 */
unsigned long hypercall(unsigned id, uintptr_t arg)
{
	switch (nyx_cpu_type) {
	case nyx_cpu_v1:
		debug_printf("\t# vmcall(0x%x,0x%lx) ..\n", id, arg);
		return kAFL_hypercall(id, arg);
	case nyx_cpu_v2:
	case nyx_cpu_none:
		debug_printf("\t# vmcall(0x%x,0x%lx) skipped..\n", id, arg);
		return 0;
	case nyx_cpu_invalid:
	default:
		fprintf(stderr, "get_nyx_cpu_type() must be called first\n");
		habort_msg("get_nyx_cpu_type() must be called first\n");
		assert(false);
	}
}

void habort_msg(const char *msg)
{
	hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)msg);
}

void hrange_submit(unsigned id, uintptr_t start, uintptr_t end)
{
	uint64_t range_arg[3] __attribute__((aligned(PAGE_SIZE)));
	memset(range_arg, 0, sizeof(range_arg));

	range_arg[0] = start;
	range_arg[1] = end;
	range_arg[2] = id;

	hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)range_arg);
}

/**
 * Stream file to hprintf in chunks of HPRINTF_MAX_SIZE
 */
ssize_t hprintf_from_file(FILE *f)
{
	size_t written = 0;
	size_t read = 0;

	static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(PAGE_SIZE)));

	while (!feof(f)) {
		read = fread(hprintf_buffer, 1, sizeof(hprintf_buffer), f);
		if (ferror(f)) {
			fprintf(stderr, "Error reading from file descriptor %d\n", fileno(f));
			return -1;
		}

		hypercall(HYPERCALL_KAFL_PRINTF, (uintptr_t)hprintf_buffer);
		written += read;
	}
	return written;
}

int hget_file(char *src_path, mode_t flags)
{
	static req_data_bulk_t req_file __attribute((aligned(PAGE_SIZE)));

	int ret = 0;
	const int num_pages = 256; // 1MB at a time

	size_t scratch_size = num_pages * PAGE_SIZE;
	uint8_t *scratch_buf = malloc_resident_pages(num_pages);

	for (int i = 0; i < num_pages; i++) {
		req_file.addresses[i] = (uintptr_t)(scratch_buf + i * PAGE_SIZE);
	}
	req_file.num_addresses = num_pages;

	if (strlen(src_path) < sizeof(req_file.file_name)) {
		strcpy(req_file.file_name, src_path);
	} else {
		return -ENAMETOOLONG;
	}

	char *dst_path = basename(src_path); // src_path mangled!
	int fd = creat(dst_path, flags);
	if (fd == -1) {
		fprintf(stderr, "[[hget]  Error opening file %s: %s\n", dst_path, strerror(errno));
		return errno;
	}

	unsigned long read = 0;
	unsigned long written = 0;
	do {
		read = hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA_BULK, (uintptr_t)&req_file);
		if (read == 0xFFFFFFFFFFFFFFFFUL) {
			fprintf(stderr, "[hget]  Could not get %s from sharedir. Check Qemu logs.\n",
			        req_file.file_name);
			ret = -EIO;
			goto err_out;
		}

		if (read != write(fd, scratch_buf, read)) {
			fprintf(stderr, "[hget]  Failed writing to %s: %s\n", dst_path, strerror(errno));
			ret = -EIO;
			goto err_out;
		}

		written += read;
		debug_printf("[hget]  %s => %s (read: %lu / written: %lu)\n",
		             req_file.file_name, dst_path, read, written);

	} while (read == scratch_size);

	fprintf(stderr, "[hget]  Successfully fetched %s (%lu bytes)\n", dst_path, written);

err_out:
	close(fd);
	free(scratch_buf);
	return ret;
}

int hpush_file(char *src_path, char *dst_name, int append)
{
	int fd = -1;
	int ret = 0;
	ssize_t total_sent = 0;
	ssize_t bytes = 0;

	uint8_t *scratch_buf = NULL;
	size_t scratch_size = 1024 * 1024;
	unsigned scratch_pages = scratch_size / PAGE_SIZE;

	kafl_dump_file_t put_req __attribute__((aligned(PAGE_SIZE)));

	fd = open(src_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "[hpush] Failed to open file %s: %s\n",
		        src_path, strerror(errno));
		ret = errno;
		goto err_out;
	}

	scratch_buf = malloc_resident_pages(scratch_pages);

	if (!scratch_buf) {
		fprintf(stderr, "[hpush] Failed to allocate file buffer for %s: %s\n",
		        src_path, strerror(errno));
		ret = errno;
		goto err_out;
	}

	put_req.file_name_str_ptr = (uintptr_t)dst_name;
	put_req.append = append;
	put_req.data_ptr = (uintptr_t)scratch_buf;

	do {
		bytes = read(fd, scratch_buf, scratch_size);
		hprintf("[hpush] %s => %s (%lu bytes)\n", src_path, dst_name, bytes);

		if (bytes == -1) {
			habort("hpush read error");
		} else if (bytes == 0) {
			break;
		} else if (bytes > 0) {
			put_req.bytes = bytes;
			kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&put_req);
			total_sent += bytes;
			// append any subsequent chunks
			put_req.append = 1;
		}
	} while (bytes > 0);

	hprintf("[hpush] %s => %s (%lu bytes)\n",
	        src_path, dst_name, total_sent);

err_out:
	free_resident_pages(scratch_buf, scratch_pages);
	close(fd);
	return ret;
}

int check_host_magic(int verbose)
{
	host_config_t host_config = { 0 };

	hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		fprintf(stdout, "[check] GET_HOST_CONFIG\n");
		fprintf(stdout, "[check]   host magic:  0x%x, version: 0x%x\n",
		        host_config.host_magic, host_config.host_version);
		fprintf(stdout, "[check]   bitmap size: 0x%x, ijon size: 0x%x\n",
		        host_config.bitmap_size, host_config.ijon_bitmap_size);
		fprintf(stdout, "[check]   payload size: %u KB\n",
		        host_config.payload_buffer_size/1024);
		fprintf(stdout, "[check]   worker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		fprintf(stderr,
		        "[check] HOST_MAGIC mismatch: %08x != %08x\n",
		        host_config.host_magic, NYX_HOST_MAGIC);
		return -1;
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		fprintf(stderr,
		        "[check] HOST_VERSION mismatch: %08x != %08x\n",
		        host_config.host_version, NYX_HOST_VERSION);
		return -1;
	}
	return 0;
}
