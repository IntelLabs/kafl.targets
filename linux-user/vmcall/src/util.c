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

#include <stdio.h>
#include <string.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <errno.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/select.h>

#include "util.h"

void* malloc_resident_pages(size_t num_pages)
{
	size_t data_size = PAGE_SIZE * num_pages;
	void *ptr = NULL;

	if ((ptr = aligned_alloc(PAGE_SIZE, data_size)) == NULL) {
		fprintf(stderr, "Allocation failure: %s\n", strerror(errno));
		goto err_out;
	}

	// ensure pages are aligned and resident
	assert(((uintptr_t)ptr % PAGE_SIZE) == 0);
	memset(ptr, 0x42, data_size);
	if (mlock(ptr, data_size) == -1) {
		fprintf(stderr, "Error locking scratch buffer: %s\n", strerror(errno));
		goto err_out;
	}

	return ptr;
err_out:
	free(ptr);
	return NULL;
}

void free_resident_pages(void *buf, size_t num_pages)
{
	if (buf) {
		munlock(buf, num_pages);
		free(buf);
	}
}

bool file_is_ready(int fd)
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

