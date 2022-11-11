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

#include "util.h"


#define cpuid(in,a,b,c,d)\
	asm("cpuid": "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "a" (in));

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY)/sizeof((ARRAY)[0]))

#ifdef DEBUG
#define debug_printf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define debug_printf(fmt, ...)
#endif

typedef enum {
	nyx_cpu_none = 0,
	nyx_cpu_v1, /* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
} nyx_cpu_type_t;

struct cmd_table {
	char *name;
	int (*handler)(int, char**);
};

nyx_cpu_type_t nyx_cpu_type = nyx_cpu_none;

static int cmd_vmcall(int argc, char **argv);

static void usage()
{
	char *msg =
		"\nUsage: vmcall [cmd] [args...]\n\n"
		"\twhere cmd := { vmcall, hcat, habort, hget, hpush, hpanic, hrange }\n";

	fputs(msg, stderr);
}

static void usage_error(const char *msg)
{
	fputs(msg, stderr);
	usage();
}

static nyx_cpu_type_t get_nyx_cpu_type(void)
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

static unsigned long hypercall(unsigned id, uintptr_t arg)
{
	switch (nyx_cpu_type) {
		case nyx_cpu_v1:
			debug_printf("\t# vmcall(0x%x,0x%lx) ..\n", id, arg);
			return kAFL_hypercall(id, arg);
		case nyx_cpu_v2:
		case nyx_cpu_none:
			debug_printf("\t# vmcall(0x%x,0x%lx) skipped..\n", id, arg);
			return 0;
		default:
			assert(false);
	}
}

static size_t file_to_hprintf(FILE *f)
{
	size_t written = 0;
	size_t read = 0;

	static char hprintf_buffer[HPRINTF_MAX_SIZE] __attribute__((aligned(PAGE_SIZE)));

	while (!feof(f)) {
		read = fread(hprintf_buffer, 1, sizeof(hprintf_buffer), f);
		if (read < 0) {
			fprintf(stderr, "Error reading from file descriptor %d\n", fileno(f));
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
	
	if (file_is_ready(fileno(stdin))) {
		written += file_to_hprintf(stdin);
	}

	for (int i = optind; i < argc; i++) {
		f = fopen(argv[i], "r");
		if (!f) {
			fprintf(stderr, "Error opening file %s: %s\n", argv[optind], strerror(errno));
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
	if (argv[optind]) {
		debug_printf("[habort] msg := '%s'\n", argv[optind]);
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)argv[optind]);
	} else {
		debug_printf("[habort] msg := '%s'\n", "vmcall/habort called.");
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"vmcall/habort called.");
	}
	return 0;
}

static int cmd_hpanic(int argc, char **argv)
{
	if (argv[optind]) {
		hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)argv[optind]);
	} else {
		hypercall(HYPERCALL_KAFL_PANIC, 0);
	}
	return 0;
}

static int hget_file(char* src_path, mode_t flags)
{
	static req_data_bulk_t req_file __attribute((aligned(PAGE_SIZE)));

	int ret = 0;
	const int num_pages = 256; // 1MB at a time

	size_t scratch_size = num_pages * PAGE_SIZE;
	uint8_t *scratch_buf = malloc_resident_pages(num_pages);

	for (int i=0; i<num_pages; i++) {
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
		fprintf(stderr, "Error opening file %s: %s\n", dst_path, strerror(errno));
		return errno;
	}

	unsigned long read = 0;
	unsigned long written = 0;
	do {
		read = hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA_BULK, (uintptr_t)&req_file);
		if (read == 0xFFFFFFFFFFFFFFFFUL) {
			fprintf(stderr, "Could not get %s from sharedir. Check Qemu logs.\n",
					req_file.file_name);
			ret = -EIO;
			goto err_out;
		}

		if (read != write(fd, scratch_buf, read)) {
			fprintf(stderr, "Failed writing to %s: %s\n", dst_path, strerror(errno));
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

static int cmd_hget(int argc, char **argv)
{
	int ret = 0;
	char *dst_root = NULL;
	int opt;
	mode_t fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

	while ((opt = getopt(argc, argv, "xo:")) != -1) {
		switch (opt) {
			case 'x':
				fmode |= S_IXUSR | S_IXGRP | S_IXOTH;
				break;
			case 'o':
				dst_root = strdup(optarg);
				break;
			default:
				fprintf(stderr, "Usage: hget [-x] [-o path/to/dest/] file [file..]\n");
				return -EINVAL;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing argument: filename\n");
		return -EINVAL;
	}

	if (dst_root) {
		ret = chdir(dst_root);
		free(dst_root);
		if (ret != 0) {
			fprintf(stderr, "Failed to access %s: %s", dst_root, strerror(errno));
			return errno;
		}
	}

	for (int i = optind; i < argc && ret == 0; i++) {
		ret = hget_file(argv[i], fmode);
		if (ret != 0)
			break;
	}
	return ret;
}

static int hpush_file(char *src_path, char *dst_name, int append)
{
	struct stat st;
	uint8_t *scratch_buf = NULL;
	size_t scratch_len = 0;
	int fd = -1;
	int ret = 0;
	
	kafl_dump_file_t put_req __attribute__((aligned(PAGE_SIZE)));

	fd = open(src_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open file %s: %s\n",
				src_path, strerror(errno));
		ret = errno;
		goto err_out;
	}

	if (fstat(fd, &st) == -1) {
		fprintf(stderr, "Failed to stat file %s: %s\n",
				src_path, strerror(errno));
		ret = errno;
		goto err_out;

	}

	size_t file_size = st.st_size;
	size_t num_pages = file_size / PAGE_SIZE + 1;
	scratch_len = num_pages * PAGE_SIZE;
	scratch_buf = malloc_resident_pages(scratch_len);
	
	if (!scratch_buf) {
		fprintf(stderr, "Failed to allocate file buffer for %s: %s\n",
				src_path, strerror(errno));
		ret = errno;
		goto err_out;
	}

	// copy file to resident memory
	assert(file_size == read(fd, scratch_buf, file_size));

	if (!dst_name) {
		dst_name = basename(src_path);
	}

	put_req.file_name_str_ptr = (uintptr_t)dst_name;
	put_req.bytes = file_size;
	put_req.append = append;
	put_req.data_ptr = (uintptr_t)scratch_buf;

	debug_printf("[hpush] %s => %s (%lu bytes)\n",
			     src_path, dst_name, scratch_len);
	hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&put_req);

err_out:
	free_resident_pages(scratch_buf, scratch_len/PAGE_SIZE);
	close(fd);
	return ret;
}

static int cmd_hpush(int argc, char **argv)
{
	int ret = 0;
	bool append = 0;
	char *dst_name = NULL;
	int opt;
	
	while ((opt = getopt(argc, argv, "ao:")) != -1) {
		switch (opt) {
			case 'a':
				append = 1;
				break;
			case 'o':
				dst_name = strdup(optarg);
				break;
			default:
				fprintf(stderr, "Usage: hpush [-o dest_pattern] file\n");
				return -EINVAL;
		}
	}

	if (optind +1 != argc) {
		fprintf(stderr, "Need exactly one argument: file\n");
		return -EINVAL;
	}

	ret = hpush_file(argv[optind], dst_name, append);
	free(dst_name);
	return ret;
}

static int cmd_hrange(int argc, char **argv) { return 0; }

static int cmd_is_nyx(int argc, char **argv)
{
		return nyx_cpu_type;
}

/**
 * Call subcommand based on argv[0]
 */
static int cmd_dispatch(int argc, char **argv)
{
	const static struct cmd_table cmd_list[] = {
		{ "vmcall", cmd_vmcall },
		{ "hcat",   cmd_hcat   },
		{ "habort", cmd_habort },
		{ "hget",   cmd_hget   },
		{ "hpush",  cmd_hpush  },
		{ "hpanic", cmd_hpanic },
		{ "hrange", cmd_hrange },
		{ "is_nyx", cmd_is_nyx },
	};

	for (int i=0; i<ARRAY_SIZE(cmd_list); i++) {
		if (0 == strncmp(basename(argv[optind]), cmd_list[i].name, strlen(cmd_list[i].name))) {
			optind += 1; // increment argv offset
			return cmd_list[i].handler(argc, argv);
		}
	}
	return -EINVAL;
}

static int cmd_vmcall(int argc, char **argv)
{
	int ret = 0;

	// check if next arg is the actual command
	ret = cmd_dispatch(argc, argv);
	if (ret == -EINVAL) {
		// fallback vmcall action
		usage();
		return 0;
	}
	return ret;
}

int main(int argc, char **argv)
{
	int ret = 0;

	nyx_cpu_type = get_nyx_cpu_type();

	optind = 0; // start parsing at argv[0]
	ret = cmd_dispatch(argc, argv);

	if (ret == -EINVAL) {
		usage_error("Invalid command");
	}

	return ret;
}
