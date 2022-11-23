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

static void usage()
{
	char *msg =
		"\nUsage: vmcall [cmd] [args...]\n\n"
		"\twhere cmd := { check, hcat, hget, hpush, habort, hpanic, hrange, hlock }\n";

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
	
	//debug_printf("CPUID string: >>%s<<\n", str);

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
			fprintf(stderr, "[hcat]  Error opening file %s: %s\n", argv[optind], strerror(errno));
			return written;
		} else {
			written += file_to_hprintf(f);
		}
	}

	debug_printf("[hcat]  %zd bytes written.\n", written);
	return (written > 0);
}

static void habort_msg(char *msg) {
	hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)msg);
}

static int cmd_habort(int argc, char **argv)
{
	if (argv[optind]) {
		debug_printf("[habort] msg := '%s'\n", argv[optind]);
		habort_msg(argv[optind]);
	} else {
		debug_printf("[habort] msg := '%s'\n", "vmcall/habort called.");
		habort_msg("vmcall/habort called.");
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
		fprintf(stderr, "[hget]  Missing argument: filename\n");
		return -EINVAL;
	}

	if (dst_root) {
		ret = chdir(dst_root);
		free(dst_root);
		if (ret != 0) {
			fprintf(stderr, "[hget]  Failed to access %s: %s", dst_root, strerror(errno));
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

int hpush_file(char *src_path, char *dst_name, int append)
{
	int fd = -1;
	int ret = 0;
	ssize_t total_sent = 0;
	ssize_t bytes = 0;

	uint8_t *scratch_buf = NULL;
	size_t scratch_size = 1024*1024;
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
		fprintf(stderr, "[hpush] Need exactly one argument: file\n");
		return -EINVAL;
	}
	
	char *src_path = argv[optind];

	if (dst_name) {
		ret = hpush_file(src_path, dst_name, append);
	} else {
		dst_name = strdup(src_path);
		ret = hpush_file(src_path, basename(dst_name), append);
	}
	free(dst_name);
	return ret;
}

static int cmd_hrange(int argc, char **argv)
{
	int ret = 0;

	typedef struct {
		uint64_t start;
		uint64_t end;
		uint64_t num;
	} kafl_range_t;

	kafl_range_t range __attribute__((aligned(PAGE_SIZE)));

	for (int i = optind; i < argc; i++) {
		if (3 != sscanf(argv[i], "%lu,%lx-%lx",
					    &range.num, &range.start, &range.end)) {
			fprintf(stderr, "Usage: hrange id,start-end [id,start-end...]");
			return -EINVAL;
		}
		if (range.num > 3) {
			fprintf(stderr, "[hrange] Error: Range id must be in [0-3].\n");
			return -EINVAL;
		}
		if (range.start >= range.end) {
			fprintf(stderr, "[hrange] Error: Range start >= end.\n");
			return -EINVAL;
		}
		if ((range.end & 0xfff) != 0) {
			uint64_t rounded = (range.end / PAGE_SIZE + 1) * PAGE_SIZE;
			fprintf(stderr, "[hrange] Rounding up to page boundary: 0x%08lx => 0x%08lx\n",
					range.end, rounded);
			range.end = rounded;
		}
		if ((range.start & 0xfff) != 0) {
			uint64_t rounded = range.start - (range.start % PAGE_SIZE);
			fprintf(stderr, "[hrange] Rounding down to page boundary: 0x%08lx => 0x%08lx\n",
					range.start, rounded);
			range.start = rounded;
		}

		fprintf(stderr, "[hrange] Submit range %lu: 0x%08lx-0x%08lx\n",
				range.num, range.start, range.end);
		hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)&range);
	}
	return 0;
}

static int check_host_config(int verbose)
{
	host_config_t host_config = { 0 };

	hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		fprintf(stderr, "[check] GET_HOST_CONFIG\n");
		fprintf(stderr, "[check]   host magic:  0x%x, version: 0x%x\n", host_config.host_magic, host_config.host_version);
		fprintf(stderr, "[check]   bitmap size: 0x%x, ijon:    0x%x\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
		fprintf(stderr, "[check]   payload size: %u KB\n", host_config.payload_buffer_size/1024);
		fprintf(stderr, "[check]   worker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		fprintf(stderr, "[check] HOST_MAGIC mismatch: %08x != %08x\n",
				host_config.host_magic, NYX_HOST_MAGIC);
		return -1;
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		fprintf(stderr, "[check] HOST_VERSION mismatch: %08x != %08x\n",
				host_config.host_version, NYX_HOST_VERSION);
		return -1;
	}
	return 0;
}

static int cmd_check(int argc, char **argv)
{
	int verbose = 1;

	switch (nyx_cpu_type) {
		case nyx_cpu_v1:
			fprintf(stderr, "[check] Detected NYX vCPU (PT)\n");
			break;
		case nyx_cpu_v2:
			fprintf(stderr, "[check] Detected NYX vCPU (NO-PT)\n");
			break;
		case nyx_cpu_none:
			fprintf(stderr, "[check] Detected No Nyx support :-(\n");
			break;
	}

	if (nyx_cpu_type != nyx_cpu_none) {
		if (0 != check_host_config(verbose)) {
			habort_msg("[check] Incompatible host magic or version.");
			return -nyx_cpu_type; /* won't reach */
		}
	}

	return nyx_cpu_type;
}

static int cmd_hlock()
{
	fprintf(stderr, "[hlock] Triggering pre-snapshot...\n");
	hypercall(HYPERCALL_KAFL_LOCK, 0);
	return 0;
}

/**
 * Call subcommand based on argv[0]
 */
static int cmd_vmcall(int argc, char **argv);
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
		{ "hlock",  cmd_hlock  },
		{ "check",  cmd_check  },
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
