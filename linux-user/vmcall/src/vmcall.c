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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <errno.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/select.h>
#include <libgen.h>

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

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY)/sizeof((ARRAY)[0]))

enum nyx_cpu_type {
	nyx_cpu_none = 0,
	nyx_cpu_v1, /* Nyx CPU used by KVM-PT */
	nyx_cpu_v2  /* Nyx CPU used by vanilla KVM + VMWare backdoor */
};

struct cmd_table {
	char *name;
	int (*handler)(int, char**);
};

static int cmd_vmcall(int argc, char **argv);
static int cmd_hcat(int argc, char **argv);
static int cmd_habort(int argc, char **argv);
static int cmd_hget(int argc, char **argv);
static int cmd_hpush(int argc, char **argv);
static int cmd_hpanic(int argc, char **argv);
static int cmd_hrange(int argc, char **argv);

struct cmd_table cmd_list[] = {
	{ "vmcall", cmd_vmcall },
	{ "hcat",   cmd_hcat   },
	{ "habort", cmd_habort },
	{ "hget",   cmd_hget   },
	{ "hpush",  cmd_hpush  },
	{ "hpanic", cmd_hpanic },
	{ "hrange", cmd_hrange  },
};

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

static unsigned hypercall(unsigned id, uintptr_t arg)
{
	if (enable_vmcall) {
		return kAFL_hypercall(id, arg);
	} else {
		debug_printf("\t# vmcall(0x%x,0x%lx) skipped..\n", id, arg);
		return 0;
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

static size_t file_to_hprintf(FILE *f)
{
	size_t written = 0;
	size_t read = 0;

	while (!feof(f)) {
		read = fread(hprintf_buffer, 1, sizeof(hprintf_buffer), f);
		if (read <= 0) {
			fprintf(stderr, "Error reading from file descriptor %d", fileno(f));
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
	
	debug_printf("[hcat] start...\n");

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
	debug_printf("[habort] start...\n");

	if (argc > 0) {
		debug_printf("[habort] abort with '%s'\n", argv[optind]);
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)argv[optind]);
	} else {
		debug_printf("[habort] abort with '%s'\n", "vmcall/habort called.");
		hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"vmcall/habort called.");
	}

	return 0;
}

static int hget_file(char* src_path, char *dst_dir, mode_t flags)
{
	static req_data_bulk_t req_file __attribute((aligned(4096)));

	int ret = 0;
	char *dst_path = NULL;
	const int PAGE_SIZE = 0x1000;
	const int MAX_PAGES = 256; // 1MB at a time

	if (strlen(src_path) >= sizeof(req_file.file_name)) {
		return -ENAMETOOLONG;
	}

	strncpy(req_file.file_name, src_path, sizeof(req_file.file_name));

	if (!dst_dir) {
		dst_path = src_path;
	} else {
		assert(asprintf(&dst_path, "%s/%s", dst_dir, basename(src_path)));
	}

	int fd = creat(dst_path, flags);
	if (fd == -1) {
		fprintf(stderr, "Error opening file %s: %s\n", dst_path, strerror(errno));
		return errno;
	}

	size_t data_size = MAX_PAGES*PAGE_SIZE;
	uint8_t *data_ptr = NULL;

	if ((data_ptr = aligned_alloc(PAGE_SIZE, data_size)) == NULL) {
		fprintf(stderr, "Error file %s: %s\n", dst_path, strerror(errno));
		return errno;
	}

	if (((uintptr_t)data_ptr % PAGE_SIZE) != 0) {
		fprintf(stderr, "Allocated data buffer is not page aligned: %p. Abort.\n", data_ptr);
		return -ENOMEM;
	}

	if (mlock(data_ptr, data_size) == -1) {
		fprintf(stderr, "Error opening file %s: %s\n", dst_path, strerror(errno));
		return errno;
	}

	for (int i=0; i<MAX_PAGES; i++) {
		req_file.addresses[i] = (uintptr_t)data_ptr + i * PAGE_SIZE;
	}
	req_file.num_addresses = MAX_PAGES;

	unsigned long read = 0;
	unsigned long written = 0;

	while (true) {
		debug_printf("[hget]  Downloading %s => %s (bytes %lu/%lu)\n", req_file.file_name, dst_path, written, read);
		read = hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA_BULK, (uintptr_t)&req_file);
		if (read == 0xFFFFFFFFFFFFFFFFUL) {
			fprintf(stderr, "Failed to get stream data, check Qemu logs.\n");
			break;
		}
		if (read == written)
			break;
		written += write(fd, data_ptr, read-written);
	}

	free(data_ptr);

	return 0;
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
				fprintf(stderr, "Usage: hget [-x] [-o path/to/dest/] filename\n");
				return -EINVAL;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing argument: filename\n");
		return -EINVAL;
	}

	for (int i = optind; i < argc; i++) {
		char *filepath  = strdup(argv[i]);
		ret = hget_file(filepath, dst_root, fmode);
		free(filepath);
	}

	return 0;
}

//static void kafl_dump_observed_payload(char *filename, int append, uint8_t *buf, uint32_t buflen)
//{
//	static char fname_buf[128];
//	strncpy(fname_buf, filename, sizeof(fname_buf));
//	dump_file.file_name_str_ptr = (uint64_t)fname_buf;
//	dump_file.data_ptr = (uint64_t)buf;
//	dump_file.bytes = buflen;
//	dump_file.append = append;
//
//	kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&dump_file);
//}

static int cmd_hpush(int argc, char **argv)
{
	kafl_dump_file_t put_req;

	return 0;
}

static int cmd_hpanic(int argc, char **argv) { return 0; }

static int cmd_hrange(int argc, char **argv) { return 0; }

/**
 * Call subcommand based on argv[0]
 */
static int cmd_dispatch(int argc, char **argv)
{
	for (int i=0; i<ARRAY_SIZE(cmd_list); i++) {
		if (0 == strncmp(basename(argv[optind]), cmd_list[i].name, strlen(cmd_list[i].name))) {
			optind += 1; // increment argv offset
			return cmd_list[i].handler(argc, argv);
		}
	}
	return -1;
}

static int cmd_vmcall(int argc, char **argv)
{
	int ret = 0;

	debug_printf("[vmcall] start...\n");

	// check if next arg is the actual command
	ret = cmd_dispatch(argc, argv);

	// fallback vmcall action
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (nyx_cpu_v1 == get_nyx_cpu_type()) {
		fprintf(stderr, "VMCALL enabled.\n");
		enable_vmcall = true;
	} else {
		fprintf(stderr, "VMCALL disabled.\n");
	}

	optind = 0; // start parsing at argv[0]
	ret = cmd_dispatch(argc, argv);

	if (ret == -1) {
		usage_error("Invalid command");
	}

	return ret;
}
