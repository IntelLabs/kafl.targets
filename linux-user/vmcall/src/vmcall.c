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

#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

#include <nyx_api.h>

#include <nyx_agent.h>
//#include "utils.h"

struct cmd_table {
	char *name;
	int (*handler)(int, char **);
};

static void usage()
{
	char *msg = "\nUsage: vmcall [cmd] [args...]\n\n"
	            "\twhere cmd := { check, hcat, hget, hpush, habort, hpanic, hrange, hlock }\n";

	fputs(msg, stderr);
}

static void usage_error(const char *msg)
{
	fputs(msg, stderr);
	usage();
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
	size_t written = 0;

	if (!isatty(fileno(stdin))) {
		written += hprintf_from_file(stdin);
	}

	for (int i = optind; i < argc; i++) {
		f = fopen(argv[i], "r");
		if (!f) {
			fprintf(stderr, "[hcat]  Error opening file %s: %s\n", argv[optind], strerror(errno));
			return written;
		} else {
			written += hprintf_from_file(f);
		}
	}

	debug_printf("[hcat]  %zd bytes written.\n", written);
	return (written > 0);
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

	if (optind + 1 != argc) {
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
	uint64_t range_id;
	uint64_t range_start;
	uint64_t range_end;

	for (int i = optind; i < argc; i++) {
		if (3 != sscanf(argv[i], "%lu,%lx-%lx", &range_id, &range_start, &range_end)) {
			fprintf(stderr, "Usage: hrange id,start-end [id,start-end...]");
			return -EINVAL;
		}
		if (range_id > 3) {
			fprintf(stderr, "[hrange] Error: Range id must be in [0-3].\n");
			return -EINVAL;
		}
		if (range_start >= range_end) {
			fprintf(stderr, "[hrange] Error: Range start >= end.\n");
			return -EINVAL;
		}
		if ((range_end & 0xfff) != 0) {
			uint64_t rounded = (range_end / PAGE_SIZE + 1) * PAGE_SIZE;
			fprintf(stderr, "[hrange] Rounding up to page boundary: 0x%08lx => 0x%08lx\n",
			        range_end, rounded);
			range_end = rounded;
		}
		if ((range_start & 0xfff) != 0) {
			uint64_t rounded = range_start - (range_start % PAGE_SIZE);
			fprintf(stderr, "[hrange] Rounding down to page boundary: 0x%08lx => 0x%08lx\n",
			        range_start, rounded);
			range_start = rounded;
		}

		fprintf(stderr, "[hrange] Submit range %lu: 0x%08lx-0x%08lx\n",
		        range_id, range_start, range_end);
		hrange_submit(range_id, range_start, range_end);
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
	default:
		fprintf(stderr, "[check] Error: Invalid CPU type %d\n", nyx_cpu_type);
		return nyx_cpu_none;
		break;
	}

	if (nyx_cpu_type != nyx_cpu_none) {
		if (0 != check_host_magic(verbose)) {
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

	for (int i = 0; i < ARRAY_SIZE(cmd_list); i++) {
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
