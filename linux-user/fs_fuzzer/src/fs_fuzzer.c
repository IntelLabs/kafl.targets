/*
 * Copyright (C) 2017 Sergej Schumilo
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/mount.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <linux/version.h>
#include <linux/loop.h>

#include "nyx_api.h"
#include "nyx_agent.h"

#define PAGE_SIZE 4096
#define KAFL_TMP_FILE "/tmp/trash"
#define PAYLOAD_MAX_SIZE (1 * 1024 * 1024)

#define CHECK_ERRNO(x, msg)                                                \
	do {                                                               \
		if (!(x)) {                                                \
			fprintf(stderr, "%s: %s\n", msg, strerror(errno)); \
			habort(msg);                                       \
			exit(1);                                           \
		}                                                          \
	} while (0)

static inline void kill_systemd(void)
{
	system("systemctl disable systemd-udevd");
	system("systemctl stop systemd-udevd");
	system("systemctl stop systemd-udevd-kernel.socket");
	system("systemctl stop systemd-udevd-control.socket");

	system("/lib/systemd/systemctl disable systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd");
	system("/lib/systemd/systemctl stop systemd-udevd-kernel.socket");
	system("/lib/systemd/systemctl stop systemd-udevd-control.socket");
}

int agent_init(int verbose)
{
	host_config_t host_config;
	
	// set ready state
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		fprintf(stderr, "GET_HOST_CONFIG\n");
		fprintf(stderr, "\thost magic:  0x%x, version: 0x%x\n",
			host_config.host_magic, host_config.host_version);
		fprintf(stderr, "\tbitmap size: 0x%x, ijon:    0x%x\n",
			host_config.bitmap_size, host_config.ijon_bitmap_size);
		fprintf(stderr, "\tpayload size: %u KB\n",
			host_config.payload_buffer_size / 1024);
		fprintf(stderr, "\tworker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		hprintf("HOST_MAGIC mismatch: %08x != %08x\n",
			host_config.host_magic, NYX_HOST_MAGIC);
		habort("HOST_MAGIC mismatch!");
		return -1;
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		hprintf("HOST_VERSION mismatch: %08x != %08x\n",
			host_config.host_version, NYX_HOST_VERSION);
		habort("HOST_VERSION mismatch!");
		return -1;
	}

	if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
		hprintf("Fuzzer payload size too large: %lu > %lu\n",
			host_config.payload_buffer_size, PAYLOAD_MAX_SIZE);
		habort("Host payload size too large!");
		return -1;
	}

	agent_config_t agent_config = { 0 };
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	//agent_config.agent_timeout_detection = 0; // timeout by host
	//agent_config.agent_tracing = 0; // trace by host
	//agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 0; // no persistent mode
	//agent_config.trace_buffer_vaddr = 0xdeadbeef;
	//agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
	agent_config.coverage_bitmap_size = host_config.bitmap_size;
	//agent_config.input_buffer_size;
	//agent_config.dump_payloads; // set by hypervisor (??)

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG,
		       (uintptr_t)&agent_config);

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	char loopname[4096];
	int loopctlfd, loopfd, backingfile;
	long devnr;
	char *filesystemtype = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: fs_fuzzer <fstype>\n"
				"(For valid fstype options, see /proc/filesystems.\n)");
		hprintf("Usage: fs_fuzzer <fstype>");
		exit(1);
	}
	filesystemtype = argv[1];

	system("mkdir -p /tmp/a/");

	//kill_systemd();

	kAFL_payload *pbuf = malloc_resident_pages(PAYLOAD_MAX_SIZE / PAGE_SIZE);
	assert(pbuf);

	loopctlfd = open("/dev/loop-control", O_RDWR);
	CHECK_ERRNO(loopctlfd != -1, "Failed to open /dev/loop-control");

	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	CHECK_ERRNO(devnr != -1, "Failed to get free loop device");

	sprintf(loopname, "/dev/loop%ld", devnr);
	close(loopctlfd);

	agent_init(1);

	//kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0); // need kernel CR3!
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)pbuf);

	loopfd = open(loopname, O_RDWR);
	CHECK_ERRNO(loopfd != -1, "Failed to open loop device");

	backingfile = open(KAFL_TMP_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	CHECK_ERRNO(backingfile != -1, "Failed to open backing file");

	ret = ioctl(loopfd, LOOP_SET_FD, backingfile);
	CHECK_ERRNO(ret != -1, "Failed to ioctl(LOOP_SET_FD)");

	pbuf->size = 20;

	while (1) {
		static unsigned long mountflags = 0;


		if ((size_t)pbuf->size > sizeof(mountflags)) {
			//memcpy(&mountflags, pbuf->data, sizeof(mountflags));

			ret = lseek(backingfile, 0, SEEK_SET);
			CHECK_ERRNO(ret != -1, "Failed to seek in backingfile");
			ret = write(backingfile, pbuf->data, pbuf->size);
			CHECK_ERRNO(ret != -1, "Failed to write backingfile");
			if (ret != pbuf->size) {
				hprintf("Incomplete write to backingfile");
			}
			ioctl(loopfd, LOOP_SET_CAPACITY, 0);
			CHECK_ERRNO(ret != -1, "Failed to ioctl(LOOP_SET_CAPACITY");

			ret = mount(loopname, "/tmp/a/", filesystemtype, mountflags, NULL);

			if (ret != 0) {
				//hprintf("mount() => %d: %s\n", ret, strerror(errno));
				//system("dmesg -c |vmcall hcat");
			} else {
				struct stat st = { 0 };
				hprintf("mount() => success!\n");
				mkdir("/tmp/a/trash", 0700);
				stat("/tmp/a/trash", &st);
				umount2("/tmp/a", MNT_FORCE);
			}
		}

		// first round for warmup - real start now
		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

	}

	close(backingfile);
	return 0;
}
