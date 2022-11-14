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

#include <linux/version.h>
#include <linux/loop.h>

#include "nyx_api.h"

#define KAFL_TMP_FILE "/tmp/trash"
#define PAYLOAD_MAX_SIZE (2 ^ 16)

#define EXT4

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

static inline uint64_t get_address(char *identifier)
{
	FILE *fp;
	char *line = NULL;
	ssize_t read;
	ssize_t len;
	char *tmp;
	uint64_t address = 0x0;
	uint8_t identifier_len = strlen(identifier);

	fp = fopen("/proc/kallsyms", "r");
	if (fp == NULL) {
		return address;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		if (strlen(line) > identifier_len &&
		    !strcmp(line + strlen(line) - identifier_len, identifier)) {
			address = strtoull(strtok(line, " "), NULL, 16);
			break;
		}
	}

	fclose(fp);
	if (line) {
		free(line);
	}
	return address;
}

int agent_init(int verbose)
{
	host_config_t host_config;

	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		fprintf(stderr, "GET_HOST_CONFIG\n");
		fprintf(stderr, "\thost magic:  0x%x, version: 0x%x\n", host_config.host_magic);
		fprintf(stderr, "\tbitmap size: 0x%x, ijon:    0x%x\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
		fprintf(stderr, "\tpayload size: %u KB\n", host_config.payload_buffer_size/1024);
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

	agent_config_t agent_config = { 0 };
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	//agent_config.agent_timeout_detection = 0; // timeout by host
	//agent_config.agent_tracing = 0; // trace by host
	//agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 1; // allow persistent mode
	//agent_config.trace_buffer_vaddr = 0xdeadbeef;
	//agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
	agent_config.coverage_bitmap_size = host_config.bitmap_size;;
	//agent_config.input_buffer_size;
	//agent_config.dump_payloads; // set by hypervisor (??)

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

	return 0;
}

int main(int argc, char **argv)
{
	struct stat st = { 0 };
	int fd, ret;
	char loopname[4096];
	int loopctlfd, loopfd, backingfile;
	long devnr;

	kAFL_payload *payload_buffer = mmap((void *)NULL, PAYLOAD_MAX_SIZE,
					    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(payload_buffer, 0xff, PAYLOAD_MAX_SIZE);

	kill_systemd();

	system("mkdir /tmp/a/");
	loopctlfd = open("/dev/loop-control", O_RDWR);
	devnr = ioctl(loopctlfd, LOOP_CTL_GET_FREE);
	sprintf(loopname, "/dev/loop%ld", devnr);
	close(loopctlfd);

	agent_init(1);

	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload_buffer);

	hprintf("printk: %lx\n", get_address("T printk\n"));
	kAFL_hypercall(HYPERCALL_KAFL_PRINTK_ADDR, get_address("T printk\n"));

	loopfd = open(loopname, O_RDWR);
	backingfile = open(KAFL_TMP_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
	ioctl(loopfd, LOOP_SET_FD, backingfile);

	while (1) {
		lseek(backingfile, 0, SEEK_SET);
		kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
		write(backingfile, payload_buffer->data,
		      payload_buffer->size - 4);
		ioctl(loopfd, LOOP_SET_CAPACITY, 0);

		kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
#ifdef EXT4
		ret = mount(loopname, "/tmp/a/", "ext4",
			    payload_buffer->data[payload_buffer->size - 4],
			    NULL);
#elif NTFS
		ret = mount(loopname, "/tmp/a/", "ntfs",
			    payload_buffer->data[payload_buffer->size - 4],
			    NULL);
#elif FAT32
		ret = mount(loopname, "/tmp/a/", "vfat", 0x1, NULL);
#endif
		if (!ret) {
			mkdir("/tmp/a/trash", 0700);
			stat("/tmp/a/trash", &st);
			umount2("/tmp/a", MNT_FORCE);
		}
		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
	close(backingfile);
	return 0;
}
