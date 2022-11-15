/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "nyx_api.h"

#define ASAN_EXIT_CODE 101
//#define REDIRECT_STDERR_TO_HPRINTF
//#define REDIRECT_STDOUT_TO_HPRINTF

#if defined(REDIRECT_STDERR_TO_HPRINTF) || defined(REDIRECT_STDOUT_TO_HPRINTF)
	char hprintf_buffer[HPRINTF_MAX_SIZE];
#endif

extern uint8_t stdin_mode;
extern char *output_filename;

extern uint32_t memlimit;

int _mlock(void *dst, size_t size)
{
	syscall(SYS_mlock, dst, size);
}

long int random(void)
{
	return 0;
}

int rand(void)
{
	return 0;
}

int __libc_start_main(int (*main) (int,char **,char **),
              int argc,char **ubp_av,
              void (*init) (void),
              void (*fini)(void),
              void (*rtld_fini)(void),
              void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
                    int argc,char **ubp_av,
                    void (*init) (void),
                    void (*fini)(void),
                    void (*rtld_fini)(void),
                    void (*stack_end)) = NULL;

	struct rlimit r;
	int fd, fd2 = 0;
	int pipefd[2];
	int ret = pipe(pipefd);

#ifdef REDIRECT_STDERR_TO_HPRINTF
	int pipe_stderr_hprintf[2];
	ret = pipe(pipe_stderr_hprintf);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
	int pipe_stdout_hprintf[2];
	ret = pipe(pipe_stdout_hprintf);
#endif

	struct iovec iov;
	int pid;
	int status = 0;
	int res = 0;
	int i;

	r.rlim_max = (rlim_t)(memlimit << 20);
	r.rlim_cur = (rlim_t)(memlimit << 20);

	original__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");

	dup2(open("/dev/null", O_WRONLY), STDOUT_FILENO);
	dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);

	if (!stdin_mode) {
		dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);
	}

	kAFL_payload *payload_buffer =
		mmap((void *)NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(payload_buffer, 0x00, PAYLOAD_SIZE);
	_mlock((void *)payload_buffer, (size_t)PAYLOAD_SIZE);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

#if defined(__i386__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

	while (1) {
		pid = fork();

		if (!pid) {
			if (stdin_mode) {
				pipe(pipefd);
			} else {
				fd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC);
			}

			kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

			if (stdin_mode) {
				iov.iov_base = payload_buffer->data;
				iov.iov_len = payload_buffer->size;

				ret = vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);
				dup2(pipefd[0], STDIN_FILENO);
				close(pipefd[1]);
			} else {
				write(fd, payload_buffer->data, payload_buffer->size);
				close(fd);
			}

#ifdef REDIRECT_STDERR_TO_HPRINTF
			dup2(pipe_stderr_hprintf[1], STDERR_FILENO);
			close(pipe_stderr_hprintf[0]);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			dup2(pipe_stdout_hprintf[1], STDOUT_FILENO);
			close(pipe_stdout_hprintf[0]);
#endif

#ifndef ASAN_BUILD
			/* disable setrlimtit in case of ASAN builds... */
			setrlimit(RLIMIT_AS, &r);
#endif
			struct itimerval timer;
			if (payload_buffer->redqueen_mode) {
				timer.it_value.tv_sec = 10;
				timer.it_value.tv_usec = 0;
			} else {
				timer.it_value.tv_sec = 0;
				timer.it_value.tv_usec = 200;
			}
			timer.it_interval.tv_sec = 0;
			timer.it_interval.tv_usec = 0;
			setitimer(ITIMER_VIRTUAL, &timer, NULL);

			return original__libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

		} else if (pid > 0) {
#ifdef REDIRECT_STDERR_TO_HPRINTF
			close(pipe_stderr_hprintf[1]);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			close(pipe_stdout_hprintf[1]);
#endif
			waitpid(pid, &status, WUNTRACED);

#ifdef REDIRECT_STDERR_TO_HPRINTF
			hprintf("------------STDERR-----------\n");
			while (read(pipe_stderr_hprintf[0], hprinf_buffer, HPRINTF_MAX_SIZE)) {
				hprintf(" => %s\n", hprintf_buffer);
			}
			hprintf("-----------------------------n");
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
			hprintf("------------STDDOUT-----------\n");
			while (read(pipe_stdout_hprintf[0], hprintf_buffer, HPRINTF_MAX_SIZE)) {
				hprintf(" => %s\n", hprintf_buffer);
			}
			hprintf("-----------------------------n");
#endif

			if (WIFSIGNALED(status)) {
				if (WTERMSIG(status) == SIGVTALRM) {
					hprintf("TIMEOUT found\n");
					kAFL_hypercall(HYPERCALL_KAFL_TIMEOUT, 1);
				} else {
					kAFL_hypercall(HYPERCALL_KAFL_PANIC, 1);
				}
			} else if (WEXITSTATUS(status) == ASAN_EXIT_CODE) {
				kAFL_hypercall(HYPERCALL_KAFL_KASAN, 1);
			}
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		} else {
			hprintf("FORK FAILED ?!\n");
		}
	}
}
