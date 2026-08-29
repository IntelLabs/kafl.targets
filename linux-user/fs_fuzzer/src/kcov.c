/*
 * kcov: code coverage for fuzzing
 * based on https://docs.kernel.org/dev-tools/kcov.html
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


#ifndef KCOV_DISABLE

#define KCOV_INIT_TRACE   _IOR('c', 1, unsigned long)
#define KCOV_ENABLE       _IO('c', 100)
#define KCOV_DISABLE      _IO('c', 101)
#define KCOV_COVER_SIZE   (64<<10)

unsigned long *kcov_buffer = NULL;
int kcov_fd = -1;

void kcov_reset()
{
	assert(kcov_fd != -1);
	assert(kcov_buffer);

    /* Reset coverage from the tail of the ioctl() call. */
    __atomic_store_n(&kcov_buffer[0], 0, __ATOMIC_RELAXED);
}

void kcov_collect()
{
    unsigned long n, i;

	assert(kcov_fd != -1);
	assert(kcov_buffer);

    /* Read number of PCs collected. */
    //n = __atomic_load_n(&kcov_buffer[0], __ATOMIC_RELAXED);
    //for (i = 0; i < n; i++)
    //        hprintf("0x%lx\n", kcov_buffer[i + 1]);

}

void kcov_init()
{
    /* A single fd descriptor allows coverage collection on a single
     * thread.
     */
    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd == -1)
            perror("open"), exit(1);

    /* Setup trace mode and trace size. */
    if (ioctl(kcov_fd, KCOV_INIT_TRACE, KCOV_COVER_SIZE))
            perror("ioctl"), exit(1);

    /* Mmap buffer shared between kernel- and user-space. */
    kcov_buffer = (unsigned long*)mmap(NULL, KCOV_COVER_SIZE * sizeof(unsigned long),
                                 PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);
    if ((void*)kcov_buffer == MAP_FAILED)
            perror("mmap"), exit(1);

    /* Enable coverage collection on the current thread. */
    if (ioctl(kcov_fd, KCOV_ENABLE, 0))
            perror("ioctl"), exit(1);

}

void kcov_cleanup()
{
    /* Disable coverage collection for the current thread. After this call
     * coverage can be enabled for a different thread.
     */
    if (ioctl(kcov_fd, KCOV_DISABLE, 0))
            perror("ioctl"), exit(1);

    /* Free resources. */
    if (munmap(kcov_buffer, KCOV_COVER_SIZE * sizeof(unsigned long)))
            perror("munmap"), exit(1);
    if (close(kcov_fd))
            perror("close"), exit(1);
}

#endif
