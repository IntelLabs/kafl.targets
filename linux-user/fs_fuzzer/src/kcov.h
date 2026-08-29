/*
 * kcov: code coverage for fuzzing
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define KCOV_DISABLE

#ifndef KCOV_DISABLE
void kcov_init();
void kcov_cleanup();
void kcov_collect();
void kcov_reset();
#else
#define kcov_init()
#define kcov_cleanup()
#define kcov_collect()
#define kcov_reset()
#endif
