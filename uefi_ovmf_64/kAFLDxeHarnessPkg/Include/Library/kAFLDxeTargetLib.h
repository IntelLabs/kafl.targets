/*
 * Copyright 2021 Intel Corporation
 * 
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#ifndef _KAFL_DXE_TARGET_LIB_H_
#define _KAFL_DXE_TARGET_LIB_H_

#include <Uefi.h>

EFI_STATUS
EFIAPI
RunkAFLTarget (
    IN VOID *input,
    IN UINTN inputSize
    );

VOID
EFIAPI
InitkAFLTarget (VOID);

#endif//_KAFL_DXE_TARGET_LIB_H_
