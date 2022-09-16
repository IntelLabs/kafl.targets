/** @file
  EFI DXE Variable Protocol is related to EDK II-specific implementation of variables
  and intended for use as a means to store data in the EFI DXE environment.

  Copyright (c) 2010 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __KAFL_DXE_H__
#define __KAFL_DXE_H__

#define EFI_KAFL_DXE_PROTOCOL_GUID \
  { \
    0xc2520636, 0x8d4b, 0x456f, { 0xbe, 0x46, 0x93, 0x5e, 0xf0, 0x6f, 0x8a, 0xd3 } \
  }

typedef struct _EFI_KAFL_DXE_PROTOCOL EFI_KAFL_DXE_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *EFI_KAFL_DXE_NOOP)(
  VOID
  );

typedef
EFI_STATUS
(EFIAPI *EFI_KAFL_DXE_FUZZ)(
  VOID
  );

///
/// EFI DXE Variable Protocol is intended for use as a means
/// to store data in the EFI DXE environment.
///
struct _EFI_KAFL_DXE_PROTOCOL {
  EFI_KAFL_DXE_NOOP kAFLDxeNoop;
  EFI_KAFL_DXE_FUZZ kAFLDxeFuzz;
};

extern EFI_GUID gEfikAFLDxeProtocolGuid;

#endif
