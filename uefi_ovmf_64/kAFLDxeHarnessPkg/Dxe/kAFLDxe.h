/** @file
  The header file for kAFL driver.
**/

#ifndef __KAFL_DXE_PKG_H__
#define __KAFL_DXE_PKG_H__

EFI_STATUS
EFIAPI
kAFLDxeNoop (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxePrint (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxePf (
  VOID
  );

EFI_STATUS
EFIAPI
kAFLDxeFuzz (
  VOID
  );

#endif//__KAFL_DXE_PKG_H__
