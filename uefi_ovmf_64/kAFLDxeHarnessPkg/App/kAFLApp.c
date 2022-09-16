/** @file
  This is kAFL harness shell application
**/

#include <Uefi.h>

#include <Protocol/kAFLDxe.h>

#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

EFI_STATUS EFIAPI UefiMain (IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS Status;

  Print(L"System Table address: 0x%08x\n", SystemTable);

  EFI_KAFL_DXE_PROTOCOL *kAFLDxe;
  Status = gBS->LocateProtocol (
                  &gEfikAFLDxeProtocolGuid,
                  NULL,
                  (VOID **)&kAFLDxe
                  );
  ASSERT_EFI_ERROR (Status);

  kAFLDxe->kAFLDxeNoop();
  kAFLDxe->kAFLDxeFuzz();

  return EFI_SUCCESS;
}
