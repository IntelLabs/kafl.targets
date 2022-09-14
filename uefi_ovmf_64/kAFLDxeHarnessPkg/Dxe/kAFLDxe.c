#include "kAFLDxe.h"

#include <Protocol/kAFLDxe.h>

#include <Library/kAFLAgentLib.h>
#include <Library/kAFLDxeTargetLib.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>

#define PAYLOAD_MAX_SIZE (128*1024)
#define PAYLOAD_MAX_DATA_SIZE (PAYLOAD_MAX_SIZE - \
    ((unsigned long int)(&((kAFL_payload *)(void *)0)->data)) \
    - \
    ((unsigned long int)(&((kAFL_payload *)(void *)0)->size)) \
)

// Communication buffer
kAFL_payload* payload_buffer;

// Protocol interface handle
EFI_HANDLE mkAFLDxeHandle = NULL;

void HarnessInit(void *panic_handler, void *kasan_handler)
{
  volatile host_config_t host_config;

  DebugPrint (DEBUG_INFO, "Initiate fuzzer handshake...\n");

  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_ACQUIRE\n");
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");

  /* submit panic and optionally kasan handlers for qemu
   * override */
  if (panic_handler) {
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, (uint_ptr)panic_handler);
  }

  if (kasan_handler) {
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, (uint_ptr)kasan_handler);
  }

  hprintf("Fuzzer handshake done\n");

  kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

  if (host_config.host_magic != NYX_HOST_MAGIC ||
      host_config.host_version != NYX_HOST_VERSION) {

    hprintf("host_config magic/version mismatch hm: 0x%08x, "
        "hv: 0x%08x, am: 0x%08x, av: 0x%08x!\n", host_config.host_magic,
        host_config.host_version, NYX_HOST_MAGIC, NYX_HOST_VERSION);
    habort("GET_HOST_CONFIG magic/version mismatch!\n");

  }
  hprintf("\thost_config.bitmap_size: 0x%lx\n",
      host_config.bitmap_size);
  hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n",
      host_config.ijon_bitmap_size);
  hprintf("\thost_config.payload_buffer_size: 0x%lx\n",
      host_config.payload_buffer_size);

  if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
    hprintf("Host payload buffer requested size is too large, "
        "please build the harness with a larger one!\n");
    habort("GET_HOST_CONFIG harness payload buffer too small\n");
  }

  /* submit agent configuration */
  volatile agent_config_t agent_config = {0};

  agent_config.agent_magic = NYX_AGENT_MAGIC;
  agent_config.agent_version = NYX_AGENT_VERSION;

  agent_config.agent_tracing = 0; // trace by host!
  agent_config.agent_ijon_tracing = 0; // no IJON
  agent_config.agent_non_reload_mode = 1; // allow persistent
  agent_config.coverage_bitmap_size = host_config.bitmap_size;

  hprintf("Sending agent configuration\n");
  kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
  hprintf("End send agent configuration\n");
}

void HarnessRun(void) {
  DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in heap 0x%016lx\n",
      (void*)payload_buffer);

  DebugPrint (DEBUG_INFO, "Payload size as pages: 0x%x\n",
      EFI_SIZE_TO_PAGES(PAYLOAD_MAX_SIZE));

  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_GET_PAYLOAD\n");
  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint_ptr)payload_buffer);

  DebugPrint (DEBUG_INFO, "Payload [%x, %x, %x, %x]\n",
      payload_buffer->data[0],
      payload_buffer->data[1],
      payload_buffer->data[2],
      payload_buffer->data[3]);

  // No CR3 filtering
  DebugPrint (DEBUG_INFO, "No CR3 filtering, crossing SMM boudaries\n");

  DebugPrint (DEBUG_INFO, "Main loop go !\n");
  DebugPrint (DEBUG_INFO, "@HarnessRun(0x%016lx)\n", HarnessRun);

  // The loop is not really required anymore thanks to snapshots
  while (1) {
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    RunkAFLTarget(payload_buffer->data, payload_buffer->size);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
  }

  return;
}

//
// kAFL Dxe Protocol
//
EFI_KAFL_DXE_PROTOCOL gkAFLDxe = {
  kAFLDxeNoop,
  kAFLDxeFuzz,
};

EFI_STATUS
EFIAPI
kAFLDxeNoop (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "kAFLDxe: NOOP!\n"));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
kAFLDxeFuzz (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "kAFLDxe: FUZZ!\n"));

  DEBUG ((DEBUG_INFO, "SmmDxeFuzz: Calling HarnessRun...\n"));
  HarnessRun();

  return EFI_SUCCESS;
}


/**
  The driver's entry point.

  kAFL DXE driver working in conjunction with SMM one

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point is executed successfully.
  @retval Others          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializekAFLDxe (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  DEBUG ((DEBUG_INFO, "Loading kAFLDxePkg DXE_DRIVER!\n"));

  //
  // Allocate memory for variable communicate buffer.
  //
//   mkAFLBufferSize = SMM_COMMUNICATE_HEADER_SIZE +
//     SMM_KAFL_COMMUNICATE_HEADER_SIZE + PAYLOAD_MAX_DATA_SIZE;
//   mkAFLBuffer = AllocateRuntimePool(mkAFLBufferSize);
//   ASSERT (mkAFLBuffer != NULL);

  // Save physical address which is BTW the same because of UEFI id mapping
//   mkAFLBufferPhysical = mkAFLBuffer;

  //
  // Install kAFL Dxe Protocol
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mkAFLDxeHandle,
                  &gEfikAFLDxeProtocolGuid, &gkAFLDxe,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Allocate memory for kAFL payload buffer
  //
  payload_buffer = AllocatePages(EFI_SIZE_TO_PAGES(PAYLOAD_MAX_SIZE));
  DebugPrint (DEBUG_INFO, "Mapping info: kAFL buffer in stack 0x%016lx\n",
      (void*)payload_buffer);

  DEBUG ((DEBUG_INFO, "SmmkAFLHandler: init kAFL...\n"));
  HarnessInit(NULL, NULL);

  DEBUG ((DEBUG_INFO, "kAFLDxePkg DXE_DRIVER loaded and ready to be used!\n"));

  return Status;
}
