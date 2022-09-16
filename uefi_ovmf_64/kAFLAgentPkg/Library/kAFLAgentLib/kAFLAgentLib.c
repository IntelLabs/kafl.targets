/*
 * kAFL Agent Lib for UEFI OVMF
 *
 * Implements fuzzing harness based on kAFL hypercall API
 *
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

#include <Library/kAFLAgentLib.h>

#define PAYLOAD_MAX_SIZE (128*1024)

#ifndef KAFL_AGENT_EXTERNAL_AGENT_INIT
void agent_init(void *panic_handler, void *kasan_handler)
{
  volatile host_config_t host_config;

  DebugPrint (DEBUG_INFO, "Initiate fuzzer handshake...\n");

  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_ACQUIRE\n");
  kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
  DebugPrint (DEBUG_INFO, "HYPERCALL_KAFL_RELEASE\n");
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

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

  /* target-specific initialization, if any */
  DebugPrint (DEBUG_INFO, "Call InitTestHarness\n");
  InitTestHarness();
}
#endif

#ifndef KAFL_AGENT_EXTERNAL_AGENT_RUN
void agent_run()
{
  uint8_t buffer[PAYLOAD_MAX_SIZE + 0x1000];
  uint8_t *b = &buffer[0];
  DebugPrint (DEBUG_INFO, "before alignement %p\n", b);
  long int a = (long int)b;
  a = (a + 0x1000) & 0xfffffffffffff000L;
  b = (void *)(long int *)a;
  DebugPrint (DEBUG_INFO, "after alignement %p\n", b);
  kAFL_payload* payload_buffer = (kAFL_payload*)b;

  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint_ptr)payload_buffer);
  kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

  while (1) {
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    RunTestHarness(payload_buffer->data, payload_buffer->size);

    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
  }
  return;
}
#endif

#ifndef KAFL_AGENT_EXTERNAL_UEFI_MAIN
EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
  /* 
   * TODO find a function that kAFL can hook to detect protection faults / crashes.
   * Hooking the exception handler or DumpCpuContext helper does not seem to work..
   *
   * As a workaround, we currently require a patch to EDK2 to inject these hypercalls.
   */
  //agent_init(DumpCpuContext, 0);
  agent_init(NULL, NULL);
  agent_run();

  return EFI_SUCCESS;
}
#endif
