/*

Copyright (C) 2017 Robert Gawlik

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "../../../nyx_api.h"
#include <psapi.h>


#define ARRAY_SIZE 1024

#define INFO_SIZE                       (128 << 10)				/* 128KB info string */

#define PAYLOAD_MAX_SIZE (128*1024)

#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)


PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}   


UINT64 resolve_KeBugCheck(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck){
                        printf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else{
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64) KeBugCheck;
}


void init_agent_handshake() {

    hprintf("Initiate fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // Submit our CR3
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // Tell KAFL we're running in 64bit mode
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilites (not optional) */
	volatile host_config_t host_config;
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
	if (host_config.host_magic != NYX_HOST_MAGIC ||
	    host_config.host_version != NYX_HOST_VERSION) {
		hprintf("host_config magic/version mismatch!\n");
		habort("GET_HOST_CNOFIG magic/version mismatch!\n");
	}
	hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
	hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
	hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* reserved guest memory must be at least as large as host SHM view */
	if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
		habort("Insufficient guest payload buffer!\n");
	}

    /* submit agent configuration */
	volatile agent_config_t agent_config = {0};
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;

	agent_config.agent_tracing = 0; // trace by host!
	agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 1; // allow persistent
	agent_config.coverage_bitmap_size = host_config.bitmap_size;

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

}


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

void set_ip_range() {
    char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(info_buffer, 0xff, INFO_SIZE);
    memset(info_buffer, 0x00, INFO_SIZE);
    int pos = 0;

   LPVOID drivers[ARRAY_SIZE];
   DWORD cbNeeded;
   int cDrivers, i;
   NTSTATUS status;

   if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
   { 
        TCHAR szDriver[ARRAY_SIZE];

        cDrivers = cbNeeded / sizeof(drivers[0]);
        PRTL_PROCESS_MODULES ModuleInfo;
 
        ModuleInfo=(PRTL_PROCESS_MODULES)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
     
        if(!ModuleInfo){
            goto fail;
        }
     
        if(!NT_SUCCESS(status=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,ModuleInfo,1024*1024,NULL))){
            VirtualFree(ModuleInfo,0,MEM_RELEASE);
            goto fail;
        }

        pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n", cDrivers);
        //_tprintf(TEXT("kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n"), cDrivers);      
        pos += sprintf(info_buffer + pos, "START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n");
        //_tprintf(TEXT("START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n"));      
        for (i=0; i < cDrivers; i++ ){
            pos += sprintf(info_buffer + pos, "0x%p\t0x%p\t%s\n", drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            if(strstr(ModuleInfo->Modules[i].FullPathName,"nyx_test") > 0 ) {
                uint64_t buffer[3];
                buffer[0] = drivers[i];
                buffer[1] = drivers[i] + ModuleInfo->Modules[i].ImageSize;
                buffer[2] = 0;
                kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)buffer);
                return;
            }
            //_tprintf(TEXT("0x%p\t0x%p\t%s\n"), drivers[i], drivers[i]+ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        }
   }
   else {
        goto fail;
   }
   fail:
        printf("FAIL! NO MATCH!\n");
        exit(1);
}

void init_panic_handlers() {
    UINT64 panic_kebugcheck = 0x0;
    UINT64 panic_kebugcheck2 = 0x0;
    panic_kebugcheck = resolve_KeBugCheck(kernel_func1);
    panic_kebugcheck2 = resolve_KeBugCheck(kernel_func2);
    hprintf("Submitting bug check handlers\n");
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
}

int main(int argc, char** argv)
{
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
    //LPVOID payload_buffer = (LPVOID)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0x0, PAYLOAD_MAX_SIZE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    BOOL status = -1;
    kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\testKafl",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        printf("[-] KAFL test: Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0);
    }

    init_agent_handshake();

    init_panic_handlers();

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // Submit PT ranges
    set_ip_range();

    // Snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

    /* request new payload (*blocking*) */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 

    /* kernel fuzzing */
    DeviceIoControl(kafl_vuln_handle,
        IOCTL_KAFL_INPUT,
        (LPVOID)(payload_buffer->data),
        (DWORD)payload_buffer->size,
        NULL,
        0,
        NULL,
        NULL
    );

    /* inform fuzzer about finished fuzzing iteration */
    // Will reset back to start of snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    

    return 0;
}

