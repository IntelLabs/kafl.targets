#include <windows.h>
#include "nyx_api.h"

#define PAYLOAD_SIZE 128 * 1024

void fuzzme(uint8_t*, int);
void end();


static inline void panic(void){
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while(1){}; /* halt */
}

kAFL_payload* kafl_agent_init(void) {
    // initial fuzzer handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // submit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // get host config
    host_config_t host_config = {0};
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
	hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size/1024);
	hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    SIZE_T buffer_size = 64 * si.dwPageSize;
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, buffer_size)){
        hprintf("[+] WARNING: Virtuallock failed on payload buffer %lp...\n", payload_buffer);
        kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

    // submit buffer
    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // filters
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // submit agent config
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    return payload_buffer;
}


int main(int argc, char** argv){
    hprintf("[+] Starting... %s\n", argv[0]);

    kAFL_payload* payload_buffer = kafl_agent_init();

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);
 
    hprintf("[+] Locking fuzzing ranges...\n");
    for(int i = 0; i < 4; i++){
        hprintf("[+] Range %d enabled: %x\t(%p-%p)\n", i, (uint8_t)range_buffer->enabled[i], range_buffer->ip[i], range_buffer->size[i]);
        if (range_buffer->ip[i] != 0){
            if (!VirtualLock((LPVOID)range_buffer->ip[i], range_buffer->size[i])){
                hprintf("[+] WARNING: VirtualLock failed on range %d...\n", (uint8_t)range_buffer->enabled[i]);
                kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
            }
            else{
                hprintf("[+] Range %d locked\n", (uint8_t)range_buffer->enabled[i]);
            }
        }
    }

    hprintf("[+] Range: 0x%p-0x%p\n", fuzzme, end);

    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    fuzzme(payload_buffer->data, payload_buffer->size);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    return 0;
}


void fuzzme(uint8_t* input, int size){
    if (size > 0x11){
        if(input[0] == 'K')
            if(input[1] == '3')
                if(input[2] == 'r')
                    if(input[3] == 'N')
                        if(input[4] == '3')
                            if(input[5] == 'l')
                                if(input[6] == 'A')
                                    if(input[7] == 'F')
                                        if(input[8] == 'L')
                                            if(input[9] == '#')
                                                panic();

        if(input[0] == 'P')
            if(input[1] == 'w')
                if(input[2] == 'n')
                    if(input[3] == 'T')
                        if(input[4] == '0')     
                            if(input[5] == 'w')     
                                if(input[6] == 'n')
                                    if(input[7] == '!')
                                        panic();

    }
};

void end(){}
