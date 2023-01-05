#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include "nyx_api.h"

int main(int argc, char** argv){ 
    uint64_t pages = sysconf(_SC_PHYS_PAGES);
    uint64_t free_pages = sysconf(_SC_AVPHYS_PAGES);
    uint64_t page_size = sysconf(_SC_PAGE_SIZE);
    uint64_t total_memory = pages * page_size;
    uint64_t free_memory = free_pages * page_size;

    printf("[*] _SC_PHYS_PAGES:   %ld\n", pages);
    printf("[*] _SC_AVPHYS_PAGES: %ld\n", free_pages);
    printf("[*] _SC_PAGE_SIZE:    %ld\n", total_memory);

    /* we leave some memory free in order to not trigger the OOM killer */
    if (free_memory >= (1024*1024*170)){
        free_memory -= (1024*1024*170);
    }

    free_memory &= ~0xFFFULL;

    printf("[*] free_memory total size: 0x%lx\n", free_memory);

    void* memory = mmap((void*)NULL, free_memory, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (memory == (void*)-1){
        perror("Error ");
    }

    printf("[*] mmap mapping at: %p\n", memory);

    mlockall(MCL_CURRENT);

    memset(memory, 0xff, free_memory);

    mlockall(MCL_CURRENT);

    for (uint64_t page = 0; page < free_memory; page += page_size){
        kAFL_hypercall(HYPERCALL_KAFL_DEBUG_TMP_SNAPSHOT, (uint64_t)(memory+page) | 7 );

        if(*((uint64_t*)(memory+page)) != (uint64_t)memory+page){
            printf("[!] ERROR: 0x%lx\n", *((uint64_t*)(memory+page)));
            printf("[!] EXPECTED: %p\n", memory+page);
            exit(1);
        }
    }

    printf("[*] all tests passed!\n");

    return 0;
}

