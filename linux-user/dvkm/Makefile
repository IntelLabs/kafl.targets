MAKEF_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
# linux kafl agent
LINUX_AGENT_DIR := ${EXAMPLES_ROOT}/linux-user/linux_kafl_agent
LINUX_AGENT_BZIMAGE := $(LINUX_AGENT_DIR)/arch/x86/boot/bzImage
# kafl_initrd.cpio.gz
GEN_INITRD_DIR := ${EXAMPLES_ROOT}/linux-user/scripts
KAFL_INITRD_PATH := $(GEN_INITRD_DIR)/kafl_initrd.cpio.gz
# dvkm.ko
DVKM_DIR := $(MAKEF_DIR)/Damn_Vulnerable_Kernel_Module
DVKM_PATH := $(DVKM_DIR)/dvkm.ko

# depend on
# - kafl_initrd.cpio.gz in linux-user/scripts/
# - dvkm.ko
all: $(KAFL_INITRD_PATH) $(LINUX_AGENT_BZIMAGE) $(DVKM_PATH)
	$(MAKE) -C $(GEN_INITRD_DIR)
	ln -sf ../Damn_Vulnerable_Kernel_Module/dvkm.ko $(MAKEF_DIR)/sharedir/dvkm.ko
	ln -sf ../Damn_Vulnerable_Kernel_Module/test_dvkm $(MAKEF_DIR)/sharedir/fuzz_dvkm

clean:
	$(MAKE) -C $(GEN_INITRD_DIR) $@
	$(MAKE) -C $(DVKM_DIR) $@
	$(MAKE) -C $(LINUX_AGENT_DIR) $@

fuzz: all
	kafl fuzz --purge

# how to build bzImage
$(LINUX_AGENT_BZIMAGE):
	$(MAKE) -C $(LINUX_AGENT_DIR) x86_64_defconfig
	cd $(LINUX_AGENT_DIR) && ./scripts/config --disable MODULE_SIG
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable DEBUG_INFO_DWARF5
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable GDB_SCRIPTS
ifdef DVKM_KASAN
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable KASAN
	cd $(LINUX_AGENT_DIR) && ./scripts/config --enable KASAN_INLINE
endif
	$(MAKE) -C $(LINUX_AGENT_DIR) olddefconfig
	$(MAKE) -C $(LINUX_AGENT_DIR) -j $(shell nproc)

# how to build kafl_initrd.cpio.gz
$(KAFL_INITRD_PATH):
	$(MAKE) -C $(GEN_INITRD_DIR)

# how to build dvkm.ko
$(DVKM_PATH):
	cd $(DVKM_DIR) && KRN_SOURCES=$(LINUX_AGENT_DIR) $(MAKE)

.PHONY: clean fuzz
