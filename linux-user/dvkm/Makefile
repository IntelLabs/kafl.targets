ifndef KAFL_ROOT
$(error KAFL_ROOT is not set. Run "make env" at kAFL root repository)
endif

MAKEF_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# Paths
EXAMPLES_ROOT := $(KAFL_ROOT)/examples
LINUX_AGENT_DIR := $(EXAMPLES_ROOT)/linux-user/linux_kafl_agent
GEN_INITRD_DIR := $(EXAMPLES_ROOT)/linux-user/scripts
DVKM_DIR := $(MAKEF_DIR)/Damn_Vulnerable_Kernel_Module

# Artifacts
LINUX_AGENT_BZIMAGE := $(LINUX_AGENT_DIR)/arch/x86/boot/bzImage
KAFL_INITRD_PATH := $(GEN_INITRD_DIR)/kafl_initrd.cpio.gz
DVKM_PATH := $(DVKM_DIR)/dvkm.ko
TEST_DVKM := $(DVKM_DIR)/test_dvkm

# Configuration options for kernel build
CONFIG_OPTS := \
	--disable MODULE_SIG \
	--enable DEBUG_INFO_DWARF5 \
	--enable GDB_SCRIPTS

ifdef DVKM_KASAN
CONFIG_OPTS += --enable KASAN --enable KASAN_INLINE
endif

.PHONY: all clean fuzz module initrd links

# Default target
all: $(KAFL_INITRD_PATH) $(LINUX_AGENT_BZIMAGE) $(DVKM_PATH) links

# Build kernel bzImage
$(LINUX_AGENT_BZIMAGE):
	$(MAKE) -C $(LINUX_AGENT_DIR) x86_64_defconfig
	cd $(LINUX_AGENT_DIR) && ./scripts/config $(CONFIG_OPTS)
	$(MAKE) -C $(LINUX_AGENT_DIR) olddefconfig
	$(MAKE) -C $(LINUX_AGENT_DIR) -j $(shell nproc)

# Build initrd
$(KAFL_INITRD_PATH):
	$(MAKE) -C $(GEN_INITRD_DIR)

# Build dvkm.ko (and test_dvkm)
$(DVKM_PATH):
	$(MAKE) -C $(DVKM_DIR) KRN_SOURCES=$(LINUX_AGENT_DIR)

# Create symlinks in sharedir/
links:
	mkdir -p $(MAKEF_DIR)/sharedir
	ln -sf $(DVKM_PATH) $(MAKEF_DIR)/sharedir/dvkm.ko
	ln -sf $(TEST_DVKM) $(MAKEF_DIR)/sharedir/fuzz_dvkm

# Clean all
clean:
	-$(MAKE) -C $(GEN_INITRD_DIR) $@
	-$(MAKE) -C $(DVKM_DIR) KRN_SOURCES=$(LINUX_AGENT_DIR) $@
	-$(MAKE) -C $(LINUX_AGENT_DIR) $@

# Run fuzzer
fuzz: all
	kafl fuzz --purge
