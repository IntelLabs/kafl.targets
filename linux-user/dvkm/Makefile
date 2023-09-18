MAKEF_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
# kafl_initrd.cpio.gz
GEN_INITRD_DIR := ${EXAMPLES_ROOT}/linux-user/scripts
KAFL_INITRD_PATH := $(GEN_INITRD_DIR)/kafl_initrd.cpio.gz
# dvkm.ko
DVKM_DIR := $(MAKEF_DIR)/Damn_Vulnerable_Kernel_Module
DVKM_PATH := $(DVKM_DIR)/dvkm.ko

# depend on
# - kafl_initrd.cpio.gz in linux-user/scripts/
# - dvkm.ko
all: $(KAFL_INITRD_PATH) $(DVKM_PATH)
	$(MAKE) -C $(GEN_INITRD_DIR)
	ln -sf ../Damn_Vulnerable_Kernel_Module/dvkm.ko $(MAKEF_DIR)/sharedir/dvkm.ko
	ln -sf ../Damn_Vulnerable_Kernel_Module/test_dvkm $(MAKEF_DIR)/sharedir/fuzz_dvkm

clean:
	$(MAKE) -C $(GEN_INITRD_DIR) $@
	$(MAKE) -C $(DVKM_DIR) $@

fuzz: all
	kafl fuzz --purge


# how to build kafl_initrd.cpio.gz
$(KAFL_INITRD_PATH):
	$(MAKE) -C $(GEN_INITRD_DIR)

# how to build dvkm.ko
$(DVKM_PATH):
	cd $(DVKM_DIR) && $(MAKE)

.PHONY: clean fuzz
