MAKEF_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
VMCALL_DIR := ${EXAMPLES_ROOT}/linux-user/vmcall
VMCALL_BIN := $(VMCALL_DIR)/vmcall
TARGET := $(MAKEF_DIR)/kafl_initrd.cpio.gz

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f $(TARGET)

# build vmcall if needed
$(VMCALL_BIN):
	$(MAKE) -C $(VMCALL_DIR)

# gen_initrd.sh depends on vmcall
$(TARGET): $(MAKEF_DIR)/gen_initrd.sh $(VMCALL_BIN) 
	$< $@ $(VMCALL_BIN)
