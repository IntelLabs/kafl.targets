NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)
KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

all: debug

LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += -ldl $(LIBNYX_AGENT_STATIC)

TARGET=syz-agent

debug:


sharedir: syzkaller/bin/linux_amd64/syz-stress
sharedir: syzkaller/bin/linux_amd64/syz-executor
sharedir:
	mkdir -p sharedir
	cp $^ sharedir/


clean:
	rm -rf sharedir

