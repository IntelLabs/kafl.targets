NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)
KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

all: test

LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += -ldl $(LIBNYX_AGENT_STATIC)

TARGET=syz-agent

$(TARGET).cpio.gz: ../vmcall/vmcall syzkaller/bin/linux_amd64/syz-stress
	../scripts/gen_initrd.sh $@ $^

test: $(TARGET).cpio.gz sharedir
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 1024 \
		--sharedir $$PWD/sharedir \
		--purge --log -t 4 -ts 2 --log-hprintf -p 4

sharedir: ../vmcall/vmcall
#sharedir: syzkaller/bin/linux_amd64/syz-stress
sharedir: syzkaller/bin/linux_amd64/syz-executor
sharedir:
	mkdir -p sharedir
	ln -sf ../agent.sh sharedir/agent.sh
	cp $^ sharedir/


clean:
	rm -rf sharedir $(TARGET).cpio.gz

