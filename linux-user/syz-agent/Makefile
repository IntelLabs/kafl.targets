NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)
KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

all: test

LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += -ldl $(LIBNYX_AGENT_STATIC)

TARGET=syz-agent

$(TARGET).cpio.gz: ../vmcall/vmcall
	../scripts/gen_initrd.sh $@ $^

../vmcall/vmcall:
	$(MAKE) -C ../vmcall

../forkserver/forkserver.so:
	$(MAKE) -C ../forkserver

test: $(TARGET).cpio.gz sharedir
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl_fuzz.py \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $$PWD/sharedir \
		--purge -t 2 -ts 1 --log-hprintf

sharedir: ../vmcall/vmcall
sharedir: ../forkserver/forkserver.so
sharedir: syzkaller/bin/linux_amd64/syz-stress
sharedir: syzkaller/bin/linux_amd64/syz-executor
sharedir:
	mkdir -p sharedir
	ln -s ../agent.sh sharedir/agent.sh
	cp $^ sharedir/


clean:
	rm -rf sharedir

