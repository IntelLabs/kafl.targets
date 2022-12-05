all: debug

include ../Makefile.inc
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)
SHAREDIR ?= $$PWD/sharedir

TARGET=vmcall

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += $(LIBNYX_AGENT_STATIC)

release: static

static: CFLAGS += -static -O2
static: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: $(TARGET)

$(TARGET): $(LIBNYX_AGENT_BUILD)
$(TARGET): src/$(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(TARGET).cpio.gz: $(TARGET)
	../scripts/gen_initrd.sh $@ $^

run: $(TARGET).cpio.gz
	@# default kAFL config enables Linux serial console, see $$KAFL_WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--sharedir $(SHAREDIR) \
		--purge -v --log

test:
	$(MAKE) clean
	$(MAKE) debug
	$(MAKE) $(TARGET).cpio.gz
	@mkdir testshare
	@dd if=/dev/random bs=1k count=1024 of=testshare/test_1M.bin
	@dd if=/dev/random bs=1k count=2048 of=testshare/test_2M.bin
	@dd if=/dev/random bs=1b count=4097 of=testshare/test_4.1K.bin
	@dd if=/dev/random bs=1b count=4095 of=testshare/test_3.9K.bin
	@dd if=/dev/random bs=1b count=4096 of=testshare/test_4K.bin
	@dd if=/dev/random bs=1b count=2048 of=testshare/test_2K.bin
	@echo foobar > testshare/foo
	@cd testshare && md5sum test_*bin > test_md5sums
	@cp test_agent.sh testshare/agent.sh
	SHAREDIR=$$PWD/testshare $(MAKE) run
	@cp testshare/test_md5sums $(KAFL_WORKDIR)/dump/test_md5sums
	@cd $(KAFL_WORKDIR)/dump/ && md5sum -c test_md5sums || echo "hpush/hget fail!"
	@test $$(grep -c foobar $(KAFL_WORKDIR)/dump/foo) -eq 3 || echo "hcat fail!"

clean:
	rm -f $(TARGET) $(TARGET).cpio.gz
	rm -rf testshare

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
