all: debug

include ../Makefile.inc
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)
SHAREDIR ?= $$PWD/sharedir

TARGET=fs_fuzzer

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += $(LIBNYX_AGENT_STATIC)

release: static

static: CFLAGS += -static -O2
static: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: $(TARGET)

../vmcall/vmcall:
	$(MAKE) -C $$(dirname $@)

$(TARGET): $(LIBNYX_AGENT_BUILD)
$(TARGET): src/$(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

$(TARGET).cpio.gz: $(TARGET) ../vmcall/vmcall
	../scripts/gen_initrd.sh $@ $^

test: $(TARGET).cpio.gz $(TARGET) seeds
	@# default kAFL config enables Linux serial console, see $$KAFL_WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--sharedir $(SHAREDIR) \
		--seed-dir $$PWD/seeds/ \
		-t 4 -ts 2 -tc -p 2 \
		--redqueen --grimoire --radamsa -D --funky \
		--purge --log-hprintf

seeds:
	mkdir seeds
	mkfs.ext4 seeds/test_256.ext4 256
	mkfs.ext4 seeds/test_260.ext4 260
	mkfs.ext4 seeds/test_280.ext4 280

clean:
	rm -f $(TARGET) $(TARGET).cpio.gz
	rm -rf seeds

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
