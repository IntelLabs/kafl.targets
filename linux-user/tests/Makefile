all: debug

include ../Makefile.inc
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)
SHAREDIR ?= $$PWD

TARGET=test_addr_translation

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

initrd.cpio.gz: ../vmcall/vmcall
	../scripts/gen_initrd.sh $@ $^

test: initrd.cpio.gz $(TARGET)
	# default kAFL config enables Linux serial console, see $$KAFL_WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 3583 \
		--sharedir $(SHAREDIR) \
		--purge -t 4 --debug --log

clean:
	rm -f $(TARGET) initrd.cpio.gz

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
