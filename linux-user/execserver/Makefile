NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

TARGET=execserver

all: debug

LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += -ldl $(LIBNYX_AGENT_STATIC)

# may have to inject via LD_PRELOAD="/lib/x86_64-linux-gnu/libasan.so.5:/fuzz/execserver"
asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: LIBS += -lasan
asan: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

release: CFLAGS += -g -Og
release: $(TARGET)

$(TARGET): $(LIBNYX_AGENT_BUILD)
$(TARGET): src/$(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

../vmcall/vmcall:
	$(MAKE) -C ../vmcall

$(TARGET).cpio.gz: $(TARGET) ../vmcall/vmcall /usr/bin/bison
	../scripts/gen_initrd.sh $@ $^

test: $(TARGET).cpio.gz $(TARGET)
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--sharedir $$PWD \
		--trace --purge -t 2 --log-hprintf

clean:
	rm -f $(TARGET).so $(TARGET).cpio.gz

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
