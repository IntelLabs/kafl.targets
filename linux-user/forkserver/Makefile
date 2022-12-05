all: debug

include ../Makefile.inc
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)
SHAREDIR ?= $$PWD

TARGET=forkserver

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += -ldl $(LIBNYX_AGENT_STATIC)

# may have to inject via LD_PRELOAD="/lib/x86_64-linux-gnu/libasan.so.5:/fuzz/forkserver.so"
asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: LIBS += -lasan
asan: $(TARGET).so

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET).so

release: CFLAGS += -g -Og
release: $(TARGET).so

$(TARGET).so: $(LIBNYX_AGENT_BUILD)
$(TARGET).so: src/$(TARGET).c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC $^ -o $@ $(LIBS)

../vmcall/vmcall:
	$(MAKE) -C ../vmcall

$(TARGET).cpio.gz: $(TARGET).so ../vmcall/vmcall /usr/bin/bison
	../scripts/gen_initrd.sh $@ $^

test: $(TARGET).cpio.gz $(TARGET).so
	# default kAFL config enables Linux serial console, see $$KAFL_WORKDIR/serial_00.log
	kafl fuzz \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--sharedir $(SHAREDIR) \
		--purge -t 2 -ts 1 --log-hprintf

clean:
	rm -f $(TARGET).so $(TARGET).cpio.gz

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
