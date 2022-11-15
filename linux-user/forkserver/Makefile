NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

CFLAGS += -Wall -Werror -I$(NYX_INCLUDE_PATH)
LIBS += -ldl

TARGET=forkserver

all: debug

# may have to inject via LD_PRELOAD="/lib/x86_64-linux-gnu/libasan.so.5:/fuzz/forkserver.so"
asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: LIBS += -lasan
asan: $(TARGET).so

debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET).so

release: CFLAGS += -g -Og
release: $(TARGET).so

$(TARGET).so: src/$(TARGET).c ../vmcall/src/nyx_agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC $^ -o $@ $(LIBS)

../vmcall/vmcall:
	$(MAKE) -C ../vmcall

$(TARGET).cpio.gz: $(TARGET).so ../vmcall/vmcall /usr/bin/bison
	../scripts/gen_initrd.sh $@ $^

test: $(TARGET).cpio.gz $(TARGET).so
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl_fuzz.py \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $$PWD \
		--purge -v --log -t 5 -ts 4 --log-hprintf

clean:
	rm -f $(TARGET).so $(TARGET).cpio.gz

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
