NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)
KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)

all: debug

LIBNYX_AGENT_ROOT ?= $(EXAMPLES_ROOT)/linux-user/libnyx_agent
include $(LIBNYX_AGENT_ROOT)/Makefile.inc

CFLAGS += -Wall -I$(NYX_INCLUDE_PATH) -I$(LIBNYX_AGENT_INCLUDE)
LIBS += $(LIBNYX_AGENT_STATIC)

static: CFLAGS += -O2 -static
static: fs_fuzzer

debug: CFLAGS += -g -O0 -DDEBUG
debug: fs_fuzzer

asan: CFLAGS += -g -O0 -DDEBUG -fsanitize=address,undefined
asan: fs_fuzzer

release: static

../vmcall/vmcall:
	$(MAKE) -C $$(dirname $@)

fs_fuzzer: $(LIBNYX_AGENT_BUILD)
fs_fuzzer: src/fs_fuzzer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

fs_fuzzer.cpio.gz: fs_fuzzer ../vmcall/vmcall
	../scripts/gen_initrd.sh $@ $^

test: fs_fuzzer.cpio.gz fs_fuzzer seeds
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	#-ip0 81000000-81e01000 -ip1 828b5000-8290f000
	kafl_fuzz.py \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--memory 512 \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $$PWD/sharedir/ \
		--seed-dir $$PWD/seeds/ \
		-t 4 -ts 2 -tc -p 32 \
		--redqueen --grimoire --radamsa -D --funky \
		--purge --log-hprintf

seeds:
	mkdir seeds
	mkfs.ext4 seeds/test_256.ext4 256
	mkfs.ext4 seeds/test_260.ext4 260
	mkfs.ext4 seeds/test_280.ext4 280

clean:
	rm -f fs_fuzzer fs_fuzzer.cpio.gz
	rm -rf seeds

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
