NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

CFLAGS += -g -O0 -I$(NYX_INCLUDE_PATH)

all: debug

static: CFLAGS += -static
static: fs_fuzzer

debug: CFLAGS += -fsanitize=address,undefined -DDEBUG
debug: fs_fuzzer

release: static

fs_fuzzer: src/fs_fuzzer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

fs_fuzzer.cpio.gz: fs_fuzzer agent.sh
	../scripts/gen_initrd.sh $@ $^

test: fs_fuzzer.cpio.gz
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl_fuzz.py \
		--kernel /boot/vmlinuz-$$(uname -r) \
		--initrd $^ \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $$(pwd) \
		--purge -v --log

clean:
	rm -f fs_fuzzer

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
