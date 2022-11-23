NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

CFLAGS += -g -O0 -I$(NYX_INCLUDE_PATH)

all: debug

static: CFLAGS += -static
static: vmcall

debug: CFLAGS += -fsanitize=address,undefined -DDEBUG
debug: vmcall

release: static

vmcall: src/vmcall.c src/util.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

vmcall.cpio.gz: vmcall
	../scripts/gen_initrd.sh $@ $^

test: vmcall.cpio.gz
	# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl_fuzz.py \
		--kernel /boot/vmlinuz-$$(uname -r) \
		--initrd $^ \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $$PWD/testshare \
		--purge -v --log

clean:
	rm -f vmcall

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
