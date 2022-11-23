NYX_INCLUDE_PATH ?= $(EXAMPLES_ROOT)

KERNEL_IMAGE ?= /boot/vmlinuz-$$(uname -r)
SHAREDIR ?= $$PWD/sharedir

CFLAGS += -g -O0 -I$(NYX_INCLUDE_PATH)

all: debug

static: CFLAGS += -static
static: vmcall

debug: CFLAGS += -fsanitize=address,undefined -DDEBUG
debug: vmcall

release: static

vmcall: src/vmcall.c src/nyx_agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

vmcall.cpio.gz: vmcall
	../scripts/gen_initrd.sh $@ $^

run: vmcall.cpio.gz
	@# default kAFL config enables Linux serial console, see $$WORKDIR/serial_00.log
	kafl_fuzz.py \
		--kernel $(KERNEL_IMAGE) \
		--initrd $< \
		--work-dir $$KAFL_WORKDIR \
		--sharedir $(SHAREDIR) \
		--purge -v --log

test:
	$(MAKE) clean
	$(MAKE) debug
	$(MAKE) vmcall.cpio.gz
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
	@cp testshare/test_md5sums $$KAFL_WORKDIR/dump/test_md5sums
	@cd $$KAFL_WORKDIR/dump/ && md5sum -c test_md5sums || echo "hpush/hget fail!"
	@test $$(grep -c foobar $$KAFL_WORKDIR/dump/foo) -eq 3 || echo "hcat fail!"

clean:
	rm -f vmcall
	rm -rf testshare

tags:
	ctags -R src $(NYX_INCLUDE_PATH)/nyx_api.h

.PHONY: tags test clean
