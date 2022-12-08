ifeq ($(KAFL_WORKDIR),)
$(error $$KAFL_WORKDIR is not set - did you activate kAFL env?)
endif

# set your own KERNEL_TREE for make build, or own KERNEL_IMAGE for make fuzz
KERNEL_TREE ?= linux-guest
KERNEL_CONFIG ?= $(KERNEL_TREE)/.config
KERNEL_IMAGE ?= $(KERNEL_TREE)/arch/x86/boot/bzImage

all: test

$(KERNEL_TREE):
	# modified kernel with example input injection, hooked printk + crash handlers
	git clone -b kafl/fuzz-5.15-4 https://github.com/IntelLabs/kafl.linux.git $@

$(KERNEL_CONFIG): $(KERNEL_TREE)
	cp config.vanilla.virtio $@
	$(MAKE) -C $< olddefconfig

build: $(KERNEL_TREE) $(KERNEL_CONFIG)
	$(MAKE) -C $<

fuzz: $(KERNEL_IMAGE)
	KAFL_CONFIG_FILE=kafl_config.yaml \
	kafl fuzz --purge -p 4 \
		--kernel $(KERNEL_IMAGE) \
		--memory 1024 \
		-t 0.1 -ts 0.01 \
		--log --log-crashes

plot:
	kafl plot

test:
	# basic smoke test. build, run, and check that we found some crashes
	$(MAKE) build
	$(MAKE) fuzz KAFL_ABORT_EXEC=20000 KAFL_ABORT_TIME=0.1
	$(MAKE) plot |tee plot.txt
	test $$(grep -c exit=R plot.txt) -gt 100
	test $$(grep -c exit=K plot.txt) -le $$(ls $$KAFL_WORKDIR/logs/kasan_*|wc -l)


.PHONY: tags test clean plot gui 
