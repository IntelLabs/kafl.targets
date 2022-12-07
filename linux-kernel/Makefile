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
	kafl fuzz --purge -p 2 \
		--kernel $(KERNEL_IMAGE) \
		--memory 1024 \
		--log --log-crashes

plot:
	kafl plot

test:
	# basic smoke test. build, run, and check that we found some crashes
	$(MAKE) build
	$(MAKE) fuzz KAFL_ABORT_EXEC=2000 KAFL_ABORT_TIME=0.1
	$(MAKE) plot |tee plot.txt
	test $$(grep -c exit=C plot.txt) -gt 10
	test $$(grep -c exit=C plot.txt) -le $$(ls $$KAFL_WORKDIR/logs/crash_*|wc -l)


.PHONY: tags test clean plot gui 
