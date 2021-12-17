obj-m += kafl_vuln_test.o

LINUX_VERSION := $(shell uname -r)
#LINUX_VERSION := "5.4.0-72-generic"

all:
	make -C /lib/modules/$(LINUX_VERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(LINUX_VERSION)/build M=$(PWD) clean
