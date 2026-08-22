obj-m += exploit.o
KDIR ?= $(CURDIR)/../optee-fvp/linux
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules ARCH=arm64 CROSS_COMPILE=$(CURDIR)/../optee-fvp/toolchains/aarch64/bin/aarch64-linux-gnu-
