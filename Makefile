MODULE_NAME = dfm
$(MODULE_NAME)-objs := main.o mem.o process_mem.o touch.o touch_v2.o syscall.o kgsl.o dfm_hwb.o udp_capture.o file_io.o sf_groups.o
obj-m := $(MODULE_NAME).o

ccflags-y += -Wno-unused-function -Wno-declaration-after-statement -Wno-gcc-compat

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
