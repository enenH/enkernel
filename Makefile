MODULE_NAME = dfm
$(MODULE_NAME)-objs := main.o mem.o process_mem.o touch.o touch_v2.o syscall.o kgsl.o dfm_hwb.o udp_capture.o file_io.o fd_query.o sf_groups.o futex.o pte_bp.o
obj-m := $(MODULE_NAME).o

ccflags-y += -Wno-unused-function -Wno-declaration-after-statement -Wno-gcc-compat

# Inspect the selected kernel tree: vendors backport swap ABI changes.
ifneq ($(wildcard $(srctree)/mm/swap_state.c),)
ccflags-y += $(shell sh $(src)/scripts/detect_swap_reader.sh $(srctree)/mm/swap_state.c)
ifneq ($(shell grep -l 'extern void swap_free_nr' $(srctree)/include/linux/swap.h),)
ccflags-y += -DDFM_SWAP_FREE_NR
endif
ifneq ($(shell grep -l 'folio_lock_killable' $(srctree)/include/linux/pagemap.h),)
ccflags-y += -DDFM_SWAP_FOLIO_LOCKS
endif
endif

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

.PHONY: all clean
