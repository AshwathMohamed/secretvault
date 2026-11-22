# SPDX-License-Identifier: GPL-2.0-only
# builds the kernel module secretvault.ko from the three .c files below
obj-m += secretvault.o
secretvault-y := sv_main.o sv_pt.o sv_debugfs.o

# KDIR = headers/build folder of the running kernel (override with: make KDIR=/path/to/headers)
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
