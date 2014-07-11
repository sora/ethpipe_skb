ifneq ($(KERNELRELEASE),)
obj-m		:= genpipe0.o genpipe1.o
else
KDIR		:= /lib/modules/$(shell uname -r)/build/
PWD		:= $(shell pwd)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) V=1 modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean 

install:
	install -m 644 $(PWD)/*.ko /lib/modules/`uname -r`/kernel/drivers/misc
	if [ -d /etc/udev/rules.d -a ! -f /etc/udev/rules.d/99-genpipe.rules ] ; then \
		install -m 644 99-genpipe.rules /etc/udev/rules.d ; \
	fi
	depmod -a
endif
