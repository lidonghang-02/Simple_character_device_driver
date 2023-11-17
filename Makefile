ifneq ($(KERNELRELEASE),)
obj-m:=encryption.o
else
KDIR :=/lib/modules/$(shell uname -r)/build
PWD  :=$(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.c *.symvers *.c~ *~ *mod *.order .encryption.* .modules.* .Module.* 
endif