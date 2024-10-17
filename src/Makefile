obj-m += rootkit.o

KDIR 		:= $(PWD)/../linux-6.11
SRC_DIR		:= $(PWD)/src

default: 
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean