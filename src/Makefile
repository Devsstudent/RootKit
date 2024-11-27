obj-m += rootkit.o

# liste des dependences
rootkit-objs := hide.o main_rootkit.o

KDIR 		:= $(PWD)/../linux-6.10.10/
SRC_DIR		:= $(PWD)/src

default: 
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean
