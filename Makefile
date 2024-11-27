obj-m += rootkit.o

rootkit-objs := hide.o rootkit_main.o

KDIR 		:= $(PWD)/linux-6.10.10/
SRC_DIR		:= $(PWD)/src

default: 
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) EXTRA_CFLAGS="-g -DDEBUG" modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean
