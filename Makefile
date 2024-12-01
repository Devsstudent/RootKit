# obj-m += rootkit.o

# rootkit-objs := hide.o rootkit_main.o

# KDIR 		:= $(PWD)/linux-6.10.10/
# SRC_DIR		:= $(PWD)/src

# default: 
# 	$(MAKE) -C $(KDIR) M=$(SRC_DIR) EXTRA_CFLAGS="-g -DDEBUG" modules

# clean:
# 	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean

KDIR 		:= $(PWD)/linux-6.11
SRC_DIR		:= $(PWD)/src
FS_DIR		:= $(PWD)/fs/lib/secret

default: 
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules
	mkdir -p $(FS_DIR)
	cp $(SRC_DIR)/rootkit.ko $(FS_DIR)
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean