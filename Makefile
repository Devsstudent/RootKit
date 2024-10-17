SRC_DIR := $(PWD)/src
FS_DIR	:= $(PWD)/fs/lib/secret

default:
	$(MAKE) -C $(SRC_DIR)
	cp $(SRC_DIR)/rootkit.ko $(FS_DIR)
	$(MAKE) -C $(SRC_DIR) clean

clean:
	$(MAKE) -C $(SRC_DIR) clean