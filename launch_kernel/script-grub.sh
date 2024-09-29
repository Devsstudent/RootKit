#!/bin/sh

sudo mkdir -p /tmp/my-rootfs/boot/grub

sudo cp ../linux-6.10.10/arch/x86/boot/bzImage /tmp/my-rootfs/boot/vmlinuz

sudo cp ./grub.cfg /tmp/my-rootfs/boot/grub/

sudo grub-install --directory=/usr/lib/grub/i386-pc \
--boot-directory=/tmp/my-rootfs/boot /dev/loop0

sudo umount /tmp/my-rootfs

sudo losetup -d /dev/loop0
