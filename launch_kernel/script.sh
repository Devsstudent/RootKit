#!/bin/bash

rm disk.img
truncate -s 450M disk.img
/sbin/parted -s ./disk.img mktable msdos
/sbin/parted -s ./disk.img mkpart primary ext4 1 "100%"
/sbin/parted -s ./disk.img set 1 boot on
sudo losetup -Pf disk.img
losetup -l
sudo mkfs.ext4 /dev/loop0p1
mkdir -p /tmp/my-rootfs
sudo mount /dev/loop0p1 /tmp/my-rootfs

sudo docker build . -t alpine-vm

sudo docker run --rm -v /tmp/my-rootfs:/my-rootfs alpine-vm > /dev/stderr /script.sh

./script-grub.sh

share_folder="/tmp/qemu-share"
mkdir -p $share_folder
export share_folder = $share_folder

echo "Running QEMU..."
qemu-system-x86_64 -drive file=disk.img,format=raw -nographic -virtfs local,path=$share_folder,mount_tag=host0,security_model=passthrough,id=foobar  -enable-kvm -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:80
