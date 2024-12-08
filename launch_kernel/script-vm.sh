#!/bin/sh

echo "root:root" | chpasswd
apk add openrc util-linux build-base
ln -s agetty /etc/init.d/agetty.ttyS0

echo ttyS0 > /etc/securettyC

cat > /etc/network/interfaces <<IFACES
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACES

rc-update add networking boot
rc-update add agetty.ttyS0 default
rc-update add root default
rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot
for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done
for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done
