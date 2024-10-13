# apk add linux-lts
apk add openrc
apk add util-linux
apk add build-base

ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 > /etc/securetty
rc-update add agetty.ttyS0 default
rc-update add root default

passwd -d root

rc-update add devfs boot
rc-update add procfs boot
rc-update add sysfs boot

apk add vim

for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done
for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done
