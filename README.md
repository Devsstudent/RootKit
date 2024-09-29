### RootKit

** There is a script that build image with our kernel **
** Run cd launch_kernel && script.sh
inside the qemu run :
- mkdir -p /tmp/share
- mount -t 9p -o trans=virtio host0 /tmp/share -oversion=9p2000.L' to share file

qemu line advice :
-virtfs local,path=$share_folder,mount_tag=host0,security_model=passthrough,id=foobar //For the shared file
-device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:80 //For the network
