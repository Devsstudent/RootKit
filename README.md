### RootKit

**There is a script that build image with our kernel**

qemu line advice :
-virtfs local,path=$share_folder,mount_tag=host0,security_model=passthrough,id=foobar //For the shared file
-device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:80 //For the network

To hook syscall, we have to enable Kernel Function Tracer:
To do so:
- make menuconfig -> Kernel Hacking -> tracers -> Kernel Function Tracer

```bash

$> ./rootkit --help
$> ./rootkit create
$> ./rootkit start

```