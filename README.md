# RootKit

## Manuel utilisateur

### Injection HTTP

Pour tester l'injection HTTP, il suffit de contacter une page HTTP avec curl et observer l'application de règles de test enregistrée.

Les trois modifications actuellement ajoutées sont:

- "Hello world" -> "Holle Lord"
- "Example Domain" -> "Rootkit Domain"
- "1234" -> "56"

Vous pouvez par exemple contacter example.com

```console
curl -4 http://example.com
```

le `-4` est important pour utiliser IPv4, IPv6 n'a pas été implémenté.

Vous pouvez aussi créer un fichier .html en local avec les valeurs de test et lancer un serveur web avec 

```console
python3 -m http.server
```

# Remove under

**There is a script that build image with our kernel**

```console
> mkdir -p /tmp/share
> mount -t 9p -o trans=virtio host0 /tmp/share -oversion=9p2000.L' to share file
```

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