# RootKit

## Manuel utilisateur

### Création et lancement du LFS

Executez la commande ci-dessous pour créer une image disk.img

```console
./rootkit create
```

Puis lancez une VM avec

```console
./rootkit start
```

Les options des commandes sont disponibles avec

```
./rootkit -h
```

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

### Companion

Veuillez placer le companion.c dans le ./fs/root/, il sera executé au chargement du rootkit en tant que root.

