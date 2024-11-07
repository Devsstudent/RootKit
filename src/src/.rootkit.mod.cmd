savedcmd_/home/hanako/base/src/src/rootkit.mod := printf '%s\n'   rootkit.o | awk '!x[$$0]++ { print("/home/hanako/base/src/src/"$$0) }' > /home/hanako/base/src/src/rootkit.mod
