---
title: Memory Forensics
date: 2025-10-02 18:07:00 +0200
categories: [TryHackMe, Challenges]
tags: [forensics]
description: Perform memory forensics to find the flags. If you are having trouble, maybe check out the volatility room first. Enjoy!
image: /assets/img/THM/MemoryForensics.png
---

>**Platform:** [TryHackMe](https://tryhackme.com/room/memoryforensics) - 2 Oct 2025

## Task 2 - Login
### Description
The forensic investigator on-site has performed the initial forensic analysis of John's computer and handed you the memory dump he generated on the computer. As the secondary forensic investigator, it is up to you to find all the required information in the memory dump.

**Question:** What is John's password?
### Solution
Using Volatility3 we can dump the user hashes with the following command:
```sh
$ vol -f Snapshot6_1609157562389.vmem windows.registry.hashdump
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
John    1001    aad3b435b51404eeaad3b435b51404ee        47fb...※\(^o^)/※
HomeGroupUser$  1002    aad3b435b51404eeaad3b435b51404ee        91c34c06b7988e216c3bfeb9530cabfb
```
>Older versions of Volatility3 has this plugin located as: windows.hashdump.Hashdump
{: .prompt-info }
Cracking this NTLM hash with Crackstation[^1] we get John's password.

## Task 3 - Analysis
### Description
On arrival a picture was taken of the suspect's machine, on it, you could see that John had a command prompt window open. The picture wasn't very clear, sadly, and you could not see what John was doing in the command prompt window.

To complete your forensic timeline, you should also have a look at what other information you can find, when was the last time John turned off his computer?

**Question 1:** When was the machine last shutdown?

**Question 2:** What did John write?
### Solution
#### Question 1
The shutdown time is stored in the registry, more specifically in: `"ControlSet001\Control\Windows"`. Look for 'ShutdownTime' under 'Name'.
```sh
$ vol -f Snapshot6_1609157562389.vmem windows.registry.printkey --key "ControlSet001\Control\Windows"
Last Write ... Name
※\(^o^)/※ ... ShutdownTime
```
>Answer format: YYYY-MM-DD HH:MM:SS
{: .prompt-info }
#### Question 2
From the task description, we know that we are looking for something that was written in the Command Prompt. The first step is the to list the processes and in order to find the PID of `cmd.exe`.
```sh
$ vol -f Snapshot6_1609157562389.vmem windows.pslist
PID     PPID    ImageFileName   Offset(V) ...
...
1920    1144    cmd.exe 0xfa80027906f0  ...
...
```
Knowing the PID we can dump the information in the memory space of this process. Then we can extract the 'strings' of this dump.
```sh
$ vol -f Snapshot6_1609157562389.vmem windows.pslist --pid 1920 --dump
$ strings 1920.cmd.exe.0x4ace0000.dmp
...
THM{※\(^o^)/※}
...
```

## Task 4 - TrueCrypt
### Description
A common task of forensic investigators is looking for hidden partitions and encrypted files, as suspicion arose when TrueCrypt was found on the suspect's machine and an encrypted partition was found. The interrogation did not yield any success in getting the passphrase from the suspect, however, it may be present in the memory dump obtained from the suspect's computer.

**Question:** What is the TrueCrypt passphrase?
### Solution
TrueCrypt is a method of disk encryption, that requires the master key to be held in memory.
Volatility has a plugin to extract either the master key or the passphrase.
>Due to the age of the system I received an error using Volatility3, therefore I use Volatility2 for this last task.
{: .prompt-warning }
```sh
$ ./volatility_2.6 -f Snapshot14_1609164553061.vmem --profile=Win7SP1x64 truecryptpassphrase
Found at 0xfffff8800512bee4 length 11: ※\(^o^)/※
```

## References
[^1]: [Crackstation.net](https://crackstation.net)