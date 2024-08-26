---
tags:
- schoolnotes
- cybersecurity
- unfinished
---


 > 
 > \[!info\] Info  
 > Formatting can be improved and will be worked on after I have all the notes transcribed over. I estimate I will have all the notes transcribed by (09/15/2024) or sooner

## Ethics

Professionals have unique ethical duties  
Cyber security is a field that requires a high standard of ethics  
There are many laws governing cyber security including  
- DMCA  
- National Security Regulations  
- Contracts (Such as EULAs and NDAs)  
Risk management is a huge part of security  
How to manage risk?  
- Rule-based: Follow guidelines to set policy  
- Relativistic management: Be as good as the rest / don't have the worst   
- Requirements-based  
-preform a form risk analysis  
- NIST'S "Risk Management Framework"  
Best practices  
- OWASP (Open Web Application Security Project)  
- Apply defense-in-depth: many layers of protection  
- Default-deny  
- Fail Securely   
- Least Privilege  
- Avoid "Security through obscurity"  
- Keep Security Simple  
- Detect Intrusions  
- "You can't block what you can't see"  
- Don't trust infrastructure  
- Establish secure defaults

## Risk Management Frameworks

Six step process  
- Prepare  
- Establish goals get ready for process  
- Categorize  
- Select  
- Implement  
- Access  
- Monitor

## Incident Response

Preserve the evidence  
Immediately report the incident  
Identify the source  
Contain the damage - change passwords  
Repair/recover  
Prevent future incidents / close the loop

## Network Attacks

### Spoofing

* sending a falsified address to make it appear traffic comes from a different system that it really does
* Easy way to do this
  * "scapy" packet manipulation tool
* Other ways to do this
  * use "iptables" firewall to rewrite address
  * "raw" packets (requires root access)
* Problem
  * You won't get the replies
  * the replies are sent to the spoofed address which will respond with a RST packet tearing down the connection

### DoS (Denial of Service)

* A attack in which a system becomes unable to do useful work
* An attack against a viability
* Often used with spoofing to prevent system from replying with RST packet
* Two types
  * Crash or freeze the attacked system
  * Exhaust the other system's resources
* Exhausting resources
  * Memory
  * Disk space
  * Computation Time (CPU)
  * Network bandwidth
  * Network sockets
* Key strategy 
  * Take advantage of an inefficiency in remote system to make it use more resources than we use to attack
* Common trick: amplification
  * use features of the system or network to turn a small amount of work (or network traffic) into a large amount of work (or network traffic)
* Preventing DoS is hard
  * mathematically indistinguishable from a flash crowd
  * Example CNN crashed on 9/11 because everyone was going to check the news 
* #### Examples of DoS attacks
  
  * WinNUKE
    * Attacked Windows 95 and NT machines by sending a packet marked "UPG" to the NetBIOS (Port 139) A bug caused the system to crash
  * Ping of Death
    * Ping sends ICMP requests that are 64 bytes long
    * The IP standard allows us to change the size up to 64kb long
    * You could crash older systems this way
  * LAND (Local Area Network Denial)
    * By spoofing a TCP SYN packet with the same address and port # from source and destination its possible to make a computer reply to itself in an infinite feedback loop until it crashes 
* #### Examples of Amplification DoS Attacks
  
  * Slow Loris
    * Opens a bunch of HTTP connections to an Apache web server tying up the "thread pool" sends just enough traffic to keep them alive but never completes or closes the request
  * SMURF Attack
    * Send a huge number of bogus packets to a broadcast address. spoof the source address using the target systems IP address
    * All systems receiving the broadcast will reply with error messages which will all hit the target
  * SYN flood
    * send many packets that have the SYN flag set but do not complete the 3-way handshake. The system will fill up its network buffers with incomplete connections and become unable to accept new connections

### Distributed Denial of Service Attack (DDoS)

* Instead of using amplification use many machines to overwhelm a single target
* often uses a large botnet of compromised systems
* #### Examples
  
  * TrinOO
  * TFN
  * Low Orbit Ion Cannon / High Orbit Ion Cannon

### Snooping / Sniffing

* Anyone connected to the network can "capture" the traffic using Wireshark/tcpdump
* Often this is for legitimate troubleshooting
* Packet captures are often stored in .pcap files for later analysis
* Switches make this more difficult but wireless networks make it easy
* #### Packet Capture Tool
  
  * tcpdump: Command line tool for capturing packets
  * Wireshark: Graphical tool makes this easier to read
  * Snort: Analysis tool often used for intrusion detection
  * Aircrack-ng: Wireless packet capture tool that can also crack WEP and WPA keys to decrypt and sniff wireless
  * cain and Abel: Windows only

### Man in the Middle Attack (MitM)

* If an attacker can insert their own system in between yours and a target, they can not only intercept your packets but modify them and send them on
* This is an attack on integrity
* #### Tools for MitM
  
  * Ettercan
  * Hak5
  * Wifi Pineapple
  * Packet Squirrel
  * LAN Turtle
* #### Replay Attacks
  
  * A kind of MitM attack in which someone captures packets and then sends duplicates of a request
  * works even if the packets are encrypted
  * can cause a site to repeat a action
* #### How to stop/prevent MitM attacks
  
  * ##### Router/Gateway
    
    * Routing rules can mitigate attacks by blocking certain external traffic
  * ##### Firewalls
    
    * Firewalls can implement access control lists that block specific ports, know "bad behaviors"
    * Firewalls can be:
      * Edge firewalls (placed between 2 networks)
      * internal firewalls (placed inside a system)
    * Two kinds of firewalls
      * packet filters: fast and efficient but can only filter based on info from packet header
      * proxy
      * firewalls / application gateway: Application-layer firewalls that can look ... 
  * ##### Vulnerability scanners
    
    * Check for vulnerable servers or workstations
    * report which ones need patching or have other known weakness

Exploit: Specially crafted string of data intended to take advantage of a vulnerability 

### Network Session Hijacking

* Uses sequence number prediction to inject packets into an already established connection, bypassing firewalls

## Attacks on Computer Security

* ### Physical Security Compromises
  
  * Direct, in-person manipulation of the hardware or software of a computer system
* ### Software Exploits
  
  * Exploits errors in logic of a program to circumvent security protections
* ### Buffer overflows
  
  * Technique that writes past the end of an array
* ### Malware
  
  * Malicious software that can infect a system and compromise security

## Physical Security

* Laptop Theft
* Vandalism
* Component Theft
* Keyloggers
* Authentication Bypass
* ### Physical access makes breaking in easier
  
  * #### More control over the system
    
    * Can use external harddrives, USB, Serial ports to access
    * Can open case and access drives/buses directly 
    * can change the BIOS/UEFI settings
    * can bypass firewall and other network protections
  * #### Harder to track
    
    * No network logs
    * can give attacker more time to break into system
* Can cause most damage
  * loss of entire computers
* Most of our other security controls don't matter if someone can get direct physical access to the system
* ### Physical Access can bypass security protections
  
  * No network protections(firewall) or monitoring
  * Can bypass authentication by booting into an OS using a disk
  * Can bypass boot restrictions by changing BIOS/UEFI
  * can reset BIOS/UEFI passwords by removing battery
* Can remove hard drive from system and clone it or install it in another system
* ### Insider Threats
  
  * #### A significant % of computer crime comes from insider threats
    
    * Disgruntled employees
    * poorly trained users (phishing scams, downloading trojans)
    * industrial espionage
  * #### Tailgating/Piggy backing
    
    * Attacker bypasses locks, card key access, or other building security protections by following another user into the area
* ### Key loggers
  
  * Devices plugged into a system between the computer and keyboard that records key strokes
  * Can use wireless to broadcast info or store info to recover later
  * can steal passwords, cc numbers, other sensitive data
* ### Have a security policy
  
  * Who is allowed to access what and when
  * #### Secure the building/area
    
    * Bollards, turn stiles, barricades
    * keys, locks, combination locks, card key access, biometrics
    * security checkpoints/guards
    * security cameras
    * HVAC systems (prevent computers from environmental threats)
    * EMP Protection
  * #### Secure the system
    
    * Case locks
    * BIOS/UEFI passwords
    * Regular backups
    * Proper erasure of deleted data
      * DBAN Nuke, Degaussing, hardware shredding, ball-peen hammer?
  * #### Secure your users
    
    * Training
    * Having a well documented security policy
    * timely account expiration
  * #### Multi-layer Security
    
    * Don't rely on just ONE mechanism use many different mechanisms in combination to improve security
    * Don't make security too onerous - or users will circumvent it 

## Software Exploits

* Any piece of software of reasonable complexity has bugs
  * These bugs can often be exploited to circumvent security protections
* Common mistakes that cause risk
  * Type errors
    * Forgetting that integers can be negative
  * Directly comparing floating point value's
  * Not validating inputs
    * Directory traversal
  * Code Injection
    * In bash shell scripts, quote marks and `$` can lead to code execution or access environment variables. 

## Buffer Overflow

In some ways an "assembly language code injection"  
Suppose a program has a fixed size array  
`char name[20];`   
It reads into that array without checking if the input fits   
`gets(name);`  
Providing more input that expected can overwrite other variables or control state of the program.   
If an array is on the stack you can overwrite the "return address" of a function.  
When the function returns the program will jump to a new memory location not back to where it was called like we would expect.  
Most modern languages have "array bounds checking" to help protect against this. 

## Mitigating Software Exploits

* Least Privilege
  * Don't run services as the admin user if not required
  * Don't make binaries [setuid](https://www.man7.org/linux/man-pages/man2/setuid.2.html)
* Patching
  * A patch is a modification to a program that fixes a bug often a security flaw
  * Patching is an arms race between hackers and devs
  * Window of Opportunity: time between patch and discovery
* Sandboxing
  * Using VMs, containers, chroot, jails, or other techniques to isolate software systems
  * Browsers hace a "javascript sandbox"
* System Hardening
  * Execute Disable/ No Execute bit (XD/NX)
  * Stock randomization (ASLR) and *stack canaries*
* Secure Programming

## Open Source Software

Having access to the source code doesn't really help the hacker that much

* They use *fuzzers* that generate lots of random strings  
  In practice, open source software has a much better record

## Malware

Malware: Malicious Software -> Mal~~icious~~ ~~Soft~~ware

### Types of malware:

* Trojan horse: designed to look like real software
* Virus: piece of code copies itself into another program spreading from system to system
* Worm: program that spreads across a network
* Spyware: program that collects info from a system without their knowledge
* Ransomeware: encrypts files and holds them hostage for money

### Rootkit

* Software used by an attacker to hide their tracks
* Deletes info from system logs to cover its tracks
* Often uses hidden files
* Sometimes replaces system utilities
* Often contains "backdoors"

### Virus Payloads

* Spam servers
* Backdoors
* Hard drive bomb / Logic bomb
* Ransome ware
* Crypto Miners
* Keyloggers

### How Viruses spread

* Boot sector infections
* Autorun files
* Phishing campaigns / infectious attachments
* Macros

## Containing Malware

### Antivirus software

* Signature based: check for particular patterns, strings, or hash values, that uniquely identify a virus
* Heuristic: Checks for particular execution and memory patterns that are common to different malware
* can quarantine, delete or repair infected files
* require constant updates
* significant performance impact on a system

### Sandboxing

* Don't allow normal users to have admin rights
* Use admin account only for admin tasks
* use permissions and other os tools to isolate processes
* disable autorun files
* disable macros
* "secure boot" verification of boot system

### Use a More Secure OS

* Why does linux have so few viruses
  * Its harder to write viruses for
  * open source means fewer bugs (2024 update: [XZ exploit](https://www.npr.org/2024/05/17/1197959102/open-source-xz-hack))
  * Linux users tend to be more tech savvy
  * Attackers tent to like linux and hate windows

### There is malware that infects Linux system though

* Tents to consist of RATs

### Linux Anti-malware tools

* clamAV free anti-virus
* rkhunter
* maldet

### Windows Anti-malware tools

* MalwareBytes
* Windows Application Firewall
* Windows Defender

### Application Whitelisting

* Only allows specifically identified programs to run
* Can prevent worms, trojans, and some viruses
* Can block warez/pirated software

### Training

* Teach users **NOT** to click links/plug-in flash drive
* Avoid "fear tactics"

## Social Engineering

Uses various psychological techniques such as 

* Authority: Social engineers often impersonate authority figures
* Urgency: Convey a sense of urgency
* Intimidation make threats to scare users

### Social Engineering takes many forms

* Vishing (phishing but over the phone) (real creative name :))
* Pharming: fake website that looks like real website
* Typo Squatting: Creation of websites with similar name but different (whitehouse.gov vs. whitehouse.com)
* Shoulder Surfing: Looking over someones shoulder
* Dumpster Diving: Gathering info by finding info in the trash
* Phishing: You know this one
* Spear Phishing: Target phishing attack
  * Include company logo and letterhead
  * uses the names of real people from an org.
  * spoofed to come from email account like yours
* Whailing: targeting phishing attack directed at a large profit target
* Foot printing or OSINT(Open Source Intelligence): process of gather info about a site to attack it
* Robots.txt: tells you exactly where the sensitive data is
  * Robots.txt is a file on a webserver that tells the web crawlers (like search engine indexers) to not index
* DirBuster: Program that takes a URL and a wordlist and uses the word list to brute force possible URLs
  * Comes with a bunch of default "word lists" that contain common paths for many web apps

### Enumeration tools

* Nmap
* Aircracking
* Nikto
* Fping
* Hping  
  A lot of information can be gathered directly from the web server's headers 
* using netcat/telnet  
  Or by attaching a proxy  
  OWASP 2AP  
  Error codes are very informative  
  Cookies  
  can be used for tracking  
  A "web bug" is a small image (often 1px by 1px) embedded into an email, websites, or other document
* When the web bug is viewed it is downloaded from a server
* This leaves a message in the server log to track you.   
  Google "Dorks" are short search strings that can often find info about compromised systems  
  Shodan searchable database of everything connected to the internet

### Software for gather and organizing OSINT info

* Recon-Ng
* Maltgo

### Archives

* Archive.org
* Caches (Google cache)
* Pastebin
* Web scrappers  
  Social engineering toolkit creates phishing emails to steal credentials

# Authentication ==IMPORTANT==

### Securing a resource has two parts

* Authentication: process of verifying the identity of a user
* Authorization: What a user has access to  
  You need both you can't just have one  
  Three main factors of authentication

1. Something you know
   * Passwords, PINs, or "Security Questions" 
1. Something you have
   * ID card, Token, Yubi Key kinda thing 
1. Something you are
   * Fingerprints, Retina Scans, Skeleton Scanning

Basic Principle: Defense in Depth

* Don't rely on just one factor for authentication (This is where multi-factor authentication comes from)

## Biometrics

### Most biometrics are "tunable"

* can adjust sensitivity to reduce false positives/negatives

### Evaluated using

* FAR (False Authentication Rate) got in when they shouldn't have
* FRRC (False Rejection Rate) didn't get in when they should have
* Cross Over Error Rate - both together

## Cryptographic Tokens

Public Key Crypto systems such as RSA use public/private key pairs 

### Cryptographic Authentication

* One Time Password
* Uses cryptographic hashing to generate a Sequence of numbers. 

## Two Kinds of Attacks

* Offline
  * Attacker has a list of passwords but they are encrypted
* Online
  * SSH in and brute force or something to get in

## What is "Salt"?

A "salt" is a randomly generated string that is added to the password before encrypting it

## Offline password cracking

* Brute force
* Dictionary Attack
* Wordlist Attack - many common passwords

## File Security

File: A block of related data stored on permanent media

* organized into "directories"

### Partitions

Disk drives are divided up into sections called partitions. Each partition can have its own filesystem

The layout of directories into a logical structure is called the filesystem hierarchy

* In Windows each drive or partition has its own separated directory hierarchy
  * each disk or partition gets its own drive letter
* In Unix these are unified into a single virtual filesystem

## Programs

Programs are also files

* Processes typically run with the permissions of the user who launched them (all though not always)

## Authorization

Authorization is the process of verifying that an entity has access rights to a particular computing resource

* Files
* Access to a computer system
* Devices
* Memory
* VMs/containers
* Network ports  
  Without Authentication there is no safety
* Anyone could access anything  
  Without Authorization there is no liveness 

There are two main types of Authorization Systems

* Discretionary Access Control: permissions on a resource are allowed to change dynamically
* ==SOMETHING I MISSED IN CLASS==

## Unix File Permissions

In Unix each file is owned by a user **AND** a group

* The owner is often the creator of the file

## File Permissions

Info about permissions is stored in the directory listing

Anyone with raw access to the disk can circumvent these protections

* by booting to a live disk as "root" and changing them

For files

* r: read
* w: write
* x: execute  
  For directories
* r: list
* w: create or delete files
* x: access contents

## Special Permissions Bits

### SetUid bit

* When program is run runs as the owner of the file rather than the current user

### SetGid bit

* When program is run, runs a group owner rather than current group
* On directories, makes files owned by directory owner rather than current user

### Sticky bit

* For files: used to "lock" a program into memory to force faster loading ==no longer used==

## Initial Permissions

### When we create a new file or directory what permissions should it have?

* Executable programs and directories are executable
* Nothing else

### What about read and write permissions?

* The "umask" determines the defaults. It lists the permissions to remove from a file

## Access Control Lists (ACLs) ==I used this in the industry==

Allow more fine-grained control over permissions

* more flexible but much more expensive
* used in windows
* available in linux
* can add new "capabilities" too so not limited to "read", "write" and "execute"

## Linux "Attributes"

Change attributes with the `chattr` command

* +a File can only be opened for appending
* +A File access time is not updated when it is edited/read
* +d Don't backup this file
* +i File is immutable It cannot be deleted
* +s File is erased with 0s when its deleted (doesn't work on ext systems)
* +u File is **NOT** overwritten when deleted and can be "un erased" (doesn't work on ext filesystems)

## Mandatory Access Control

MAC - permissions on a resource are governed by a policy   
Used by SELinux

* Developed by the NSA
* Uses concept of "labels" and "domains"
  * A Label is a bit like a permission (more like ACL)
* Different permissions are available on different systems depending on which "modules" have been loaded  
  Labels are mapped to files and network sockets using a policy file

### SELinux Policies

* Domain: Identifies a group of related processes/programs
* User: Identifies a particular authentication entity
* Role: Identifies different "roles" the user can be preforming
  * manager role
  * user role
  * admin role
  * cleanup role
* Type: for processes which other processes can access it
* Label: What can be done to the resource 

### Example Rule:

* Allow webmin_t web_log_t file perms append_file perms
* Allow the webmaster to read and append to the web server log file but not to erase it

### AppArmor

* Another MAC system
* Less rigorous and not as secure
* But MUCH easier to use

### Grsecurity:

* Software suite that contains "hardened" programs such as compilers with special security flags enabled
* RBAC: Similar to MAC but easier to work with
* Automated: Can put in "learning mode" and let it build a policy for you

## Administrative Rights

Most DAC systems have one or more "Admin users"

* or at least a "root" user  
  "Root" user can access pretty much any file, reset any permissions (except on network mounted drives), install and remove software create and delete users, and set passwords

### Is the super-user a good thing?

* MAC advocates say "No"  
  On most systems network ports 0-1023 are reserved ports
* Can only be used by the super-user
* Or users specifically granted permissions using Linux capabilities 

### The sudo command

* grants limited access to admin privileges 
* visudo command safely edits the letc/sudoers policy file 

### The su command

* Allows one user to elevate privileges "into" another users

### The newgrp command

* Allows a user to elevate group privileges "into" another group

## Capabilities

Can be managed with the capget and setcap commands  
Or by running a program using the setpriv command  
Example:

* setcap cap_net_admin=tep /usr/bin/my_server

## Sandboxes

### Software that isolates a program or part of a program from the rest of the OS is called a Sandbox

* Used by web browsers to prevent JS code on a website from infecting the rest of the computer
* Used by OS's to isolate dangerous processed like FTP servers 
  * A chroot jail restricts the files a program can access to those under one particular directory 

## Containers

A chroot jail only limits which files a program can access. Linux lets you limit software in other ways using "Linux Container Namespaces"

* Resource limits
* Access to other running processes
* Network isolation
  * A program can have a different IP address than the rest of the system or only use a few ports
* Separate user and group accounts
  * we can isolate the program to only see certain users
* Access to drivers and devices

We can isolate each process in any of these ways independently

However we can also use tools like Docker, LXC, or CoreOS to run programs in an environment that uses all of these to isolate software

This accomplishes many of the same goals as a VM

# Enumeration

In order to break into a network we need to id potentially vulnerable systems and services

## Port Scanning

http: 80  
https: 443  
ssh: 22

Nmap (by insecure.org)

* GUI: pen map

Angry IP Scanner (angryip.org)

* written in Java

Port scanning has many legitimate uses

* testing wether a network service is up

### Basic idea of port scanning

* Send a packet to each port and check for a reply
* Takes a long time to scan 65536 legal TCP ports
* Takes even longer when scanning 65536 UDP ports as well
* Attackers can focus on well known ports
  * or at least 1-1023 the "privileged" ports
* Defenders have to scan **ALL** ports which may be used by malware, backdoors, or rootkits

Port scanner tools report

* Open: Allows access
* Closed: Doesn't allow access
* Filtered: Access is restricted - it may be blocked by firewall

## Types of port scans

#### Ping Scan

* Use ICMP echo request to "ping" a system

### Connect Scan

* Send a complete three-way TCP handshake connecting to the service then disconnect
* Often this connection will be logged

### SYN Scan

* Port scanner sends packets with a SYN flag use to initiate TCP connection
* If we get a SYN/ACK packet we send back a RST/ACK to avoid being logged
* considered a "stealth scan" or "stealth attack"

### NULL Scan

* A null packet is one with no TCP flags turned on 
* If we send one to a closed port we get a RST packet back
* If we don't get one the port might be open
* Windows systems don't always send RST packets back

### XMAS Scan

* A "Christmas Tree" packet is one that has **ALL** the TCP flags set
  * Used in Some DoS attacks
* However, for scanning we only use the FIN, PSH, and URG flag
  * Like NULL scan we expect an RST packet if port = closed

### ACK Scan / ACK Attack

* Most firewalls filter out only new connections not established ones
* A packet with only ACK flag set looks like an established connection so it may bypass firewalls
* Expect a RST if port is closed

### Fin Scan

* Sends packet with only FIN flag set. Expect RST flag

### UDP Scan

* Use UDP packets instead of TCP packets expect "port unreachable"

### nmap {compSciServer}.longwood.edu (I didn't want to put the actual URL online)

* Scans 1000 most common ports then reports if they are in open, closed, filtered, unfiltered, open|filtered, or closed|filtered
* Uses a SYN scan if you are root a connect scan if not 

Many nmap options require privileged access

nmap flags

* -sS SYN scan
* -sT TCP scan
* -sU UDP scan
* -sN Null scan
* -sF FIN scan
* -sX XMAS Tree scan
* -sA ACK scan
* -sC script scan

The -T option adjusts nmaps timing parameters 

* Shorter delays between packets are faster
* But more likely to be detected
* Also more likely to inadvertently crash the target system

In addition to scanning for open ports nmap can be used to

* Id which systems are online without running port deteching `nmap -sn`
* Run port detection without pining the system first `nmap -Pn`

## Host Enumeration

### Fping

* can ping multiple systems in parallel
* use -g flag to specify address

### Ping sweeps don't always Succeed

* Some admins configure their systems to block ICMP echo requests (ping)
* If a system is rebooting we miss it

### Ping sweeps can be dangerous

* If you accidentally hit a broadcast you could take everything down accidentally 

nmap comes with a bunch of scripts these are written in LUA

Port scanning is only one enumeration step  
In addition to identifying available services we need to know

* Which of these services can actually be exploited to give us access
* The topology of the network
* Which OS, servers, and software are being used
* usernames and passwords

### NetBIOS

* Microsoft file sharing protocol
* First introduced in '83 by Sytek then adopted by MS in '85
* Also called NetBOUI
* Originally designed for NBF, Token Ring, and IPX/SPX protocols
* Ported to TCP/IP in '87 as NBT (NetBIOS over TCP)

#### Provides three services

* Name service: advertises available resources on UDP port 137
* Datagram Distribution Service: to exchange messages 
* Session Service: allows to connect to each other on port 139

The "NbtScan" tool can be used to find systems running NetBIOS and list which resources they provide

* The -r flag does this

The SMB (Server Message Block) how to share printers and such

Every Windows computer gets a "network name" not related to DNS or its IP address this is to Id it on the SMB network

Many NetBIOS Systems allowed "null session"

* You can login with no username and passwords

Windows Vista and following eliminate null sessions

Gain access even without null sessions using vulnerabilities in the protocol

* The enum4linux does this

Pass-the-hash (PTH)

  


When clients connect they give us their credentials

* We can crack passwords with "John the ripper" (This is a password cracking tool)

## Software Vulnerabilities

Many exploits rely on poor design or bugs

### Design issues

* Missing or poor authentication
* Bad default credentials
* Not clearing credentials from memory
* Predictable random number generation
* Use of weak cryptographic algorithms

### Static Analysis tools

* Splint
* Jsling/eslint/cpplint

### Dynamic Analysis tools:

* valgrind

### Compiler Features

* Don't ignore compiler warnings?

## DLL Injection

### Even if your software is free from bugs and injection attacks

* The libraries you use may be vulnerable
* In Unix, libraries are also files and are stored in protected directories
  * This can sometimes be bypassed
* In Windows libraries are in .dll files and can in various places
  * System Folder
  * 16-bit System Folder
  * Windows Folder
  * The "current folder"

## Preventing Injection Attacks

### Sanitize your inputs

* Don't allow control characters like quotes
* Three approaches
  * Black listing - excluding "bad" characters
    * but what if you miss one
  * Whitelisting - allowing only "good" characters
    * but what if ß or ü is a good character
  * Escaping
    * Encoding special characters with codes that render them harmless
    * But if the document passes through several rendering steps you could miss one
    * Example: Blog posted with embedded JS that is stored in a SQL db using PHP backend

## HTML Injection Example

### HTML Injection

* Add malicious links by embedding \<a> tags in a document
* Can be prevented by encoding \< and > using entity tags

Javascript injection is also something you need to watch out for. 

## Other Inputs to sanitize

* Command line arguments
* Environment Variables
  * Including the PWD
* FileNames
* File Content
* Web forms / CGI script input

## Sanitizing URLs

### URLs / Links

* Especially "javascript" and "mailto" links
* usernames and passwords in links
* userscores in URLs
* ../ in a URL
* URL Escape sequences like %20 for a space
* Query strings that start with ?

One way to defeat many functions that sanitize inputs is to split output over many lines

## Preventing Injection Attacks

### TESTING !!!

* Test your program for invalid input
* And for logic errors
* Fuzzing: Inserting millions of random inputs into a program to see if any of them cause
  * Crashing
  * Error Messages
  * Differences in behavior 

### Formal Methods

* Model Checking
* Static Analysis
* Code Review
* Software Theorem Provers

### Using Established Libraries

* Don't reinvent the wheel
* Existing code has been well tested and is safer

## System Solutions

### NX/XD bit

* Can prevent some buffer overflow attacks
* Marks some parts of memory as "no execute" segments
* Allow us to Separate data from code

### Stack Canaries

* Write a special value onto the stack between the inputs and the return address
* Compiler inserts code at the end of every function that checks that value is still there before returning
* Buffer overflow exploits will overload the canary and we will know 

### Stack Randomization

* Buffer overflow exploits depend on the return address being predictable
* Randomly adding empty arrays of varying sizes moves the return address around and makes this harder
* However, attackers can now use a NO-OP sled 

## Exploit tools

### Metasploit

* Enormous database of known software vulnerabilities and code for exploiting them

Armitage  
Nmap  
Ghidra  
IDA Pro

## Fuzzers

### Webfuzzers

* Web scarab
* Jbro Fuzz
* Ws Fuzzer

## Database Security

Database Security: Use of vulnerabilities in a DB to circumvent security controls

### Threats against DB Security

* misconfiguration
  * No authentication / poor authentication

We can use ' to test wether injection is possible

* If we get an error the ' is probably not being escaped

We can use -- to prevent the final ' from causing an error

### Some Injection Tricks:

* Adding "OR 1" since 1 means "true" this can be used to bypass certain checks

We could leak info using UNION  
Blind SQL injection attack

* If we can't leak data directly, we might be able to leak it indirectly by modifying the behaviour of the database. 
* For example by makes a query take a long time by using "SLEEP" or "WAIT FOR" or "DELAY" commands

## Protecting DB Security

### Proper input validation

* whitelist or escape all user input
* Both on client AND on server

### Don't reinvent the wheel

* Use library functions for processing input
* Use stored procedures

Verify database config not just the SQL queries 

## Web Security

### Attacks against web security

* Snooping
* Pharming / Typo squatting
* Enumeration Attacks
* XSS (Cross-site scripting)
* CSRF (Cross-site request forgery)
* vulnerable web applications

## Snooping

### Web traffic is transmitted using either the HTTP or HTTPS protocol

* HTTPS is encrypted using TLS/SSL
  * A Crypto hash to ensure message integrity
  * A public key cipher to exchange cipher keys and digitally sign a host certificate 
  * A symmetric cipher to encrypt info
* HTTP is not encrypted but is faster
* If info is sent using http, it is sent in clear text. Anyone that can intercept the web session can see passwords, credit card numbers, social security numbers, and other PII

### When does a connection use HTTPS?

* When the server supports it
* When the browser supports it
* When the client requests it

A misconfigured server can sometimes fall back to plain-text HTTP if it is unable to agree on the correct HTTPS ciphers

### Furthermore even if we use HTTPS:

* We might be using weak ciphers that are easily cracked such as RC4 or SSL
* There might be a bug in the browser or the server
  * The "Heartbleed" attack took advantage of a bug in OpenSSL to leak info like ciphers and passwords

## Pharming and Typo Squatting

A pharming website is a duplicate of another web page set up by an attacker 

Different ways of getting users to visit the site

* Spam email banner ads, XSS, or CSRF attacks
* Typo squatting: Registering a domain name that is similar to the cloned site but off by just one or two letters
  * Ex. amzon.com

To prevent typo squatting companies buy a bunch of similar domain names

## Enumeration Attacks

Enumeration is part of the process of gathering intelligence on a site

### Attackers often need to know

* Usernames
* Directories
* API Endpoints
* Potential Passwords

### Misconfigured web servers can leak some of this info

* By allowing a user to view a list of home directories
* Or providing a site map
* By listing directories

## Enumeration Tools

### Dirbuster

* Brute force search for common directories

### Cewl

* Scrapes a web page for likely passwords

### Nikto

* Examines a web server for common misconfigurations

### Robots.txt

* File on many websites containing info you don't want bots to see

### Salmap

* Automates many SQL injection attacks

## Vulnerable Web Applications

Performing authentication or input validation on the client instead of the server  
Storing sensitive info in cooking  
Storing sensitive info in URL's  
Using poor encryption  
Using insecure 3rd party libraries   
Not using secure 3rd party libraries  
Not logging/monitoring for attacks  
Logging reporting to much

## Cross site Scripting

### Cross site scripting (XSS) is a form of injection attack

* If website includes user input as part of the content of a page
* The user can inject malicious HTML tags

## Cross Site Request Forgery

### CSRF

* Many sites record logging by storing a "session key" that records that you have logged in

## Wireless Security

### Wireless networks have unique security challenges

* All communication is being broadcast by nature
* Inherently less safe
* Authentication is more difficult because we have little control over who is communicating

### Solution

* Use encryption to limit access and provide authentication

### Problem

* Not all encryption is strong encryption

## Wireless Encryption Standard

### WEP

* Notoriously weak standard
* Uses the deprecated RC4 cipher
  * A passphrase is used to seed a random number generator
  * Originally key was only 10 hex (40 bits) or 26 hex digits (104 bits)
    * Because us. had laws forbidding strong encryption
  * Eventually upgraded to 32-digit (128 bit)

### Attacking WEP

* Fragmentation attack
  * Takes advantage of poorly generated init vectors in the RC4 implementation
* No longer widely used

## Wifi Protected Access

### Replaced WEP as a standard in 2003

* Intended as a quick temp patch
* Only "secure" if you use the full 64-character (256 bit) key

## Wifi Protected Access 2 (electric boogaloo)

### WPA2 a.k.a. RSN

* Based on IEEE 802.11i amendment to 802.11
* Not compatible with WEP hardware

## Cracking WPA/WPA2

Attacker causes a client to become deauthenticated  
When client reconnects, it sends the encrypted password  
Attacker captures packets in the four-way wireless handshake used to reconnect  
Attacker uses a dictionary or brute force attack to decrypt the packets

## PSK and Enterprise

### WPA/WPA2 are modular

* They allow for other, more secure ciphers, to be used
* WPA PSK
  * PSK: Pre-shared key
  * Default mode
  * Every client that connects uses the same key

## WPA PSK

Traffic is encrypted using either TKIP(Temporal Key Integrity Protocol) or AES-CCMP (Counter Mode (BC-MAC) Encryption)  
Using a long enough password or passphrase makes the key much harder to crack  
In WPA, TKIP is the default, designed to replace WEP

* like WEP

## WPA Enterprise

WPA Enterprise provides RADIUS-based authentication using the IEEE 802.11 protocol

### RADIUS (Remote Authentication Dial-in User Service)

* Provides Authentication, Authorization and Accounting (AAA) for network

### EAP(Extensible Authentication Protocol)

* Uses RADIUS for authentication
* Has some security flaws

### LEAP (Lightweight Extensible Protocol)

* Based on 802.1x
* Uses WEP and a sophisticated key management system
* Not considered secure
* Used by some Cisco devices

### PEAP (Protected EAP)

* Used by Longwood
* Developed by Cisco, Microsoft, and RSA security
* Allows for secure data exchange without a certificate server

## Common Wireless attacks

### DoS (Denial of Service)

* Attacker bombards access points
* Often abused weakness in EAP
* Used to cause wireless hosts to timeout/deauthenticate clients

### Key Cracking

* Tools such as "Aircrack-ng" can crack a weak passphrase in less then 1 minute other software = Airsnort/Auditor Security Coll 

### Access Point Spoofing (Evil Twin)

* Attacker sets the SSID on their on their wireless device to look like a legit access point
* Victim associates with the attackers system instead of the AP

### Man-In-The-Middle (MitM) attacks

* LANjack and AirJack automate MitM attacks
* Hotspots at hotels and restaurants are particularly vulnerable to attack since they often have little security

### Network Injection

* Attacker inserts bogus network control packets onto the network causing network devices to reconfigure their connections

### Caffe Latte Attack

* Attack against WEP
* targets the windows network stack 
* Allows remote exploitation of a wireless client
* Attacker sends a flood of ARP Packets

### Krack attack

* Tricks OS into setting the encryption key to all zero's

### Hole 196

* Uses WPA2 Group Temporal Key (GTK)
  * This is a shared key among all users of the same ESSID
  * Launches attacks on other users of the ESSID

### ESSID Hiding

* ordinarily the SSID for a network is broadcast
* turning off this feature makes it slightly harder to id a network

### RF shielding

* special paint or glass can block wireless signals

### Reducing TX Power

* reduce the range of wifi

### MAC ID Filtering

* Whitelist a MAC address
* Blacklist unwanted MAC addresses
* neither of these is really effective because attackers can spoof MAC addresses

### Static IP Addressing

* Instead of using DHCP to assign IP addresses automatically to specific clients
* makes attacks slightly more difficult
* spoofing can run into IP conflicts resulting in connections being torn down
* But only if the other system is online at the same time

### End-to-End Encryption

* WPA2 is a form of point-to-point encryption
* it only encrypts data between the client and the access point
* Any traffic forwarded to other systems

### VPN

* Form of end-to-end encryption where all traffic is encrypted
* All data to the proxy is encrypted
* However this makes traffic analysis very difficult
* And encrypts ALL network sent to the proxy

### Black holing

* Dropping all IP Packets from an attacker
* Somewhat effective at stopping DoS attacks

### Validating the four way handshake

* create a 'false open'

### Rate limiting

* Capping the amount of traffic someone can use
