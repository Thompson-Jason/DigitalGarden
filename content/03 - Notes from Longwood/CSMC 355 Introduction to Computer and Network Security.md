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
