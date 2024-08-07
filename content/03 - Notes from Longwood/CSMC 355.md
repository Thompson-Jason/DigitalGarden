---
tags:
- schoolnotes
- cybersecurity
- unfinished
---

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
