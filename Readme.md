# Port Scanner
Network Mapper or Nmap is a module in python which is used to create an open port scanner. It is better known as a foot-printing or reconnaissance tool. Reconnaissance in ethical hacking terms means finding information about the target. The target can be in the form of a website or IP address. We will perform this Reconnaissance using the python nmap module. 

Information can be the name of the operating system used or characteristics of the network devices. But the primary use of Nmap is to design an open port scanner. An open port scanner is used to scan what all ports are open and what all ports are closed.  

## What is Nmap in Python? 

In technical terms, nmap is a tool that is used for security auditing and network discovery. The way nmap works is by sending raw IP packets to determine if the target host is available on the network, what services the target host is providing, what type of firewalls are in use, what operating system versions are running, and tons of other characteristics. 

We will do it all using python. Although there is a GUI tool available, the fun part is only when using a command line or python scripts. 

***Note***: We cannot target any website or IP address as that is illegal so that we will use the localhost i.e., 127.0.0.1 

### 1. SYN-ACK Scanning using nmap python-

> When we want to know about the state of the port without establishing the full connection, we perform SYN scanning. This is possible by sending synchronous packets to every port of the target host (for three-way handshaking). If the target host server responds with SYN/ACK (synchronization acknowledged), it means that the port is open 
### 2. UDP Scanning Using Nmap –

> User Datagram Packet is a connectionless protocol for video streaming or audio streaming purposes. It is fast but unreliable. We perform a UDP Scan when we want to search for UDP ports that are open or vulnerable. The process to know about the state is mostly the same as above. There are four types of state based on the responses.

> If we get a response, then the state is ‘OPEN.’ 
Response is not there , then the state is ‘OPEN|FILTER’ 
For ‘ICMP port unreachable error (type 3, code 3)’, then the state is ‘closed.’ 

>And if we get ‘Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13)’, it means the state is ‘FILTERED.’ 
### 3. COMPREHENSIVE Scanning Using Nmap Python-

> This scan does a lot of hard work in information gathering. Even if the handshake is not possible in the first attempt, it will keep trying, and if it gets success, it will try to know about the Operating System Version and other relevant information.  
### 4. Regular Scanning Using Nmap –

> A regular scan tries to find 1000 most common scans and uses the ICMP Echo request for host detection.  
### 5. OS DETECTION Using Nmap Python

> Using nmap we can detect what OS does the target work on, and service detection for devices. It is possible by using the TCP/IP stack fingerprinting method. In our program, we get a lot of results when we try os detection, but we will only show you the relevant information.
### 6. Multiple IP Range Using Nmap Python

> It is quite common that we will want to check the services of multiple hosts, so in nmap we have an option to give a range of ip addresses for scanning.
### 7. Ping Scan Scanning Using Nmap

> Pinging means scanning if a host is active on the network or not. To check for more than one host, we perform ping sweep (also known as ICMP sweep).

