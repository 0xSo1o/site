---
title: "Network Enumeration With Nmap"
classes: wide
header:
  teaser: /assets/images/htb/Network-Enumeration-With-Nmap/teaser.png
  overlay_image: /assets/images/htb/Network-Enumeration-With-Nmap/logo.png
  overlay_filter: 0.5
ribbon: Red
excerpt: ""
description: "Part. 2"
categories:
  - HTB Write Up
tags:
  - HTB
  - Nmap
  - IDS
toc: true
toc_depth: 2
toc_sticky: true
toc_label: "On This Blog"
toc_icon: "terminal"
---

<!-- Toc Color -->
<style>
.toc .nav__title {
  color: #fff;
  font-size: .75em;
  background: #ff0000;
  border-top-left-radius: 4px;
  border-top-right-radius: 4px;
</style>

# Intro

The <b>Network Enumeration with Nmap</b> module comprises a total of eight sub-modules. This write-up will focus on the coverage of the last three sections, providing detailed explanations and analysis for each.

1. Firewall and IDS/IPS Evasion - Easy Lab
2. Firewall and IDS/IPS Evasion - Medium Lab
3. Firewall and IDS/IPS Evasion - Hard Lab

## 1. Firewall and IDS/IPS Evasion - Easy Lab
**Task:** Our client wants to know if we can identify which operating system their provided machine is running on. Submit the OS name as the answer. 
{: .notice}

To determine the operating system of the client's machine, we need to make use of the either <b>-A</b> flag or the notably faster <b>smb-os-discovery</b> script.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap --script smb-os-discovery -vv 10.129.2.48
```

```console
PORT    STATE SERVICE     REASON
21/tcp  open  ftp         syn-ack
22/tcp  open  ssh         syn-ack
80/tcp  open  http        syn-ack
110/tcp open  pop3        syn-ack
139/tcp open  netbios-ssn syn-ack
143/tcp open  imap        syn-ack

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nix-nmap-medium
|   NetBIOS computer name: HTB984NIFN97CBO783QBNJCPAS984UIN\x00
|   Domain name: \x00
|   FQDN: nix-nmap-medium
|_  System time: 2023-10-25T07:13:04+02:0
```
<b></b>

 <span style="background-color: #38263ef0">Answer: Windows</span>

## 2. Firewall and IDS/IPS Evasion - Medium Lab

**Task:** After the configurations are transferred to the system, our client wants to know if it is possible to find out our target's DNS server version. Submit the DNS server version of the target as the answer.
{: .notice}

The task at hand is straightforward: we have to find out the target's DNS server version. We will start by utilizing -<b>sSU</b> flag to indicate that both TCP and UDP ports will be subject to the scanning process. Then we will target the port <b>53</b> as this is commonly used for DNS services. Lastly, we will deploy the <b>dns-nsid</b> script.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -sSU -p 53 --script dns-nsid 10.129.94.169
```

```
PORT   STATE    SERVICE
53/tcp filtered domain
53/udp open     domain
| dns-nsid: 
|_  bind.version: HTB{GoTtgUnyze9Psw4vGjcuMpHRp}
```
<b></b>

<span style="background-color: #38263ef0">Answer: HTB{GoTtgUnyze9Psw4vGjcuMpHRp}</span>

## 3. Firewall and IDS/IPS Evasion - Hard Lab

**Task:** Now our client wants to know if it is possible to find out the version of the running services. Identify the version of service our client was talking about and submit the flag as the answer.
{: .notice}

The objective is to determine the versions of the currently active services. To achieve this, we will use the <b>netcat</b> tool. However, before proceeding, we need to determine the specific port we are targeting. This will be accomplished by conducting a full port scan (<b>-p-</b> ) which will reveal the port <b>50000</b>. Following this, we will set up a netcat listener to operate between the DNS port 53 and the recently discovered port 50000.


```console
┌──(solo㉿HTB)-[~]
└─$ sudo nc -nv -p 53 10.129.2.47 50000
```

```
(UNKNOWN) [10.129.2.47] 50000 (?) open
220 HTB{kjnsdf2n982n1827eh76238s98di1w6}
```
<b></b>

<span style="background-color: #38263ef0">Answer: HTB{kjnsdf2n982n1827eh76238s98di1w6}</span>

# Conclusion

This module offers an exceptional opportunity for individuals seeking to acquire proficient skills in utilizing Nmap, an indispensable tool that holds immense value for professionals in the realm of Cyber Security. Mastery of Nmap is highly recommended for anyone aspiring to excel in this field, making this module an essential resource for knowledge acquisition.