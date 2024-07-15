---
title: "Footprinting Part 2"
classes: wide
header:
  teaser: /assets/images/htb/Footprinting/teaser.png
  overlay_image: /assets/images/htb/Footprinting/logo.png
  overlay_filter: 0.5
ribbon: Red
excerpt: ""
description: "Part. 2"
categories:
  - HTB Write Up
tags:
  - HTB
  - Footprinting
  - FTP
  - SMB
  - NFS
  - DNS
  - SMTP
  - IMAP
  - POP3
  - SNMP
  - MySQL
  - MSSQL
  - Oracle TNS
  - IPMI
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

The <b>Footprinting</b> module consists of eleven sub-modules. This write-up is continuation of the previous one and focuses on covering the middle section of this module, providing detailed explanations and analysis for each.

4. DNS
5. SMTP
6. IMAP

## 4. DNS
**Task 1:** Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.
{: .notice}

A fully qualified domain name (FQDN) is the complete domain name for a specific computer, or host, on the internet. The FQDN consists of two parts: the hostname and the domain name.

Let's start with enumerating the target DNS by using the following <b>dig ns</b> command which lists information about the domain.

```console
┌──(solo㉿HTB)-[~]
└─$ dig inlanefreight.htb @10.129.245.156
```
```
; <<>> DiG 9.19.19-1-Debian <<>> ns inlanefreight.htb @10.129.245.156
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11861
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 15b8a2fc4d46bd520100000065f439050017661c744bde19 (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1

;; Query time: 1008 msec
;; SERVER: 10.129.245.156#53(10.129.245.156) (UDP)
;; WHEN: Date
;; MSG SIZE  rcvd: 107

```

 <span style="background-color: #38263ef0">Answer: ns.inlanefreight.htb</span>

 **Task 2:** Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...)) 
{: .notice}

Zone transfer refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated Asynchronous Full Transfer Zone (AXFR). 

The original data of a zone is located on a DNS server, which is called the primary name server for this zone. However, to increase the reliability, realize a simple load distribution, or protect the primary from attacks, <b>one or more</b> additional servers are installed in practice in almost all cases, which are called secondary name servers for this zone.

We will continue enumerating with <b>dig axfr</b> command to see if get any results.

```console
┌──(solo㉿HTB)-[~]
└─$ dig axfr inlanefreight.htb @10.129.245.156
```
```
; <<>> DiG 9.19.19-1-Debian <<>> axfr inlanefreight.htb @10.129.245.156
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
dev.inlanefreight.htb.  604800  IN      A       10.12.0.1
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       127.0.0.1
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 2232 msec
;; SERVER: 10.129.245.156#53(10.129.245.156) (TCP)
;; WHEN: date
;; XFR size: 11 records (messages 1, bytes 560)

```
We can see that there is in fact a secondary name server <b>(internal.inlanefreight.htb)</b>. Let's enumerate it.

```console
┌──(solo㉿HTB)-[~]
└─$ dig axfr internal.inlanefreight.htb @10.129.245.156
```
```
; <<>> DiG 9.19.19-1-Debian <<>> axfr internal.inlanefreight.htb @10.129.245.156
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      127.0.0.1
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.245.156#53(10.129.245.156) (TCP)
;; WHEN: date
;; XFR size: 15 records (messages 1, bytes 677)

```

 <span style="background-color: #38263ef0">Answer: HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}</span>

  **Task 3:** What is the IPv4 address of the hostname DC1? 
{: .notice}

This question is straightforward and we have already enumerated this information in the previous task.

 <span style="background-color: #38263ef0">Answer: 10.129.34.16</span>


 **Task 4:** What is the FQDN of the host where the last octet ends with "x.x.x.203"?
{: .notice}

This task took us awhile to figure out and by no means is a obvious one. The individual A records with the hostnames can be found out with the help of a brute-force attack. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by <a href="https://github.com/danielmiessler/SecLists">SecLists</a>. Download the <a href="https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/fierce-hostlist.txt">fierce-hostlist.txt</a> and make sure the path (<b>/home/yourfilespath/fierce-hostlist.txt</b>) of the command is correct.


```console
┌──(solo㉿HTB)-[~]
└─$ for sub in $(cat /home/fierce-hostlist.txt);do dig $sub.dev.inlanefreight.htb @10.129.245.156 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

```
```
dev1.dev.inlanefreight.htb. 604800 IN   A       10.12.3.6
ns.dev.inlanefreight.htb. 604800 IN     A       127.0.0.1
win2k.dev.inlanefreight.htb. 604800 IN  A       10.12.3.203
```
<span style="background-color: #38263ef0">Answer: win2k.dev.inlanefreight.htb</span>



## 5. SMTP

**Task 1:**  Enumerate the SMTP service and submit the banner, including its version as the answer.
{: .notice}

To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, <b>HELO</b> or <b>EHLO</b>.


```console
┌──(solo㉿HTB)-[~]
└─$ telnet 10.129.245.156 25
```

```
Trying 10.129.245.156...
Connected to 10.129.245.156.
Escape character is '^]'.
220 InFreight ESMTP v2.11
```
<span style="background-color: #38263ef0">Answer: InFreight ESMTP v2.11</span>

**Task 2:** Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer. 
{: .notice}


```console
┌──(solo㉿HTB)-[~]
└─$ telnet 10.129.245.156 25
```

```
Trying 10.129.245.156...
Connected to 10.129.245.156.
Escape character is '^]'.
220 InFreight ESMTP v2.11
```

# Conclusion

This module offers an exceptional opportunity for individuals seeking to acquire proficient skills in utilizing different Host Based Enumeration tools. Mastery of these tools is highly recommended for anyone aspiring to excel in this field, making this module an essential resource for knowledge acquisition.