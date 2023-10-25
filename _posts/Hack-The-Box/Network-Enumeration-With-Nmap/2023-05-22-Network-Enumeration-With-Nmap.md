---
title: "Network Enumeration With Nmap"
classes: wide
header:
  teaser: /assets/images/htb/Network-Enumeration-With-Nmap/teaser.png
  overlay_image: /assets/images/htb/Network-Enumeration-With-Nmap/logo.png
  overlay_filter: 0.5
ribbon: Red
excerpt: ""
description: "Part. 1"
categories:
  - HTB Write Up
tags:
  - HTB
  - Nmap
  - NSE
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

The <b>Network Enumeration with Nmap</b> module comprises a total of eight sub-modules. This write-up will focus on the coverage of the first four sections, providing detailed explanations and analysis for each.

1. Host and Port Scanning
2. Saving the Results
3. Service Enumeration
4. Nmap Script Engine (NSE)

## 1. Host and Port Scanning
**Task 1:** Find all TCP ports on your target. Submit the total number of found TCP ports as the answer. 
{: .notice}

In order to find all of the <b>TCP</b> ports, the <span style="background-color: #38263ef0">-Pn</span> flag is utilized to deactivate host discovery, focusing solely on port scanning. The inclusion of the <span style="background-color: #38263ef0">-v</span> flag serves the purpose of providing detailed insights into nmap's operations. Specifically, with increased verbosity (<span style="background-color: #38263ef0">-vv</span>), interactive mode displays open ports in real-time as they are encountered.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -Pn -vv 10.129.11.154
```

```console
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
110/tcp   open  pop3         syn-ack ttl 63
139/tcp   open  netbios-ssn  syn-ack ttl 63
143/tcp   open  imap         syn-ack ttl 63
445/tcp   open  microsoft-ds syn-ack ttl 63
31337/tcp open  Elite        syn-ack ttl 63

```
<b></b>

 <span style="background-color: #38263ef0">Answer: 7</span>

**Task 2:** Enumerate the hostname of your target and submit it as the answer. (case-sensitive)
{: .notice}

We are tasked to enumerate the hostname of our target, and various approaches can be employed to accomplish this task. Below, I present two methods for enumerating the hostname.
<b></b>

The first method involves utilizing the <span style="background-color: #38263ef0">-A</span> flag. It is worth noting that this method exhibits slower performance compared to the second approach due to the flag enabling OS detection, version detection, script scanning, and traceroute.

```console
┌──(solo㉿HTB)-[~]
└─$ nmap -A -vv 10.129.79.161
```

```
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1accacd49552d64d71e7341e14273c3c
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AA5AAIMYSP2Z8qyfE4cFAGOW1EWXDnPnCPbw2MGkB25pCXL/
80/tcp    open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp   open  pop3        syn-ack Dovecot pop3d
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open  imap        syn-ack Dovecot imapd
445/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
31337/tcp open  Elite?      syn-ack
Service Info: Host: NIX-NMAP-DEFAULT; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
<b></b>

The second method entails employing the <span style="background-color: #38263ef0">smb-os-discovery</span> script, which is notably faster in terms of execution time when compared to the first method. This script specifically aims to ascertain critical system information such as the operating system, computer name, domain, workgroup, and current time, making it an ideal choice for accomplishing the task.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap --script=smb-os-discovery -vv 10.129.79.161
```

```
Not shown: 993 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
110/tcp   open  pop3         syn-ack ttl 63
139/tcp   open  netbios-ssn  syn-ack ttl 63
143/tcp   open  imap         syn-ack ttl 63
445/tcp   open  microsoft-ds syn-ack ttl 63
31337/tcp open  Elite        syn-ack ttl 63

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nix-nmap-default
|   NetBIOS computer name: NIX-NMAP-DEFAULT\x00
|   Domain name: \x00
|   FQDN: nix-nmap-default
```
<b></b>

<span style="background-color: #38263ef0">Answer: NIX-NMAP-DEFAULT</span>

## 2. Saving the Results

**Task:** Perform a full TCP port scan on your target and create an HTML report. Submit the number of the highest port as the answer. 
{: .notice}

The task at hand is straightforward: we have to perform full TCP port scan which is done by utilizing the <span style="background-color: #38263ef0">-p-</span> flag. This approach aligns with task 1 of the <b>Host and Port Scanning</b> module. To exclusively focus on port scanning, we will once again employ the <span style="background-color: #38263ef0">-Pn</span> flag to deactivate host discovery. Furthermore, we are utilizing the aggressive timing mode, denoted by the <span style="background-color: #38263ef0">-T</span> flag, to expedite our scans.

<b></b>

Finally, we save the scan output to an XML file using the <span style="background-color: #38263ef0">-oX</span> flag, which we can subsequently convert into an HTML report.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -Pn -p- -T4 -vv -oX fulltcp 10.129.236.139
```
```
Starting Nmap 7.93 ( https://nmap.org )
Initiating Parallel DNS resolution of 1 host. at 12:10
Completed Parallel DNS resolution of 1 host. at 12:10, 0.00s elapsed
Initiating SYN Stealth Scan at 12:10
Scanning 10.129.236.139 [65535 ports]
SYN Stealth Scan Timing: About 0.45% done
Discovered open port 22/tcp on 10.129.236.139
Discovered open port 139/tcp on 10.129.236.139
Discovered open port 110/tcp on 10.129.236.139
Discovered open port 445/tcp on 10.129.236.139
Discovered open port 143/tcp on 10.129.236.139
Discovered open port 80/tcp on 10.129.236.139
SYN Stealth Scan Timing: About 46.54% done; ETC: 12:12 (0:01:10 remaining)
Discovered open port 31337/tcp on 10.129.236.139
Completed SYN Stealth Scan at 12:11, 74.35s elapsed (65535 total ports)
Nmap scan report for 10.129.236.139
Host is up, received user-set (0.040s latency).
Scanned for 75s
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
110/tcp   open  pop3         syn-ack ttl 63
139/tcp   open  netbios-ssn  syn-ack ttl 63
143/tcp   open  imap         syn-ack ttl 63
445/tcp   open  microsoft-ds syn-ack ttl 63
31337/tcp open  Elite        syn-ack ttl 63
```
<b></b>

With the XML output, we can easily create HTML reports that are easy to read, even for non-technical people. This is very useful for documentation, as it presents our results in a detailed and clear way. To convert the stored results from XML format to HTML, we can use the tool <span style="background-color: #38263ef0">xsltproc</span>.

```console
┌──(solo㉿HTB)-[~]
└─$ xsltproc fulltcp -o fulltcp.html
```
<b></b>

When we open the newly converted HTML report. This is what it looks like:
<b></b>

![image.png](/assets/images/htb/Network-Enumeration-With-Nmap/2.png)
<b></b>

<span style="background-color: #38263ef0">Answer: 31337</span>

## 3. Service Enumeration

**Task:** Enumerate all ports and their services. One of the services contains the flag you have to submit as the answer.
{: .notice}

The task is to enumerate all ports and their services. We will find the flag in one of the services. 

<b></b>

Let's start by enumerating all ports and their services with the <span style="background-color: #38263ef0">-sV</span> flag. Here, we are telling Nmap to perform service version detection on the specified ports which in our case are all ports, denoted by the <span style="background-color: #38263ef0">-p-</span> flag. 

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -sV -Pn- -p- -T4 -vv 10.129.33.227
```
<b></b>

```
Nmap scan report for 10.129.33.227
Host is up, received user-set (0.044s latency).
Scanned for 120s
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http        syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
110/tcp   open  pop3        syn-ack ttl 63 Dovecot pop3d
139/tcp   open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp   open  imap        syn-ack ttl 63 Dovecot imapd
445/tcp   open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
31337/tcp open  Elite?      syn-ack ttl 63
Service Info: Host: NIX-NMAP-DEFAULT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.90 seconds
           Raw packets sent: 65712 (2.891MB) | Rcvd: 65708 (2.628MB)
```
<b></b>

In the initial phase of this task, our objective was to enumerate all ports along with their corresponding services, and we have achieved this successfully. However, one limitation is that we lack detailed information about the specific flag associated with the ports. To overcome this limitation, we will employ the use of <b>netcat</b> (nc), a versatile utility that allows us to establish <b>TCP</b> or <b>UDP</b> connections between two computers. This tool enables us to both write and read data through an open port, facilitating our exploration of the ports in question.

```console
┌──(solo㉿HTB)-[~]
└─$ nc -nv 10.129.33.227 31337 
```
<b></b>

```
(UNKNOWN) [10.129.33.227] 31337 (?) open
220 HTB{pr0F7pDv3r510nb4nn3r}
```
<b></b>

<span style="background-color: #38263ef0">Answer: HTB{pr0F7pDv3r510nb4nn3r}</span>

## 4. Nmap Script Engine (NSE)

**Task:** Use NSE and its scripts to find the flag that one of the services contain and submit it as the answer. 
{: .notice}

The objective of this task is to utilize the Nmap Scripting Engine (NSE) scripts to search for the flag within one of the services. By leveraging the capabilities of NSE scripts, we can automate the process of scanning and probing the services in order to identify the specific location of the flag.
<b></b>

To begin the process, we will deploy the default script by using the <span style="background-color: #38263ef0">-sC</span> flag. This flag instructs Nmap to run the default NSE scripts, which are designed to perform a comprehensive analysis of the target services. By executing these scripts, we can gather valuable information and potentially uncover the location of the flag.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -sC -vv 10.129.33.227
```
<b></b>

```
Scanned for 143s
Not shown: 993 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 63
| ssh-hostkey: 
80/tcp    open  http         syn-ack ttl 63
|_http-title: Apache2 Ubuntu Default Page: It works
110/tcp   open  pop3         syn-ack ttl 63
|_pop3-capabilities: TOP SASL RESP-CODES AUTH-RESP-CODE UIDL PIPELINING CAPA
139/tcp   open  netbios-ssn  syn-ack ttl 63
143/tcp   open  imap         syn-ack ttl 63
|_imap-capabilities: Pre-login more SASL-IR capabilities LOGIN-REFERRALS OK IMAP4rev1 LITERAL+ IDLE have post-login listed ENABLE LOGINDISABLEDA0001 ID
445/tcp   open  microsoft-ds syn-ack ttl 63
31337/tcp open  Elite        syn-ack ttl 63

Host script results:
|_clock-skew: mean: -38m02s, deviation: 1h09m16s, median: 1m56s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nix-nmap-default
|   NetBIOS computer name: NIX-NMAP-DEFAULT\x00
|   Domain name: \x00
|   FQDN: nix-nmap-default
|_  System time:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 
|_  start_date: N/A
| nbstat: NetBIOS name: NIX-NMAP-DEFAUL, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   NIX-NMAP-DEFAUL<00>  Flags: <unique><active>
|   NIX-NMAP-DEFAUL<03>  Flags: <unique><active>
|   NIX-NMAP-DEFAUL<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53108/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 57139/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 15310/udp): CLEAN (Failed to receive data)
|   Check 4 (port 26426/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 14:19
Completed NSE at 14:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 14:19
Completed NSE at 14:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 144.37 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.056KB)
```
<b></b>

Please pay close attention to the output specifically related to <b>port 80</b>. This port is of particular interest as it may provide crucial information regarding the location of the flag.

```
80/tcp    open  http         syn-ack ttl 63
|_http-title: Apache2 Ubuntu Default Page: It works
```
<b></b>

Next, we will explore the NSE scripts folder to find a suitable script that allows us to specifically target the HTTP protocol. By selecting an appropriate script from the NSE scripts folder, we can effectively scan and analyze the HTTP service for potential flag-related information.

```console
┌──(solo㉿HTB)-[~]
└─$ cd /usr/share/nmap/scripts
```
<b></b>

```
┌──(solo㉿HTB)-[/usr/share/nmap/scripts]
└─$ ls
```
[//]: # (NSE Scripts)
```
carsd-info.nse                       fcrdns.nse                              https-redirect.nse               ms-sql-info.nse                 smb-flood.nse
address-info.nse                      finger.nse                              http-stored-xss.nse              ms-sql-ntlm-info.nse            smb-ls.nse
afp-brute.nse                         fingerprint-strings.nse                 http-svn-enum.nse                ms-sql-query.nse                smb-mbenum.nse
afp-ls.nse                            firewalk.nse                            http-svn-info.nse                ms-sql-tables.nse               smb-os-discovery.nse
afp-path-vuln.nse                     firewall-bypass.nse                     http-title.nse                   ms-sql-xp-cmdshell.nse          smb-print-text.nse
afp-serverinfo.nse                    flume-master-info.nse                   http-tplink-dir-traversal.nse    mtrace.nse                      smb-protocols.nse
afp-showmount.nse                     fox-info.nse                            http-trace.nse                   murmur-version.nse              smb-psexec.nse
ajp-auth.nse                          freelancer-info.nse                     http-traceroute.nse              mysql-audit.nse                 smb-security-mode.nse
ajp-brute.nse                         ftp-anon.nse                            http-trane-info.nse              mysql-brute.nse                 smb-server-stats.nse
ajp-headers.nse                       ftp-bounce.nse                          http-unsafe-output-escaping.nse  mysql-databases.nse             smb-system-info.nse
ajp-methods.nse                       ftp-brute.nse                           http-useragent-tester.nse        mysql-dump-hashes.nse           smb-vuln-conficker.nse
ajp-request.nse                       ftp-libopie.nse                         http-userdir-enum.nse            mysql-empty-password.nse        smb-vuln-cve2009-3103.nse
allseeingeye-info.nse                 ftp-proftpd-backdoor.nse                http-vhosts.nse                  mysql-enum.nse                  smb-vuln-cve-2017-7494.nse
amqp-info.nse                         ftp-syst.nse                            http-virustotal.nse              mysql-info.nse                  smb-vuln-ms06-025.nse
asn-query.nse                         ftp-vsftpd-backdoor.nse                 http-vlcstreamer-ls.nse          mysql-query.nse                 smb-vuln-ms07-029.nse
auth-owners.nse                       ftp-vuln-cve2010-4221.nse               http-vmware-path-vuln.nse        mysql-users.nse                 smb-vuln-ms08-067.nse
auth-spoof.nse                        ganglia-info.nse                        http-vuln-cve2006-3392.nse       mysql-variables.nse             smb-vuln-ms10-054.nse
backorifice-brute.nse                 giop-info.nse                           http-vuln-cve2009-3960.nse       mysql-vuln-cve2012-2122.nse     smb-vuln-ms10-061.nse
backorifice-info.nse                  gkrellm-info.nse                        http-vuln-cve2010-0738.nse       nat-pmp-info.nse                smb-vuln-ms17-010.nse
bacnet-info.nse                       gopher-ls.nse                           http-vuln-cve2010-2861.nse       nat-pmp-mapport.nse             smb-vuln-regsvc-dos.nse
banner.nse                            gpsd-info.nse                           http-vuln-cve2011-3192.nse       nbd-info.nse                    smb-vuln-webexec.nse
bitcoin-getaddr.nse                   hadoop-datanode-info.nse                http-vuln-cve2011-3368.nse       nbns-interfaces.nse             smb-webexec-exploit.nse
bitcoin-info.nse                      hadoop-jobtracker-info.nse              http-vuln-cve2012-1823.nse       nbstat.nse                      smtp-brute.nse
bitcoinrpc-info.nse                   hadoop-namenode-info.nse                http-vuln-cve2013-0156.nse       ncp-enum-users.nse              smtp-commands.nse
bittorrent-discovery.nse              hadoop-secondary-namenode-info.nse      http-vuln-cve2013-6786.nse       ncp-serverinfo.nse              smtp-enum-users.nse
bjnp-discover.nse                     hadoop-tasktracker-info.nse             http-vuln-cve2013-7091.nse       ndmp-fs-info.nse                smtp-ntlm-info.nse
broadcast-ataoe-discover.nse          hbase-master-info.nse                   http-vuln-cve2014-2126.nse       ndmp-version.nse                smtp-open-relay.nse
broadcast-avahi-dos.nse               hbase-region-info.nse                   http-vuln-cve2014-2127.nse       nessus-brute.nse                smtp-strangeport.nse
broadcast-bjnp-discover.nse           hddtemp-info.nse                        http-vuln-cve2014-2128.nse       nessus-xmlrpc-brute.nse         smtp-vuln-cve2010-4344.nse
broadcast-db2-discover.nse            hnap-info.nse                           http-vuln-cve2014-2129.nse       netbus-auth-bypass.nse          smtp-vuln-cve2011-1720.nse
broadcast-dhcp6-discover.nse          hostmap-bfk.nse                         http-vuln-cve2014-3704.nse       netbus-brute.nse                smtp-vuln-cve2011-1764.nse
broadcast-dhcp-discover.nse           hostmap-crtsh.nse                       http-vuln-cve2014-8877.nse       netbus-info.nse                 sniffer-detect.nse
broadcast-dns-service-discovery.nse   hostmap-robtex.nse                      http-vuln-cve2015-1427.nse       netbus-version.nse              snmp-brute.nse
broadcast-dropbox-listener.nse        http-adobe-coldfusion-apsa1301.nse      http-vuln-cve2015-1635.nse       nexpose-brute.nse               snmp-hh3c-logins.nse
broadcast-eigrp-discovery.nse         http-affiliate-id.nse                   http-vuln-cve2017-1001000.nse    nfs-ls.nse                      snmp-info.nse
broadcast-hid-discoveryd.nse          http-apache-negotiation.nse             http-vuln-cve2017-5638.nse       nfs-showmount.nse               snmp-interfaces.nse
broadcast-igmp-discovery.nse          http-apache-server-status.nse           http-vuln-cve2017-5689.nse       nfs-statfs.nse                  snmp-ios-config.nse
broadcast-jenkins-discover.nse        http-aspnet-debug.nse                   http-vuln-cve2017-8917.nse       nje-node-brute.nse              snmp-netstat.nse
broadcast-listener.nse                http-auth-finder.nse                    http-vuln-misfortune-cookie.nse  nje-pass-brute.nse              snmp-processes.nse
broadcast-ms-sql-discover.nse         http-auth.nse                           http-vuln-wnr1000-creds.nse      nntp-ntlm-info.nse              snmp-sysdescr.nse
broadcast-netbios-master-browser.nse  http-avaya-ipoffice-users.nse           http-waf-detect.nse              nping-brute.nse                 snmp-win32-services.nse
broadcast-networker-discover.nse      http-awstatstotals-exec.nse             http-waf-fingerprint.nse         nrpe-enum.nse                   snmp-win32-shares.nse
broadcast-novell-locate.nse           http-axis2-dir-traversal.nse            http-webdav-scan.nse             ntp-info.nse                    snmp-win32-software.nse
broadcast-ospf2-discover.nse          http-backup-finder.nse                  http-wordpress-brute.nse         ntp-monlist.nse                 snmp-win32-users.nse
broadcast-pc-anywhere.nse             http-barracuda-dir-traversal.nse        http-wordpress-enum.nse          omp2-brute.nse                  socks-auth-info.nse
broadcast-pc-duo.nse                  http-bigip-cookie.nse                   http-wordpress-users.nse         omp2-enum-targets.nse           socks-brute.nse
broadcast-pim-discovery.nse           http-brute.nse                          http-xssed.nse                   omron-info.nse                  socks-open-proxy.nse
broadcast-ping.nse                    http-cakephp-version.nse                iax2-brute.nse                   openflow-info.nse               ssh2-enum-algos.nse
broadcast-pppoe-discover.nse          http-chrono.nse                         iax2-version.nse                 openlookup-info.nse             ssh-auth-methods.nse
broadcast-rip-discover.nse            http-cisco-anyconnect.nse               icap-info.nse                    openvas-otp-brute.nse           ssh-brute.nse
broadcast-ripng-discover.nse          http-coldfusion-subzero.nse             iec-identify.nse                 openwebnet-discovery.nse        ssh-hostkey.nse
broadcast-sonicwall-discover.nse      http-comments-displayer.nse             ike-version.nse                  oracle-brute.nse                ssh-publickey-acceptance.nse
broadcast-sybase-asa-discover.nse     http-config-backup.nse                  imap-brute.nse                   oracle-brute-stealth.nse        ssh-run.nse
broadcast-tellstick-discover.nse      http-cookie-flags.nse                   imap-capabilities.nse            oracle-enum-users.nse           sshv1.nse
broadcast-upnp-info.nse               http-cors.nse                           imap-ntlm-info.nse               oracle-sid-brute.nse            ssl-ccs-injection.nse
broadcast-versant-locate.nse          http-cross-domain-policy.nse            impress-remote-discover.nse      oracle-tns-version.nse          ssl-cert-intaddr.nse
broadcast-wake-on-lan.nse             http-csrf.nse                           informix-brute.nse               ovs-agent-version.nse           ssl-cert.nse
broadcast-wpad-discover.nse           http-date.nse                           informix-query.nse               p2p-conficker.nse               ssl-date.nse
broadcast-wsdd-discover.nse           http-default-accounts.nse               informix-tables.nse              path-mtu.nse                    ssl-dh-params.nse
broadcast-xdmcp-discover.nse          http-devframework.nse                   ip-forwarding.nse                pcanywhere-brute.nse            ssl-enum-ciphers.nse
cassandra-brute.nse                   http-dlink-backdoor.nse                 ip-geolocation-geoplugin.nse     pcworx-info.nse                 ssl-heartbleed.nse
cassandra-info.nse                    http-dombased-xss.nse                   ip-geolocation-ipinfodb.nse      pgsql-brute.nse                 ssl-known-key.nse
cccam-version.nse                     http-domino-enum-passwords.nse          ip-geolocation-map-bing.nse      pjl-ready-message.nse           ssl-poodle.nse
cics-enum.nse                         http-drupal-enum.nse                    ip-geolocation-map-google.nse    pop3-brute.nse                  sslv2-drown.nse
cics-info.nse                         http-drupal-enum-users.nse              ip-geolocation-map-kml.nse       pop3-capabilities.nse           sslv2.nse
cics-user-brute.nse                   http-enum.nse                           ip-geolocation-maxmind.nse       pop3-ntlm-info.nse              sstp-discover.nse
cics-user-enum.nse                    http-errors.nse                         ip-https-discover.nse            port-states.nse                 stun-info.nse
citrix-brute-xml.nse                  http-exif-spider.nse                    ipidseq.nse                      pptp-version.nse                stun-version.nse
citrix-enum-apps.nse                  http-favicon.nse                        ipmi-brute.nse                   puppet-naivesigning.nse         stuxnet-detect.nse
citrix-enum-apps-xml.nse              http-feed.nse                           ipmi-cipher-zero.nse             qconn-exec.nse                  supermicro-ipmi-conf.nse
citrix-enum-servers.nse               http-fetch.nse                          ipmi-version.nse                 qscan.nse                       svn-brute.nse
citrix-enum-servers-xml.nse           http-fileupload-exploiter.nse           ipv6-multicast-mld-list.nse      quake1-info.nse                 targets-asn.nse
clamav-exec.nse                       http-form-brute.nse                     ipv6-node-info.nse               quake3-info.nse                 targets-ipv6-map4to6.nse
clock-skew.nse                        http-form-fuzzer.nse                    ipv6-ra-flood.nse                quake3-master-getservers.nse    targets-ipv6-multicast-echo.nse
coap-resources.nse                    http-frontpage-login.nse                irc-botnet-channels.nse          rdp-enum-encryption.nse         targets-ipv6-multicast-invalid-dst.nse
couchdb-databases.nse                 http-generator.nse                      irc-brute.nse                    rdp-ntlm-info.nse               targets-ipv6-multicast-mld.nse
couchdb-stats.nse                     http-git.nse                            irc-info.nse                     rdp-vuln-ms12-020.nse           targets-ipv6-multicast-slaac.nse
creds-summary.nse                     http-gitweb-projects-enum.nse           irc-sasl-brute.nse               realvnc-auth-bypass.nse         targets-ipv6-wordlist.nse
cups-info.nse                         http-google-malware.nse                 irc-unrealircd-backdoor.nse      redis-brute.nse                 targets-sniffer.nse
cups-queue-info.nse                   http-grep.nse                           iscsi-brute.nse                  redis-info.nse                  targets-traceroute.nse
cvs-brute.nse                         http-headers.nse                        iscsi-info.nse                   resolveall.nse                  targets-xml.nse
cvs-brute-repository.nse              http-hp-ilo-info.nse                    isns-info.nse                    reverse-index.nse               teamspeak2-version.nse
daap-get-library.nse                  http-huawei-hg5xx-vuln.nse              jdwp-exec.nse                    rexec-brute.nse                 telnet-brute.nse
daytime.nse                           http-icloud-findmyiphone.nse            jdwp-info.nse                    rfc868-time.nse                 telnet-encryption.nse
db2-das-info.nse                      http-icloud-sendmsg.nse                 jdwp-inject.nse                  riak-http-info.nse              telnet-ntlm-info.nse
deluge-rpc-brute.nse                  http-iis-short-name-brute.nse           jdwp-version.nse                 rlogin-brute.nse                tftp-enum.nse
dhcp-discover.nse                     http-iis-webdav-vuln.nse                knx-gateway-discover.nse         rmi-dumpregistry.nse            tls-alpn.nse
dicom-brute.nse                       http-internal-ip-disclosure.nse         knx-gateway-info.nse             rmi-vuln-classloader.nse        tls-nextprotoneg.nse
dicom-ping.nse                        http-joomla-brute.nse                   krb5-enum-users.nse              rpcap-brute.nse                 tls-ticketbleed.nse
dict-info.nse                         http-jsonp-detection.nse                ldap-brute.nse                   rpcap-info.nse                  tn3270-screen.nse
distcc-cve2004-2687.nse               http-litespeed-sourcecode-download.nse  ldap-novell-getpass.nse          rpc-grind.nse                   tor-consensus-checker.nse
dns-blacklist.nse                     http-ls.nse                             ldap-rootdse.nse                 rpcinfo.nse                     traceroute-geolocation.nse
dns-brute.nse                         http-majordomo2-dir-traversal.nse       ldap-search.nse                  rsa-vuln-roca.nse               tso-brute.nse
dns-cache-snoop.nse                   http-malware-host.nse                   lexmark-config.nse               rsync-brute.nse                 tso-enum.nse
dns-check-zone.nse                    http-mcmp.nse                           llmnr-resolve.nse                rsync-list-modules.nse          ubiquiti-discovery.nse
dns-client-subnet-scan.nse            http-methods.nse                        lltd-discovery.nse               rtsp-methods.nse                unittest.nse
dns-fuzz.nse                          http-method-tamper.nse                  lu-enum.nse                      rtsp-url-brute.nse              unusual-port.nse
dns-ip6-arpa-scan.nse                 http-mobileversion-checker.nse          maxdb-info.nse                   rusers.nse                      upnp-info.nse
dns-nsec3-enum.nse                    http-ntlm-info.nse                      mcafee-epo-agent.nse             s7-info.nse                     uptime-agent-info.nse
dns-nsec-enum.nse                     http-open-proxy.nse                     membase-brute.nse                samba-vuln-cve-2012-1182.nse    url-snarf.nse
dns-nsid.nse                          http-open-redirect.nse                  membase-http-info.nse            script.db                       ventrilo-info.nse
dns-random-srcport.nse                http-passwd.nse                         memcached-info.nse               servicetags.nse                 versant-info.nse
dns-random-txid.nse                   http-phpmyadmin-dir-traversal.nse       metasploit-info.nse              shodan-api.nse                  vmauthd-brute.nse
dns-recursion.nse                     http-phpself-xss.nse                    metasploit-msgrpc-brute.nse      sip-brute.nse                   vmware-version.nse
dns-service-discovery.nse             http-php-version.nse                    metasploit-xmlrpc-brute.nse      sip-call-spoof.nse              vnc-brute.nse
dns-srv-enum.nse                      http-proxy-brute.nse                    mikrotik-routeros-brute.nse      sip-enum-users.nse              vnc-info.nse
dns-update.nse                        http-put.nse                            mmouse-brute.nse                 sip-methods.nse                 vnc-title.nse
dns-zeustracker.nse                   http-qnap-nas-info.nse                  mmouse-exec.nse                  skypev2-version.nse             voldemort-info.nse
dns-zone-transfer.nse                 http-referer-checker.nse                modbus-discover.nse              smb2-capabilities.nse           vtam-enum.nse
docker-version.nse                    http-rfi-spider.nse                     mongodb-brute.nse                smb2-security-mode.nse          vulners.nse
domcon-brute.nse                      http-robots.txt.nse                     mongodb-databases.nse            smb2-time.nse                   vuze-dht-info.nse
domcon-cmd.nse                        http-robtex-reverse-ip.nse              mongodb-info.nse                 smb2-vuln-uptime.nse            wdb-version.nse
domino-enum-users.nse                 http-robtex-shared-ns.nse               mqtt-subscribe.nse               smb-brute.nse                   weblogic-t3-info.nse
dpap-brute.nse                        http-sap-netweaver-leak.nse             mrinfo.nse                       smb-double-pulsar-backdoor.nse  whois-domain.nse
drda-brute.nse                        http-security-headers.nse               msrpc-enum.nse                   smb-enum-domains.nse            whois-ip.nse
drda-info.nse                         http-server-header.nse                  ms-sql-brute.nse                 smb-enum-groups.nse             wsdd-discover.nse
duplicates.nse                        http-shellshock.nse                     ms-sql-config.nse                smb-enum-processes.nse          x11-access.nse
eap-info.nse                          http-sitemap-generator.nse              ms-sql-dac.nse                   smb-enum-services.nse           xdmcp-discover.nse
enip-info.nse                         http-slowloris-check.nse                ms-sql-dump-hashes.nse           smb-enum-sessions.nse           xmlrpc-methods.nse
epmd-info.nse                         http-slowloris.nse                      ms-sql-empty-password.nse        smb-enum-shares.nse             xmpp-brute.nse
eppc-enum-processes.nse               http-sql-injection.nse                  ms-sql-hasdbaccess.nse           smb-enum-users.nse              xmpp-info.nse
```
<b></b>

Considering the large number of scripts available, running a simple vulnerability scan specifically targeting the HTTP protocol on <b>port 80</b> can be a more efficient approach. By focusing on vulnerability scanning, we can quickly identify any potential security weaknesses that may be relevant to the flag.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap -sV -script vuln -vv 10.129.33.227 -p 80
```
[//]: # (Found vulnerability)
```
Nmap scan report for 10.129.33.227
Host is up, received echo-reply ttl 63 (0.037s latency).
Scanned for 320s

PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| http-enum: 
|_  /robots.txt: Robots file
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       PACKETSTORM:171631      7.5     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       EDB-ID:51193    7.5     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       CVE-2023-25690  7.5     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    7.5     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9  *EXPLOIT*
|       1337DAY-ID-38427        7.5     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    *EXPLOIT*
|       EDB-ID:46676    7.2     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   6.8     https://vulners.com/cve/CVE-2016-5387
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2022-36760  5.1     https://vulners.com/cve/CVE-2022-36760
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       EXPLOITPACK:2666FB0676B4B582D689921651A30355    5.0     https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355    *EXPLOIT*
|       EDB-ID:42745    5.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       EDB-ID:40909    5.0     https://vulners.com/exploitdb/EDB-ID:40909      *EXPLOIT*
|       CVE-2022-37436  5.0     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-8740   5.0     https://vulners.com/cve/CVE-2016-8740
|       CVE-2016-4979   5.0     https://vulners.com/cve/CVE-2016-4979
|       CVE-2006-20001  5.0     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2016-1546   4.3     https://vulners.com/cve/CVE-2016-1546
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
```
<b></b>

Based on the provided output, it appears that there is a text file named "robots.txt" located on <b>port 80</b>. Let's directly connect to [http://10.129.33.227/robots.txt](http://10.129.33.227/robots.txt) and investigate the contents of the file. By accessing this URL, we can gather more information that might be relevant to our task.

```html
User-agent: *

Allow: /
<body><pre>User-agent: *

Allow: /

HTB{873nniuc71bu6usbs1i96as6dsv26}
</pre></body>
```
<b></b>

<span style="background-color: #38263ef0">Answer: HTB{873nniuc71bu6usbs1i96as6dsv26}</span>

# Conclusion

This module offers an exceptional opportunity for individuals seeking to acquire proficient skills in utilizing Nmap, an indispensable tool that holds immense value for professionals in the realm of Cyber Security. Mastery of Nmap is highly recommended for anyone aspiring to excel in this field, making this module an essential resource for knowledge acquisition.