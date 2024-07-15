---
title: "Footprinting"
classes: wide
header:
  teaser: /assets/images/htb/Footprinting/teaser.png
  overlay_image: /assets/images/htb/Footprinting/logo.png
  overlay_filter: 0.5
ribbon: Red
excerpt: ""
description: ""
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

The <b>Footprinting</b> module consists of eleven sub-modules. This write-up will focus on the coverage of the first three sections, providing detailed explanations and analysis for each.

1. FTP
2. SMB
3. NFS

## 1. FTP
**Task 1:** Which version of the FTP server is running on the target system? Submit the entire banner as the answer.
{: .notice}

To determine which version of the FTP server is running on the target's system, we can directly connect to it or use Nmap by running <b> -sV target ip </b> command.

```console
┌──(solo㉿HTB)-[~]
└─$ ftp 10.129.199.51
Connected to 10.129.199.51.
220 InFreight FTP v1.1
```
<b></b>

 <span style="background-color: #38263ef0">Answer: InFreight FTP v1.1</span>

 **Task 2:** Enumerate the FTP server and find the flag.txt file. Submit the contents of it as the answer.
{: .notice}

Let's start with anonymous login and hit enter during password prompt.

```console
┌──(solo㉿HTB)-[~]
└─$ ftp 10.129.199.51
Connected to 10.129.199.51.
220 InFreight FTP v1.1
Name (10.129.199.51:solo): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Now, we will simply use <b>ls -al</b> command to list everything. Lastly we will download the flag by using <b>get</b> command.

```console
ftp> ls -al
229 Entering Extended Passive Mode (|||63808|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftpuser  ftpuser      4096 Nov  8  2021 .
drwxr-xr-x   2 ftpuser  ftpuser      4096 Nov  8  2021 ..
-rw-r--r--   1 ftpuser  ftpuser       220 Nov  8  2021 .bash_logout
-rw-r--r--   1 ftpuser  ftpuser      3771 Nov  8  2021 .bashrc
-rw-r--r--   1 ftpuser  ftpuser        39 Nov  8  2021 flag.txt
-rw-r--r--   1 ftpuser  ftpuser       807 Nov  8  2021 .profile
226 Transfer complete

ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||24376|)
150 Opening BINARY mode data connection for flag.txt (39 bytes)
    39       27.81 KiB/s 
226 Transfer complete
39 bytes received in 00:00 (0.93 KiB/s)
ftp> 

```

<b></b>

 <span style="background-color: #38263ef0">Answer: HTB{b7skjr4c76zhsds7fzhd4k3ujg7nhdjre}</span>


## 2. SMB

**Task 1:** What version of the SMB server is running on the target system? Submit the entire banner as the answer.
{: .notice}

To find out which version of SMB is running in the target system, we will utilize NMAP. SMB usually connects to the Samba server over TCP ports <b>137</b>, <b>138</b>, <b>139</b> but CIFS which is the extension of the SMB protocol uses TCP port <b>445</b> only.


```console
┌──(solo㉿HTB)-[~]
└─$ nmap -p 139,445 -sV -Pn 10.129.83.52
```

```
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```
<b></b>

<span style="background-color: #38263ef0">Answer: Samba smbd 4.6.2</span>

**Task 2:** What is the name of the accessible share on the target?
{: .notice}

By deploying <b>-L</b> flag, we can display a list of the server's shares with the <b>smbclient</b> command from our host. Additionally, using the <b>-N</b> flag allows us to use <b>null session</b>, which is <b>anonymous</b> access without the input of existing users or valid passwords.

```console
┌──(solo㉿HTB)-[~]
└─$ smbclient -N -L //10.129.83.52
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
sambashare      Disk      InFreight SMB v3.1
IPC$            IPC       IPC Service (InlaneFreight SMB server (Samba, Ubuntu))
```
<b></b>

<span style="background-color: #38263ef0">Answer: sambashare</span>

**Task 3:** Connect to the discovered share and find the flag.txt file. Submit the contents as the answer. 
{: .notice}

Let's connect and provide nothing as password.

```console
┌──(solo㉿HTB)-[~]
└─$ smbclient //10.129.83.52
Password for [WORKGROUP\htb]:
Try "help" to get a list of possible commands.
smb: \> 
```
We used <b>help</b> command to get a list of possible commands from which we used the <b>l</b> command to list everything. Afterwards we navigated to the contents path and deployed the <b>l</b> command again. Lastly we used the <b>get</b> command to download the flag.txt file.

```
smb: \> l
  .
  .. 
  .profile 
  contents 
  .bash_logout  
  .bashrc 

smb: \> cd contents\
smb: \contents\> ls
  .
  ..
  flag.txt

smb: \contents\> get flag.txt
getting file \contents\flag.txt of size 38 as flag.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```
<b></b>

<span style="background-color: #38263ef0">Answer: sambashare</span>

**Task 4:** Find out which domain the server belongs to. 
{: .notice}

After using <b>NMAP</b> and its NSE scripts which provided us with limited information, we decided to resort to other tools. One of the handy tools for this is <b>rpcclient</b>. The tool is a concept and a central tool to realize operational and work-sharing structures in networks and client-server architectures.

```console
┌──(solo㉿HTB)-[~]
└─$ rpcclient -U "" 10.129.83.52
Password for [WORKGROUP\]:
```
Once again we used <b>help</b> command to get a list of possible commands from which we used the <b>srvinfo</b> command to get server query info. 

```
rpcclient $> querydominfo

Domain: DEVOPS
Server: DEVSMB                              
Comment: InlaneFreight SMB server (Samba, Ubuntu)
Total Users: 0                       
Total Groups: 0                       
Total Aliases: 0                      
Sequence No: 1709712810               
Force Logoff: -1                                                    
Domain Server State:
Server Role: ROLE_DOMAIN_PDC                                       
Unknown 3: 0x1              
```
<b></b>

<span style="background-color: #38263ef0">Answer: DEVOPS</span>

**Task 5:** Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer.
{: .notice}

This task was rather confusing and it took us longer than we wish to admit as the additional information could have been anything. We started by enumerating all of the netnames. Through trial and error we managed to find the correct answer which in this case is <b>InFreight SMB v3.1</b>.

```console
┌──(solo㉿HTB)-[~]
└─$ rpcclient $> netshareenumall
netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: sambashare
        remark: InFreight SMB v3.1
        path:   C:\home\sambauser\
        password:
netname: IPC$
        remark: IPC Service (InlaneFreight SMB server (Samba, Ubuntu))
        path:   C:\tmp
        password:
```
<b></b>

<span style="background-color: #38263ef0">Answer: InFreight SMB v3.1</span>

**Task 6:** What is the full system path of that specific share? (format: "/directory/names")
{: .notice}

This task is easy and we already have the answer at hand. We just have to convert the system path from Windows to Linux.

```console
┌──(solo㉿HTB)-[~]
└─$ C:\home\sambauser\ ----> /home/sambauser
```      
<b></b>

<span style="background-color: #38263ef0">Answer: /home/sambauser</span>

## 3. NFS

**Task 1:**  Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" and the "nfsshare" share as the answer. 
{: .notice}

When footprinting NFS, the TCP ports <b>111</b> and <b>2049</b> are essential. We can also get information about the NFS service and the host via RPC, as shown below.


```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap 10.129.202.5 -p 111,2049 -sV -sC 
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.202.5
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      43200/udp   mountd
|   100005  1,2,3      51516/udp6  mountd
|   100005  1,2,3      51981/tcp6  mountd
|   100005  1,2,3      54673/tcp   mountd
|   100021  1,3,4      40933/tcp6  nlockmgr
|   100021  1,3,4      41459/tcp   nlockmgr
|   100021  1,3,4      42432/udp6  nlockmgr
|   100021  1,3,4      56017/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs     3-4 (RPC #100003)
```

Next we will deploy NSE script to retrieve list of all currently running RPC services, their names and descriptions, and the ports they use.

```console
┌──(solo㉿HTB)-[~]
└─$ sudo nmap --script nfs* 10.129.202.5 -sV -p 111,2049
Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.202.5
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /var/nfs
|   access: Read Lookup Modify Extend Delete NoExecute
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxr-xr-x   65534  65534  4096  2021-11-08T15:08:27  .
| ??????????  ?      ?      ?     ?                    ..
| rw-r--r--   65534  65534  39    2021-11-08T15:08:27  flag.txt
| 
| 
| Volume /mnt/nfsshare
|   access: Read Lookup Modify Extend Delete NoExecute
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxr-xr-x   65534  65534  4096  2021-11-08T14:06:40  .
| ??????????  ?      ?      ?     ?                    ..
| rw-r--r--   65534  65534  59    2021-11-08T14:06:40  flag.txt
|_
|_rpcinfo: ERROR: Script execution failed (use -d to debug)
| nfs-statfs: 
|   Filesystem     1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|   /var/nfs       4062912.0  3330488.0  506328.0   87%   16.0T        32000
|_  /mnt/nfsshare  4062912.0  3330488.0  506328.0   87%   16.0T        32000
| nfs-showmount: 
|   /var/nfs 10.0.0.0/8
|_  /mnt/nfsshare 10.0.0.0/8
2049/tcp open  nfs     3-4 (RPC #100003)
```
Now that we have discovered NFS services, let's mount it to our local machine.

```console
┌──(solo㉿HTB)-[~]
└─$ showmount -e 10.129.202.5                           
Export list for 10.129.202.5:
/var/nfs      10.0.0.0/8
/mnt/nfsshare 10.0.0.0/8
```
```console
┌──(solo㉿HTB)-[~]
└─$ mkdir target-NFS
```
```console
┌──(solo㉿HTB)-[~]
└─$ sudo mount -t nfs 10.129.202.5:/ ./target-NFS/ -o nolock
```
```console
┌──(solo㉿HTB)-[~]
└─$ cd target-NFS
tree .
.
├── mnt
│   └── nfsshare
│       └── flag.txt
└── var
    └── nfs
        └── flag.txt

```

<b></b>

<span style="background-color: #38263ef0">Answer: HTB{hjglmvtkjhlkfuhgi734zthrie7rjmdze}</span>

<span style="background-color: #38263ef0">Answer: HTB{8o7435zhtuih7fztdrzuhdhkfjcn7ghi4357ndcthzuc7rtfghu34}</span>


# Conclusion

This module offers an exceptional opportunity for individuals seeking to acquire proficient skills in utilizing different Host Based Enumeration tools. Mastery of these tools is highly recommended for anyone aspiring to excel in this field, making this module an essential resource for knowledge acquisition.