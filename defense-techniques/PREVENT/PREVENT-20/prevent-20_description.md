# PREVENT-20

## Description
Block unnecessary connections to site systems

## Summary
> **IMPORTANT:** These protocols may be necessary to permit in your environment, depending on the configuration. For example, it may be difficult to block SMB traffic to site servers if they are also distribution points, or to HTTP(S) if they are both a management point and an SMS Provider. Review the referenced documentation and test thoroughly prior to implementing these rules in production.

To help prevent NTLM coercion and relay and remote management from untrusted, non-admin networks, block connections from **unnecessary** sources to site systems via protocols and ports that can be used for coercion, relay, and remote management, including:
- HTTPS and WMI traffic to SMS Providers
- MSSQL traffic to site databases
- SMB traffic to primary (including CAS) and passive site servers

## Linked Defensive IDs
- [PREVENT-9: Enforce MFA for SMS Provider calls](../PREVENT-9/prevent-9_description.md)
- [PREVENT-12: Require SMB signing on site systems](../PREVENT-12/prevent-12_auth-vs-session.png)
- [PREVENT-14: Require EPA on AD CS and site databases](../PREVENT-14/prevent-14_description.md)

## Associated Offensive IDs
- [CRED-5: Dump credentials from the site database](../../../attack-techniques/CRED/CRED-5/cred-5_description.md)
- [CRED-6: Loot domain credentials, SSH keys, and more from SCCM Distribution Points (DP)](../../../attack-techniques/CRED/CRED-6/cred-6_description.md)
- [CRED-7: Retrieve credentials via AdminService API](../../../attack-techniques/CRED/CRED-7/cred-7_description.md)
- [CRED-8: Extract credentials from SCCM policies by coercing and relaying management point (MP) NTLM authentication to the site database](../../../attack-techniques/CRED/CRED-8/cred-8_description.md)
- [ELEVATE-1: NTLM relay site server to SMB on site systems](../../../attack-techniques/ELEVATE/ELEVATE-1/ELEVATE-1_description.md)
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)
- [EXEC-1: Application deployment](../../../attack-techniques/EXEC/EXEC-1/exec-1_description.md)
- [EXEC-2: PowerShell script execution](../../../attack-techniques/EXEC/EXEC-2/exec-2_description.md)
- [RECON-2: Enumerate SCCM roles via SMB](../../../attack-techniques/RECON/RECON-2/recon-2_description.md)
- [RECON-3: Enumerate SCCM roles via HTTP](../../../attack-techniques/RECON/RECON-3/recon-3_description.md)
- [RECON-4: Query client devices via CMPivot](../../../attack-techniques/RECON/RECON-4/recon-4_description.md)
- [RECON-5: Locate users via SMS Provider](../../../attack-techniques/RECON/RECON-5/RECON-5_description.md)
- [RECON-6: Enumerate SCCM roles via the SMB Named Pipe winreg](../../../attack-techniques/RECON/RECON-6/recon-6_description.md)
- [TAKEOVER-1: NTLM coercion and relay to MSSQL on remote site database](../../../attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
- [TAKEOVER-2: NTLM coercion and relay to SMB on remote site database](../../../attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md)
- [TAKEOVER-3: NTLM coercion and relay to HTTP on AD CS](../../../attack-techniques/TAKEOVER/TAKEOVER-3/)
- [TAKEOVER-4: NTLM coercion and relay from CAS to origin primary site server](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-5: NTLM coercion and relay to AdminService on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-6: NTLM coercion and relay to SMB on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md)
- [TAKEOVER-7: NTLM coercion and relay to SMB between primary and passive site servers](../../../attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md)
- [TAKEOVER-8: NTLM coercion and relay HTTP to LDAP on domain controller](../../../attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description.md)

## References
Microsoft, [Ports used in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/ports)