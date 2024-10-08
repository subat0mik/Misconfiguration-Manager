# RECON-6

## Description
Enumerate SCCM roles via the SMB Named Pipe winreg

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements
- Valid Active Directory domain credentials

## Summary
When a primary site server or distribution point role is installed an entry of  "SOFTWARE\Microsoft\SMS" is created in the "Computer Config -> Security Settings -> Local Policies -> Security Options -> Network Access: Remotely Accessible Registry Paths and Sub-Paths" in local group policy. This security setting determines which registry paths and sub-paths can be accessed over the network, regardless of the users or groups listed in the access control list (ACL) of the winreg registry key.

This registry key and sub keys contain information about the current site server and other site servers within the hierarchy. Enumerating this registry key and sub keys on a primary site server and distribution point contributes to attack path discovery.  
## Impact
1. Profiling site system roles is a supplementary step in building potential attack paths
2. A resolved DP role can be a target for PXE abuse to recover domain credentials detailed in [CRED-1](../../CRED/CRED-1/cred-1_description.md)
3. A resolved DP role can be a target for [sensitive information hunting in the Content Library](https://rzec.se/blog/looting-microsoft-configuration-manager)
4. A resolved MP role can be a target for spoofing client enrollment [CRED-2](../../CRED/CRED-2/cred-2_description.md)
5. A resolved MP site system role can be used to elevate privileges via credential relay attacks [ELEVATE-1](../../ELEVATE/ELEVATE-1/ELEVATE-1_description.md)
6. A resolved Site Database role can be a target for lateral movement or privilege escalation detailed in [TAKEOVER-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
 
## Defensive IDs
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples
Use [pssrecon](https://github.com/slygoo/pssrecon) to enumerate a PSS or DP over winreg.
### Primary Site Server

```
pssrecon -u lowpriv -p password -d corp.local -host pss.corp.local

[+] Distrubution Point Installed
[+] Site Code Found: COR
[+] Site Server Found: SCCM.corp.local
[+] Management Point Found: http://SCCM.corp.local
[+] Management Point Found: http://SCCMMP.corp.local
[+] Management Point Installed
[+] Site Database Found: SCCMDB01.CORP.LOCAL
```
### Distribution Point

```
pssrecon -u lowpriv -p password -d corp.local -host dp.corp.local

[+] Distrubution Point Installed
[+] Site Code Found: COR
[+] Site Server Found: SCCM.CORP.local
[+] Management Point Found: http://SCCM.corp.local
[+] Management Point Found: http://SCCMMP.corp.local
[+] Anonymous Access On This Distrubution Point Is Enabled
[+] PXE Installed
```
## References
- Dylan Bradley, [pssrecon](https://github.com/slygoo/pssrecon)
- Tomas Rzepka, [Looting Microsoft Configuration Manager](https://rzec.se/blog/looting-microsoft-configuration-manager/)
- Microsoft, [Network Access: Remotely Accessible Registry Paths and Sub-Paths](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-remotely-accessible-registry-paths-and-subpaths)
