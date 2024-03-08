# RECON-2

## Description
Enumerate SCCM roles via SMB

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements
- Valid Active Directory domain credentials

## Summary
When certain site system roles are installed, part of the installation process involves configuring file shares on the host system. These shares contain detailed descriptions and unique naming conventions that may disclose what site they're deployed in and what roles are installed. Reviewing shares on potential site systems contributes to attack path discovery. 

## Impact
1. Profiling site system roles is a supplementary step in building potential attack paths.
2. A resolved DP role can be a target for PXE abuse to recover domain credentials detailed in [CRED-1](../../CRED/CRED-1/cred-1_description.md).
3. A resolved DP role can be a target for [sensitive information hunting in the Content Library](https://rzec.se/blog/looting-microsoft-configuration-manager).
4. A resolved WSUS role can be a target for lateral movement or privilege escalation detailed in [ELEVATE-1](../../ELEVATE/ELEVATE-1/ELEVATE-1_description.md)

## Defensive IDs
- 

## Examples
The following examples are a sampling and are not an exhaustive representation of site system roles and their shares.

### Site Server Shares
The primary site server is configured with multiple default shares when deployed and these shares persist even in configurations where content delivery is migrated to a remote file share. Other than the quantity of shares, shares like the `SMS_SITE` share or specific strings like "Site Server DP share" for the `SMS_DP$` share's description identify the system is hosting the site server role.

```
Name                  Description
----                  -----------
ADMIN$                Remote Admin
AdminUIContentPayload AdminUIContentPayload share for AdminUIContent Packages
C$                    Default share
EasySetupPayload      EasySetupPayload share for EasySetup Packages
IPC$                  Remote IPC
SCCMContentLib$       'Configuration Manager' Content Library for site LAB (2/9/2024)
SMSPKGC$              SMS Site LAB DP 2/9/2024
SMSSIG$               SMS Site LAB DP 2/9/2024
SMS_CPSC$             SMS Compressed Package Storage
SMS_DP$               ConfigMgr Site Server DP share
SMS_LAB               SMS Site LAB 02/09/24
SMS_OCM_DATACACHE     OCM inbox directory
SMS_SITE              SMS Site LAB 02/09/24
SMS_SUIAgent          SMS Software Update Installation Agent -- 02/09/24
```

### Distribution Point
Distribution points (DP) and site servers have shares in common but their descriptions differentiate the two. Consider the `SMS_DP$` share's description from both roles:

|Role| Description|
|---------|------|
|Site server| ConfigMgr Site Server DP share|
|Distribution Point|SMS Site LAB DP 2/20/2024|

Further, the presence of the REMINST file share indicates that Windows Deployment Services is installed on the host and it is likely a PXE enabled distribution point.

```
Name            Description
----            -----------
ADMIN$          Remote Admin
C$              Default share
IPC$            Remote IPC
REMINST         RemoteInstallation
SCCMContentLib$ 'Configuration Manager' Content Library for site LAB (2/20/2024)
SMSPKGC$        SMS Site LAB DP 2/20/2024
SMSSIG$         SMS Site LAB DP 2/20/2024
SMS_DP$         SMS Site LAB DP 2/20/2024
```
### Windows Server Update Services
Windows Server Update Services file shares don't necessarily disclose what site they're in, or if they're enrolled at all, but the default file shares persist. Additionally, a site system can have multiple roles installed, so in some cases a system could have the WSUS and DP roles installed, which would correlate the site and roles. The host for the WSUS service is also granted the `smsdbrole_SUP` role in the site database, which is useful for identifying the site database when hosted remotely from the site server. 
```
Name                   Description
----                   -----------
ADMIN$                 Remote Admin
C$                     Default share
IPC$                   Remote IPC
UpdateServicesPackages A network share to be used by client systems for collecting all software packages (usually ap...
WsusContent            A network share to be used by Local Publishing to place published content on this WSUS system.
WSUSTemp               A network share used by Local Publishing from a Remote WSUS Console Instance.
```

## References
- Garrett Foster, [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- Tomas Rzepka, [Looting Microsoft Configuration Manager](https://rzec.se/blog/looting-microsoft-configuration-manager/)
- Tomas Rzepka, [CMLoot](https://github.com/1njected/CMLoot)
- Andreas Vikerup and Dan Rosenqvist, [cmloot](https://github.com/shelltrail/cmloot)
- Microsoft, [smsdbrole_SUP](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#smsdbrole_sup)