# Technique Name
Retrieve secrets from PXE boot media

## Code Name
- CREDENTIAL01

## ATT&CK TTPs
- [TA0001 - Initial Access](https://attack.mitre.org/tactics/TA0001)
- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Required Privilege / Context
- Unauthenticated network access
- Line of sight to DHCP server
- Line of sight to PXE-enabled distrution point

## Summary
SCCM contains a preboot execution environment (PXE) feature which allows systems to load a specific operating system image on boot.

When PXE is configured, SCCM will make various [configuration changes](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot#pxe-service-point-installation) to the distribution point (DP). Most notably, the `PxeInstalled` and `IsPxe` values under the `HKLM\Software\Microsoft\SMS\DP` registry key are set to `1`.

The boot images are then [deployed](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot#add-boot-images-to-a-pxe-enabled-dp) from the site server to the DP's file system at `C:\RemoteInstall\`.

The three required components for PXE boot to work are: a PXE client, a DHCP server, and a PXE-enabled DP. A non-domain-joined computer (the PXE client in this case) that has network access could initiate the [DHCP process](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences), resulting in the PXE client receiving a DHCPPACK request containing the `BootFileName` location and Windows Deployment Services (WDS) network boot program (NBP). Next, the client initiates a TFTP session to [download](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot#downloading-the-boot-files) the NBP. The NBP contains several files and and programs that are used to boot the computer into a Windows Preinstallation Environment (WinPE).

To Summarize this process, how PXE works in SCCM:
1. PXE client gets an IP from DHCP server​
2. Client sends new DHCPREQUEST to DP, DP responds with DHCPACK that contains the BootFileName​
3. Client starts TFTP session targeting the boot file​
4. Client downloads the network boot program (NBP)​
5. NBP downloads the operating system loader and boot files​
6. The WinPE image is loaded into a RAMDISK in memory​
7. WinPE boots, loading a task sequence (TS) boot shell, TS manager boot strap (TsPxe.dll)​
8. TS environment variables and a client certificate are downloaded via TFTP​
9. TSPXE locates the MP and downloads policy assignments​
10. Collection and machine variables are downloaded

**Note:** This goes beyond the scope of this article but Microsoft's [documentation](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot) covers it in more depth.

This process can be abused because the files and policies can be accessed without booting the PXE media. By initiating the DHCPDISCOVER request, an attacker can locate the PXE media on the network and check if they are password-protected. If they are protected, the hash can be retrieved and cracked offline using [hashcat](https://github.com/hashcat/hashcat) and [this custom module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module) from Christopher Panayi. If not protected, the cleartext data can be directly used. [PXEThief](https://github.com/MWR-CyberSec/PXEThief​) and [pxethiefy](https://github.com/csandker/pxethiefy​) both enable and trivialize this attack.

Once the media file is decrypted, it may contain credential material in the `NAAConfig` (network access account(NAA)), `TaskSequence`, and `CollectionSettings` (collection variables) policies.


## Impact

Attackers may recover domain credentials from this process, the difficulty of which is a direct function of the complexity of the password set on the PXE media file. If a weak password is set, cracking the password is relatively computionally "easy," depending on the hardware.

With these credentials, attackers may transition from an unauthenticated context on the network to a domain-authenticated context. If any of the credentials recovered are privileged, it may also enable privilege escalation and lateral movement vectors.

## Defensive IDs
- [PROTECT04](../../defense-techniques/PROTECT04/protect04-description.md)
- [PROTECT07](../../defense-techniques/PROTECT07/protect07-description.md)
- [PROTECT08](../../defense-techniques/PROTECT08/protect08-description.md)
- [PROTECT11](../../defense-techniques/PROTECT11/protect11-description.md)

## Examples

```

```

## References
- Christopher Panayi, Identifying and Retrieving Credentials From SCCM/MECM Task Sequences, https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences
- Christopher Panayi, Pulling Passwords Out of Configuration Manager, https://www.youtube.com/watch?v=Ly9goAud0gs
- Christopher Panayi, PXEThief, https://github.com/MWR-CyberSec/PXEThief
- Christopher Panayi, AES-128 ConfigMgr CryptDeriveKey Hashcat Module, https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
- Carsten Sandker, pxethiefy, https://github.com/csandker/pxethiefy​
- Microsoft, Understanding PXE Boot, https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot
