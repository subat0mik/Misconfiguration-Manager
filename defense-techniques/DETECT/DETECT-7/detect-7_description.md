# DETECT-7

## Description
Monitor read access to the SMSTemp directory

## Summary
SCCM contains a preboot execution environment (PXE) feature which allows systems to load a specific operating system image on boot.

Attackers can recover domain credentials from PXE media if weak passwords are used, potentially transitioning from an unauthenticated network context to a domain-authenticated one, allowing for privilege escalation and lateral movement.

Several forms of offensive tooling (sccmhunter, pxethief, pxethiefy) will typically follow this operational flow:

1. Connect to Distribution Point via SMB
2. Enumerate “REMINST” (Remote Install) share (Windows Deployment Services (WDS) and often contains PXE boot files)
3. Enumerate SMSTemp directory
4. Spider .var extensions, which likely contain PXE boot configuration variables

Different tooling will conduct step 2. differently. For example, sccmhunter's `smb` module will search and access the `\\.\REMINST\` share path prior to connecting to `SMSTemp` directory. In contrast, pxethiefy will utilize the `\\.\IPC$\winreg` named pipe to connect to `SMSTemp`. No one method is "stealthier" than the other, as there are opportunities for detection with either connection choice.
### PXEThief Exmaple:
```
root@DEBIAN:/home/labadmin/PXEThief# python pxethief.py 2 192.168.57.50
________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|

[+] Generating and downloading encrypted media variables file from MECM server located at 192.168.57.50
[+] Using interface: eth0 - eth0
[+] Targeting user-specified host: 192.168.57.50

[+] Asking ConfigMgr for location to download the media variables and BCD files...

/home/labadmin/PXEThief/env/lib/python3.10/site-packages/scapy/sendrecv.py:726: SyntaxWarning: 'iface' has no effect on L3 I/O sr1(). For multicast/link-local see https://scapy.readthedocs.io/en/latest/usage.html#multicast
  warnings.warn(
Begin emission

Finished sending 1 packets
*
Received 1 packets, got 1 answers, remaining 0 packets

[!] Variables File Location: \SMSTemp\2024.10.18.16.34.38.0001.{F43C5F34-8623-40AA-88B1-875EED83DEDF}.boot.var
[!] BCD File Location: \SMSTemp\2024.10.18.16.34.36.06.{F43C5F34-8623-40AA-88B1-875EED83DEDF}.boot.bcd
[!] Blank password on PXE boot found!
[!] Attempting automatic exploitation.
[+] Media variables file to decrypt: 2024.10.18.16.34.38.0001.{F43C5F34-8623-40AA-88B1-875EED83DEDF}.boot.var
[+] Password bytes provided: 0x5300fdfff1ffbdff75008cff42001c000a00a1ff
[+] Successfully decrypted media variables file with the provided password!
...SNIP...
```
Notice that the `SMSTemp` directory is enumerated for `.var` files and `.bcd` files containing credentials or blank passwords. Defenders can monitor the connections to the `\\REMINST\` file share and the `SMSTemp` directory with Event ID: 5145 and SACLs set on the `SMSTemp` directory.

The below example displays a successful Event ID 5145 generation upon the connection to `\\REMINST\` file share:
```
Event ID: 5145
A network share object was checked to see whether client can be granted desired access.
	
Subject:
	Security ID:		APERTURE\TESTSUBJECT1
	Account Name:		TESTSUBJECT1
	Account Domain:		APERTURE
	Logon ID:		0x6AB6CBBE

Network Information:	
	Object Type:		File
	Source Address:		10.1.0.201
	Source Port:		38590
	
Share Information:
	Share Name:		\\*\REMINST
	Share Path:		\??\C:\RemoteInstall
	Relative Target Name:	SMSTemp

Access Request Information:
	Access Mask:		0x81
	Accesses:		ReadData (or ListDirectory)
				ReadAttributes
				
Access Check Results:
	ReadData (or ListDirectory):	Granted by	D:(A;;0x1200a9;;;WD)
				ReadAttributes:	Granted by	D:(A;;0x1200a9;;;WD)
```

The below example displays a successful SACL generation upon the access of the `SMSTemp` directory within `C:\RemoteInstall\` on the distribution point:
```
Event ID: 4663
An attempt was made to access an object.

Subject:
	Security ID:		SYSTEM
	Account Name:		ATLAS$
	Account Domain:		APERTURE
	Logon ID:		0x3E7

Object:
	Object Server:		Security
	Object Type:		File
	Object Name:		C:\RemoteInstall\SMSTemp\2024.09.07.09.10.30.0001.{7CEC8AFB-6AD5-45C1-A6E2-433D7F4D2E71}.boot.var
	Handle ID:		0x528
	Resource Attributes:	S:AI

Process Information:
	Process ID:		0xfbc
	Process Name:		C:\Windows\System32\svchost.exe

Access Request Information:
	Accesses:		ReadData (or ListDirectory)
```
## Associated Offensive IDs
- [RECON-1: Enumerate SCCM site information via LDAP](../../../attack-techniques/RECON/RECON-1/recon-1_description.md)
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)

## References
- Garrett Foster, [SCCMHunter Find Module](https://github.com/garrettfoster13/sccmhunter/wiki/find)
- Christopher Panayi, [Identifying and Retrieving Credentials From SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences)
- Christopher Panayi, [Pulling Passwords Out of Configuration Manager](https://www.youtube.com/watch?v=Ly9goAud0gs)
- Christopher Panayi, [PXEThief](https://github.com/MWR-CyberSec/PXEThief)
- Josh Prager & Nico Shyne, [Detection and Triage of Domain Persistence](https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024/blob/main/Detection%20and%20Triage%20of%20Domain%20Persistence-BSidesNYC.pdf)
- Microsoft, [Understanding PXE Boot](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot#)
- SpecterOps, [Cred1py](https://github.com/specterops/Cred1py)