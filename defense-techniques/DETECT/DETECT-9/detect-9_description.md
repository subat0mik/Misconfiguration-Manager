# DETECT-9

## Description
Monitor local object access for local SCCM logs and settings

## Summary
An attacker enumerate SCCM infrastructure by locally accessing SCCM client logs that are stored on the local endpoint that the adversary has compromised. 
By default all SCCM-enrolled clients will have specific directories associated to SCCM:
* C:\Windows\CCMCACHE
* C:\Windows\CCMSETUP
* C:\Windows\CCM\Logs

The `C:\Windows\CCM` file path is readable by non-administrators by default. From the logs located within this file path, attackers can enumerate details about SCCM infrastructure hostnames, deployments, and other details.

From a tradecraft perspective, offensive operators would only need to review the files from within the file browser of the C2, making this method of enumeration one of the most evasive from the perspective of default telemetry generation.

Additionally, the registry key/value of HKLM:\SOFTWARE\Microsoft\SMS\DP\ManagementPoints will enumerate the DPs and MPs for that particular SCCM-enrolled client.

By default, most forms of telemetry will not generate an event for file access or registry key/value queries. Defenders can generate custom auditing on these default file/registry locations and identify anomalous process and users accessing the files via a SACL set on the locations.

The following is an example of a SACL set on the C:\Windows\CCM\Logs\* file path:
```
Event ID: 4663
An attempt was made to access an object.

Subject:
	Security ID:		APERTURE\TESTSUBJECT1
	Account Name:		TESTSUBJECT1
	Account Domain:		APERTURE
	Logon ID:		0x7FE94D

Object:
	Object Server:		Security
	Object Type:		File
	Object Name:		C:\Windows\CCM\Logs\CcmMessaging.log
	Handle ID:		0x4a4
	Resource Attributes:	S:AI

Process Information:
	Process ID:		0x1594
	Process Name:		C:\Tools\SharpSCCM.exe

Access Request Information:
	Accesses:		ReadData (or ListDirectory)
				
	Access Mask:		0x1
```

The following is an example of a SACL set on the HKLM:\SOFTWARE\Microsoft\SMS\DP registry key/values:
```
Event ID: 4663
An attempt was made to access an object.

Subject:
	Security ID:		APERTURE\TESTSUBJECT1
	Account Name:		TESTSUBJECT1
	Account Domain:		APERTURE
	Logon ID:		0x7FE94D

Object:
	Object Server:		Security
	Object Type:		Key
	Object Name:		\REGISTRY\MACHINE\SOFTWARE\Microsoft\SMS\DP
	Handle ID:		0x8c0
	Resource Attributes:	-

Process Information:
	Process ID:		0x514
	Process Name:		C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Access Request Information:
	Accesses:		Query key value
				
	Access Mask:		0x1
```

## Associated Offensive IDs
- [RECON-7: Enumerate SCCM site information via local files](../../../attack-techniques/RECON/RECON-7/recon-7_description.md)


## References
- Chris Thompson, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM/)
- Josh Prager & Nico Shyne, Domain Persistence: Detection Triage and Recovery, https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024