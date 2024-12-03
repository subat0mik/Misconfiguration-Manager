# DETECT-8

## Description
Monitor connections to winreg named pipe

## Summary
An attacker may enumerate PXE configurations or primary (including CAS) and secondary site configuration information via the winreg named pipe (`\\.\pipe\winreg`).
The winreg named pipe is primarily used by Windows for remote access to the Windows registry. The use of the named pipe in a client environment may be an anomaly in and of itself.

The following is an example of `RECON-6 SMB Winreg` named pipe enumeration.
```
C:\Tools>pssrecon -u testsubject4 -p BlackMesa004 -d aperture.local -host atlas.aperture.local
[+] Distrubution Point Installed
[+] Site Code Found: PS1
[+] Site Server Found: atlas.aperture.local
[+] Management Point Found: http://atlas.aperture.local
[+] PXE Installed
[+] Management Point Installed
[+] Site Database Found: P-BODY.APERTURE.LOCAL
```

Defenders can leverage several assumptions to identify the connections to the winreg named pipe and reduce false positives:
1. The connection will be made from an attacker controlled host
2. The connection will target Tier0 infrastructure or a Distribution Point

To identify connections to the winreg named pipe, defenders can create composite events based on the source network connection Sysmon `Event ID: 3` referencing destination port `445` and the name of the Tier 0, Primary (including CAS) or Secondary site servers, in combination with the destination Sysmon `Event ID: 18` winreg named pipe connection.

The below Sysmon `Event ID: 3` (Source host) displays the connection to a site server over destination port `445`:
```
Event ID: 3
Network connection detected:
RuleName: -
UtcTime: 2024-10-24 15:02:05.024
ProcessGuid: {00000000-0000-0000-0000-000000000000}
ProcessId: 6392
Image: <unknown process>
User: -
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.1.0.101
SourceHostname: sentry1.aperture.local
SourcePort: 49839
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 10.1.0.50
DestinationHostname: ATLAS
DestinationPort: 445
DestinationPortName: microsoft-ds
```

The above event would need to be combined with a destination Sysmon `Event ID: 18` named pipe connection:

```
Event ID: 18
Pipe Connected:
RuleName: -
EventType: ConnectPipe
UtcTime: 2024-10-24 15:02:05.541
ProcessGuid: {8288158a-ce46-66cf-eb03-000000000000}
ProcessId: 4
PipeName: \winreg
Image: System
User: NT AUTHORITY\SYSTEM
```

Additionally, defenders can enable detailed file access auditing (either for the entire domain (GPO) or local group policy). Enabling this audit category will generate an Windows Security `Event ID: 5145` detailed file share access event that displays the winreg named pipe connection and the source host that the connection originated from. Proxied execution of offensive tooling will still generate these event IDs.

The below Windows Security Detailed File Share Access `Event ID: 5145` which will display the connection to the winreg named pipe:
```
Event ID: 5145	
Subject:
	Security ID:		APERTURE\TESTSUBJECT4
	Account Name:		TESTSUBJECT4
	Account Domain:		APERTURE
	Logon ID:		0x6CB896C6

Network Information:	
	Object Type:		File
	Source Address:		10.1.0.101
	Source Port:		49839
	
Share Information:
	Share Name:		\\*\IPC$
	Share Path:		
	Relative Target Name:	winreg

Access Request Information:
	Access Mask:		0x120089
	Accesses:		READ_CONTROL
				SYNCHRONIZE
				ReadData (or ListDirectory)
				ReadEA
				ReadAttributes
				
Access Check Results:
	-
```

## Associated Offensive IDs
- [RECON-6: Enumerate SCCM roles via the SMB Named Pipe winreg](../../../attack-techniques/RECON/RECON-6/recon-6_description.md)
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)

## References
- Garrett Foster,[SCCMHunter SMB Module](https://github.com/garrettfoster13/sccmhunter/wiki/SMB)
- Josh Prager & Nico Shyne, [Detection and Triage of Domain Persistence](https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024/blob/main/Detection%20and%20Triage%20of%20Domain%20Persistence-BSidesNYC.pdf)