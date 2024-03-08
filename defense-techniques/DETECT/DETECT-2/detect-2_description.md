# DETECT-2

## Description
Monitor the read access requests of the `System Management` container within Active Directory Users and Computers.

## Summary
An attacker may utilize LDAP requests targeting the domain controller's `System` container which contains the `System Management` container. This `System Management` container usually has `GenericAll` permissions set on the container object and contains the SCCM published site information. An attacker can query this container to resolve the potential site servers.

Defenders can set focused auditing on the `System Management` container to identify anomalous read access attempts. Defenders can enable a SACL (System Access Control List) on the `System Management` container and set the audit categories to monitor for `Read all properties`. Upon the querying of the `System Management` container within Active Directory Users and Computers, a [Event ID: 4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662) will highlight that a Read operation was performed on the container object.

The below example displays the `sccmhunter.py` `find` command. 

```
python3 sccmhunter.py find -u 'john' -p 'Ieshoh5chael' -d sccmlab.local -dc-ip 10.10.0.100

SCCMHunter v1.0.0 by @garrfoster
[23:01:38] INFO     [!] First time use detected.
[23:01:38] INFO     [!] SCCMHunter data will be saved to /root/.sccmhunter
[23:01:38] INFO     [*] Checking for System Management Container.
[23:01:38] INFO     [+] Found System Management Container. Parsing DACL.
[23:01:38] INFO     [-] System Management Container not found.
[23:01:38] INFO     [*] Searching LDAP for anything containing the strings 'SCCM' or 'MECM'
[23:01:39] INFO     [+] Found 7 principals that contain the string 'SCCM' or 'MECM'.   

```

The below example displays a successful SACL generation upon the use of an LDAP request reading the properties of the `System Management` container.

```
Event ID: 4662
An operation was performed on an object.

Subject :
	Security ID:		S-1-5-21-549653051-3181377268-3861266315-1108
	Account Name:		john
	Account Domain:		SCCMLAB
	Logon ID:		0x40C307

Object:
	Object Server:		DS
	Object Type:		%{bf967a8b-0de6-11d0-a285-00aa003049e2}
	Object Name:		%{fa360eb8-3156-4989-85b6-c15d8a2b4a05}
	Handle ID:		0x0

Operation:
	Operation Type:		Object Access
	Accesses:		List Contents
				
	Access Mask:		0x4
	Properties:		List Contents
	{bf967a8b-0de6-11d0-a285-00aa003049e2}


Additional Information:
	Parameter 1:		-
	Parameter 2:
```
The below example displays the System Management translation between the GUID identified in the Object Name field of the 4662 event and the actual plain text Object Name. 

```
TimeCreated     : 3/4/2024 11:20:32 PM
UserName        : Administrator
Computer        : System Management
RequestedObject : container
ObjectGuid      : %{fa360eb8-3156-4989-85b6-c15d8a2b4a05}
```

## Linked Defensive IDs
- 


## Associated Offensive IDs
- [RECON-1: Enumerate SCCM site information via LDAP](../../../attack-techniques/RECON/RECON-1/recon-1_description.md)

## References
- Garrett Foster, SCCMHunter Find Module, https://github.com/garrettfoster13/sccmhunter/wiki/find
- Josh Prager & Nico Shyne, Domain Persistence: Detection Triage and Recovery, https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024