# DETECT-1

## Description
Monitor site server domain computer accounts authenticating from another source

## Summary
An attacker may use coercion methods to force the the SCCM site server's domain computer account to authenticate to an attacker-controlled machine and relay that authentication to another target. This elevation method enables privilege escalation and lateral movement if the attacker targets any other SCCM site system, as the site server requires local administrator privileges on other site systems.

A defender can compare the `Account Name` field of [Event ID: 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) to that of the `Source_Host` field, or the static IP address of the site server to the `Source Network Address` field. If the site server's domain computer account generates a successful logon event from a source that is not that site server, an NTLM relay attack may have taken place.

The example below displays a successful logon event for the SCCM site server from a host that is not the site server.

```
    Source_Host: server2.sccmlab.local
    An account was successfully logged on.

    Subject:
        Security ID:		S-1-0-0
        Account Name:		-
        Account Domain:		-
        Logon ID:		0x0

    Logon Information:
        Logon Type:		3
        Restricted Admin Mode:	-
        Virtual Account:		No
        Elevated Token:		No

    Impersonation Level:		Impersonation

    New Logon:
        Security ID:		S-1-5-21-549653051-3181377268-3861266315-1105
        Account Name:		SCCM$
        Account Domain:		SCCMLAB
        Logon ID:		0x36E669
        Linked Logon ID:		0x0
        Network Account Name:	-
        Network Account Domain:	-
        Logon GUID:		{00000000-0000-0000-0000-000000000000}

    Process Information:
        Process ID:		0x0
        Process Name:		-

    Network Information:
        Workstation Name:	SCCM
        Source Network Address:	10.10.0.188 <--- Attacker
        Source Port:		58292

    Detailed Authentication Information:
        Logon Process:		NtLmSsp 
        Authentication Package:	NTLM
        Transited Services:	-
        Package Name (NTLM only):	NTLM V2
        Key Length:		128

```

## Linked Defensive IDs
- [DETECT-3: Monitor client push installation accounts authenticating from anywhere other than the primary site server](../DETECT-3/detect-3_description.md)
- [PREVENT-5: Disable automatic side-wide client push installation](../../PREVENT/PREVENT-5/prevent-5_description.md)

## Associated Offensive IDs
- [ELEVATE-1: NTLM relay site server to SMB on site systems](../../../attack-techniques/ELEVATE/ELEVATE-1/ELEVATE-1_description.md)
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)
- [TAKEOVER-1: NTLM coercion and relay to MSSQL on remote site database](../../../attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
- [TAKEOVER-2: NTLM coercion and relay to SMB on remote site database](../../../attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md)
- [TAKEOVER-3: NTLM coercion and relay to HTTP on AD CS](../../../attack-techniques/TAKEOVER/TAKEOVER-3/)
- [TAKEOVER-4: NTLM coercion and relay from CAS to origin primary site server](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-5: NTLM coercion and relay to AdminService on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-6: NTLM coercion and relay to SMB on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md)
- [TAKEOVER-7: NTLM coercion and relay to SMB between primary and passive site servers](../../../attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md)
- [TAKEOVER-8: NTLM coercion and relay HTTP to LDAP on domain controller](../../../attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description.md)

## References
- Chris Thompson, [SCCM Hierarchy Takeover](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087)
- Josh Prager and Nico Shyne, [Domain Persistence: Detection Triage and Recovery](https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024)
- Daniel Petri, [How to Defend Against an NTLM Relay Attack](https://www.semperis.com/blog/how-to-defend-against-ntlm-relay-attack/)
- Fox-IT, [Relaying credentials everywhere with ntlmrelayx](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/)