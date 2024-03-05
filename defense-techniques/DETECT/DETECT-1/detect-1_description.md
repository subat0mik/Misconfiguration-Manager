# DETECT-1

## Description

Monitor site system computer accounts authenticating from a source that is not its static netbios name.

## Summary

An attacker could use authentication coercion methods to coerce the NTLM authentication from the SCCM site server's host system and then relay that coerced authentication to another target. This elevation method would enable privilege escalation and lateral movement if the attacker targets the SCCM site system.

A defender can compare the account name field of [Event ID: 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) to that of the source host name field. The SCCM site server's machine account will generate the successful logon event of the machine account authentication on a server or host that is not the SCCM site server.

For reduction of false positives, defenders can allow list the SCCM site server machine account's authentication to the domain controllers, as this behavior is expected and benign.

## Examples

The below example displays a successful logon event for the SCCM site server on a host that is not the SCCM site server.

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
## References
- Chris Thompson, SCCM Hierarchy Takeover, https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087
- Josh Prager & Nico Shyne, Domain Persistence: Detection Triage and Recovery, https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024
- Daniel Petri, How to Defend Against an NTLM Relay Attack, https://www.semperis.com/blog/how-to-defend-against-ntlm-relay-attack/
- Fox-IT, Relaying credentials everywhere with ntlmrelayx, https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/
