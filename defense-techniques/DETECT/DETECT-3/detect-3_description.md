# DETECT-3

## Description
Monitor client push installation accounts authenticating from anywhere other than the primary site server

## Summary
An attacker may use coercion methods to force the the SCCM site server's client push installation accounts to authenticate to an attacker-controlled machine and relay that authentication to another target. This elevation method enables privilege escalation and lateral movement if the attacker targets other systems where the client push installation accounts have administrator privileges, as client push installation requires local administrator privileges to successfully install the client software.

A defender can compare the `Account Name` field of [Event ID: 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) to that of the `Source_Host` field, or the static IP address of the site server to the `Source Network Address` field. If the site server's domain computer account generates a successful logon event from a source that is not that site server, an NTLM relay attack may have taken place.

The example below displays a successful logon event for a client push installation account from a host that is not the site server.

```
    Source_Host: server2.sccmlab.local
    An account was successfully logged on.

    ...

    New Logon:
        Security ID:		S-1-5-21-549653051-3181377268-3861266315-1106
        Account Name:		clientpush
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
        Workstation Name:	
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
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../DETECT-1/detect-1_description.md)
- [PREVENT-5: Disable automatic side-wide client push installation](../../PREVENT/PREVENT-5/prevent-5_description.md)

## Associated Offensive IDs
- [ELEVATE-1: NTLM relay site server to SMB on site systems](../../../attack-techniques/ELEVATE/ELEVATE-1/ELEVATE-1_description.md)
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)

## References
- Chris Thompson, [Coercing NTLM Authentication from SCCM Servers](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
- Daniel Petri, [How to Defend Against an NTLM Relay Attack](https://www.semperis.com/blog/how-to-defend-against-ntlm-relay-attack/)
- Fox-IT, [Relaying credentials everywhere with ntlmrelayx](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/)