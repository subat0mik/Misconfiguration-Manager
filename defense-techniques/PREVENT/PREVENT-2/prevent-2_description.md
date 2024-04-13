# PREVENT-2

## Description
Disable Fallback to NTLM

## Summary
Within SCCM's client push installation properties, there exists a setting to "Allow connection fallback to NTLM." This setting allows the site server to fallback to NTLM if Kerberos fails (Figure 1).

![Figure 1](./prevent-2_ntlm-fallback.png)

_Figure 1 - Client Push Installation Properties_

Adversaries commonly abuse NTLM authentication by coercing computers to authenticate to an attacker-controlled machine then either capturing or relaying the authentication to another resource.

Disabling this setting prevents the use of NTLM authentication and coercion.

**NOTE:** This technique must be used in conjunction with [PREVENT-1](../PREVENT-1/prevent-1_description.md). 

## Linked Defensive IDs
- [PREVENT-1: Patch site server with KB15599094](../PREVENT-1/prevent-1_description.md)
- [PREVENT-5: Disable automatic side-wide client push installation](../PREVENT-5/prevent-5_description.md)

## Associated Offensive IDs
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)
- [ELEVATE-3: NTLM relay via automatic client push installation and AD System Discovery](../../../attack-techniques/ELEVATE/ELEVATE-3/ELEVATE-3_description.md)

## References
- Chris Thompson, [Coercing NTLM Authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
