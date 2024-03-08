# TAKEOVER-3

## Description
Hierarchy takeover via NTLM coercion and relay to HTTP on AD CS

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
-
-

## Summary

## Impact

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Subtechniques
- TAKEOVER-3.1: Coerce primary site server
- TAKEOVER-3.2: Coerce passive site server

## Examples
The steps to execute TAKEOVER-3.1 and TAKEOVER-3.2 are mostly the same except that a different system is targeted for coercion of NTLM authentication.


## References
Author, Title, URL