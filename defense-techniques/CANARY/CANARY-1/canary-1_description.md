# CANARY-1

## Description
Configure an appropriately-privileged NAA with interactive logon restricted

## Summary
Monitor for any usage of these account, which will be pushed out to all clients in the site.

## Linked Defensive IDs
- [PREVENT-3: Harden or disable network access accounts](../../PREVENT/PREVENT-3/prevent-3_description.md)
- [PREVENT-10: Enforce the principle of least privilege for accounts](../../PREVENT/PREVENT-10/prevent-10_description.md)

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)
- [CRED-2: Request machine policy and deobfuscate secrets](../../../attack-techniques/CRED/CRED-2/cred-2_description.md)
- [CRED-3: Dump currently deployed secrets via WMI](../../../attack-techniques/CRED/CRED-3/cred-3_description.md)
- [CRED-4: Retrieve legacy secrets from the CIM repository](../../../attack-techniques/CRED/CRED-4/cred-4_description.md)
- [CRED-5: Dump credentials from the site database](../../../attack-techniques/CRED/CRED-5/cred-5_description.md)

## References
- [An Inside Look: How to Distribute Credentials Securely in SCCM, by Christopher Panayi](https://www.mwrcybersec.com/an-inside-look-how-to-distribute-credentials-securely-in-sccm)
- Duane Michael, [The Phantom Credentials of SCCM: Why the NAA Won’t Die](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)