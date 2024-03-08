# PREVENT-22

## Description
Do not manage assets in two or more segmented forests, domains, networks, or security tiers

## Summary
SCCM can be used to manage client devices in and store credentials for multiple Active Directory forests, domains, and networks. Due to its asynchronous client -> server architecture, an attacker with SCCM administrator access may abuse this to cross security boundaries intended to segment networks (e.g., firewalls) as well as those that separate systems of a higher security level (e.g., tier zero or control plane assets) from those of a lower security level by executing applications or scripts on devices that are members of different forests, domains, and networks.

Separate systems of a higher security level into another SCCM hierarchy that is treated as such, or omit them from management via SCCM.

Examples of misconfigurations that violate this principle:
- Domain controllers and other tier zero assets are clients of SCCM, allowing an attacker with SCCM admin privileges to compromise all domain accounts and any keys used to establish trust between Active Directory forests to cross forest boundaries.
- Sensitive systems reside on a segmented network or in another forest that the attacker cannot reach directly, but they can execute code within the segment because they control the SCCM server for client devices in that network or forest.
- Active Directory forest accounts are configured in SCCM for multiple forests, allowing an attacker with SCCM admin privileges to dump and decrypt the credentials from the site database and cross forest boundaries.
- Network access accounts in two different forests are configured, allowing an attacker with control of any client device or domain computer credentials to cross forest boundaries.

## Linked Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../PREVENT-10/prevent-10_description.md)

## Associated Offensive IDs
- [CRED-5: Dump credentials from the site database](../../../attack-techniques/CRED/CRED-5/cred-5_description.md)

## References
Jonas Bülow Knudsen, [What is Tier Zero - Part 1](https://posts.specterops.io/what-is-tier-zero-part-1-e0da9b7cdfca)