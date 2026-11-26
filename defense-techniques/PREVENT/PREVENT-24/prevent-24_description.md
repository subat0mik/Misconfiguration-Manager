# PREVENT-24

## Description
Review distribution point and site server shares for plaintext credentials and remove unneeded non-default shares

## Summary
Distribution points (DPs) and site servers expose file shares that Domain Users can often read. This includes the default `SCCMContentLib$` share and non-default shares that admins add over time for scripts, software sources and backups. Both tend to collect files with plaintext credentials, which attackers can loot as described in [CRED-6](../../../attack-techniques/CRED/CRED-6/cred-6_description.md).

To reduce this risk:

1. Compare the shares on each DP and site server to the [standard SCCM shares in RECON-2](../../../attack-techniques/RECON/RECON-2/recon-2_description.md). Remove the non-default shares that are not needed, and restrict access to the ones that are. Check both share and NTFS permissions, because effective access is the more restrictive of the two.
2. Search the remaining shares, including `SCCMContentLib$`, for plaintext credentials in scripts, config files and backups.3. Remove any credentials you find, and change the passwords for those accounts.
4. Do not put credentials in packages, applications or scripts that are distributed through SCCM.

Repeat this review on a schedule, because new content is added all the time.

## Linked Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../PREVENT-10/prevent-10_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../PREVENT-20/prevent-20_description.md)
- [DETECT-7: Monitor read access to sensitive distribution point share content](../../DETECT/DETECT-7/detect-7_description.md)

## Associated Offensive IDs
- [CRED-6: Loot domain credentials, SSH keys, and more from SCCM Distribution Points (DP) and other site server shares](../../../attack-techniques/CRED/CRED-6/cred-6_description.md)

## References
- Microsoft, [The content library in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/the-content-library)