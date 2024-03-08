# PREVENT-21

## Description
Restrict PXE boot to authorized VLANs

## Summary
As outlined in [CRED-1](../../../attack-techniques/CRED/CRED-1/cred-1_description.md), if an adversary meets certain conditions, such as having line of sight to a PXE-enabled distribution point, they may be able to PXE boot or retrieve PXE boot media.

An option to mitigate such access or attacks is restricting PXE boot to specific VLAN(s). There are two general approaches for configuring this setup:

1. Deploy the PXE-enabled DP on the authorized VLAN, preventing any traffic originating from other VLANs, and also disabling PXE on DPs within non-authorized VLANs.
2. Configure IP helpers to forward DHCP requests from authorized VLANs to the PXE-enabled DP, else ignore PXE requests.

There is another method: DHCP options. Microsoft [does not recommend](https://techcommunity.microsoft.com/t5/configuration-manager-blog/you-want-to-pxe-boot-don-t-use-dhcp-options/ba-p/275562) this approach.

## Linked Defensive IDs
- N/A

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)

## References
- Microsoft, Boot From PXE Server, https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/boot-from-pxe-server
- Reddit, PXE Boot from only one VLAN?, https://www.reddit.com/r/SCCM/comments/nkkv1a/pxe_boot_from_only_one_vlan/