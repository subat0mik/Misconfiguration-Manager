# PREVENT-7

## Description
Disable command support in PXE boot configuration

## Summary
When configuring a boot image for preboot execution environment (PXE) booting in SCCM, there exists a setting to "Enable command support (testing only)." This setting allows any user that PXE boots into the WinPE environment to press `F8` to launch a command prompt, thus enabling more control over the  WinPE deployment. This can be abused by attackers attempting to PXE boot from the network.

As the setting text implies, this setting should only be used for testing and debugging the boot image. It should be disabled before the boot image is used in production.

## Linked Defensive IDs
- [PREVENT-6: Configure a strong PXE boot password](../../../defense-techniques/PREVENT/PREVENT-6/prevent-6_description.md)
- [PREVENT-21: Restrict PXE boot to authorized VLANs](../../../defense-techniques/PREVENT/PREVENT-21/prevent-21_description.md)

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)

## References
- Christopher Panayi, [Pulling Passwords Out of Configuration Manager](https://www.youtube.com/watch?v=Ly9goAud0gs)
- Microsoft, [WinPE Boot](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot#winpe-boot)
- Jason Barrett, [How to Enable Command Support Console in WinPE](https://learnmesccm.com/ts/enable-command-support-console-winpe.html)