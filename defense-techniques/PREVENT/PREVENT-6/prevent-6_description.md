# PREVENT-6

## Description
Configure strong PXE boot password

## Summary

PXE (Preboot eXecution Environment) boot passwords in ConfigMgr are a security to protect the PXE boot process from unauthorized access. When attempting to network boot from the PXE-enabled distribution point, the user must enter a password to access the boot media. The password is configured in the PXE settings for the distribution point (Figure 1).

![Figure 1](./prevent-6_pxe-password.png)

_Figure 1 - Distribution Point PXE Settings_

This password can be retrieve using tools like [PXEThief](https://github.com/MWR-CyberSec/PXEThief) and [pxethiefy](https://github.com/csandker/pxethiefy) and subjected to offline password attacks. Therefore, it is paramount to choose a unique, strong password that can withstand cryptographic interogation.

## Linked Defensive IDs
- N/A

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)

## References
- Microsoft, Understanding PXE Boot, https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot
- Christopher Panayi, Identifying and Retrieving Credentials From SCCM/MECM Task Sequences, https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences
- Christopher Panayi, Pulling Passwords Out of Configuration Manager, https://www.youtube.com/watch?v=Ly9goAud0gs
- Christopher Panayi, PXEThief, https://github.com/MWR-CyberSec/PXEThief
- Christopher Panayi, AES-128 ConfigMgr CryptDeriveKey Hashcat Module, https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module
- Carsten Sandker, pxethiefy, https://github.com/csandker/pxethiefy​


