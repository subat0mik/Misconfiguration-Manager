# PREVENT-23

## Description
Ensure the SCCM client cache directory (`ccmcache`) is not writable or renameable by non-administrative users

## Summary
Microsoft Configuration Manager (SCCM/MECM) clients download application and package content to a local cache directory before installation. This cache directory (`ccmcache`) is typically located under `C:\Windows\ccmcache`, though administrators may configure a custom location such as `C:\ccmcache` or `D:\SCCMCache\ccmcache` during SCCM client deployment.

Packages distributed through SCCM are executed by the SCCM client service (`CcmExec`), which runs with **NT AUTHORITY\SYSTEM** privileges. If the cache directory is misconfigured such that standard users have **write, modify, or rename permissions**, an attacker may tamper with cached package contents prior to installation or reinstallation.

By modifying installation files (e.g., MSI installers, scripts, or binaries) inside the cache directory, an attacker can inject malicious code that will be executed by the SCCM client service with SYSTEM privileges when the package is installed or reinstalled via **Software Center**.

To prevent this attack vector, administrators should ensure that SCCM cache directories are **only writable by privileged accounts**, typically **SYSTEM and local administrators**, and that standard users do not have the ability to modify or rename the cache directory or its contents.

Example mitigations include:

- Ensuring the `ccmcache` directory inherits secure permissions from `C:\Windows`
- Verifying that **BUILTIN\Users** or **Authenticated Users** do not have `Modify` or `Write` permissions on the cache directory
- Avoiding custom cache paths that reside in locations writable by standard users (e.g., `D:\SCCMCache` with permissive ACLs)
- Periodically auditing SCCM client cache permissions across endpoints

## Examples of misconfigurations that violate this principle

- The SCCM cache directory (`C:\Windows\ccmcache` or custom path) grants **Modify permissions to BUILTIN\Users**, allowing local users to replace package installers with malicious binaries.
- The SCCM cache directory is placed on a secondary drive (e.g., `D:\SCCMCache`) with inherited permissions that allow **Authenticated Users** to modify directory contents.
- The cache directory is **renameable by non-administrative users**, allowing attackers to manipulate the cache structure and insert malicious package content.
- A custom SCCM cache path is configured on a shared or loosely permissioned directory accessible to standard users.

## Linked Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../PREVENT-10/prevent-10_description.md)

## Associated Offensive IDs
- [ELEVATE-6: Local Privilege Escalation via Writable SCCM Client Cache](../../../attack-techniques/ELEVATE/ELEVATE-6/ELEVATE-6_description.md)

## References
- Microsoft, [Configure client cache settings for Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/manage/configure-client-cache)
