# PREVENT-5

## Description
Disable automatic side-wide client push installation

## Summary
[Client push installation](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers) involves the installation of the client software from the primary site server. This method is initiated from the primary site server and can target individual computers, collections of computers, or newly discovered systems that appear in the ConfigMgr database. 

The process uses one or more stored configured client push installation account credentials to authenticate to the ADMIN$ share on a remote host, copy the installation files there, and execute the client software setup binary. These accounts must have administrative rights on the target computers to install the client software. If the site server fails to authenticate with any of the configured accounts, it falls back to attempting to authenticate with its domain computer account, the default setting. Each of these authentication attempts may enable NTLM relay opportunities, depending on the configuration.

In ConfigMgr versions 1806+, the site server will attempt to authenticate to the client using Kerberos. However, if this fails, the site server will fallback to NTLM authentication. The "Allow connection fallback to NTLM" setting [PREVENT-2](../PREVENT-2/prevent-2_description.md) is enabled by default in versions prior to 2207.

Automatic site-wide client push installation can be configured such that the site server will attempt to install the client on any discovered computer. When configured in conjunction with settings that enable NTLM authentication, this setting may allow an attacker to relay NTLM authentication as any of the client push installation account and the site server's domain computer account.

Additionally, we commonly see the [client push installation account](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#client-push-installation-account) with much more privilege than it requires. It does **NOT** require domain administrator privileges, only local administrator on the target computers.

## Linked Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../DETECT/DETECT-1/detect-1_description.md)
- [DETECT-3: Monitor client push installation accounts authenticating from anywhere other than the primary site server](../../DETECT/DETECT-3/detect-3_description.md)
- [PREVENT-1: Patch site server with KB15599094](../PREVENT-1/prevent-1_description.md)
- [PREVENT-2: Disable Fallback to NTLM ](../PREVENT-2/prevent-2_description.md)

## Associated Offensive IDs
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)

## References
- Chris Thompson, [Coercing NTLM Authentication from SCCM](https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
- Microsoft, [Configuration Manager Accounts](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#client-push-installation-account)
- Microsoft, [How to deploy clients to Windows computers in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers)