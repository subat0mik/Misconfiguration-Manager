# PREVENT-5

## Description
Disable automatic side-wide client push installation

## Summary
[Client push installation](https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers) involves the automatic installation of the client software on discovered computers that meet specified criteria. This method is initiated from the ConfigMgr console and can target individual computers, collections of computers, or newly discovered systems that appear in the ConfigMgr database. The process uses a client push installation account, which must have administrative rights on the target computers, to remotely install the client software. This behavior requires the site server to authenticate to the client, thus potentially enabling authentication coercion opportunities, depending on the configuration.

In ConfigMgr versions 1806+, the site server will attempt to authenticate to the client using Kerberos. However, if this fails, the site server will fallback to NTLM authentication. The "Allow connection fallback to NTLM" setting [PREVENT-2](../PREVENT-2/prevent-2_description.md) is enabled by default in versions prior to 2207.

Client push installation can be configured such that the site server will attempt to install the client on any discovered computer. When configured in conjunction with settings that enable NTLM authentication, this setting may allow an attacker to relay NTLM authentication as the client push installation account.

Additionally, we commonly see the [client push installation account](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#client-push-installation-account) with much more privilege than it requires. It does **NOT** require domain administrator privileges, only local administrator on the target computers.

If a client push installation account is not configured, the site server will use it's computer account instead.

## Linked Defensive IDs
- [PREVENT-2: Disable Fallback to NTLM ](../PREVENT-2/prevent-2_description.md)

## Associated Offensive IDs


## References
- Chris Thompson, Coercing NTLM Authentication from SCCM, https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a
- Microsoft, Configuration Manager Accounts, https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#client-push-installation-account
- Microsoft, How to deploy clients to Windows computers in Configuration Manager, https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/deploy-clients-to-windows-computers