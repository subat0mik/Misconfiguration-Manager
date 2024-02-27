# Patch SCCM to Disable NTLM Fallback for Automatic Client Push Installation

## Code Name
PREVENT-1

## Summary

Within SCCM's client push installation properties, there exists a setting to "Allow connection fallback to NTLM." In SCCM versions prior to 2207, there exists a bug such that without this setting enabled, the connection will fallback to NTLM regardless of the setting. Microsoft patched this bug in [KB15599094](https://learn.microsoft.com/en-us/mem/configmgr/hotfix/2207/15599094). This patch is applied by default to new site installations of version 2207+.

## References
- Jitesh Kumar, SCCM Hotfix KB15599094 NTLM Client Installation Update, https://www.anoopcnair.com/sccm-hotfix-kb15599094-ntlm-client-installation/
- Brandon Colley, Push Comes To Shove: Bypassing Kerberos Authentication of SCCM Client Push Accounts, https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-bypassing-kerberos-authentication-of-sccm-client-push-accounts