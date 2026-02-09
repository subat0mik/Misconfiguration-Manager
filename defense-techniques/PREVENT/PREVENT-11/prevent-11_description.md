# PREVENT-11

## Description
Disable and uninstall WebClient on site servers

## Summary
`WebClient` is the name of the service used for WebDAV operations on Windows hosts. WebDAV is a protocol extension to HTTP that allows file operations, similar to SMB. By default, Windows will attempt to access a resource over SMB but will fallback to HTTP if `WebClient` is running. This is commonly used to coerce authentication from remote systems, as NTLM authentication over HTTP can be relayed to other protocols, such as LDAP.

This service is installed by default on workstation versions of Windows and can be triggered to start from a local standard user context. Therefore, disabling it is not enough to prevent local privilege escalation attack vectors but it will help prevent lateral movement. If workstations are not accessing SMB shares over HTTP(S), `WebClient` can be removed. Server versions of Windows do not have `WebClient` installed by default. If it is installed on a server, evalute its purpose and remove if it is not necessary.

## Linked Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-14: Require EPA on AD CS and site databases](../../../defense-techniques/PREVENT/PREVENT-14/prevent-14_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Associated Offensive IDs
- [ELEVATE-2: NTLM relay via automatic client push installation](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)
- [TAKEOVER-3: NTLM coercion and relay to HTTP on AD CS](../../../attack-techniques/TAKEOVER/TAKEOVER-3/takeover-3_description.md)
- [TAKEOVER-8: NTLM relay primary site server HTTP to LDAP on domain controller](../../../attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description.md)

## References
- Microsoft, [Disable the WebDAV protocol](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-interception-defense?tabs=group-policy#disable-the-webdav-protocol)
- Charlie Bromberg, [The Hacker Recipes](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/webclient)