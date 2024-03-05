# PREVENT-11

## Disable / Uninstall WebClient on site servers

## Summary
`WebClient` is the name of the service used for WebDAV operations on Windows hosts. WebDAV is a protocol extension to HTTP that allows file operations, similar to SMB. By default, Windows will attempt to access a resource over SMB but will fallback to HTTP if `WebClient` is running. This is commonly used to coerce authentication from remote systems, as NTLM authentication over HTTP can be relayed to other protocols, such as LDAP. 

This service is installed by default on workstation versions of Windows and can be triggered to start from a local standard user context. Therefore, disabling it is not enough to prevent local privilege escalation attack vectors but it will help prevent lateral movement. If workstations are not accessing SMB shares over HTTP(S), `WebClient` can be removed. Server versions of Windows do not have `WebClient` installed by default. If it is installed on a server, evalute its purpose and remove if it is not necessary.

## Linked Defensive IDs
- 

## Associated Offensive IDs
- [Hierarchy takeover via NTLM coercion and relay HTTP to LDAP on domain controller](../../../attack-techniques/TAKEOVER/TAKEOVER-8/takeover-8_description.md)

## References
- Microsoft, Disable the WebDAV protocol, https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-interception-defense?tabs=group-policy#disable-the-webdav-protocol
- Charlie Bromberg, The Hacker Recipes, https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/webclient