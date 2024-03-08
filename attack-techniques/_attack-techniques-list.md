| Codename | Description | Security Context | Network Access |
|----------|-------------|------------------|----------------|
| CRED&#x2011;1 | Retrieve secrets from PXE boot media | Unauthenticated | Internal network |
| CRED&#x2011;2 | Request machine policy and deobfuscate secrets | Domain computer creds | Internal network |
| CRED&#x2011;3 | Dump currently deployed secrets via WMI | Client device admin | Any |
| CRED&#x2011;4 | Retrieve legacy secrets from the CIM repository | Client device admin | Any |
| CRED&#x2011;5 | Dump credentials from the site database | Primary site server admin, site database read | Internal network |
| ELEVATE&#x2011;1 | NTLM relay site server to SMB on site systems | Domain user creds | Internal network |
| ELEVATE&#x2011;2 | NTLM relay via automatic client push installation | Domain user creds | Internal network |
| EXEC&#x2011;1 | Application deployment | SCCM administrator | Internal network |
| EXEC&#x2011;2 | PowerShell script execution | SCCM administrator | Internal network |
| RECON&#x2011;1 | Enumerate SCCM site information via LDAP | Authenticated domain user | Internal network |
| RECON&#x2011;2 | Enumerate SCCM roles via SMB | Authenticated domain user | Internal network |
| RECON&#x2011;3 | Enumerate SCCM roles via HTTP | Authenticated domain user | Internal network |
| RECON&#x2011;4 | Query client devices via CMPivot | SCCM administrator | Internal network |
| RECON&#x2011;5 | Locate users via SMS Provider | SCCM administrator | Internal network |
| TAKEOVER&#x2011;1 | NTLM coercion and relay to MSSQL on remote site database | Domain user creds | Internal network |
| TAKEOVER&#x2011;2 | NTLM coercion and relay to SMB on remote site database | Domain user creds | Internal network |
| TAKEOVER&#x2011;3 | NTLM coercion and relay to HTTP on AD CS | Domain user creds | Internal network |
| TAKEOVER&#x2011;4 | NTLM coercion and relay from CAS to origin primary site server | Domain user creds | Internal network |
| TAKEOVER&#x2011;5 | NTLM coercion and relay to AdminService on remote SMS Provider | Domain user creds | Internal network |
| TAKEOVER&#x2011;6 | NTLM coercion and relay to SMB on remote SMS Provider | Domain user creds | Internal network |
| TAKEOVER&#x2011;7 | NTLM coercion and relay to SMB between primary and passive site servers | Domain user creds | Internal network |
| TAKEOVER&#x2011;8 | NTLM coercion and relay HTTP to LDAP on domain controller | Domain user creds | Internal network |
| TAKEOVER&#x2011;9 | Crawl site database links configured with DBA privileges | Authenticated database user | Internal network |