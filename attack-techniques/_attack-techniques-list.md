| Codename | Matrix Shortname | Description | Security Context | Network Access |
|----------|------------------|-------------|------------------|----------------|
| [CRED&#x2011;1](./CRED/CRED-1/cred-1_description.md) | PXE Credentials | Retrieve secrets from PXE boot media | Unauthenticated | Internal network |
| [CRED&#x2011;2](./CRED/CRED-2/cred-2_description.md) | Policy Request Credentials | Request machine policy and deobfuscate secrets | Domain computer creds | Internal network |
| [CRED&#x2011;3](./CRED/CRED-3/cred-3_description.md) | DPAPI Credentials | Dump currently deployed secrets via WMI | Client device admin | Any |
| [CRED&#x2011;4](./CRED/CRED-4/cred-4_description.md) | Legacy Credentials | Retrieve legacy secrets from the CIM repository | Client device admin | Any |
| [CRED&#x2011;5](./CRED/CRED-5/cred-5_description.md) | Site Database Credentials | Dump credentials from the site database | Primary site server admin, site database read | Internal network |
| [ELEVATE&#x2011;1](./ELEVATE/ELEVATE-1/ELEVATE-1_description.md) | Relay to Site System (SMB) | NTLM relay site server to SMB on site systems | Domain user creds | Internal network |
| [ELEVATE&#x2011;2](./ELEVATE/ELEVATE-2/ELEVATE-2_description.md) | Relay Client Push Installation | NTLM relay via automatic client push installation | Domain user creds | Internal network |
| [EXEC&#x2011;1](./EXEC/EXEC-1/exec-1_description.md) | App Deployment | Application deployment | SCCM administrator | Internal network |
| [EXEC&#x2011;2](./EXEC/EXEC-2/exec-2_description.md) | Script Deployment | PowerShell script execution | SCCM administrator | Internal network |
| [RECON&#x2011;1](./RECON/RECON-1/recon-1_description.md) | LDAP Enumeration | Enumerate SCCM site information via LDAP | Authenticated domain user | Internal network |
| [RECON&#x2011;2](./RECON/RECON-2/recon-2_description.md) | SMB Enumeration | Enumerate SCCM roles via SMB | Authenticated domain user | Internal network |
| [RECON&#x2011;3](./RECON/RECON-3/recon-3_description.md) | HTTP Enumeration | Enumerate SCCM roles via HTTP | Authenticated domain user | Internal network |
| [RECON&#x2011;4](./RECON/RECON-4/recon-4_description.md) | CMPivot | Query client devices via CMPivot | SCCM administrator | Internal network |
| [RECON&#x2011;5](./RECON/RECON-5/recon-5_description.md) | SMS Provider Enumeration | Locate users via SMS Provider | SCCM administrator | Internal network |
| [TAKEOVER&#x2011;1](./TAKEOVER/TAKEOVER-1/takeover-1_description.md) | Relay to Site DB (MSSQL) | NTLM coercion and relay to MSSQL on remote site database | Domain user creds | Internal network |
| [TAKEOVER&#x2011;2](./TAKEOVER/TAKEOVER-2/takeover-2_description.md) | Relay to Site DB (SMB) | NTLM coercion and relay to SMB on remote site database | Domain user creds | Internal network |
| [TAKEOVER&#x2011;3](./TAKEOVER/TAKEOVER-3/takeover-3_description.md) | Relay to AD CS | NTLM coercion and relay to HTTP on AD CS | Domain user creds | Internal network |
| [TAKEOVER&#x2011;4](./TAKEOVER/TAKEOVER-4/takeover-4_description.md) | Relay CAS to Child | NTLM coercion and relay from CAS to origin primary site server | Domain user creds | Internal network |
| [TAKEOVER&#x2011;5](./TAKEOVER/TAKEOVER-5/takeover-5_description.md) | Relay to AdminService | NTLM coercion and relay to AdminService on remote SMS Provider | Domain user creds | Internal network |
| [TAKEOVER&#x2011;6](./TAKEOVER/TAKEOVER-6/takeover-6_description.md) | Relay to SMS Provider (SMB) | NTLM coercion and relay to SMB on remote SMS Provider | Domain user creds | Internal network |
| [TAKEOVER&#x2011;7](./TAKEOVER/TAKEOVER-7/takeover-7_description.md) | Relay Between HA | NTLM coercion and relay to SMB between primary and passive site servers | Domain user creds | Internal network |
| [TAKEOVER&#x2011;8](./TAKEOVER/TAKEOVER-8/takeover-8_description.md) | Relay to LDAP | NTLM coercion and relay HTTP to LDAP on domain controller | Domain user creds | Internal network |
| [TAKEOVER&#x2011;9](./TAKEOVER/TAKEOVER-9/takeover-9_description.md) | SQL Linked as DBA | Crawl site database links configured with DBA privileges | Authenticated database user | Internal network |