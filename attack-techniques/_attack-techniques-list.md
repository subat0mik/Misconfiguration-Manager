| Codename | Description | Notes | Links | Status |
|----------|-------------|-------| ----- | ------ |
| CRED-1 | PXE boot creds | | PREVENT-3, PREVENT-6, PREVENT-7, PREVENT-21 | Complete |
| CRED-2 | Request machine policy and deobfuscate secrets | | PREVENT-3, PREVENT-4, PREVENT-10 | Complete
| CRED-3 | Current NAA DPAPI blobs | | PREVENT-3, PREVENT-4, PREVENT-10 | Complete
| CRED-4 | Legacy NAA DPAPI blobs | | CRED-3, PREVENT-3, PREVENT-4, PREVENT-10, PREVENT-15 | Complete
| CRED-5 | SCCM database credential dump | | | QA
| ELEVATE-1 | NTLM relay site server to SMB on site systems | | | Not started
| ELEVATE-2 | NTLM relay via automatic client push installation | | |
| EXEC-1 | Application deployment | | | Not started
| EXEC-2 | PowerShell script execution | | | Not started
| TAKEOVER-1 | NTLM relay site server or SMS Provider SMB to MSSQL on remote site database | X - or SMS Provider? | PREVENT-2, PREVENT-12, PREVENT-14 | QA
| TAKEOVER-2 | NTLM relay site server SMB to SMB on remote site database | | | Partial
| TAKEOVER-3 | NTLM relay site server SMB to AdminService on remote SMS Provider | | | Partial
| TAKEOVER-4 | NTLM relay site server SMB to SMB on remote SMS Provider | | | Partial
| TAKEOVER-5 | NTLM relay passive site server SMB to SMB on primary site server | | | Partial
| TAKEOVER-6 | NTLM relay site server HTTP to LDAP on domain controller | | | Not started
| TAKEOVER-7 | NTLM relay site server HTTP to HTTP on ADCS | | | Not started
| TAKEOVER-8 | NTLM relay CAS SMB to SMB on originating child primary site server | X (prerelease) | | Not started
| RECON01 | Remote LDAP Recon | | | Partial
| RECON02| Remote SMB Recon | | | Not started
| RECON03| Remote HTTP(s) Recon | | | Not started
| RECON04| CMPivot Recon | | PREVENT-9 | QA
| TAKEOVER01 | NTLM relay primary site server SMB to MSSQL on remote site database | X
| TAKEOVER02 | NTLM relay primary site server SMB to AdminService on remote SMS Provider | X
| TAKEOVER08 | NTLM relay primary site server SMB to SMB on remote site database | *
| TAKEOVER02 | NTLM relay primary site server SMB to SMB on remote SMS Provider (auth to local AdminService/WMI or remote MSSQL) | *
| TAKEOVER01 | NTLM relay primary site server HTTP to LDAP on domain controller | *
| TAKEOVER01 | NTLM relay primary site server HTTP to HTTP on ADCS | *
| TAKEOVER03 | NTLM relay passive site server SMB to MSSQL on remote site database | X
| TAKEOVER04 | NTLM relay passive site server SMB to AdminService on remote SMS Provider | X
| TAKEOVER08 | NTLM relay passive site server SMB to SMB on remote site database | *
| TAKEOVER05 | NTLM relay passive site server SMB to SMB on primary site server (auth to MSSQL) | X
| TAKEOVER02 | NTLM relay passive site server SMB to SMB on remote SMS Provider (auth to local AdminService/WMI or remote MSSQL) | *
| TAKEOVER03 | NTLM relay SMS Provider SMB to MSSQL on remote site database | *
| TAKEOVER08 | NTLM relay SMS Provider SMB to SMB on remote site database | *
| TAKEOVER08 | NTLM relay SMS Provider SMB to AdminService on remote SMS Provider | *
| TAKEOVER08 | NTLM relay SMS Provider SMB to SMB on remote SMS Provider | *
| TAKEOVER06 | NTLM relay CAS SMB to AdminService on remote CAS SMS Provider | *
| TAKEOVER06 | NTLM relay CAS SMB to SMB on remote CAS SMS Provider | *
| TAKEOVER06 | NTLM relay CAS SMB to AdminService on originating child primary site SMS Provider | X (prerelease)
| TAKEOVER07 | NTLM relay CAS SMB to SMB on originating child primary site server (auth to MSSQL) | X (prerelease)
| TAKEOVER07 | NTLM relay site database SMB to MSSQL on another site database in availability group? | 

