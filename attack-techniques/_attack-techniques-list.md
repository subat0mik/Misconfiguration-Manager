| Codename | Description | Notes |
|---------|-------------|-------|
| CRED01 | PXE boot creds | 
| CRED02 | Request machine policy and deobfuscate secrets |
| CRED03 | Current NAA DPAPI blobs |
| CRED04 | Legacy NAA DPAPI blobs |
| CRED05 | SCCM database credential dump |
| ELEVATION01 | NTLM relay site server to SMB on component servers |
| EXEC01 | Application deployment |
| EXEC02 | PowerShell script execution |
| TAKEOVER01 | NTLM relay site server or SMS Provider SMB to MSSQL on remote site database | X - or SMS Provider?
| TAKEOVER02 | NTLM relay site server SMB to SMB on remote site database | *
| TAKEOVER03 | NTLM relay site server SMB to AdminService on remote SMS Provider | X
| TAKEOVER04 | NTLM relay site server SMB to SMB on remote SMS Provider | *
| TAKEOVER05 | NTLM relay passive site server SMB to SMB on primary site server | X
| TAKEOVER06 | NTLM relay site server HTTP to LDAP on domain controller | *
| TAKEOVER07 | NTLM relay site server HTTP to HTTP on ADCS | *
| TAKEOVER08 | NTLM relay CAS SMB to SMB on originating child primary site server | X (prerelease)


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

| RECON01 | Remote LDAP Recon |
| RECON02| Remote SMB Recon |
| RECON03| Remote HTTP(s) Recon |