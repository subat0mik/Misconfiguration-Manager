| Codename | Description |
|----------|-------------|
| TAKEOVER&#x2011;1 | Hierarchy takeover via NTLM coercion and relay to MSSQL on remote site database
&emsp;TAKEOVER&#x2011;1.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;1.2: Coerce SMS Provider
&emsp;TAKEOVER&#x2011;1.3: Coerce passive site server
| TAKEOVER&#x2011;2 | Hierarchy takeover via NTLM coercion and relay to SMB on remote site database |
&emsp;TAKEOVER&#x2011;2.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;2.2: Coerce passive site server
| TAKEOVER&#x2011;3 | Hierarchy takeover via NTLM coercion and relay to HTTP on ADCS |
&emsp;TAKEOVER&#x2011;3.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;3.2: Coerce SMS Provider
&emsp;TAKEOVER&#x2011;3.3: Coerce passive site server
&emsp;TAKEOVER&#x2011;3.4: Coerce site database server
| TAKEOVER&#x2011;4 | Hierarchy takeover via NTLM coercion and relay from CAS to origin primary site server |
&emsp;TAKEOVER&#x2011;4.1: Relay to SMB
&emsp;TAKEOVER&#x2011;4.2: Relay to AdminService
| TAKEOVER&#x2011;5 | Hierarchy takeover via NTLM coercion and relay to AdminService on remote SMS Provider |
&emsp;TAKEOVER&#x2011;5.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;5.2: Coerce passive site server
| TAKEOVER&#x2011;6 | Hierarchy takeover via NTLM coercion and relay to SMB on remote SMS Provider |
&emsp;TAKEOVER&#x2011;6.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;6.2: Coerce passive site server
| TAKEOVER&#x2011;7 | Hierarchy takeover via NTLM coercion and relay to SMB between primary and passive site servers |
&emsp;TAKEOVER&#x2011;7.1: Coerce primary site server
&emsp;TAKEOVER&#x2011;7.2: Coerce passive site server
| TAKEOVER&#x2011;8 | Hierarchy takeover via NTLM coercion and relay HTTP to LDAP on domain controller |
&emsp;TAKEOVER&#x2011;8.1: Coerce primary site server 
&emsp;TAKEOVER&#x2011;8.2: Coerce SMS Provider
&emsp;TAKEOVER&#x2011;8.3: Coerce passive site server
&emsp;TAKEOVER&#x2011;8.4: Coerce site database server
| TAKEOVER-9 | Hierarchy takeover via crawling site database links configured with DBA privileges |