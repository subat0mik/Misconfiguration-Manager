# RECON-5

## Description
User hunting via SMS Provider

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements
Permitted security roles:
- Full Administrator
- Application Administrator
- Application Deployment Manager
- Operations Administrator
- Read-only Analyst

## Summary
Several SCCM security roles are granted permission to query SMS Providers for client data via WMI and the AdminService REST API. 

User device affinity is a relationship created between a client device and a user account to identify devices that users frequently access to perform their work (e.g., their workstations and laptops). These relationships can be manually imported into SCCM by administrators or an option can be configured to automatically create these relationships, by default when a user is logged on to a client device for 48 hours or more in a 30 day period. Administrators may also allow users to define their own primary devices through Software Center.

Clients also periodically send their hardware inventory to their management point, which is stored in the site database and can be queried via an SMS Provider. The inventory contains the domain, username, and timestamp for the last account to log on.

## Impact
Attributes that clients periodically report to their management point can be queried by attackers. Default attributes contain information that can inform further attacks (e.g., EXEC techniques, lateral movement), including the primary users on devices, the primary devices for users, and the last user to log on to devices. 

Attackers can assume that these users either have an active session or may log onto these systems again, in which case stored credentials in memory could be used to conduct further actions in the context of that user. For example, they could identify devices where a member of the `Domain Admins` group is the primary user or the last to log on and move laterally to the system or coerce NTLM authentication to compromise their account (EXEC-1).

## Subtechniques
- RECON-5.1 - User device affinity
- RECON-5.2 - LastLogon

## Defensive IDs
- 

## Examples

### RECON-5.1
To find computers where the user `MAYYHEM\sccmadmin` has user device affinity, execute:

```
SharpSCCM.exe get primary-users -sms <SMS_PROVIDER> -sc <SITECODE> -u sccmadmin --no-banner

[+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
[+] Executing WQL query: SELECT * FROM SMS_UserMachineRelationship WHERE UniqueUserName LIKE '%sccmadmin%'
-----------------------------------
SMS_UserMachineRelationship
-----------------------------------
CreationTime: 20230828055956.247000+000
IsActive: True
RelationshipResourceID: 25165826
ResourceClientType: 1
ResourceID: 16777219
ResourceName: CLIENT
Sources: 4, 9
Types:
UniqueUserName: mayyhem\sccmadmin
-----------------------------------
```

From this output, we can identify that `MAYYHEM\sccmadmin` has user device affinity on `CLIENT`. 

To find which accounts have user device affinity on `CLIENT`, execute:

```
SharpSCCM.exe get primary-users -sms <SMS_PROVIDER> -sc <SITECODE> -d CLIENT --no-banner

[+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
[+] Executing WQL query: SELECT * FROM SMS_UserMachineRelationship WHERE ResourceName='CLIENT'
-----------------------------------
SMS_UserMachineRelationship
-----------------------------------
CreationTime: 20230828055956.247000+000
IsActive: True
RelationshipResourceID: 25165826
ResourceClientType: 1
ResourceID: 16777219
ResourceName: CLIENT
Sources: 4, 9
Types:
UniqueUserName: mayyhem\sccmadmin
-----------------------------------
[+] Completed execution in 00:00:00.4523001
```

From this output, we can identify that `MAYYHEM\sccmadmin` has user device affinity on `CLIENT`. 


### RECON-5.2
To find computers where the user `MAYYHEM\sccmadmin` was the last account to log on, execute:

    ```
    SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -w "LastLogonUserName='sccmadmin' AND LastLogonUserDomain='MAYYHEM'" --no-banner

    [+] Connecting to \\<SMS_PROVIDER>\root\SMS\site_<SITECODE>
    [+] Executing WQL query: SELECT ResourceId,Active,ADSiteName,Client,DistinguishedName,FullDomainName,HardwareID,IPAddresses,IPSubnets,IPv6Addresses,IPv6Prefixes,IsVirtualMachine,LastLogonTimestamp,LastLogonUserDomain,LastLogonUserName,MACAddresses,Name,NetbiosName,Obsolete,OperatingSystemNameandVersion,PrimaryGroupID,ResourceDomainORWorkgroup,ResourceNames,SID,SMSInstalledSites,SMSUniqueIdentifier,SNMPCommunityName,SystemContainerName,SystemGroupName,SystemOUName FROM SMS_R_System WHERE LastLogonUserName='sccmadmin' AND LastLogonUserDomain='MAYYHEM'
    -----------------------------------
    SMS_R_System
    -----------------------------------
    Active: 1
    ADSiteName: Default-First-Site-Name
    Client: 1
    DistinguishedName: CN=CLIENT,CN=Computers,DC=MAYYHEM,DC=LOCAL
    FullDomainName: MAYYHEM.LOCAL
    HardwareID: 2:16769A2823C1D12FD0F3C9C40D27F07E93C795AF
    IPAddresses: 192.168.57.101, fe80::63a2:f59:74e6:742a
    IPSubnets: 192.168.57.0
    IPv6Addresses:
    IPv6Prefixes:
    IsVirtualMachine: True
    LastLogonTimestamp: 20240122191812.000000+***
    LastLogonUserDomain: MAYYHEM
    LastLogonUserName: sccmadmin
    MACAddresses: 00:50:56:25:F6:37
    Name: CLIENT
    NetbiosName: CLIENT
    Obsolete: 0
    OperatingSystemNameandVersion: Microsoft Windows NT Workstation 10.0 (Tablet Edition)
    PrimaryGroupID: 515
    ResourceDomainORWorkgroup: MAYYHEM
    ResourceId: 16777219
    ResourceNames: CLIENT.MAYYHEM.LOCAL
    SID: S-1-5-21-622943703-4251214699-2177406285-1104
    SMSInstalledSites: PS1
    SMSUniqueIdentifier: GUID:218E1B2C-A7C0-4AC7-86A1-A2BA238C164F
    SNMPCommunityName:
    SystemContainerName: MAYYHEM\COMPUTERS
    SystemGroupName: MAYYHEM\Domain Computers
    SystemOUName:
    -----------------------------------
    [+] Completed execution in 00:00:00.5312592
    ```

From this output, we can identify that `MAYYHEM\sccmadmin` was the last user to log on to `CLIENT`. 

However, the accuracy of the output of this command should not be treated as fact. The `LastLogonUser` attribute identifies the last account that logged into the system at the point in time the last data discovery collection was sent from the client to the management point (default: every 7 days), so it is likely going to be stale for devices with multiple daily users. Also, [apparently by design](https://learn.microsoft.com/en-us/archive/blogs/askds/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works), the `LastLogonTimestamp` attribute cannot be relied upon for near real-time accuracy.

That said, it is possible to force a group of computers to update the `LastLogonUser` attribute using the official [Configuration Manager PowerShell `Invoke-CMClientAction` command](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/invoke-cmclientaction?view=sccm-ps) to execute the `ClientNotificationRequestDDRNow` action on a collection of devices, but this has to be run on the site server with local admin privileges.

NOTE: If you use this method of force-updating the `LastLogonUser` attribute, you are asking every device in the collection to send a data discovery record (DDR) to the management point at once. Doing this while targeting a large device collection (e.g., `All Systems`) could flood the management point with a ton of requests at once, so please be mindful of the size and sensitivity of the environment you’re testing in. It’s much safer to create a device collection that only includes the specific group of targets you would like to update.

## References
- Chris Thompson, Relaying NTLM Authentication from SCCM Clients, https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867
- Microsoft, Link users and devices with user device affinity in Configuration Manager, https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/link-users-and-devices-with-user-device-affinity
- Prajwal Desai, Allow Users to Set Primary Device in Software Center, https://www.prajwaldesai.com/allow-users-to-set-primary-device-in-software-center/