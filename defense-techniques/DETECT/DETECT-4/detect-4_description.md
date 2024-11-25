# DETECT-4

## Description
Monitor application deployment logs in the site's Audit Status Messages

## Summary
Configuration Manager (CM) allows administrators to deploy applications located at specified UNC paths (e.g., `C:\Windows\System32\calc.exe`) to client devices. Additionally, the deployment can be selected to execute as SYSTEM, the currently logged in user, or a specified user.

The CM clients can be any domain-joined host that is managed by a primary (including CAS) and passive site servers where the SCCM client has been installed. Typical methods of deploying application packages to CM clients are conducted via the CM console. To reference an application to deploy to an application, the administrator can reference a binary that is locally or remotely hosted. Referencing binaries that are remotely hosted is of particular importance when we consider the impact of offensive staging and "pushing" application packages to a CM client. Typically, system administrators will host application packages on remote file servers and "push" the CM client agent to retrieve and execute a copy of the binary hosted on the shares (e.g., deployment content= `\\ServerName\SharedFolder\MyApplicationInstaller.msi`). CM clients need only `Read` access to the remote file shares to retrieve the binaries. 
Application deployment is executed in the following steps:

1. Create a "Collection"

* A collection is a group of users or devices targeted for deployment in SCCM. When a collection is created, the SCCM site database (hosted in the `CM_<SiteCode>` MSSQL database) creates an entry for the collection. A collection is typically created in the SCCM console by navigating to `Assets and Compliance > Device Collections > Create Device Collection`.

2. Add a device to the Collection

* Devices are added to the Collection to define the deployment scope.

3. Create an "Application" to deploy

* The application can reference a locally or remotely hosted binary via UNC paths.

4. Create a "Deployment"

* The deployment defines how and when the application is sent to devices. In this step, the application is deployed to the previously created collection.
* This deployment creates records in the SCCM site database under tables such as `Deployment` and `ApplicationAssignments`, which link the application to the collection. This will also generate a new deployment policy for the collection's members.

5. Initiate a "Deployment"

* The deployment will deploy the scoped application to execute on the CM clients as defined by the collection.

The Configuration Manager Status Message Queue contains corresponding Message IDs related to each of the steps explained above. The following examples display Message IDs related to the generation of a Collection, Application, and Deployment. Additionally, the examples below will share the relevant Message ID details related to initiating a Deployment.

**Message ID: 30015** Create a Collection:

```
Timestamp: 6:13:01.210 PM 
EventID: 30015
Severity: Information
System: Unknown Machine
Source: SMS Provider
Component: Unknown Application
Message: User "APERTURE\SCCMADMIN" created a collection named "Devices_030d6b2d-ebef-45f3-b8f4-19c9db0338ec" (PS10001E)
```

**Message ID: 30152** Create an Scope/Application

```
Timestamp: 6:13:14.670 PM
EventID: 30152
Severity: Information
System: Unknown Machine
Source: SMS Provider
Component: Unknown Application
Message: User "APERTURE\SCCMADMIN" created configuration item "16777549" (CI_UniqueID=ScopeId_018F0AC9-4FE2-4A84-A682-BF719C02DD7D/Application_970b5828-cca0-4a18-835f-924954b932fb/1, CIVersion=1).
Properties:
- User Name : APERTURE\SCCMADMIN
```

**Message ID: 30226** Create a Deployment

```
Timestamp: 6:13:16.593 PM 
EventID: 30226
Severity: Information
System: Unknown Machine
Source: SMS Provider
Component: Unknown Application
Message: User "APERTURE\SCCMADMIN" created a deployment of application "Application_d8d60e91-0e89-4a85-aae5-97ebc8b65f07" to collection "Devices_030d6b2d-ebef-45f3-b8f4-19c9db0338ec".
Properties:
- User Name : APERTURE\SCCMADMIN
```

**Message ID: 40800** Deployment Initiated

```
Timestamp: 6:13:52.433 PM  
EventID: 40800
Severity: Information
System: Unknown Machine
Source: SMS Provider
Component: Unknown Application
Message: User APERTURE\SCCMADMIN initiated client operation 8 to collection APERTURE\SCCMADMIN.
Properties:
- User Name : APERTURE\SCCMADMIN
```
## Associated Offensive IDs
- [EXEC-1: Application deployment](../../../attack-techniques/EXEC/EXEC-1/exec-1_description.md)

## References
- Brandon McMillan, [Enhanced Audit Status Message Queries](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/enhanced-audit-status-message-queries/ba-p/884897)
- Brandon McMillan, [EnhancedAuditStatusMsgQueries](https://github.com/brmcmill/EnhancedAuditStatusMsgQueries)
- Microsoft Learn, [Use the status system in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/servers/manage/use-status-system#bkmk_Status)
