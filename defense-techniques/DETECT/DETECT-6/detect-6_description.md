# DETECT-6

## Description
Monitor group membership changes for RBAC_Admins table

## Summary
The RBAC_Admins table within the MSSQL database server controls the additions and deletions to the SMS Admins local security group. That means if a user is inserted into the RBAC_Admins table, then the user's SID is added to the SMS Admins local security group on the SMS Provider.  

Attackers who relay the site server computer account to the MSSQL database server and insert a new user into the RBAC_Admins table will automatically add that user to the SMS Admins local security group.

Defenders can implement custom auditing into the Application or Security log of the MSSQL database server. SQL Server Auditing will track changes on the RBAC_Admins table.

1. Within the MSSQL database server, open SQL Server Management Studio (SSMS), expand your SQL Server instance.
2. Go to Security > Audits > Right-click > New Audit.
3. Configure the audit to log to a file or the event log.
4. Create an audit specification to track access to the RBAC_Admins table:
```
USE [master];
GO

-- aim events to the Application log
CREATE SERVER AUDIT [Audit_RBAC_Admins_Additions]
TO APPLICATION_LOG 
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO

-- turn on the server audit
ALTER SERVER AUDIT [Audit_RBAC_Admins_Additions]
WITH (STATE = ON);
GO
```
5. Create a database specific audit:
```
USE [CM_XXX];  -- Replace XXX w/ SCCM database name
GO

-- track additions to RBAC_Admins
CREATE DATABASE AUDIT SPECIFICATION [DBAudit_RBAC_Admins_Additions]
FOR SERVER AUDIT [Audit_RBAC_Admins_Additions]
ADD (INSERT ON dbo.RBAC_Admins BY PUBLIC)
WITH (STATE = ON);
GO
```
After implementing the above audit, when a user is added to the RBAC_Admins table, an Event ID: 33205 will be generated within the MSSQL database server's application log. The following Event ID: 33205 displays the information expected from an "INSERT" into the RBAC_Admins table:
```
Audit event: audit_schema_version:1
event_time:2024-10-23 03:11:01.1300947
sequence_number:1
action_id:IN  
succeeded:true
is_column_permission:false
session_id:64
server_principal_id:268
database_principal_id:1
target_server_principal_id:0
target_database_principal_id:0
object_id:1597248745
user_defined_event_id:0
transaction_id:219732354
class_type:U 
duration_milliseconds:0
response_rows:0
affected_rows:0
client_ip:10.1.0.201
permission_bitmask:00000000000000000000000000000008
sequence_group_id:C48FC797-C20A-488D-83F6-F23EA8B17687
session_server_principal_name:APERTURE\ATLAS$
server_principal_name:APERTURE\atlas$
server_principal_sid:0105000000000005150000007d2e52aa5ad54377c5fc12f35c040000
database_principal_name:dbo
target_server_principal_name:
target_server_principal_sid:
target_database_principal_name:
server_instance_name:P-BODY
database_name:CM_PS1
schema_name:dbo
object_name:RBAC_Admins
statement:INSERT INTO RBAC_Admins (AdminSID, LogonName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite) SELECT 0x0105000000000005150000007D2E52AA5AD54377C5FC12F357040000, 'APERTURE\testsubject1', 0, 0, '', '', '', '', 'ps1' WHERE NOT EXISTS ( SELECT 1 FROM RBAC_Admins WHERE LogonName = 'APERTURE\testsubject1' )
additional_information:
user_defined_information:
application_name:sVVsXNEb
connection_id:E26F1BB6-1A98-488B-ADDF-7B7C19FA1BB4
data_sensitivity_information:
host_name:UVJyJtIi
.
```


## Associated Offensive IDs
- [TAKEOVER-4: NTLM coercion and relay from CAS to origin primary site server](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-5: NTLM coercion and relay to AdminService on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-6: NTLM coercion and relay to SMB on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md)
- [TAKEOVER-7: NTLM coercion and relay to SMB between primary and passive site servers](../../../attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md)

## References
* Garrett Foster, [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)
* Microsoft Learn, [Plan for the SMS Provider](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider#about)
