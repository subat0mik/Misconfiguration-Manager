# DETECT-4

## Description
Monitor application deployment logs in the site's Audit Status Messages

## Summary
The following message ID's can be used to monitor application deployment:
- 30226: Creation of application deployment
- 30228: Deletion of application deployment

The following SQL query can be run against the SCCM MSSQL database to retrieve these message types:
```
select stat.*, ins.*, att1.*, stat.Time from v_StatusMessage as stat left join v_StatMsgInsStrings as ins on stat.RecordID = ins.RecordID left join v_StatMsgAttributes as att1 on stat.RecordID = att1.RecordID where stat.MessageType = 768 and stat.MessageID >= 30224 and stat.MessageID <= 30228 and stat.Time >= ##PRM:v_StatusMessage.Time## order by stat.Time desc
```
## Associated Offensive IDs
- [EXEC-1: Application deployment](../../../attack-techniques/EXEC/EXEC-1/exec-1_description.md)

## References
Marshall Price, [SCCM Exploitation: Evading Defenses and Moving Laterally with SCCM Application Deployment](https://www.guidepointsecurity.com/blog/sccm-exploitation-evading-defenses-and-moving-laterally-with-sccm-application-deployment/)
Microsoft, [Status and alert views in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/develop/core/understand/sqlviews/status-alert-views-configuration-manager)
