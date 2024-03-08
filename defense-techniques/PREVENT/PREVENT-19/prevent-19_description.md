# PREVENT-19

## Description
Remove unnecessary links to site databases

## Summary
Configuration Manager installations with multiple sites in a hierarchy will create SQL server and replication links between the different site databases. However, other unnecessary SQL server links to SCCM servers should be audited and removed, particularly if the links were created with DBA privileges, preventing unintended attack vectors from non-SCCM servers. 

It is crucial to ensure the links to other SCCM site database servers are not removed, as this will break functionality. Therefore, ensure proper due diligence for the target servers and databases before removing links.

## Linked Defensive IDs
- N/A

## Associated Offensive IDs
- TAKEOVER-9

## References
- Microsoft, Database Replication, https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/database-replication
- Microsoft, Linked Servers (Database Engine), https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine