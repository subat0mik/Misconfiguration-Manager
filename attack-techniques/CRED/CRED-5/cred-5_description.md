# Dump SCCM Credentials from Site Database

## Code Name
- CRED05

## ATT&CK TTPs
- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Required Privilege / Context
- SCCM site database server access and access to the private key used for encryption
- SCCM site database access

## Summary
SCCM uses many different accounts for various purposes. All of these credentials are stored in the `SC_UserAccount` table in the site MSSQL database.

The secrets in this table are encrypted with an RSA private key which is stored in the "Microsoft Systems Management Server" cryptographic service provider (CSP) container on the server. From the server it is possible to query the MSSQL database for the username and password, where the password is stored as a hexidecimal version of the encrypted blob. 

Example query (from [mimikatz source code](https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/kuhl_m_misc.c#L1980C34-L1980C103)): `SELECT SiteNumber, UserName, Password, Availability FROM SC_UserAccount`

Current tooling to abuse this technique are mimikatz' `misc::sccm` [command](https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/kuhl_m_misc.c#L33) and Adam Chester's `sccmdecryptpoc.cs` [gist](https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1) (required manual retrieval of the hexidecimal string first).

## Impact

If an attacker can compromise the site server and site database, they can recover any SCCM-related account stored in the database. This is particularly dangerous if the database is compromise through some attack path where SCCM credentials may not yet have been compromised, such as SQL links.

## Defensive IDs
TODO

## Examples

TODO

## References
- Benjamin Delpy, X, https://x.com/gentilkiwi/status/1392204021461569537?s=20
- Benjamin Delpy, mimikatz, https://github.com/gentilkiwi/mimikatz
- Adam Chester, X, https://twitter.com/_xpn_/status/1543682652066258946
- Adam Chester, sccmdecryptpoc.cs, https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1
