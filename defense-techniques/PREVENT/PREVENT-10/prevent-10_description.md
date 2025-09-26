# PREVENT-10

## Description
Enforce the principle of least privilege for accounts

## Summary
Overprivileged accounts and unnecessary permissions are common misconfigurations in Configuration Manager. It is paramount to ensure the various accounts in use are assigned only the necessary permissions to perform their function. This article does not cover every account. Do not use these accounts for multiple purposes.

Note that using accounts from different Active Directory forests or domains will allow an attacker who has compromised the SCCM hierarchy to cross forest boundaries after dumping and decrypting the credentials ([CRED-5](../../../attack-techniques/CRED/CRED-5/cred-5_description.md)). See [PREVENT-22](../PREVENT-22/prevent-22_description.md) for more information.

As always, test these configurations in a lower environment before implementing in production to ensure there are no issues.

### Active Directory forest account
The site uses the Active Directory forest account to discover network infrastructure from Active Directory forests. Central administration sites and primary sites also use it to publish site data to Active Directory Domain Services for a forest. 

### Capture OS image account
This account is used as part of task sequences. If configured, it may be deployed to various systems and recoverable as admininstrator on those systems.

- Do NOT assign interactive logon permissions
- Do NOT use the network access account

### Client push installation account
This account is used to connect to computers and install the SCCM client software. Under certain conditions, attackers can coerce authentication from this account and potentially perform NTLM relay attacks ([ELEVATE-2](../../../attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md)).

- Must be a member of the local `Administrators` group on target computers
- Do NOT use a domain administrator account
- Use domain or local group policy to `Deny log on locally`

### Enrollment point connection account
This account is used for an MDM enrollment point to connect to the SCCM site database. If this is not configured, the computer account will be used.

- Required when the enrollment point is in an untrusted domain
- Requires Read and Write access to the site database

### Exchange Server connection account
This account is used to establish a connection to an Exchange Server. This connection is used to find and manage mobile devices that connect to the Exchange Server.

- Requires Exchange PowerShell cmdlets

### Management point connection account
This account is used by management points to connect to the site database for the purpose of sending and receiving client information. If this is not configured, the management point's computer account will be used.

- Required when the management point is in an untrusted domain
- Do NOT add this account to `Administrators` on the MSSQL server
- Do NOT assign interactive logon permissions

### Multicast connection account
This account is used to read multicast information from the site database. If this is not a configured, the computer account will be used.

- Required when the site database is in an untrusted domain
- Do NOT add this account to `Administrators` on the MSSQL server
- Do NOT assign interactive logon permissions

### Network access account
This account is used to access content on distribution points when the computer account cannot be used (e.g., not domain joined). There are several scenarios where this account is required. Please refer to the [documentation](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#actions-that-require-the-network-access-account).

- Requires the `Access this computer from the network` right on the distribution point
- Do NOT grant interactive logon permissions
- Do NOT grant administrative rights to any systems

### Package access account
This account enables custom, granular permissions on content and packages on a distribution point.

### Reporting services point account
This account is used to retrieve report data from the site database

- Requires the `Log on locally` permission on the MSSQL server hosting SQL Server Reporting Services

### Site installation account
This account is used to install a new site.

- Requires membership in the local `Administrators` group on the site server, each site database server, each SMS provider instance
- Requires Sysadmin on the site database

### Site system installation account
This account is used to install, reinstall, uninstall, and configure site systems.

- Requires membership in the local `Administrators` group on the target site system
- Requires `Access this computer from the network` right on the target site system

### SMTP server connection account
This account is used to send email alerts.

- Requires ONLY ability to send emails, nothing more

### Software update point connection account
This account is used for Windows Server Update Services (WSUS) functionality.

- Required if the software update point is in an untrusted forest
- Requires membership in the local `Administrators` group on the computer where WSUS is installed
- Requires membership in the local `WSUS Administrators` group on the computer where WSUS is installed

### Task sequence domain join account
This account is used by task sequences to join a computer to the domain.

**Note:** When this account joins computers to the domain, it will be become the owner of those computer objects, effectively having full control. Remove this ownership after joining the computer to the domain ([PREVENT-17](../PREVENT-17/prevent-17_description.md)).

- Requires permissions to add a computer to the domain
- Do NOT assign interactive sign-in permissions
- Do NOT use the network access account

### Task sequence network folder connection account
This account is used by task sequences to connect to a network share.

- Requires access to the target network share
- Do NOT assign interactive sign-in permissions
- Do NOT use the network access account

### Task sequence run as account
This account is used in task sequences to execute commands or scripts as an account other than the Local System account. This account should be configured with the minimum permissions necessary to complete the associated task sequence step. Create multiple run as accounts, each with tightly-scoped permissions for its specific task sequence step.

- Requires interactive sign-in permissions
- Do NOT use the network access account
- Do NOT use a domain administrator

### Collection Variables
One of the configuration settings that can be applied to collections are custom environment variable, called collection variables, that are exposed to members of the collection.

Nothing specifically requires that these variables be credentials, but they can be used for this purpose. In transit and on disk, they are encrypted by SCCM in the same way as credentials and can be recovered using the same techniques as for the network access account (CRED-1 through CRED-4).

## Linked Defensive IDs
- [PREVENT-3: Harden or disable network access accounts](../PREVENT-3/prevent-3_description.md)
- [PREVENT-4: Enable Enhanced HTTP](../PREVENT-4/prevent-4_description.md)
- [PREVENT-15: Disable and change passwords of legacy NAAs and collection variables/task sequence secrets in Active Directory](../PREVENT-15/prevent-15_description.md)
- [PREVENT-17: Remove Extended Rights assignment from accounts that do not require it](../PREVENT-17/prevent-17_description.md)
- [PREVENT-22: Do not manage assets in two or more segmented forests, domains, networks, or security tiers](../PREVENT-22/prevent-22_description.md)

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)
- [CRED-2: Request and deobfuscate machine policy to retrieve credential material](../../../attack-techniques/CRED/CRED-2/cred-2_description.md)
- [CRED-3: Dump currently deployed credentials via WMI](../../../attack-techniques/CRED/CRED-3/cred-3_description.md)
- [CRED-4: Retrieve legacy network access account (NAA) credentials from the CIM Repository](../../../attack-techniques/CRED/CRED-4/cred-4_description.md)
- [CRED-5: Dump SCCM credentials from site database](../../../attack-techniques/CRED/CRED-5/cred-5_description.md)
- [CRED-8: NTLM relay remote MP to site database to extract machine policy secrets](../../../attack-techniques/CRED/CRED-8/cred-8_description.md)]

## References
- Microsoft, [Accounts used in Configuration Manager](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts)
- Christopher Panayi, [An inside look: How to distribute credentials securely in SCCM
](https://www.mwrcybersec.com/an-inside-look-how-to-distribute-credentials-securely-in-sccm)