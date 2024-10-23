# DETECT-5

## Description
Monitor group membership changes for SMS Admins

## Summary
The SMS Admins group is a local security group created on each SMS Provider in the hierarchy. The SMS Admins local security group provides access to the SMS Provider which is a WMI provider that assigns read and write access to configuration manager databases.
```
PS C:\Users\SCCMADMIN> get-localgroup

Name            Description
----            -----------
SMS Admins      Members have access to the SMS Provider.
```

The RBAC_Admins table within the MSSQL database server controls the additions and deletions to the SMS Admins local security group. That means if a user is inserted into the RBAC_Admins table, then the user's SID is added to the SMS Admins local security group on the SMS Provider.  

Attackers who relay the site server computer account to the MSSQL database server and insert a new user into the RBAC_Admins table will automatically add that user to the SMS Admins local security group.

While defenders cannot set a SACL on the local security group directly, auditing can be enabled for `Object Access` via `auditpol.exe`: 
```
auditpol /set /category:"Object Access" /success:enable /failure:enable
```
Once this audit category is enabled, defenders can monitor the SMS Admins group for modification via Event ID: 4732. When a user is added to the RBAC_Admins table and inherently added to the SMS Admins local security group, the following Event ID: 4732 will display the following information:
```
A member was added to a security-enabled local group.

Subject:
	Security ID:		SYSTEM
	Account Name:		ATLAS$
	Account Domain:		APERTURE
	Logon ID:		0x3E7

Member:
	Security ID:		APERTURE\TESTSUBJECT1
	Account Name:		-

Group:
	Security ID:		ATLAS\SMS Admins
	Group Name:		SMS Admins
	Group Domain:		ATLAS

Additional Information:
	Privileges:		-
```
When a user is removed from the RBAC_Admins table in MSSQL database server or the SMS Admins local security group, an Event ID: 4733, is generated:
```
A member was removed from a security-enabled local group.

Subject:
	Security ID:		SYSTEM
	Account Name:		ATLAS$
	Account Domain:		APERTURE
	Logon ID:		0x3E7

Member:
	Security ID:		APERTURE\TESTSUBJECT1
	Account Name:		-

Group:
	Security ID:		ATLAS\ConfigMgr_CollectedFilesAccess
	Group Name:		ConfigMgr_CollectedFilesAccess
	Group Domain:		ATLAS

Additional Information:
	Privileges:		-
```

Additionally, telemetry is generated as the MSSQL database server connects and enumerates the SMS Admins group prior to adding the specified user via Event ID 4799. However, this event is generated frequently by legitmate activiaty and is not directly indicative malicious additions to the local security group without the corresponding Event ID 4799. The following displays two Event ID: 4799s in relation to the addition of a user to the SMS Admins group:
```
A security-enabled local group membership was enumerated.

Subject:
	Security ID:		SYSTEM
	Account Name:		ATLAS$
	Account Domain:		APERTURE
	Logon ID:		0x3E7

Group:
	Security ID:		ATLAS\SMS Admins
	Group Name:		SMS Admins
	Group Domain:		ATLAS

Process Information:
	Process ID:		0x244c
	Process Name:		C:\Windows\System32\wbem\WmiPrvSE.exe
```
```
A security-enabled local group membership was enumerated.

Subject:
	Security ID:		SYSTEM
	Account Name:		ATLAS$
	Account Domain:		APERTURE
	Logon ID:		0x3E7

Group:
	Security ID:		ATLAS\SMS Admins
	Group Name:		SMS Admins
	Group Domain:		ATLAS

Process Information:
	Process ID:		0xdec
	Process Name:		C:\Program Files\Microsoft Configuration Manager\bin\X64\smsexec.exe
```

## Associated Offensive IDs
- [TAKEOVER-4: NTLM coercion and relay from CAS to origin primary site server](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-5: NTLM coercion and relay to AdminService on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)
- [TAKEOVER-6: NTLM coercion and relay to SMB on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-6/takeover-6_description.md)
- [TAKEOVER-7: NTLM coercion and relay to SMB between primary and passive site servers](../../../attack-techniques/TAKEOVER/TAKEOVER-7/takeover-7_description.md)

## References
* Garrett Foster, [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)
* Microsoft Learn, [Plan for the SMS Provider](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider#about)
* Microsoft Learn, [4732(S): A member was added to a security-enabled local group.](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)