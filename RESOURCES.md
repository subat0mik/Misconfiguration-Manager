# SCCM Offensive Security Resources

## Labs

### Lab Environments

| Environment | Author | Notes | Link |
|---|---|---|---|
| Ludus SCCM Lab | Zach Stein ([@synzack21](https://twitter.com/synzack21)) | Covers most of the techniques in this repo | [Link](https://github.com/Synzack/ludus_sccm) |
| Ludus SCCM Lab Expansion | Chris Thompson ([@_Mayyhem](https://x.com/_Mayyhem)) | Adds a 3-tier hierarchy (CAS → PS1 → SEC) on top of the original Ludus lab | [Link](https://specterops.io/blog/2026/04/01/ludus-sccm-lab-expansion/) |
| GOAD SCCM Lab | [@M4yFly](https://twitter.com/m4yfly/status/1771643303164891262) | SCCM lab for the Game of Active Directory (GOAD) project; works with VMware or VirtualBox | [Link](https://github.com/Orange-Cyberdefense/GOAD) |
| Snap Labs SCCM Range | [@an0n_r0](https://twitter.com/an0n_r0/status/1687230842601451522) | Hosted range covering most of the SCCM tradecraft in this repo | [Link](https://dashboard.snaplabs.io/templates/121fda0a-6cc3-4889-bee3-2fe83856f530) |
| Grow Your Own SCCM Lab | @HTTP418 | Guide for building your own SCCM lab from scratch | [Link](https://http418infosec.com/grow-your-own-sccm-lab) |

The following are usable too, but don't separate the site database or SMS Provider roles from the primary site server, which prevents use of most TAKEOVER techniques:

| Environment | Link |
|---|---|
| Microsoft and Office 365 deployment lab kit | [Link](https://learn.microsoft.com/en-us/microsoft-365/enterprise/modern-desktop-deployment-and-management-lab?view=o365-worldwide) |
| SCCM Technical Preview Azure Template | [Link](https://learn.microsoft.com/en-us/samples/azure/azure-quickstart-templates/sccm-technicalpreview/) |
| AutomatedLab | [Link](https://automatedlab.org/en/latest/Wiki/Roles/configurationmanager/) |

### Practice Boxes

| Name | Source | Link |
|---|---|---|
| Push | Vulnlab | [Link](https://www.vulnlab.com/machines) |

### Lab Walkthroughs

| Title | Author | Link |
|---|---|---|
| SCCM lab walkthrough | mayfly277 | [Link](https://mayfly277.github.io/categories/sccm/) |
| SCCM lab walkthrough | ice0 | [Link](https://ice0.vercel.app/docs/sccm-docs) |
| SCCM lab walkthrough (video) | — | [Link](https://youtu.be/6-ZkV8zg_FY) |

## Blog Posts

| Title | Author | Category |
|---|---|---|
| [Active Directory Spotlight: Attacking The Microsoft Configuration Manager (SCCM/MECM)](https://www.securesystems.de/blog/active-directory-spotlight-attacking-the-microsoft-configuration-manager/) | Carsten Sandker | Offensive |
| [Adding MSSQL to BloodHound using OpenGraph](https://specterops.io/blog/2025/08/04/adding-mssql-to-bloodhound-with-opengraph/) | Chris Thompson (@_Mayyhem) | Tooling |
| [An Inside Look: How to Distribute Credentials Securely in SCCM](https://www.mwrcybersec.com/an-inside-look-how-to-distribute-credentials-securely-in-sccm) | Christopher Panayi | Defensive |
| [Attacking and Defending Configuration Manager - An Attacker's Easy Win](https://logan-goins.com/2025-04-25-sccm/) | Logan Goins | Offensive/Defensive |
| [Automating SCCM with Ludus](https://specterops.io/blog/2024/06/06/automating-sccm-with-ludus-a-configuration-manager-for-your-configuration-manager/) | Zach Stein (@synzack21) | Lab/Tooling |
| [CISA Red Team Report Featuring SCCM](https://www.cisa.gov/sites/default/files/2023-03/aa23-059a-cisa_red_team_shares_key_findings_to_improve_monitoring_and_hardening_of_networks_1.pdf) | CISA | Defensive/Report |
| [Client Push Installation Abuse](https://twitter.com/enigma0x3/status/962095579068354561?lang=ar-x-fm) | Matt Nelson (enigma0x3) | Offensive |
| [cmloot](https://www.shelltrail.com/research/cmloot/) | Andreas Vikerup & Dan Rosenqvist, Shelltrail | Offensive/Tooling |
| [Coercing NTLM Authentication from SCCM](https://medium.com/specter-ops-posts/coercing-ntlm-authentication-from-sccm-e6e23ea8260a) | Chris Thompson (@_Mayyhem) | Offensive |
| [ConfigManBearPig 2.0 – Things Are Getting Cereal](https://specterops.io/blog/2026/08/03/configmanbearpig-2-0/) | Chris Thompson (@_Mayyhem) | Tooling |
| [Decrypting credentials from SCCM site servers configured for high availability](https://www.ibm.com/think/x-force/decrypting-credentials-from-sccm-site-servers) | Dave Cossa | Offensive |
| [Defending the Castle](https://www.oscc.be/sccm/Defending-the-Castle/) | Tom Degreef & Kim Oppalfens | Defensive |
| [Exploring SCCM by Unobfuscating Network Access Accounts](https://blog.xpnsec.com/unobfuscating-network-access-accounts/) | Adam Chester (xpn) | Offensive |
| [From Domain User to Enterprise Control: Microsoft Configuration Manager RCE 0-Day Exploit Chain](https://medium.com/@omribaso/from-domain-user-to-enterprise-control-microsoft-configuration-manager-rce-0-day-exploit-chain-393c63c680ca) | Omri Baso | Offensive |
| [Hierarchy Takeover without SOCKS](https://twitter.com/_Mayyhem/status/1700602445603209236) | Chris Thompson (@_Mayyhem) | Offensive |
| [I'd Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/) | Garrett Foster (@unsigned_sh0rt) | Offensive |
| [Identifying and Retrieving Credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences) | Christopher Panayi | Offensive |
| [Introducing ConfigManBearPig, a BloodHound OpenGraph Collector for SCCM](https://specterops.io/blog/2026/01/13/introducing-configmanbearpig-a-bloodhound-opengraph-collector-for-sccm/) | Chris Thompson (@_Mayyhem) | Tooling |
| [Less Praying More Relaying – Enumerating EPA Enforcement for MSSQL and HTTPS](https://specterops.io/blog/2025/11/25/less-praying-more-relaying-enumerating-epa-enforcement-for-mssql-and-https/) | Nick Powers (@zyn3rgy) & Matt Creel (@Tw1sm) | Offensive |
| [Looting Microsoft Configuration Manager](https://labs.withsecure.com/publications/looting-microsoft-configuration-manager) | Tomas Rzepka | Offensive |
| [Ludus SCCM Lab Expansion](https://specterops.io/blog/2026/04/01/ludus-sccm-lab-expansion/) | Chris Thompson (@_Mayyhem) | Lab/Tooling |
| [Mapping Deception Solutions With BloodHound OpenGraph – Configuration Manager](https://specterops.io/blog/2026/02/19/mapping-deception-solutions-with-bloodhound-opengraph-configuration-manager/) | Joshua Prager | Defensive |
| [Microsoft Configuration Manager (ConfigMgr) 2403 Unauthenticated SQL Injections](https://www.synacktiv.com/advisories/microsoft-configuration-manager-configmgr-2403-unauthenticated-sql-injections) | Mehdi Elyassa, Synacktiv | Offensive |
| [Microsoft's Accidental Enterprise DFIR Tool](https://informationonsecurity.blogspot.com/2015/11/microsofts-accidental-enterprise-dfir.html) | Keith Tyler | Defensive/Historical |
| [Mimikatz dpapi::sccm](https://twitter.com/gentilkiwi/status/1392594113745362946?lang=en) | Benjamin Delpy (gentilkiwi) | Tooling |
| [Mimikatz misc::sccm](https://twitter.com/gentilkiwi/status/1392204021461569537?lang=en) | Benjamin Delpy (gentilkiwi) | Tooling |
| [Misconfiguration Manager: Detection Updates](https://specterops.io/blog/2024/12/16/misconfiguration-manager-detection-updates/) | Joshua Prager | Defensive |
| [Misconfiguration Manager: Overlooked and Overprivileged](https://specterops.io/blog/2024/03/05/misconfiguration-manager-overlooked-and-overprivileged/) | Duane Michael (@subat0mik) | Offensive |
| [Misconfiguration Manager: Still Overlooked, Still Overprivileged](https://specterops.io/blog/2025/06/26/misconfiguration-manager-still-overlooked-still-overprivileged/) | Duane Michael (@subat0mik) & Garrett Foster (@unsigned_sh0rt) | Offensive/Defensive |
| [MSSQL and SCCM Elevation of Privilege Vulnerabilities](https://specterops.io/blog/2026/01/15/mssql-and-sccm-elevation-of-privilege-vulnerabilities/) | Chris Thompson (@_Mayyhem) | Offensive |
| [Network Access Accounts are evil...](https://rzander.azurewebsites.net/network-access-accounts-are-evil/) | Roger Zander | Defensive |
| [Offensive Operations with PowerSCCM](https://enigma0x3.net/2016/02/29/offensive-operations-with-powersccm/) | Matt Nelson (enigma0x3) | Offensive |
| [Offensive SCCM Summary](https://http418infosec.com/offensive-sccm-summary) | @HTTP418 | Offensive |
| [Push Comes to Shove Part 1](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-exploring-the-attack-surface-of-sccm-client-push-accounts) | Brandon Colley | Offensive |
| [Push Comes to Shove Part 2](https://www.hub.trimarcsecurity.com/post/push-comes-to-shove-bypassing-kerberos-authentication-of-sccm-client-push-accounts) | Brandon Colley | Offensive |
| [Red Team Ops SCCM Module](https://twitter.com/zeropointsecltd/status/1707385897979654508) | Zero Point Security | Training |
| [Relaying NTLM Authentication from SCCM Clients](https://medium.com/specter-ops-posts/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867) | Chris Thompson (@_Mayyhem) | Offensive |
| [SCCM - Microsoft's Native C2](https://redheadsec.tech/sccm-exploitation/) | RedHeadSec | Offensive |
| [SCCM and Incident Response Part 1](http://www.hexacorn.com/blog/2013/11/01/sccm-system-center-configuration-manager-and-incident-response/) | hexacorn | Defensive/Historical |
| [SCCM and Incident Response Part 2](http://www.hexacorn.com/blog/2015/01/30/sccm-system-center-configuration-manager-and-incident-response-part-2/) | hexacorn | Defensive/Historical |
| [SCCM Credential Recovery for Network Access Accounts](https://gist.github.com/EvanMcBroom/525d84b86f99c7a4eeb4e3495cffcbf0) | Evan McBroom | Offensive |
| [SCCM Decrypt POC](https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1) | Adam Chester (xpn) | Offensive |
| [SCCM Exploitation: Account Compromise Through Automatic Client Push & AD System Discovery](https://www.guidepointsecurity.com/blog/sccm-exploitation-account-compromise-through-automatic-client-push-amp-ad-system-discovery/) | Marshall Price | Offensive |
| [SCCM Exploitation: Compromising Network Access Accounts](https://www.guidepointsecurity.com/blog/sccm-exploitation-compromising-network-access-accounts/) | Marshall Price & Connor Dowling | Offensive |
| [SCCM Exploitation: Evading Defenses and Moving Laterally with SCCM Application Deployment](https://www.guidepointsecurity.com/blog/sccm-exploitation-evading-defenses-and-moving-laterally-with-sccm-application-deployment/) | Marshall Price | Offensive |
| [SCCM Hierarchy Takeover](https://specterops.io/blog/2023/09/25/sccm-hierarchy-takeover/) | Chris Thompson (@_Mayyhem) | Offensive |
| [SCCM Hierarchy Takeover via Entra Integration…Because of the Implication](https://specterops.io/blog/2025/11/19/sccm-hierarchy-takeover-via-entra-integrationbecause-of-the-implication/) | Garrett Foster (@unsigned_sh0rt) | Offensive |
| [SCCM Hierarchy Takeover with High Availability](https://specterops.io/blog/2024/02/21/sccm-hierarchy-takeover-with-high-availability/) | Garrett Foster (@unsigned_sh0rt) | Offensive |
| [SCCM Shenanigans 101](https://www.deloitte.com/be/en/blogs/sccm-shenanigans.html) | Deloitte | Defensive |
| [SCCM Site Takeover via Automatic Client Push Installation](https://specterops.io/blog/2023/01/12/sccm-site-takeover-via-automatic-client-push-installation/) | Chris Thompson (@_Mayyhem) | Offensive |
| [SCCM/MECM Hacker Recipes](https://www.thehacker.recipes/a-d/movement/sccm-mecm) | Charlie Bromberg | Offensive |
| [SCCMSecrets.py: exploiting SCCM policies distribution](https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial) | Quentin Roland, Synacktiv | Offensive/Tooling |
| [SeeSeeYouExec: Windows Session Hijacking via CcmExec](https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec) | Andrew Oliveau, Mandiant | Offensive |
| [Site Takeover via SCCM's AdminService API](https://posts.specterops.io/site-takeover-via-sccms-adminservice-api-d932e22b2bf) | Garrett Foster (@unsigned_sh0rt) | Offensive |
| [Targeted Workstation Compromise with SCCM](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/) | Matt Nelson (enigma0x3) | Offensive |
| [The Phantom Credentials of SCCM: Why the NAA Won't Die](https://specterops.io/blog/2022/06/28/the-phantom-credentials-of-sccm-why-the-naa-wont-die/) | Duane Michael (@subat0mik) | Offensive/Defensive |
| [Wait, Why is my WebClient Started?: SCCM Hierarchy Takeover via NTLM Relay to LDAP](https://specterops.io/blog/2026/01/14/wait-why-is-my-webclient-started-sccm-hierarchy-takeover-via-ntlm-relay-to-ldap/) | Logan Goins (@_logangoins) | Offensive |

## Videos & Talks

| Year | Title | Presenter | Topic |
|---|---|---|---|
| 2026 | [Exposing SCCM and MSSQL Attack Paths in Hardened Environments with OpenGraph \| SO-CON 26](https://www.youtube.com/watch?v=vd5UWRBg6ps) | Chris Thompson (@_Mayyhem) | ConfigManBearPig |
| 2026 | [Attacking SCCM with SCCMHunter \| Wild West Hacking Fest](https://www.youtube.com/watch?v=sh3Zb7MbiIg) | Garrett Foster (@unsigned_sh0rt) | sccmhunter / tooling |
| 2026 | [DEF CON 33 - SCCM: The tree that always bears bad fruits](https://www.youtube.com/watch?v=epyI3b8Vl0M) | Mehdi 'kalimer0x00' Elyassa | Post-exploitation and SCCM internals |
| 2026 | [SCCM: The tree that always bears bad fruits \| SO-CON 26](https://www.youtube.com/watch?v=cNgRbT4I97w) | Mehdi 'kalimer0x00' Elyassa | Post-exploitation and SCCM internals |
| 2025 | [TROOPERS25: Misconfiguration Manager - Still Overlooked, Still Overprivileged](https://youtu.be/H9zujF9bTjc) | Duane Michael (@subat0mik) & Garrett Foster (@unsigned_sh0rt) | Misconfiguration Manager updates |
| 2025 | [The Admin's Guide to Preventing SCCM Attacks \| SO-CON 2025](https://www.youtube.com/watch?v=Rc2J6fmhcJ4) | Chris Thompson (@_Mayyhem) & Garrett Foster (@unsigned_sh0rt) | Defensive guidance |
| 2024 | [Detecting Configuration Manager Attack Paths \| SO-CON 2025](https://www.youtube.com/watch?v=DoUyX9zx8m4) | Joshua Prager | Defensive guidance |
| 2024 | [Misconfiguration Manager: Overlooked and Overprivileged \| SO-CON 2024](https://www.youtube.com/watch?v=nvaOszFzXCQ) | Duane Michael (@subat0mik) & Chris Thompson (@_Mayyhem) | Misconfiguration Manager |
| 2024 | [The State of SCCM Exploitation in 2024](https://www.youtube.com/watch?v=zLeTmXkmBcQ) | Christopher Panayi | Exploitation |
| 2023 | [SCCM Exploitation: The First Cred Is the Deepest II](https://www.youtube.com/watch?v=W9PC9erm_pI) | Gabriel Prud'homme | Exploitation |
| 2023 | [Push Comes to Shove: Exploring SCCM Attack Paths](https://www.youtube.com/watch?v=qLBJJPUGk9U) | Brandon Colley | Exploitation |
| 2023 | [Black Hat USA Arsenal 2023: SharpSCCM - Abusing Microsoft's C2 Framework](https://www.youtube.com/watch?v=uyI5rgR0D-s) | Chris Thompson (@_Mayyhem) & Diego Lomellini | Tooling |
| 2023 | [Black Hat USA SpecterOps Booth 2023: SharpSCCM - Abusing Microsoft's C2 Framework](https://www.youtube.com/watch?v=Q8mEMFKscnk) | Chris Thompson (@_Mayyhem) & Diego Lomellini | Tooling |
| 2023 | [SCCM w/ Garrett Foster, Trimarc Happy Hour](https://www.youtube.com/watch?v=I5YTH0kQlr8) | Brandon Colley (host), Garrett Foster (@unsigned_sh0rt) (guest) | Interview |
| 2023 | [We Have C2 at Home: Leveraging Microsoft's C2 Framework](https://www.youtube.com/watch?v=jLoOa5xXkIs) | Garrett Foster (@unsigned_sh0rt) | Exploitation |
| 2022 | [Black Hat USA Arsenal 2022: SharpSCCM](https://www.youtube.com/watch?v=19F_Io1Tykg) | Chris Thompson (@_Mayyhem) & Duane Michael (@subat0mik) | Tooling |
| 2022 | [Pulling Passwords Out of Configuration Manager](https://www.youtube.com/watch?v=Ly9goAud0gs) | Christopher Panayi | Exploitation |
| 2012 | [Owning One to Rule Them All](https://www.youtube.com/watch?v=v4-S2903rOI) | Dave Kennedy & Dave DeSimone | DEF CON 20 |

## Tools

| Tool | Author | Language | Purpose |
|---|---|---|---|
| [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) | Chris Thompson | C# | Core post-ex C# tool: SCCM interaction, NTLM coercion, hierarchy takeover. CMPivot support contributed by Diego Lomellini ([PR](https://github.com/Mayyhem/SharpSCCM/pull/27)); PXE media cert credential support by Carsten Sandker ([PR](https://github.com/Mayyhem/SharpSCCM/pull/28)) |
| [sccmhunter](https://github.com/garrettfoster13/sccmhunter) | Garrett Foster | Python | Recon/attack framework for SCCM assets in AD |
| [ConfigManBearPig](https://github.com/SpecterOps/ConfigManBearPig) | SpecterOps / Chris Thompson | Python | SCCM attack path collector for BloodHound OpenGraph |
| [sccmhound](https://github.com/CrowdStrike/sccmhound) | CrowdStrike | C# | BloodHound collector for SCCM |
| [PowerSCCM](https://github.com/PowerShellMafia/PowerSCCM) | PowerShellMafia (Matt Nelson, Will Schroeder, Jared Atkinson, Matt Graeber) | PowerShell | Original PowerShell SCCM offensive module |
| [SCCMSecrets.py](https://github.com/synacktiv/SCCMSecrets) | Synacktiv | Python | Exploits SCCM policy distribution for creds/initial access |
| [MalSCCM](https://github.com/nettitude/MalSCCM) | Nettitude (Phil Keeble) | C# | Abuses SCCM application deployment |
| [sccm-http-looter](https://github.com/badsectorlabs/sccm-http-looter) | badsectorlabs | Go | Finds interesting files on SCCM shares via HTTP(S) |
| [sccm-http-looter (fork)](https://github.com/chryzsh/sccm-http-looter) | chryzsh | Go | Fork adding NTLM authentication support |
| [CMLoot](https://github.com/1njected/CMLoot) | Tomas Rzepka | PowerShell | Loots files from SCCM SMB shares |
| [go-cmloot](https://github.com/jfjallid/go-cmloot) | jfjallid | Go | Go reimplementation of CMLoot for SCCMContentLib SMB share |
| [go-cmloot (fork)](https://github.com/chryzsh/go-cmloot) | chryzsh | Go | Fork containing the `acl-hunt` branch |
| [sccmwtf](https://github.com/xpn/sccmwtf) | Adam Chester (xpn) | Python | NAA deobfuscation / policy request tooling. Python port of the deobfuscator contributed by @SkelSec ([PR](https://github.com/xpn/sccmwtf/pull/3)) |
| [SCCMVNC](https://github.com/netero1010/SCCMVNC) | Chris Au | C# | Modifies SCCM remote control settings for stealthy remote access |
| [ludus_sccm](https://github.com/Synzack/ludus_sccm) | Zach Stein | PowerShell | Original Ludus SCCM Ansible deployment |
| [ludus_sccm (fork)](https://github.com/Mayyhem/ludus_sccm) | Chris Thompson | PowerShell | 3-tier hierarchy expansion (CAS → PS1 → SEC) |
| [SCCM-CVE-2026-47301-RCE-Exploit](https://github.com/OmriBaso/SCCM-CVE-2026-47301-Remote-Code-Execution-Exploit) | OmriBaso | C# | PoC exploit chain for CVE-2026-47301 |
| [SCCMDecryptor-BOF](https://github.com/NocteDefensor/SCCMDecryptor-BOF) | NocteDefensor | C | BOF for decrypting SCCM credentials |
| [SharpPXE](https://github.com/leftp/SharpPXE) | Lefteris Panos | C# | Extracts info from SCCM PXE boot media |
| [WimWizard](https://github.com/TacII/WimWizard) | TacII | PowerShell | Builds patched OS images w/ language packs for SCCM OSD |
| [offlineSCCMdecrypt](https://github.com/MartinoTommasini/offlineSCCMdecrypt) | MartinoTommasini | Python | Step-by-step offline decryption of SCCM database secrets |
| [mssqlkaren](https://github.com/garrettfoster13/mssqlkaren) | Garrett Foster | Python | Modified impacket mssqlclient to extract SCCM DB policies |
| [sccmsqlclient](https://github.com/synacktiv/sccmsqlclient) | Synacktiv | Python | MSSQL client tailored for SCCM DB |
| [SCCMVersionGuesser](https://github.com/synacktiv/SCCMVersionGuesser) | Synacktiv (Mehdi Elyassa) | Python | Fingerprints SCCM/ConfigMgr version |
| [SQLRecon (SCCM module)](https://github.com/skahwah/SQLRecon) | Sanjiv Kawa | C# | MSSQL recon/exploitation tool with SCCM-specific module |
| [impacket SCCM Relay fork](https://github.com/Tw1sm/impacket/tree/feature/sccm-relay) | Matt Creel | Python | NTLM relay support for SCCM in impacket |
| [SharpDPAPI (SCCM module)](https://github.com/GhostPack/SharpDPAPI/blob/81e1fcdd44e04cf84ca0085cf5db2be4f7421903/SharpDPAPI/Commands/SCCM.cs) | Duane Michael / GhostPack | C# | SCCM credential gathering via DPAPI |
| [cred1py](https://github.com/SpecterOps/cred1py) | Adam Chester (xpn) / SpecterOps | Python | SOCKS5-enabled CRED-1 PoC, AES-256 auto-detect, pure-Python CMS/PKCS7 |
| [PXEThief](https://github.com/MWR-CyberSec/PXEThief) | Christopher Panayi (MWR-CyberSec) | Python | OSD/PXE credential extraction — original tool, direct ancestor of the PXE lineage below |
| [PXEThief (blurbdust fork)](https://github.com/blurbdust/PXEThief) | blurbdust | Python | Actively-maintained fork — AES-256, dynamic hash-type detection, legacy 3DES |
| [pxethiefy](https://github.com/csandker/pxethiefy) | Carsten Sandker | Python | First Linux port of PXEThief |
| [pxethiefup](https://github.com/evildaemond/pxethiefup) | Adam Jon Foster | Python | Fork adding weak/default password auto-try, hashcat-mode wiring |
| [powerpxe](https://github.com/wavestone-cdt/powerpxe) | wavestone-cdt | PowerShell | Extracts info from PXE boot media (predates PXEThief) |
| [hashcat-6.2.6-SCCM](https://github.com/The-Viper-One/hashcat-6.2.6-SCCM) | The-Viper-One | C | Hashcat fork adding mode 19850 for SCCM PXE media hashes |
| [hashcat-6.2.6-SCCM (fork)](https://github.com/chryzsh/hashcat-6.2.6-SCCM) | chryzsh | C | Fork adding AES-256 support (mode 19851) |
| [PXEHacker](https://github.com/chryzsh/PXEHacker) | chryzsh | Python | Linux-first CLI combining PXEThief and cred1py to cover the full CRED-1 chain, with SOCKS5, AES-128/192/256 and legacy 3DES support, weak-password attempts, and hashcat integration |
| [mprecon](https://github.com/temp43487580/mprecon) | temp43487580 | Python | Collects management point info (site details, distribution point data, credentials) from an SCCM management point |
| [SCCMSiteCodeHunter](https://github.com/ZephrFish/SCCMSiteCodeHunter) | Andy Gill | C# | Enumerates SCCM servers/site codes by querying Active Directory via LDAP |
| [SCCM-Enumeration](https://github.com/Cr0n1c/SCCM-Enumeration/) | Cr0n1c | PowerShell | Enumerates an SCCM SQL database for computers, users, applications, and their relationships |
| [SCCM_SQL_Collector](https://github.com/G0ldenGunSec/SCCM_SQL_Collector) | Dave Cossa | C# | PoC that collects SCCM attack paths from the SQL database for BloodHound OpenGraph visualization |
