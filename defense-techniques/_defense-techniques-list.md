| Codname | Description | Notes |
|---------|-------------|-------|
| SCCM-PREVENT01 | Treat SCCM as Tier 0 |
| SCCM-PREVENT02 | Do not manage Tier 0 assets | 
| SCCM-PREVENT03 | Disable Fallback to NTLM
| SCCM-PREVENT04 | Disable Network Access Accounts |
| SCCM-PREVENT05 | Configure Enhanced HTTP |
| SCCM-PREVENT06 | Disable automatic side-wide client push installation |
| SCCM-PREVENT07 | Configure strong PXE boot password | Prevents cracking to obtain OSD secrets |
| SCCM-PREVENT08 | Disable command support in PXE boot configuration| Prevents entering "F8-debugging" |
| SCCM-PREVENT09 | Require PKI certificates for client authentation | Prevents rogue device registration
| SCCM-PREVENT10 | Enforce MFA for SMS Provider calls | 
| SCCM-PREVENT11 | Principle of Least Privilege | Don't over-privilege accounts
| SCCM-PREVENT12 | Disable / Uninstall WebClient on site servers  | Prevents NTLM coercion over HTTP |
| SCCM-PREVENT13 | Require SMB signing on site systems | Prevents SMB relay |
| SCCM-PREVENT14 | Require LDAP channel binding and signing on DCs | Prevents relay to LDAP
| SCCM-PREVENT15 | Require Extended Protection for Authentication (EPA) on AD CS CAs and standalone site databases | Prevents relay to HTTP and MSSQL
| SCCM-PREVENT16 | Disable NAAs in AD |
| SCCM-PREVENT17 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Prevent users from adding machine accounts
| SCCM-PREVENT18 | Remove Extended Rights assignment from accounts that do not require it | Prevents GetLapsPassword for created accounts |
| SCCM-PREVENT19 | Enable Windows LAPs in Azure with password encryption |
| SCCM-PREVENT20 | Remove database links from site database |
| SCCM-PREVENT21 | Block unnecessary connections to site systems (E.g., SMB, MSSQL) | Reduces coercion via SMB and relay to SMB/MSSQL
| SCCM-PREVENT22 | Restrict PXE boot to authorized VLANs
| SCCM-DETECT01 | Monitor siste system computer accounts authenticating from a source that is not its static IP |
| SCCM-DETECT02 | Monitor client push installation accounts authenticating from anywhere other than the primary site server |
| SCCM-DETECT03 | Monitor application deployment logs  in the site's Audit Status Messages |
| SCCM-CANARY01 | Configure an appropriately-privileged NAA with interactive logon restricted, monitor for usage |
| SCCM-CANARY02 | Configure a minimally privileged client push account
