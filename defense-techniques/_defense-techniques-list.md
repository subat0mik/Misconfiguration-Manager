| Codname | Description | Notes |
|---------|-------------|-------|
| PROTECT01 | Treat SCCM as Tier 0 |
| PROTECT02 | Do not manage Tier 0 assets | 
| PROTECT03 | Disable Fallback to NTLM
| PROTECT04 | Disable Network Access Accounts |
| PROTECT05 | Configure Enhanced HTTP |
| PROTECT06 | Disable automatic side-wide client push installation |
| PROTECT07 | Configure strong PXE boot password | Prevents cracking to obtain OSD secrets |
| PROTECT08 | Disable command support in PXE boot configuration| Prevents entering "F8-debugging" |
| PROTECT09 | Require PKI certificates for client authentation | Prevents rogue device registration
| PROTECT10 | Enforce MFA for SMS Provider calls | 
| PROTECT11 | Principle of Least Privilege | Don't over-privilege accounts
| PROTECT12 | Disable / Uninstall WebClient on site servers  | Prevents NTLM coercion over HTTP |
| PROTECT13 | Require SMB signing on site systems | Prevents SMB relay |
| PROTECT14 | Require LDAP channel binding and signing on DCs | Prevents relay to LDAP
| PROTECT15 | Require Extended Protection for Authentication (EPA) on AD CS CAs and standalone site databases | Prevents relay to HTTP and MSSQL
| PROTECT16 | Disable NAAs in AD |
| PROTECT17 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Prevent users from adding machine accounts
| PROTECT18 | Remove Extended Rights assignment from accounts that do not require it | Prevents GetLapsPassword for created accounts |
| PROTECT19 | Enable Windows LAPs in Azure with password encryption |
| PROTECT20 | Remove database links from site database |
| PROTECT21 | Block unnecessary connections to site systems (E.g., SMB, MSSQL) | Reduces coercion via SMB and relay to SMB/MSSQL
| PROTECT22 | Restrict PXE boot to authorized VLANs
| DETECT01 | Monitor siste system computer accounts authenticating from a source that is not its static IP |
| DETECT02 | Monitor client push installation accounts authenticating from anywhere other than the primary site server |
| DETECT03 | Monitor application deployment logs  in the site's Audit Status Messages |
| CANARY01 | Configure an appropriately-privileged NAA with interactive logon restricted, monitor for usage |
| CANARY02 | Configure a minimally privileged client push account
