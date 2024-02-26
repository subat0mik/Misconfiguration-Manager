| Codname | Description | Notes |
|---------|-------------|-------|
| PROTECT01 | Do not manage Tier 0 assets | 
| PROTECT02 | Disable Fallback to NTLM
| PROTECT03 | Disable Network Access Accounts |
| PROTECT04 | Configure Enhanced HTTP |
| PROTECT05 | Disable automatic side-wide client push installation |
| PROTECT06 | Configure strong PXE boot password | Prevents cracking to obtain OSD secrets |
| PROTECT07 | Disable command support in PXE boot configuration| Prevents entering "F8-debugging" |
| PROTECT08 | Require PKI certificates for client authentation | Prevents rogue device registration
| PROTECT09 | Enforce MFA for SMS Provider calls | 
| PROTECT10 | Principle of Least Privilege | Don't over-privilege accounts
| PROTECT11 | Disable / Uninstall WebClient on site servers  | Prevents NTLM coercion over HTTP |
| PROTECT12 | Require SMB signing on site systems | Prevents SMB relay |
| PROTECT13 | Require LDAP channel binding and signing on DCs | Prevents relay to LDAP
| PROTECT14 | Require Extended Protection for Authentication (EPA) on AD CS CAs and standalone site databases | Prevents relay to HTTP and MSSQL
| PROTECT15 | Disable NAAs in AD |
| PROTECT16 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Prevent users from adding machine accounts
| PROTECT17 | Remove Extended Rights assignment from accounts that do not require it | Prevents GetLapsPassword for created accounts |
| PROTECT18 | Enable Windows LAPs in Azure with password encryption |
| PROTECT19 | Remove database links from site database |
| PROTECT20 | Block unnecessary connections to site systems (E.g., SMB, MSSQL) | Reduces coercion via SMB and relay to SMB/MSSQL
| PROTECT21 | Restrict PXE boot to authorized VLANs
| DETECT01 | Monitor siste system computer accounts authenticating from a source that is not its static IP |
| DETECT02 | Monitor client push installation accounts authenticating from anywhere other than the primary site server |
| DETECT03 | Monitor application deployment logs  in the site's Audit Status Messages |
| CANARY01 | Configure an appropriately-privileged NAA with interactive logon restricted, monitor for usage |
| CANARY02 | Configure a minimally privileged client push account
