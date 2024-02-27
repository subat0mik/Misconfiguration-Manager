| Codname | Description | Notes |
|---------|-------------|-------|
| PREVENT-1 | Install KB15599094 |
| PREVENT-2 | Disable Fallback to NTLM |
| PREVENT-3 | Disable Network Access Accounts |
| PREVENT-4 | Configure Enhanced HTTP |
| PREVENT-5 | Disable automatic side-wide client push installation |
| PREVENT-6 | Configure strong PXE boot password | Prevents cracking to obtain OSD secrets |
| PREVENT-7 | Disable command support in PXE boot configuration| Prevents entering "F8-debugging" |
| PREVENT-8 | Require PKI certificates for client authentation | Prevents rogue device registration
| PREVENT-9 | Enforce MFA for SMS Provider calls | 
| PREVENT-10 | Principle of Least Privilege | Don't over-privilege accounts
| PREVENT-11 | Disable / Uninstall WebClient on site servers  | Prevents NTLM coercion over HTTP |
| PREVENT-12 | Require SMB signing on site systems | Prevents SMB relay |
| PREVENT-13 | Require LDAP channel binding and signing on DCs | Prevents relay to LDAP
| PREVENT-14 | Require Extended Protection for Authentication (EPA) on AD CS CAs and standalone site databases | Prevents relay to HTTP and MSSQL
| PREVENT-15 | Disable NAAs in AD |
| PREVENT-16 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Prevent users from adding machine accounts
| PREVENT-17 | Remove Extended Rights assignment from accounts that do not require it | Prevents GetLapsPassword for created accounts |
| PREVENT-18 | Enable Windows LAPs in Azure with password encryption |
| PREVENT-19 | Remove database links from site database |
| PREVENT-20 | Block unnecessary connections to site systems (E.g., SMB, MSSQL) | Reduces coercion via SMB and relay to SMB/MSSQL
| PREVENT-21 | Restrict PXE boot to authorized VLANs
| PREVENT-X | Do not manage Tier 0 assets | 
| DETECT01 | Monitor siste system computer accounts authenticating from a source that is not its static IP |
| DETECT02 | Monitor client push installation accounts authenticating from anywhere other than the primary site server |
| DETECT03 | Monitor application deployment logs  in the site's Audit Status Messages |
| CANARY01 | Configure an appropriately-privileged NAA with interactive logon restricted, monitor for usage |
| CANARY02 | Configure a minimally privileged client push account
