| Codname | Description | Notes | Links | Status |
|---------|-------------|-------| ----- | ------ |
| CANARY-1 | Configure an appropriately-privileged NAA with interactive logon restricted |
| CANARY-2 | Configure a minimally privileged client push account |
| DETECT-1 | Monitor site server domain computer accounts authenticating from another source |
| DETECT-2 | Monitor the read access requests of the System Management container within Active Directory Users and Computers | | | X
| DETECT-3 | Monitor client push installation accounts authenticating from anywhere other than the primary site server |
| DETECT-4 | Monitor application deployment logs in the site's Audit Status Messages |
| DETECT-5 | Monitor group membership changes for SMS Admins | | TAKEOVER-2 |
| PREVENT-1 | Patch site server with KB15599094 | |  | QA
| PREVENT-2 | Disable Fallback to NTLM | | TAKEOVER-1| QA
| PREVENT-3 | Harden or disable network access accounts | | CRED-1, CRED-2, CRED-3 | QA
| PREVENT-4 | Configure Enhanced HTTP | | CRED-2, CRED-3, CRED-4, PREVENT-3, PREVENT-8, PREVENT-15| QA
| PREVENT-5 | Disable automatic side-wide client push installation | | PREVENT-2 | QA
| PREVENT-6 | Configure a strong PXE boot password | Prevents cracking to obtain OSD secrets | CRED-1 | QA
| PREVENT-7 | Disable command support in PXE boot configuration| Prevents entering "F8-debugging" | CRED-1 | QA
| PREVENT-8 | Require PKI certificates for client authentation | Prevents rogue device registration | TAKEOVER-2 |
| PREVENT-9 | Enforce MFA for SMS Provider calls | | RECON-4, TAKEOVER-2 |
| PREVENT-10 | Enforce the principle of least privilege for accounts | | | QA
| PREVENT-11 | Disable/uninstall WebClient on site servers  | Prevents NTLM coercion over HTTP | | QA
| PREVENT-12 | Require SMB signing on site systems | Prevents SMB relay | TAKEOVER-1 | QA
| PREVENT-13 | Require LDAP channel binding and signing | Prevents relay to LDAP | | QA
| PREVENT-14 | Require EPA on AD CS and site databases | Prevents relay to HTTP and MSSQL | TAKEOVER-1
| PREVENT-15 | Disable and change passwords of legacy NAAs and collection variables/task sequence secrets in Active Directory |
| PREVENT-16 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Prevent users from adding machine accounts
| PREVENT-17 | Remove Extended Rights assignment from accounts that do not require it | Prevents GetLapsPassword for created accounts |
| PREVENT-18 | Use strong passwords for DBA accounts | | |
| PREVENT-19 | Remove unnecessary links to site databases | | | QA
| PREVENT-20 | Block unnecessary connections to site systems | Reduces coercion via SMB and relay to SMB/MSSQL
| PREVENT-21 | Restrict PXE boot to authorized VLANs | | | QA
| PREVENT-22 | Do not manage Tier 0 assets |