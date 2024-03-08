| Codname | Description | Admin Roles |
|---------|-------------|-------------|
| CANARY-1 | Configure an appropriately-privileged NAA with interactive logon restricted | SCCM, domain |
| DETECT-1 | Monitor site server domain computer accounts authenticating from another source | Security |
| DETECT-2 | Monitor read access to the System Management Active Directory container | Security |
| DETECT-3 | Monitor client push installation accounts authenticating from anywhere other than the primary site server | Security |
| DETECT-4 | Monitor application deployment logs in the site's Audit Status Messages | SCCM, security |
| DETECT-5 | Monitor group membership changes for SMS Admins | SCCM, server, security |
| PREVENT-1 | Patch site server with KB15599094 | SCCM, server |
| PREVENT-2 | Disable Fallback to NTLM | SCCM |
| PREVENT-3 | Harden or disable network access accounts | SCCM, domain, security |
| PREVENT-4 | Configure Enhanced HTTP | SCCM |
| PREVENT-5 | Disable automatic side-wide client push installation | SCCM |
| PREVENT-6 | Configure a strong PXE boot password | SCCM |
| PREVENT-7 | Disable command support in PXE boot configuration| SCCM |
| PREVENT-8 | Require PKI certificates for client authentation | SCCM, network, security, server, domain |
| PREVENT-9 | Enforce MFA for SMS Provider calls | SCCM |
| PREVENT&#x2011;10 | Enforce the principle of least privilege for accounts | SCCM, domain, server, security |
| PREVENT&#x2011;11 | Disable and uninstall WebClient on site servers | SCCM, server |
| PREVENT&#x2011;12 | Require SMB signing on site systems | Domain, server, SCCM |
| PREVENT&#x2011;13 | Require LDAP channel binding and signing | Domain, server |
| PREVENT&#x2011;14 | Require EPA on AD CS and site databases | Domain, security, SCCM, server, database |
| PREVENT&#x2011;15 | Disable and change passwords of legacy NAAs and collection variables/task sequence secrets in Active Directory | Domain, SCCM |
| PREVENT&#x2011;16 | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Domain |
| PREVENT&#x2011;17 | Remove Extended Rights assignment from accounts that do not require it | Domain, desktop |
| PREVENT&#x2011;18 | Use strong passwords for DBA accounts | Database, security, domain |
| PREVENT&#x2011;19 | Remove unnecessary links to site databases | SCCM, database |
| PREVENT&#x2011;20 | Block unnecessary connections to site systems | Network, server |
| PREVENT&#x2011;21 | Restrict PXE boot to authorized VLANs | SCCM, network |
| PREVENT&#x2011;22 | Do not manage assets in two or more segmented forests, domains, networks, or security tiers | SCCM, network, security, domain |
