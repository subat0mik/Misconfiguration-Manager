| Codname | Description | Admin Roles |
|---------|-------------|-------------|
| [CANARY&#x2011;1](./CANARY/CANARY-1/canary-1_description.md) | Configure an appropriately-privileged NAA with interactive logon restricted | SCCM, domain |
| [DETECT&#x2011;1](./DETECT/DETECT-1/detect-1_description.md) | Monitor site server domain computer accounts authenticating from another source | Security |
| [DETECT&#x2011;2](./DETECT/DETECT-2/detect-2_description.md) | Monitor read access to the System Management Active Directory container | Security |
| [DETECT&#x2011;3](./DETECT/DETECT-3/detect-3_description.md) | Monitor client push installation accounts authenticating from anywhere other than the primary site server | Security |
| [DETECT&#x2011;4](./DETECT/DETECT-4/detect-4_description.md) | Monitor application deployment logs in the site's Audit Status Messages | SCCM, security |
| [DETECT&#x2011;5](./DETECT/DETECT-5/detect-5_description.md) | Monitor group membership changes for SMS Admins | SCCM, server, security |
| [DETECT&#x2011;6](./DETECT/DETECT-6/detect-6_description.md) | Monitor group membership changes for RBAC_Admins table | SCCM, server, security |
| [PREVENT&#x2011;1](./PREVENT/PREVENT-1/prevent-1_description.md) | Patch site server with KB15599094 | SCCM, server |
| [PREVENT&#x2011;2](./PREVENT/PREVENT-2/prevent-2_description.md) | Disable Fallback to NTLM | SCCM |
| [PREVENT&#x2011;3](./PREVENT/PREVENT-3/prevent-3_description.md) | Harden or disable network access accounts | SCCM, domain, security |
| [PREVENT&#x2011;4](./PREVENT/PREVENT-4/prevent-4_description.md) | Configure Enhanced HTTP | SCCM |
| [PREVENT&#x2011;5](./PREVENT/PREVENT-5/prevent-5_description.md) | Disable automatic side-wide client push installation | SCCM |
| [PREVENT&#x2011;6](./PREVENT/PREVENT-6/prevent-6_description.md) | Configure a strong PXE boot password | SCCM |
| [PREVENT&#x2011;7](./PREVENT/PREVENT-7/prevent-7_description.md) | Disable command support in PXE boot configuration| SCCM |
| [PREVENT&#x2011;8](./PREVENT/PREVENT-8/prevent-8_description.md) | Require PKI certificates for client authentation | SCCM, network, security, server, domain |
| [PREVENT&#x2011;9](./PREVENT/PREVENT-9/prevent-9_description.md) | Enforce MFA for SMS Provider calls | SCCM |
| [PREVENT&#x2011;10](./PREVENT/PREVENT-10/prevent-10_description.md) | Enforce the principle of least privilege for accounts | SCCM, domain, server, security |
| [PREVENT&#x2011;11](./PREVENT/PREVENT-11/prevent-11_description.md) | Disable and uninstall WebClient on site servers | SCCM, server |
| [PREVENT&#x2011;12](./PREVENT/PREVENT-12/prevent-12_description.md) | Require SMB signing on site systems | Domain, server, SCCM |
| [PREVENT&#x2011;13](./PREVENT/PREVENT-13/prevent-13_description.md) | Require LDAP channel binding and signing | Domain, server |
| [PREVENT&#x2011;14](./PREVENT/PREVENT-14/prevent-14_description.md) | Require EPA on AD CS and site databases | Domain, security, SCCM, server, database |
| [PREVENT&#x2011;15](./PREVENT/PREVENT-15/prevent-15_description.md) | Disable and change passwords of legacy NAAs and collection variables/task sequence secrets in Active Directory | Domain, SCCM |
| [PREVENT&#x2011;16](./PREVENT/PREVENT-16/prevent-16_description.md) | Remove SeMachineAccountPrivilege and set MachineAccountQuota to 0 for non-admin accounts | Domain |
| [PREVENT&#x2011;17](./PREVENT/PREVENT-17/prevent-17_description.md) | Remove Extended Rights assignment from accounts that do not require it | Domain, desktop |
| [PREVENT&#x2011;18](./PREVENT/PREVENT-18/prevent-18_description.md) | Use strong passwords for DBA accounts | Database, security, domain |
| [PREVENT&#x2011;19](./PREVENT/PREVENT-19/prevent-19_description.md) | Remove unnecessary links to site databases | SCCM, database |
| [PREVENT&#x2011;20](./PREVENT/PREVENT-20/prevent-20_description.md) | Block unnecessary connections to site systems | Network, server |
| [PREVENT&#x2011;21](./PREVENT/PREVENT-21/prevent-21_description.md) | Restrict PXE boot to authorized VLANs | SCCM, network |
| [PREVENT&#x2011;22](./PREVENT/PREVENT-22/prevent-22_description.md) | Do not manage assets in two or more segmented forests, domains, networks, or security tiers | SCCM, network, security, domain |