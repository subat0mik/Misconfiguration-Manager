# PREVENT-9

## Description 
Enforce MFA for SMS Provider calls

## Summary
Configure a requirement for multi-factor authentication to access WMI/AdminService on SMS Providers to help prevent an attacker with only an SCCM administrator's username and password from compromising the hierarchy.

## Linked Defensive IDs
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Associated Offensive IDs
- [EXEC-1: Application deployment](../../../attack-techniques/EXEC/EXEC-1/exec-1_description.md)
- [EXEC-2: PowerShell script execution](../../../attack-techniques/EXEC/EXEC-2/exec-2_description.md)
- [RECON-4: Query client devices via CMPivot](../../../attack-techniques/RECON/RECON-4/recon-4_description.md)
- [RECON-5: Locate users via SMS Provider](../../../attack-techniques/RECON/RECON-5/recon-5_description.md)
- [RECON-7: Enumerate SCCM site information via local files](../../../attack-techniques/RECON/RECON-7/recon-7_description.md)
- [TAKEOVER-5: NTLM coercion and relay to AdminService on remote SMS Provider](../../../attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md)

## References
Microsoft, [Enable MFA for SMS Provider Calls](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/setup-migrate-backup-recovery/enable-mfa-for-sms-provider-calls)