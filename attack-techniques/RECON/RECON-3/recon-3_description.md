# RECON-3

## Description
Enumerating SCCM roles via HTTP

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements

Valid Active Directory domain credentials

## Summary

When certain site system roles are installed part of the installation process involves configuring web services on the host system. Depending on the role, static and predictable URLs can be enumerated when a request sent to the URL provides an expected response. Fuzzing these URLS on potential site systems contributes to attack path discovery. 

## Defensive IDs

## Examples
The following examples are a sampling and are not an exhaustive representation.

### Management Points

Management points (MP) host several web applications for multiple functions including client communication, policy distribution, and health monitoring. Site systems configured with this role have predictable URL paths that require authenticaiton when interacting.  

```
C:\Users\administrator.LAB>%systemroot%\system32\inetsrv\AppCmd.exe list app
APP "Default Web Site/" (applicationPool:DefaultAppPool)
APP "Default Web Site/CCM_CLIENT" (applicationPool:CCM Client Deployment Pool)
APP "Default Web Site/CCM_Incoming" (applicationPool:CCM Server Framework Pool)
APP "Default Web Site/CCM_System" (applicationPool:CCM Server Framework Pool)
APP "Default Web Site/CCM_System_WindowsAuth" (applicationPool:CCM Windows Auth Server Framework Pool)
APP "Default Web Site/CCM_System_TokenAuth" (applicationPool:CCM Server Framework Pool)
APP "Default Web Site/CCM_STS" (applicationPool:CCM Security Token Service Pool)
APP "Default Web Site/CMUserService" (applicationPool:CCM User Service Pool)
APP "Default Web Site/CMUserService_WindowsAuth" (applicationPool:CCM Windows Auth User Service Pool)
APP "Default Web Site/SMS_MP" (applicationPool:SMS Management Point Pool)
APP "Default Web Site/SMS_MP_WindowsAuth" (applicationPool:SMS Windows Auth Management Point Pool)
APP "Default Web Site/SMS_MP_TokenAuth" (applicationPool:SMS Management Point Pool)
APP "Default Web Site/BGB" (applicationPool:CCM Client Notification Proxy Pool)
```

### SMS Provider

 The SMS Provider role hosts a collection of Windows Management Instrumentation (WMI) classes that translate queries to access data stored in the site’s database. In addition to WMI, the SMS Provider also hosts the Administration Service (AdminService) API which has two static routes that require authentication:

 ```
https://<SMSProvier.FQDN>/AdminService/wmi/
https://<SMSProvier.FQDN>/AdminService/v1.0/
 ```


## Impact

1. Profiling site system roles is a supplmentary step in building potential attack paths
2. A resolved MP role can be a target for spoofing client enrollment [CRED-2](../../CRED/CRED-2/cred-2_description.md)
3. A resolved SMS Provider role can be a target for privilege escalation [ELEVATE-2](../../ELEVATE/ELEVATE-2/ELEVATE-2_description.md) 



## References


Microsoft, What is the administration service in Configuration Manager?, https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview

Microsoft, Plan for the SMS Provider, https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/plan-for-the-sms-provider