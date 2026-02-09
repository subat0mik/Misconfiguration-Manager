# RECON-7

## Description
Enumerate SCCM site information via local files

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements
- Valid Active Directory domain credentials

## Summary
Upon the enrollment of a client to SCCM, default directories are created where SCCM client specific debugging logs can be stored. The log files contain details about deployments, hostnames related to SCCM servers, and other relevant information.

These log files can be enumerated simply by using the command and control file browser. Default defensive telemetry isn't usually generated upon the access of these SCCM log directories unless custom auditing is enabled.

Log files located on the SCCM-enrolled clients will typically originate from the following directories:
* `C:\Windows\CCM\Logs`
* `C:\Windows\ccmcache`
* `C:\Windows\ccmsetup`

The `C:\Windows\CCM\Logs` directory is one of the most useful from an enumeration perspective, as it contains the SCCM server names in multiple logs:
* `C:\Windows\CCM\Logs\StatusAgent.log`
* `C:\Windows\CCM\Logs\LocationServices.log`
* `C:\Windows\CCM\Logs\DataTransferService.log`
* `C:\Windows\CCM\Logs\ClientServicing.log`
* `C:\Windows\CCM\Logs\CcmNotificationAgent.log`
* `C:\Windows\CCM\Logs\CcmMessaging.log`
* `C:\Windows\CCM\Logs\CcmEval.log`

Additionally, the registry key/value of `HKLM:\SOFTWARE\Microsoft\SMS\DP\ManagementPoints` will enumerate the `Distribution Points` and `Management Points` for that particular SCCM-enrolled client. Defenders will typically have some default auditing aimed at accessing the registry.

## Impact
1. Profiling site servers is a supplementary step in building potential attack paths
2. A resolved DP role can be a target for PXE abuse to recover domain credentials detailed in [CRED-1](../../CRED/CRED-1/cred-1_description.md)
3. A resolved DP role can be a target for [sensitive information hunting in the Content Library](https://rzec.se/blog/looting-microsoft-configuration-manager)
4. A resolved MP role can be a target for spoofing client enrollment [CRED-2](../../CRED/CRED-2/cred-2_description.md)
5. A resolved MP site system role can be used to elevate privileges via credential relay attacks [ELEVATE-1](../../ELEVATE/ELEVATE-1/ELEVATE-1_description.md)
 
## Defensive IDs
- [DETECT-7: Monitor local object access for SCCM logs and settings](../../../defense-techniques/DETECT/DETECT-7/detect-7_description.md)
- [DETECT-9: Monitor local object access for local SCCM logs and settings](../../../defense-techniques/DETECT/DETECT-9/detect-9_description.md)

## Examples
Use [SharpSCCM](https://github.com/Mayyhem/SharpSCCM/) to enumerate local SCCM log files containing UNC paths:

### SCCM-Enrolled Client

```
.\SharpSCCM.exe local triage

  _______ _     _ _______  ______  _____  _______ _______ _______ _______
  |______ |_____| |_____| |_____/ |_____] |______ |       |       |  |  |
  ______| |     | |     | |    \_ |       ______| |______ |______ |  |  |    @_Mayyhem

[+] Client cache contents and permissions for the current user:
    Perms      Size  Date modified          Name
      drw             8/31/2024 1:51:07 AM  C:\Windows\ccmcache
      -rw      0.0B   8/31/2024 1:51:07 AM  C:\Windows\ccmcache\skpswi.dat

[+] Searching logs for possible UNC paths:
    Found match in C:\Windows\CCM\Logs\InventoryAgent-20241019-033813.log
      \\localhost\root\cimv2
      \\localhost\root\vm\VirtualServer
      \\localhost\root\vm\VirtualServer Namespace
      \\localhost\root\Microsoft\appvirt\client
      \\localhost\root\Microsoft\appvirt\client Namespace
    Found match in C:\Windows\CCM\Logs\InventoryAgent.log
      \\localhost\root\cimv2
      \\localhost\root\vm\VirtualServer
      \\localhost\root\vm\VirtualServer Namespace

[+] Searching logs for possible URLs:
    Found match in C:\Windows\CCM\Logs\CcmEval-20241020-204501.log
      http://atlas.aperture.local
    Found match in C:\Windows\CCM\Logs\CcmEval.log
      http://atlas.aperture.local
    Found match in C:\Windows\CCM\Logs\CcmMessaging-20241020-062929.log
      http://atlas.aperture.local/CCM_Incoming/
      http://atlas.aperture.local:80/CCM_Incoming/
    Found match in C:\Windows\CCM\Logs\CcmMessaging.log
      http://atlas.aperture.local/CCM_Incoming/
      http://atlas.aperture.local:80/CCM_Incoming/
    Found match in C:\Windows\CCM\Logs\ClientLocation.log
      http://atlas.aperture.local
    Found match in C:\Windows\CCM\Logs\ClientServicing.log
      http://atlas.aperture.local
      http://atlas.aperture.local/CCM_Client
    Found match in C:\Windows\CCM\Logs\DataTransferService.log
      http://atlas.aperture.local/SMS_MP
      http://atlas.aperture.local:80/SMS_MP
    Found match in C:\Windows\CCM\Logs\DeltaDownload-20241012-184715.log
      http://localhost:8005
    Found match in C:\Windows\CCM\Logs\DeltaDownload.log
      http://localhost:8005
    Found match in C:\Windows\CCM\Logs\SensorEndpoint-20241023-173719.log
      http://www.w3.org/2001/XMLSchema
      http://www.w3.org/2001/XMLSchema-instance
      http://schemas.microsoft.com/win/2004/08/events/event
    Found match in C:\Windows\CCM\Logs\SensorEndpoint.log
      http://www.w3.org/2001/XMLSchema
      http://www.w3.org/2001/XMLSchema-instance
      http://schemas.microsoft.com/win/2004/08/events/event
    Found match in C:\Windows\CCM\Logs\SensorManagedProvider-20241024-144230.Log
      http://www.w3.org/2001/XMLSchema-instance
      http://www.w3.org/2001/XMLSchema
    Found match in C:\Windows\CCM\Logs\SensorManagedProvider.Log
      http://www.w3.org/2001/XMLSchema-instance
      http://www.w3.org/2001/XMLSchema

[+] Completed execution in 00:00:09.8748192
```

Use PowerShell to enumerate the Distribution Point value within the `HKLM:\SOFTWARE\Microsoft\SMS\DP` registry key:

```
PS C:\Tools> (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name ManagementPoints).ManagementPoints

atlas.aperture.local
```

## References
- Chris Thompson, [SharpSCCM](https://github.com/Mayyhem/SharpSCCM/)
