# DETECT-9

## Description
Monitor local object access for local SCCM logs and settings

## Summary
An attacker enumerate SCCM infrastructure by locally accessing SCCM client logs that are stored on the local endpoint that the adversary has compromised. 
By default all SCCM-enrolled clients will have specific directories associated to SCCM:
* C:\Windows\CCMCACHE
* C:\Windows\CCMSETUP
* C:\Windows\CCM\Logs

The `C:\Windows\CCM` file path is readable by non-administrators by default. From the logs located within this file path, attackers can enumerate details about SCCM infrastructure hostnames, deployments, and other details.

From a tradecraft perspective, offensive operators would only need to review the files from within the file browser of the C2, making this method of enumeration one of the most evasive from the perspective of default telemetry generation.

Defenders can generate custom auditing on these default file locations and identify anomalous process and users accessing the files.

## Associated Offensive IDs
- [RECON-1: Enumerate SCCM site information via LDAP](../../../attack-techniques/RECON/RECON-1/recon-1_description.md)

## References
- Garrett Foster, SCCMHunter Find Module, https://github.com/garrettfoster13/sccmhunter/wiki/find
- Josh Prager & Nico Shyne, Domain Persistence: Detection Triage and Recovery, https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024