# PREVENT-14

## Description
Require EPA on AD CS and site databases

## Summary
**IMPORTANT:** Implementing these settings **do** have a performance impact and the authors have only tested them to confirm that NTLM relay is prevented in a lab environment, so it is crucial to first test these changes in your environment before implementing in production.

Extended Protection uses service binding and channel binding to help prevent NTLM relay attacks. In an authentication relay attack, a client that can perform NTLM authentication connects to an attacker-controlled system. The attacker uses the client's credentials to masquerade as the client and authenticate to a service (for example, an instance of the MSSQL Database Engine service or Active Directory Certificate Services). NTLM relay attacks are made simple due to the presence of won't-fix issues (e.g., Printerbug, PetitPotam) that allow an attacker to automatically force a computer to authenticate to an arbitrary location. These issues are present on current versions of Windows Server by default.

In another type of NTLM authentication relay technique called a spoofing attack, the client intends to connect to a valid service, but is unaware that one or both of DNS and IP routing are poisoned to redirect the connection to the attacker instead.

### Active Directory Certificate Services (AD CS)
You are potentially vulnerable to this attack if you are using Active Directory Certificate Services (AD CS) with either of the following services: 
- Certificate Authority Web Enrollment
- Certificate Enrollment Web Service

If your environment is potentially affected, please refer to the mitigation guidance from Microsoft [here](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)

### Site Databases
SQL Server supports service binding and channel binding to help reduce these attacks on SQL Server instances. 

#### Service Binding
Service binding addresses luring attacks by requiring a client to send a signed service principal name (SPN) of the SQL Server service that the client intends to connect to. As part of the authentication response, the service validates that the SPN received in the packet matches its own SPN. If a client is lured to connect to an attacker, the client will include the signed SPN of the attacker. The attacker cannot relay the packet to authenticate to the real SQL Server service as the client, because it would include the SPN of the attacker. Service binding incurs a one-time, negligible cost, but it does not address spoofing attacks. Service Binding occurs when a client application does not use encryption to connect to the SQL Server.

#### Channel Binding
Channel binding establishes a secure channel (Schannel) between a client and an instance of the SQL Server service. The service verifies the authenticity of the client by comparing the client's channel binding token (CBT) specific to that channel, with its own CBT. Channel binding addresses both luring and spoofing attacks. However, it incurs a larger runtime cost, because it requires Transport Layer Security (TLS) encryption of all the session traffic. Channel Binding occurs when a client application uses encryption to connect to the SQL Server, regardless of whether encryption is enforced by the client or by the server.

#### Configuration
On every site database server, including for every primary site and the central administration site (if using a CAS), open `Sql Server Configuration Manager`, expand `Sql Server Network Configuration`, right click `Protocols for MSSQLSERVER`, click `Properties`, navigate to the `Advanced` tab, then set `Extended Protection` to `Required`: 

<img width="683" alt="image" src="https://github.com/subat0mik/Misconfiguration-Manager/assets/30671833/85cbbb4d-53c8-4a7c-bc59-a93834e13145">

## Linked Defensive IDs
- [DETECT-1: Monitor site server domain computer accounts authenticating from another source](../../../defense-techniques/DETECT/DETECT-1/detect-1_description.md)
- [PREVENT-20: Block unnecessary connections to site systems](../../../defense-techniques/PREVENT/PREVENT-20/prevent-20_description.md)

## Associated Offensive IDs
- [TAKEOVER-1: NTLM coercion and relay to MSSQL on remote site database](../../../attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md)
- [TAKEOVER-3: NTLM coercion and relay to HTTP on AD CS](../../../attack-techniques/TAKEOVER/TAKEOVER-3/takeover-3_description.md)

## References
- Microsoft, [KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS)](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
- Microsoft, [Connect to the Database Engine with Extended Protection](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection)
