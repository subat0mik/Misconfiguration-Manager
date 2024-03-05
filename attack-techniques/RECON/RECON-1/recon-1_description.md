# RECON-1
## Description
Enumerating LDAP for SCCM Related Assets

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements

Valid Active Directory domain credentials

## Summary

When designing a SCCM hierarchy, an optional, however very common, configuration step is to configure Active Directory for publishing SCCM information. This process involves [extending](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/network/schema-extensions) the Active Directory (AD) schema to include new attributes and classes. The `System Management` container is added within the `System` container and is used to house all data published to the domain. SCCM publishes information for clients such as providing a record to query for the client's default management point for DNS resolution.

The following attributes and classes are added to the schema:

| Attributes | Classes |
|----------|-------------|
|cn=mS-SMS-Assignment-Site-Code| cn=MS-SMS-Management-Point|
|cn=mS-SMS-Capabilities| cn=MS-SMS-Roaming-Boundary-Range
|cn=MS-SMS-Default-MP|cn=MS-SMS-Server-Locator-Point
|cn=mS-SMS-Device-Management-Point|cn=MS-SMS-Site
|cn=mS-SMS-Health-State|
|cn=MS-SMS-MP-Address|
|cn=MS-SMS-MP-Name|
|cn=MS-SMS-Ranged-IP-High|
|cn=MS-SMS-Ranged-IP-Low|
|cn=MS-SMS-Roaming-Boundaries|
|cn=MS-SMS-Site-Boundaries|
|cn=MS-SMS-Site-Code|
|cn=mS-SMS-Source-Forest|
|cn=mS-SMS-Version


While not every site system role is published to AD, there is still plenty of information to be gathered to identify infrastructure. 

### System Management Container

First, the existence of the manually created `System Management` container indicates SCCM is, or was, installed in the domain. Second, to allow SCCM to publish site data to the  container,  all site servers in the domain are required to have FULL CONTROL permissions for the container. Querying for the container itself and then resolving the principals granted Full Control permissions can identify potential site servers.

### cn=MS-SMS-Site

For each individual site published to AD an `mSSMSSite` class is published. This class provides the opportunity to identify how many individual sites may be published to a domain using the following attributes.

|Attribute| Notes|
|---------|------|
|mSSMSSiteCode|Each site's unique three character site code|
|mSSMSSourceForest| The originating forest for the site|


### cn=MS-SMS-Management-Point

The mSMSManagementPoint class is used by SCCM to publish details for SCCM clients to identify their respective default management point (MP)(cn=MS-SMS-Management-Point). This class provides the opportunity to identify potential attack paths in NAASPOOFTAKEVER, TAKEOVER06, TAKEOVER07 using the following attributes.

|Attribute|Notes|
|---------|-----|
|dNSHostName|The DNS hostanme for the MP's host operating system|
|msSMSSiteCode|The site the MP is a member of|


### Predictable Naming Conventions

We (SpecterOps) frequently observe predictable naming conventions in use to help system administrators identify and organize SCCM related assets. We've observed security groups, organizational units, usernames, and group policy objects using strings such as "SCCM" or "MECM" to identify their purpose. Consequently, a broader, recursive search for principals that contain these strings can help identify site system roles that are not published to AD via extenson of the schema. In some cases, we have observed the specific role for the user group or site system included in the hostname. For example:

- "sccmadmins" for a security group that contained all SCCM administrative users
- "sccm site servers" for a security group that contained all SCCM site systems in the domain
- "SCCMDP1" for a SCCM site system configured with the distribution point role


## Impact

1. Identifying the presence of site server systems is typically the first step in building potential attack paths
2. A resolved MP site system role can be abused to spoof SCCM client enrollment and potentially recover credentials
3. A resolved MP site system role can be used to elevate privileges via credential relay attacks
4. All SCCM sites require at least one MP role except for central administration sites (CAS) which [do not](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites#BKMK_ChooseCAS) support roles that interact with clients. However, the CAS site code is still published via the `mSSMSSite` class. Additionally, the CAS primary site server requires FULL CONTROL for the `System Management` container for publish purposes. Therefore, a query for all published site codes in a domain can be used to identify the CAS primary site server by elimintating site codes that have a published MP. Knowlege of the CAS can be used to perform credential relay attacks to elevate privileges in the domain or for the SCCM service
5. Predictble naming conventions help identify high value targets associated with the SCCM service that are not to AD


## Defensive IDs
- [DETECT-2: Monitor read property access to the System Management container within Active Directory Users and Computers](../../../defense-techniques/DETECT/DETECT-2/detect-2_description.md)

## Examples

## References
Author, Title, URL