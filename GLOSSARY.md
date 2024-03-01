# Glossary
Familiarity with the terms and concepts presented on this page are required for understanding the various attack and defense techniques covered in this repository.

## Allow connection fallback to NTLM
A client push installation setting that allows the server to attempt NTLM authentication when Kerberos authentication fails. This option is enabled by default.

Beginning with Configuration Manager current branch, version 2207, the “Allow connection fallback to NTLM” option is disabled by default on new site installations. Hotfix KB15599094 must be applied to existing installations for the “Allow connection fallback to NTLM” setting to prevent NTLM connections from occurring when disabled.

## Automatic Site-wide Client Push Installation
When automatic site assignment and this setting are enabled, the site automatically tries client push installation on any computers it discovers within a boundary group. This option is not enabled by default.

## Automatic Site Assignment
A setting that automatically assigns systems discovered in a specific boundary group to a specific site (e.g., all systems discovered in AD domain X are automatically assigned to site Y). This setting must be configured by the SCCM admin to enable automatic site-wide client push installation.

## Boundary Group
Network locations (e.g., IP subnets/address ranges, Active Directory sites) that include client systems managed by the site

## Central Administration Site (CAS)
An optional top-level site that can be used to manage multiple primary sites

## Client/Device
SCCM clients are systems that are joined to, managed by, and receive content from an SCCM site

## Client Push Installation
A method for deploying the SCCM client software where the site server connects to a machine’s ADMIN$ share, copies over the files needed for installation, and executes the installer (ccmsetup.exe). By default, this connection occurs over SMB, but can occur over HTTP if WebClient is enabled on the site server and the target machine’s NetBIOS name is set to a value that specifies a port number (e.g., machine@8080).

## Client Push Installation Accounts
The list of accounts that the site server tries to authenticate with to install the client. By default, if none of the configured accounts can successfully authenticate, or if no accounts are configured, the site server attempts to authenticate with its machine account.

## ConfigMgr Console
The software that administrators use to manage a site

## Discovery Methods
Configurable methods the site uses to discover computers

## Hierarchy
All of the sites in one instance of SCCM

## Management Point
A site system that receives client configuration data, forwards it to the site server to be processed, and responds to client requests for policy and service locations

## Passive Site Server
A failover primary site server used for redundancy in high availability configurations

## Primary Site
A site that clients are assigned to and that is administered using the Configuration Manager console

## Primary Site Server
The server responsible for processing client-generated data and interacting with the site database. Also referred to as the site server. Note that the central administration site has its own primary site server, so takeovers and other attack primitives in this knowledge base that are applicable to primary site servers are also applicable to the central administration site server.

## Registration Request
A message sent to the management point to register a new client with the site

## SCCM
A client-server solution commonly used to deploy software and updates to Windows systems, currently named Microsoft Configuration Manager (ConfigMgr, Config Man, or MCM), but formerly:
- Microsoft Endpoint Configuration Manager (MECM)
- Microsoft Endpoint Manager Configuration Manager (MEMCM)
- System Center Configuration Manager (SCCM)
- Systems Management Server (SMS)

## Secondary Site
A child of a primary site used to distribute content to clients in remote locations with low bandwidth connections

## Security Role
A set of permissions applied to admin users to control access to SCCM objects (e.g., sites, device collections) and actions (e.g., read, modify, deploy)

## Security Scope
A container of objects to which a security role can be granted access (e.g., an admin is granted the permissions in security role A to the objects added to security scope B)

## Site
The SCCM site consists of the various systems that compose the SCCM environment. Each site is identified by a three character site code (e.g., PS1).

## Site Database
A required site system role for central administration sites, primary sites, and secondary sites that stores and processes data. This database is fully replicated between CAS sites and primary sites and partially replicated to secondary sites.

## Site Database Server
Hosts the site database for a site, can be colocated on the site server or hosted on a remote system

## Site System
A computer that is assigned one or more site system roles in the site.

## Site System Role
A role installed on a site system to host functionality for a site (e.g., site server, site database, distribution point)

## SMS Provider
A site system with Windows Management Instrumentation (WMI) and HTTPS REST API providers that allow indirect access to the site database. This role is installed on the primary site server by default but can also be installed elsewhere.