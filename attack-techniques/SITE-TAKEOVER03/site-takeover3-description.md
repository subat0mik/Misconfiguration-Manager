# Site Takeover via NTLM Coercion and MSSQL Relay in High Availability Configurations

## Code Name
SITETAKEOVER03

## ATT&CK TTPs
- Privilege Escalation

## Required Privilege / Context

Valid domain credentials with network connectivity to the active primary site server and passive primary site server.

## Summary
A passive site server is server role configuration available to add redundancy to SCCM sites where high availability for the site server role is required. A passive site server share's the same configuration as the active site server yet performs no writes or changes to the site until promoted manually or during an automated failover. By default, the passive site server machine account is required to be a local administrator on the active site server host. If SMB signing is disabled or not required, the 

## Impact

This technique may allow an attacker to coerce and relay authentication from a passive primary site server machine account to the SMB service of an active primary site server, compromise the site server's machine account, and elevate their privileges to "Full Administrator" via the Administration Service REST API. 

## Defensive IDs

## Examples

## References
Author, Title, URL