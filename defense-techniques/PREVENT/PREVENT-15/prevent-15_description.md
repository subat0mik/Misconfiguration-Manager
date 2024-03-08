# PREVENT-15

## Description
Disable and change passwords of legacy NAAs/collection variables/task sequences in Active Directory

## Summary
The [network access account](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/accounts#network-access-account) (NAA) is a domain account that can be configured on the site server. Clients use the NAA to access and retrieve software from a distribution point but serves no other purpose on the client. The credentials are retrieved by clients as part of the Computer Policy. Once received by the client, the credentials are stored in the `CCM_NetworkAccessAccount` class in the `root\ccm\policy\Machine\ActualConfig` WMI namespace.

This technique may apply whether an NAA is currently configured [CRED-3](../CRED-3/cred-3_description.md) or not. Therefore, even if [CRED-3](../CRED-3/cred-3_description.md) is fruitless, there is still hope.

Data stored within WMI classes exists on disk in the CIM repository file located at `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`. Due to the [nuance](https://github.com/mandiant/flare-wmi/blob/master/python-cim/doc/data-recovery.md) of how WMI and CIM clean up these objects, they may be cleared from the database (as read from a WMI context) but still persist on disk in the CIM repository file.

Therefore, even if the NAA _account_ (not password) is changed, say from NAA1 to NAA2, the credentials for NAA1 may still reside on disk on every SCCM client.

In the scenario where a legacy, dedicated NAA was used, it is recommended to disable the account in Active Directory and change its password. In scenarios where a domain account serving other purposes was used as an NAA, it is crucial to rotate the account's password and ensure it is no longer used as an NAA.

The same prevention strategy applies to collection variables, which may include credentials in environment variables accessible to a specific device collection, and task sequences, which may include credentials to conduct actions in a certain context (e.g., software installation). These secrets are stored in the CIM repository on clients and as a result, may persist well beyond their removal from SCCM.


## Linked Defensive IDs
- [PREVENT-4: Enable Enhanced HTTP](../PREVENT-4/prevent-4_description.md)

## Associated Offensive IDs
- [CRED-4: Retrieve legacy secrets from the CIM repository](../../../attack-techniques/CRED/CRED-4/cred-4_description.md)

## References
- Duane Michael, The Phantom Credentials of SCCM: Why the NAA Won't Die, https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9