# PREVENT-17
## Description
Remove unnecessary privileges from accounts

## Summary
Certain SCCM accounts unintentionally inherit privileges such that they become highly overprivileged over time.

The canonical example of this is task sequence domain join account. When an account joins a computer to the domain, the account gains ownership over the computer. [Ownership](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#owns) allows the owner to modify the security description on the object, regardless of the explicit permissions in the object's DACL. Therefore, the account can modify the DACL on the object and grant itself any privilege (i.e., full control of the object).

When combined with [CRED-1](../../../attack-techniques/CRED/CRED-1/cred-1_description.md), this becomes extremely dangerous, as an attacker could potentially retrieve the task sequence domain join account credentials and takeover any computer it owns.

This can be abused to grant the account the ability to read LAPS passwords, perform Kerberos [resource-based constrained delegation](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html), and various other attacks.

At SpecterOps, we've seen this account have ownership over _hundreds of thousands_ of computers, including domain controllers.

We recommend auditing the permissions of the task sequence domain join account, and any other SCCM account as outlined in [PREVENT-10](../PREVENT-10/prevent-10_description.md). Remove computer ownership from the domain join account and assign it to the `Domain Admins` group.

We can use the following PowerShell script to:

1. Create  the necessary `System.Security.Principal.NTAccount` object for `SetOwner`
2. Enumerate all computers with a name like `win11*`
3. Iterate over each computer, creating an ACL variable for each
4. Set the owner on each ACL to the account specificed in `$user`

```
$user = New-Object System.Security.Principal.NTAccount("contoso\djoin")
Get-ADComputer -filter 'name -like "win11*"' |
foreach{
    $acl = Get-Acl -Path "AD:$($_.DistinguishedName)"
    $acl.SetOwner($user)
    Set-Acl -Path "AD:$($_.DistinguishedName)" $acl
    }
```

## Linked Defensive IDs
- [PREVENT-10: Enforce the principle of least privilege for accounts](../PREVENT-10/prevent-10_description.md)

## Associated Offensive IDs
- [CRED-1: Retrieve secrets from PXE boot media](../../../attack-techniques/CRED/CRED-1/cred-1_description.md)
- [CRED-2: Request computer policy and deobfuscate secrets](../../../attack-techniques/CRED/CRED-2/cred-2_description.md)
- [CRED-3: Dump currently deployed secrets via WMI](../../../attack-techniques/CRED/CRED-3/cred-3_description.md)
- [CRED-4: Retrieve legacy secrets from the CIM repository](../../../attack-techniques/CRED/CRED-4/cred-4_description.md)
- [CRED-5: Dump credentials from the site database](../../../attack-techniques/CRED/CRED-5/) 

## References
- Wolfgang Sommergut, Change the Owner of Computer Objects in Active Directory, https://4sysops.com/archives/change-the-owner-of-computer-objects-in-active-directory/
- Elad Shamir, Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory, https://eladshamir.com/2019/01/28/Wagging-the-Dog.html
