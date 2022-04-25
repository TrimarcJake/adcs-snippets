# adcs-snippets
Just a bunch of code snippets to identify and remediate common Active Directory Certificate Services issues.

## Common Misconfigurations
### Common Misconfiguration #1: Insufficient Auditing
#### Check current configuration
```powershell
certutil -getreg CA\AuditFilter
````

If you receive a result like the following, auditing is not enabled:
```batch
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\horse-CA1-CA-1\AuditFilter:

  AuditFilter REG_DWORD = 0
CertUtil: -getreg command completed successfully.
```

#### Enable all auditing
```powershell
certutil –setreg CA\AuditFilter 127
net stop certsvc
net start certsvc
```

### Common Misconfiguration #2: Single-Tier Architecture
Wonderful guide by Pete Long on building a two-tier PKI: https://www.petenetlive.com/KB/Article/0001309

### Common Misconfiguration #3: Unsafe Ownership
#### Find Objects with Unsafe Owners
```powershell
$ADRoot = (Get-ADRootDSE).rootDomainNamingContext

$Safe_Owners = "Enterprise Admins|Domain Admins|Administrators"

$ADCS_Objects = Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *

$ADCS_Objects | Where-Object { $_.nTSecurityDescriptor.Owner -notmatch $Safe_Owners } | Format-Table Name,DistinguishedName
```

#### Reset Owner to "Domain Admins"
```powershell
$DNSRoot = (Get-ADDomain).DNSRoot
$StandardOwner = New-Object System.Security.Principal.NTAccount($DNSRoot, "Domain Admins")

$ADCS_Objects_BadOwner = $ADCS_Objects | Where-Object {
    $_.nTSecurityDescriptor.Owner -notmatch $Safe_Owners
}

$ADCS_Objects_BadOwner | ForEach-Object {
    $ObjectPath = "AD:$($_.DistinguishedName)"
    $ObjectCN = $_.CanonicalName
    $ACL = Get-Acl -Path $ObjectPath
    $ACL.SetOwner($StandardOwner)
    Set-ACL -Path $ObjectPath -AclObject $ACL
}
```
