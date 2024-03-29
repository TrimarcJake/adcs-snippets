# adcs-snippets
Just a bunch of code snippets to identify and remediate common Active Directory Certificate Services issues.

## Common Misconfiguration #1: Insufficient Auditing
### Check current configuration
```powershell
certutil -getreg CA\AuditFilter
````

If you receive a result like the following, auditing is not enabled:
```batch
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\horse-CA1-CA-1\AuditFilter:

  AuditFilter REG_DWORD = 0
CertUtil: -getreg command completed successfully.
```

### Enable all auditing
```powershell
certutil –setreg CA\AuditFilter 127
net stop certsvc
net start certsvc
```

Notes:
  - These snippets must be run on each CA host individually.
  - Fully enabling auditing requires 2 additional GPO settings to be configured.

## Common Misconfiguration #2: Single-Tier Architecture
Wonderful guide by Pete Long on building a two-tier PKI: https://www.petenetlive.com/KB/Article/0001309

## Common Misconfiguration #3: Unsafe Ownership
### Find Objects with Unsafe Owners
```powershell
$ADRoot = (Get-ADRootDSE).rootDomainNamingContext

$Safe_Owners = "Enterprise Admins|Domain Admins|Administrators"

$ADCS_Objects = Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot" -SearchScope 2 -Properties *

$ADCS_Objects | Where-Object {
    $_.nTSecurityDescriptor.Owner -notmatch $Safe_Owners
} | Format-Table Name,DistinguishedName
```

### Reset Owner to "Enterprise Admins"
```powershell
$DNSRoot = (Get-ADDomain).DNSRoot
$StandardOwner = New-Object System.Security.Principal.NTAccount($DNSRoot, "Enterprise Admins")

$ADCS_Objects_BadOwner = $ADCS_Objects | Where-Object {
    $_.nTSecurityDescriptor.Owner -notmatch $Safe_Owners
}

$ADCS_Objects_BadOwner | ForEach-Object {
    $ObjectPath = "AD:$($_.DistinguishedName)"
    $ACL = Get-Acl -Path $ObjectPath
    $ACL.SetOwner($StandardOwner)
    Set-ACL -Path $ObjectPath -AclObject $ACL
}
```

## Dangerous Misconfiguration #1: Unsafe ACLs
### Find Objects with Dangerous ACLs
```powershell
$Safe_Users = "Domain Admins|Enterprise Admins BUILTIN\\Administrators NT AUTHORITY\\SYSTEM|$env:userdomain\\Cert Publishers|$env:userdomain\\Administrator"

$DangerousRights = "GenericAll|WriteDacl|WriteOwner"

foreach ( $object in $ADCS_Objects ) {
    $BadACE = $object.nTSecurityDescriptor.Access | Where-Object {
        ( $.IdentityReference -notmatch $Safe_Users ) -and ( $_.ActiveDirectoryRights -match $DangerousRights )
    }
    if ( $BadACE ) {
        Write-Host "Object: $object" -ForegroundColor Red
        $BadACE
    }
}
```
*Note: This snippet is very simple will likely return some false positives. CAs, PKI Admin users/groups, and other safe entities may end up in the results. This list should be a starting point for future investigation.*

## Dangerous Misconfiguration #2: Templates with Bad Configs
### Find Templates with Bad Configs
```powershell
$ClientAuthEKUs = "1\.3\.6\.1\.5\.5\.7\.3\.2|
    1\.3\.6\.1\.5\.2\.3\.4|
    1\.3\.6\.1\.4\.1\.311\.20\.2\.2|
    2\.5\.29\.37\.0"
    
$ADCS_Objects | Where-Object {
    ($_.ObjectClass -eq "pKICertificateTemplate") -and
    ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
    ($_."msPKI-Certificate-Name-Flag" -band 1) -and
    !($_.'msPKI-Enrollment-Flag' -band 2) -and
    ( ($_."msPKI-RA-Signature" -eq 0) -or ($null -eq $_."msPKI-RA-Signature") )
} | Format-Table Name,DistinguishedName
```

### Fix #1 for Templates with Bad Configs - Remove Ability to Set a SAN
```powershell
$ADCS_Objects_BadConfig = $ADCS_Objects | Where-Object {
    ($_.ObjectClass -eq "pKICertificateTemplate") -and
    ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
    ($_."msPKI-Certificate-Name-Flag" -band 1) -and
    !($_.'msPKI-Enrollment-Flag' -band 2) -and
    ( ($_."msPKI-RA-Signature" -eq 0) -or ($null -eq $_."msPKI-RA-Signature") )
}

$ADCS_Objects_BadConfig | ForEach-Object {
    $_."msPKI-Certificate-Name-Flag" = 0
}
```

### Fix #2 for Templates with Bad Configs - Require Manager Approval (generally less impactful)
```powershell
$ADCS_Objects_BadConfig = $ADCS_Objects | Where-Object {
    ($_.ObjectClass -eq "pKICertificateTemplate") -and
    ($_.pkiExtendedKeyUsage -match $ClientAuthEKUs) -and
    ($_."msPKI-Certificate-Name-Flag" -band 1) -and
    !($_.'msPKI-Enrollment-Flag' -band 2) -and
    ( ($_."msPKI-RA-Signature" -eq 0) -or ($null -eq $_."msPKI-RA-Signature") )
}

$ADCS_Objects_BadConfig | ForEach-Object {
    $_."msPKI-Enrollment-Flag" = 2
}
```

## Dangerous Misconfiguration #3: Dangerous Flag on CA
### Check if the Flag is Set
```powershell
certutil -getreg policy\EditFlags
```

### Unset the Dangerous Flag
```powershell
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
