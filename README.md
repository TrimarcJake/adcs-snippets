# cheese-swiss-snippets
Just a bunch of code snippets to identify and remediate common Active Directory Certificate Services issues.

## Common Misconfiguration #1: Insufficient Auditing
### Check current configuration
````
certutil -getreg CA\AuditFilter
````
### Enable all auditing
````
certutil –setreg CA\AuditFilter 127
net stop certsvc
net start certsvc
````
## Common Misconfiguration #3: Unsafe Ownership
```
$ADRoot = (Get-ADRootDSE).rootDomainNamingContext
$Safe_Owners = "Enterprise Admins|Domain Admins|Administrators"

$ADCS_Objects = Get-ADObject -Filter * -SearchBase 
	"CN=Public Key Services,CN=Services,CN=Configuration,$ADRoot"
    -SearchScope 2 -Properties *

$ADCS_Objects | Where-Object {
    $_.nTSecurityDescriptor.Owner -notmatch $Safe_Owners } |
    Format-Table Name,DistinguishedName
}
```
