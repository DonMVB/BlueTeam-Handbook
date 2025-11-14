# Requires Active Directory PowerShell module
Import-Module ActiveDirectory -ErrorAction Stop

# Get the domain Distinguished Name
$domainDN = (Get-ADDomain).DistinguishedName

# Get the ACL for the domain root
$acl = Get-Acl -Path "AD:$domainDN"

# Define the GUIDs for the three DCSync-related extended rights
$rightsGUIDs = @{
    'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
}

# Set to $true to expand group memberships
$expandGroups = $true

# Array to store results
$results = @()

# Process each ACE in the ACL
foreach ($ace in $acl.Access) {
    # Skip deny ACEs
    if ($ace.AccessControlType -eq 'Deny') { continue }
    
    # Check if the ACE grants any of the DCSync permissions
    foreach ($rightName in $rightsGUIDs.Keys) {
        $rightGUID = [GUID]$rightsGUIDs[$rightName]
        
        if ($ace.ObjectType -eq $rightGUID) {
            # Try to resolve the identity
            try {
                $identity = $ace.IdentityReference.Value
                
                # Try to get the AD object details
                try {
                    $sidString = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $adObject = Get-ADObject -Filter "objectSID -eq '$sidString'" -Properties Name, objectClass, SAMAccountName -ErrorAction SilentlyContinue
                    
                    if ($adObject) {
                        $accountName = if ($adObject.SAMAccountName) { $adObject.SAMAccountName } else { $adObject.Name }
                        $accountType = $adObject.objectClass
                        
                        # Add the direct ACL entry
                        $results += [PSCustomObject]@{
                            Account = $accountName
                            AccountType = $accountType
                            Permission = $rightName
                            Source = "Direct ACL"
                            IsInherited = $ace.IsInherited
                        }
                        
                        # If it's a group and expandGroups is enabled, get members
                        if ($expandGroups -and $accountType -eq 'group') {
                            try {
                                $members = Get-ADGroupMember -Identity $adObject.DistinguishedName -Recursive -ErrorAction SilentlyContinue
                                foreach ($member in $members) {
                                    $results += [PSCustomObject]@{
                                        Account = $member.SamAccountName
                                        AccountType = $member.objectClass
                                        Permission = $rightName
                                        Source = "Via group: $accountName"
                                        IsInherited = $ace.IsInherited
                                    }
                                }
                            } catch {
                                # Group might be empty or inaccessible
                            }
                        }
                    } else {
                        $results += [PSCustomObject]@{
                            Account = $identity
                            AccountType = "Unknown"
                            Permission = $rightName
                            Source = "Direct ACL"
                            IsInherited = $ace.IsInherited
                        }
                    }
                } catch {
                    $results += [PSCustomObject]@{
                        Account = $identity
                        AccountType = "Unknown"
                        Permission = $rightName
                        Source = "Direct ACL"
                        IsInherited = $ace.IsInherited
                    }
                }
            } catch {
                # If resolution fails, use the raw identity
                $results += [PSCustomObject]@{
                    Account = $ace.IdentityReference.Value
                    AccountType = "Unknown"
                    Permission = $rightName
                    Source = "Direct ACL"
                    IsInherited = $ace.IsInherited
                }
            }
        }
    }
}

# Display results
if ($results.Count -gt 0) {
    Write-Host "`n=== Accounts with DCSync Permissions ===`n" -ForegroundColor Cyan
    $results | Sort-Object Source, Account, Permission | Format-Table Account, AccountType, Permission, Source -AutoSize
    
    $directCount = ($results | Where-Object {$_.Source -eq "Direct ACL"} | Select-Object -Unique Account | Measure-Object).Count
    $totalCount = ($results | Select-Object -Unique Account | Measure-Object).Count
    
    Write-Host "`nDirect ACL entries: $directCount" -ForegroundColor Yellow
    Write-Host "Total unique accounts (including group members): $totalCount" -ForegroundColor Yellow
} else {
    Write-Host "No DCSync permissions found." -ForegroundColor Green
}
