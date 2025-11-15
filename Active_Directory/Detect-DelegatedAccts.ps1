# Script: Detect Delegated Administrative Access Accounts
# Purpose: Identifies accounts with various forms of administrative delegation in Active Directory
# Requires: Domain Admin or equivalent read permissions
# Note: If you have nexted groups in the PrivilegedGroups list, include them. If you use
# other group names for the traditional function for these groups add that as well. 

Import-Module ActiveDirectory

Write-Host "=== Active Directory Administrative Delegation Detection ===" -ForegroundColor Cyan
Write-Host "Scanning for accounts with elevated privileges and delegations...`n" -ForegroundColor Cyan

$Results = @()

# Part 1: Built-in Privileged Groups
Write-Host "[1] Checking Built-in Privileged Group Memberships..." -ForegroundColor Green

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners"
)

foreach ($Group in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue | 
            Where-Object {$_.objectClass -eq 'user'}
        
        if ($Members) {
            Write-Host "  [!] $Group ($($Members.Count) members):" -ForegroundColor Yellow
            foreach ($Member in $Members) {
                $User = Get-ADUser -Identity $Member -Properties Enabled, LastLogonDate, PasswordLastSet
                Write-Host "    - $($User.SamAccountName) (Enabled: $($User.Enabled), Last Logon: $($User.LastLogonDate))" -ForegroundColor White
                
                $Results += [PSCustomObject]@{
                    AccountName = $User.SamAccountName
                    DistinguishedName = $User.DistinguishedName
                    DelegationType = "Privileged Group Membership"
                    Details = $Group
                    Enabled = $User.Enabled
                    LastLogon = $User.LastLogonDate
                    PasswordLastSet = $User.PasswordLastSet
                }
            }
        }
    } catch {
        Write-Host "  [-] Could not query group: $Group" -ForegroundColor Red
    }
}

# Part 2: AdminCount Attribute (Protected Admin Accounts)
Write-Host "`n[2] Checking for Accounts with AdminCount=1..." -ForegroundColor Green

$AdminCountUsers = Get-ADUser -Filter {AdminCount -eq 1 -and Enabled -eq $true} -Properties AdminCount, LastLogonDate, PasswordLastSet, MemberOf

if ($AdminCountUsers) {
    Write-Host "  [!] Found $($AdminCountUsers.Count) enabled accounts with AdminCount=1:" -ForegroundColor Yellow
    foreach ($User in $AdminCountUsers) {
        Write-Host "    - $($User.SamAccountName) (Last Logon: $($User.LastLogonDate))" -ForegroundColor White
        
        $Results += [PSCustomObject]@{
            AccountName = $User.SamAccountName
            DistinguishedName = $User.DistinguishedName
            DelegationType = "AdminCount Protected"
            Details = "AdminCount=1 (Protected Admin Object)"
            Enabled = $User.Enabled
            LastLogon = $User.LastLogonDate
            PasswordLastSet = $User.PasswordLastSet
        }
    }
} else {
    Write-Host "  [+] No additional accounts with AdminCount=1 found" -ForegroundColor Green
}

# Part 3: Accounts with Kerberos Delegation
Write-Host "`n[3] Checking for Kerberos Delegation..." -ForegroundColor Green

# Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
$UnconstrainedDelegation = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, LastLogonDate, PasswordLastSet

if ($UnconstrainedDelegation) {
    Write-Host "  [!] Found $($UnconstrainedDelegation.Count) accounts with UNCONSTRAINED delegation:" -ForegroundColor Red
    foreach ($User in $UnconstrainedDelegation) {
        Write-Host "    - $($User.SamAccountName) - HIGH RISK!" -ForegroundColor Red
        
        $Results += [PSCustomObject]@{
            AccountName = $User.SamAccountName
            DistinguishedName = $User.DistinguishedName
            DelegationType = "Kerberos Unconstrained Delegation"
            Details = "TRUSTED_FOR_DELEGATION - HIGH RISK"
            Enabled = $User.Enabled
            LastLogon = $User.LastLogonDate
            PasswordLastSet = $User.PasswordLastSet
        }
    }
} else {
    Write-Host "  [+] No user accounts with unconstrained delegation found" -ForegroundColor Green
}

# Constrained Delegation
$ConstrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo, LastLogonDate, PasswordLastSet

if ($ConstrainedDelegation) {
    Write-Host "  [!] Found $($ConstrainedDelegation.Count) accounts with CONSTRAINED delegation:" -ForegroundColor Yellow
    foreach ($User in $ConstrainedDelegation) {
        $DelegatedServices = $User.'msDS-AllowedToDelegateTo' -join ', '
        Write-Host "    - $($User.SamAccountName)" -ForegroundColor White
        Write-Host "      Delegated to: $DelegatedServices" -ForegroundColor Gray
        
        $Results += [PSCustomObject]@{
            AccountName = $User.SamAccountName
            DistinguishedName = $User.DistinguishedName
            DelegationType = "Kerberos Constrained Delegation"
            Details = "Delegated to: $DelegatedServices"
            Enabled = $User.Enabled
            LastLogon = $User.LastLogonDate
            PasswordLastSet = $User.PasswordLastSet
        }
    }
} else {
    Write-Host "  [+] No user accounts with constrained delegation found" -ForegroundColor Green
}

# Resource-Based Constrained Delegation
$RBCDAccounts = Get-ADUser -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | 
    Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}

if ($RBCDAccounts) {
    Write-Host "  [!] Found $($RBCDAccounts.Count) accounts with RESOURCE-BASED constrained delegation:" -ForegroundColor Yellow
    foreach ($User in $RBCDAccounts) {
        Write-Host "    - $($User.SamAccountName)" -ForegroundColor White
        
        $Results += [PSCustomObject]@{
            AccountName = $User.SamAccountName
            DistinguishedName = $User.DistinguishedName
            DelegationType = "Resource-Based Constrained Delegation"
            Details = "msDS-AllowedToActOnBehalfOfOtherIdentity set"
            Enabled = $User.Enabled
            LastLogon = $User.LastLogonDate
            PasswordLastSet = $User.PasswordLastSet
        }
    }
}

# Part 4: Accounts with Extended Rights
Write-Host "`n[4] Checking for Dangerous Extended Rights Delegation..." -ForegroundColor Green

try {
    $Domain = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName
    $RootDSE = Get-ADRootDSE
    
    # Get ACL on domain root
    $DomainACL = Get-ACL -Path "AD:\$DomainDN"
    
    # Check for DCSync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
    $DCSyncRights = $DomainACL.Access | Where-Object {
        ($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or  # DS-Replication-Get-Changes
         $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or  # DS-Replication-Get-Changes-All
         $_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c') -and # DS-Replication-Get-Changes-In-Filtered-Set
        $_.ActiveDirectoryRights -match 'ExtendedRight' -and
        $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN|S-1-5-32'
    }
    
    if ($DCSyncRights) {
        Write-Host "  [!] Found accounts/groups with DCSync rights (HIGH RISK):" -ForegroundColor Red
        $DCSyncRights | Select-Object IdentityReference, ActiveDirectoryRights -Unique | ForEach-Object {
            Write-Host "    - $($_.IdentityReference) - Can perform DCSync attack!" -ForegroundColor Red
            
            # Try to resolve the identity to user accounts
            try {
                $Identity = $_.IdentityReference.Value.Split('\')[-1]
                $Object = Get-ADObject -Filter {Name -eq $Identity} -Properties objectClass
                
                if ($Object.objectClass -eq 'group') {
                    $GroupMembers = Get-ADGroupMember -Identity $Identity -Recursive | Where-Object {$_.objectClass -eq 'user'}
                    foreach ($Member in $GroupMembers) {
                        $Results += [PSCustomObject]@{
                            AccountName = $Member.SamAccountName
                            DistinguishedName = $Member.DistinguishedName
                            DelegationType = "DCSync Rights"
                            Details = "Via group: $Identity"
                            Enabled = "Unknown"
                            LastLogon = "Unknown"
                            PasswordLastSet = "Unknown"
                        }
                    }
                }
            } catch {
                # Identity might be a group or external
            }
        }
    } else {
        Write-Host "  [+] No unusual DCSync permissions found" -ForegroundColor Green
    }
    
} catch {
    Write-Host "  [-] Error checking extended rights: $($_.Exception.Message)" -ForegroundColor Red
}

# Part 5: Accounts in Protected Users Group
Write-Host "`n[5] Checking Protected Users Group..." -ForegroundColor Green

try {
    $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
    if ($ProtectedUsers) {
        Write-Host "  [+] Found $($ProtectedUsers.Count) accounts in Protected Users group (good):" -ForegroundColor Green
        foreach ($User in $ProtectedUsers) {
            Write-Host "    - $($User.SamAccountName)" -ForegroundColor White
        }
    } else {
        Write-Host "  [!] No accounts in Protected Users group - consider adding high-value accounts" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [-] Could not query Protected Users group" -ForegroundColor Red
}

# Part 6: Service Accounts with High Privileges
Write-Host "`n[6] Checking for Service Accounts with Administrative Access..." -ForegroundColor Green

$ServiceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalNames, MemberOf, LastLogonDate, PasswordLastSet, AdminCount

$PrivilegedServiceAccounts = $ServiceAccounts | Where-Object {
    $_.AdminCount -eq 1 -or 
    ($_.MemberOf -match "Domain Admins|Enterprise Admins|Administrators")
}

if ($PrivilegedServiceAccounts) {
    Write-Host "  [!] Found $($PrivilegedServiceAccounts.Count) service accounts with administrative privileges:" -ForegroundColor Red
    foreach ($Account in $PrivilegedServiceAccounts) {
        Write-Host "    - $($Account.SamAccountName) - SERVICE ACCOUNT WITH ADMIN RIGHTS!" -ForegroundColor Red
        Write-Host "      SPNs: $($Account.ServicePrincipalNames -join ', ')" -ForegroundColor Gray
        
        $Results += [PSCustomObject]@{
            AccountName = $Account.SamAccountName
            DistinguishedName = $Account.DistinguishedName
            DelegationType = "Privileged Service Account"
            Details = "Service account with admin rights - HIGH RISK"
            Enabled = $Account.Enabled
            LastLogon = $Account.LastLogonDate
            PasswordLastSet = $Account.PasswordLastSet
        }
    }
} else {
    Write-Host "  [+] No service accounts with direct administrative privileges found" -ForegroundColor Green
}

# Summary Report
Write-Host "`n=== Summary Report ===" -ForegroundColor Cyan
Write-Host "Total delegated/privileged accounts found: $($Results.Count)" -ForegroundColor Yellow

if ($Results.Count -gt 0) {
    Write-Host "`nExporting results to CSV..." -ForegroundColor Green
    $Results | Export-Csv -Path ".\AD_Delegated_Admin_Accounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
    Write-Host "[+] Results exported to: .\AD_Delegated_Admin_Accounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -ForegroundColor Green
    
    # Display summary table
    Write-Host "`nDelegation Type Summary:" -ForegroundColor Cyan
    $Results | Group-Object DelegationType | Select-Object Name, Count | Format-Table -AutoSize
}

# Recommendations
Write-Host "`n=== Security Recommendations ===" -ForegroundColor Cyan
Write-Host "  • Review all accounts with AdminCount=1 and remove from privileged groups if no longer needed"
Write-Host "  • Eliminate unconstrained delegation wherever possible (high risk for golden ticket attacks)"
Write-Host "  • Audit accounts with DCSync rights - only DCs should have these permissions"
Write-Host "  • Service accounts should NEVER be in Domain Admins or other privileged groups"
Write-Host "  • Add high-value admin accounts to the Protected Users group"
Write-Host "  • Implement tiered administration model to limit privilege scope"
Write-Host "  • Regular audit privileged access (at least monthly)"
Write-Host "  • Enable advanced auditing for sensitive privilege use"

Write-Host "`n=== Scan Complete ===" -ForegroundColor Cyan
