
<# 
    OneDrive Audit Script (Corrected)
    - Detects OneDrive accounts (Personal + Business)
    - Extracts account identity information
    - Retrieves cloud quota (Business registry or Personal INI)
    - Computes local replication size
    - Reports first sync date when available
    - Skips accounts with no SyncRoot to avoid null-path errors
#>

Write-Host "=== OneDrive Account Detection ==="

$baseReg = "HKCU:\Software\Microsoft\OneDrive\Accounts"
$accounts = Get-ChildItem $baseReg -ErrorAction SilentlyContinue

if (-not $accounts) {
    Write-Host "No OneDrive accounts found."
    return
}

$results = @()

foreach ($acct in $accounts) {

    $props = Get-ItemProperty $acct.PSPath

    $type        = $acct.PSChildName
    $displayName = $props.UserName
    $cid         = $props.CID
    $mount       = $props.UserFolder
    $tenantId    = $props.TenantID
    $orgName     = $props.DisplayName

    # Skip accounts with no sync root (prevents null-path errors)
    if ([string]::IsNullOrWhiteSpace($mount)) {
        Write-Host "Skipping account '$type' (no SyncRoot configured)."
        continue
    }

    # --- First Sync Date (from OneDrive metadata if available) ---
    $settingsPath = Join-Path $env:LOCALAPPDATA "Microsoft\OneDrive\settings\$type"
    $iniFile = Join-Path $settingsPath "$type.ini"

    $firstSync = $null
    if (Test-Path $iniFile) {
        $ini = Get-Content $iniFile
        $syncLine = $ini | Where-Object { $_ -match "^UserFolderCreationTime=" }
        if ($syncLine) {
            $raw = ($syncLine -split "=")[1]
            $firstSync = [DateTime]::FromFileTimeUtc([int64]$raw)
        }
    }

    $results += [PSCustomObject]@{
        AccountType   = $type
        UserName      = $displayName
        CID           = $cid
        TenantID      = $tenantId
        Organization  = $orgName
        SyncRoot      = $mount
        FirstSyncDate = $firstSync
    }
}

$results | Format-Table -AutoSize

# ============================================================
# === CLOUD STORAGE QUOTA DETECTION (Business or Personal) ===
# ============================================================

Write-Host "`n=== Cloud Storage Information ==="

$quotaFound = $false

# --- 1. OneDrive for Business (most reliable) ---
$businessKey = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"

if (Test-Path $businessKey) {
    try {
        $q = Get-ItemProperty -Path $businessKey -ErrorAction Stop

        if ($q.UserQuota -gt 0) {
            $totalCloud = [math]::Round($q.UserQuota / 1GB, 2)
            $usedCloud  = [math]::Round($q.UserUsedQuota / 1GB, 2)

            Write-Host "Cloud Total (Business): $totalCloud GB"
            Write-Host "Cloud Used  (Business): $usedCloud GB"

            $quotaFound = $true
        }
    }
    catch { }
}

# --- 2. OneDrive Personal (ClientPolicy.ini) ---
if (-not $quotaFound) {
    $policyPath = Join-Path $env:LOCALAPPDATA "Microsoft\OneDrive\settings\Personal\ClientPolicy.ini"

    if (Test-Path $policyPath) {
        $content = Get-Content $policyPath -ErrorAction SilentlyContinue

        $quotaLine = $content | Where-Object { $_ -match "^UserQuota=" }
        $usedLine  = $content | Where-Object { $_ -match "^UserUsedQuota=" }

        if ($quotaLine -and $usedLine) {
            $quotaValue = ($quotaLine -split "=")[1]
            $usedValue  = ($usedLine  -split "=")[1]

            $totalCloud = [math]::Round($quotaValue / 1GB, 2)
            $usedCloud  = [math]::Round($usedValue  / 1GB, 2)

            Write-Host "Cloud Total (Personal): $totalCloud GB"
            Write-Host "Cloud Used  (Personal): $usedCloud GB"

            $quotaFound = $true
        }
    }
}

# --- 3. If neither source worked ---
if (-not $quotaFound) {
    Write-Host "Cloud quota information not available for this account."
}

# =====================================
# === LOCAL REPLICATION CALCULATION ===
# =====================================

Write-Host "`n=== Local Replication Size ==="

foreach ($acct in $results) {

    $path = $acct.SyncRoot

    # Safety check (should never trigger now)
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-Host "Skipping null SyncRoot entry."
        continue
    }

    if (-not (Test-Path $path)) {
        Write-Host "Path not found: $path"
        continue
    }

    Write-Host "`nCalculating local size for: $path"

    $localBytes = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.Attributes -notmatch 'ReparsePoint' } |
        Measure-Object -Property Length -Sum

    $localGB = [math]::Round(($localBytes.Sum / 1GB), 2)

    Write-Host "Locally Replicated: $localGB GB"
}
