#Requires -RunAsAdministrator

# ***************************************************************************
# *  Script      : synthetic_runkey_test_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-16 07:23 EST
# *  Purpose     : Seeds (or removes) benign "Synthetic Test" entries across
# *                the same Run keys that asep_analyzer inspects, so you can
# *                confirm the analyzer detects them. Each entry is a registry
# *                value named "Synthetic Test <date time>" whose data is the
# *                path to Notepad.exe (harmless).
# *
# *  IMPORTANT   : Writes to HKLM autostart locations, so run ELEVATED. The
# *                Run/RunOnce entries point at Notepad and WILL launch it at
# *                the next logon if left in place - remove them when done.
# *
# *  Command-line options (exactly one required):
# *     -Add      Create one "Synthetic Test <timestamp>" value in every
# *               target Run key (and a RunOnceEx section subkey).
# *     -Remove   Search the same keys and delete every value whose name
# *               begins with "Synthetic Test", plus the RunOnceEx section
# *               this script creates.
# *     -WhatIf   Preview changes without writing. (-Confirm also supported.)
# * Copyright (c) 2026 Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Add,
    [switch]$Remove
)

# ---------------------------------------------------------------------------
# Require exactly one action.
# ---------------------------------------------------------------------------
if ($Add -and $Remove) {
    Write-Error "Specify only one of -Add or -Remove, not both."
    return
}
if (-not $Add -and -not $Remove) {
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\synthetic_runkey_test_V_01.ps1 -Add       # seed synthetic entries"
    Write-Host "  .\synthetic_runkey_test_V_01.ps1 -Remove    # remove them again"
    Write-Host "  (add -WhatIf to preview)"
    return
}

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
# Benign target: the value data is just the path to Notepad.exe.
$Notepad = Join-Path $env:SystemRoot 'System32\notepad.exe'

# Value-name prefix. -Remove matches "<prefix>*" so it catches entries from any
# previous -Add run regardless of the timestamp that follows.
$NamePrefix = 'Synthetic Test'

# Flat Run keys that accept ARBITRARY value names - these are exactly the keys
# the analyzer detects via its flat value read, so a synthetic value here is a
# valid detection test.
#
# NOTE - two keys the analyzer lists are deliberately EXCLUDED here:
#   HKLM\...\Session Manager\Environment  and  HKCU\Environment
# The analyzer only inspects the single fixed value 'UserInitMprLogonScript' in
# those keys, so an arbitrarily named "Synthetic Test" value would NOT be
# detected there - and writing stray values into the Environment keys is
# undesirable. They are left alone on purpose.
$flatRunKeys = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

# RunOnceEx base keys. RunOnceEx does not store commands as direct values; they
# live under numbered section subkeys. To keep cleanup unambiguous we write our
# value into a dedicated, clearly-owned section named 'SyntheticTest'. The
# analyzer enumerates ALL section subkeys, so it still detects it.
$runOnceExBases = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
)
$SyntheticSection = 'SyntheticTest'

# ===========================================================================
# ADD
# ===========================================================================
if ($Add) {
    $stamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $valueName = "$NamePrefix $stamp"

    Write-Host "[*] Adding synthetic entries: '$valueName' -> $Notepad" -ForegroundColor Yellow
    $added = 0

    # --- flat Run keys -----------------------------------------------------
    foreach ($path in $flatRunKeys) {
        $regPath = "Registry::$path"
        if ($PSCmdlet.ShouldProcess($path, "Add value '$valueName'")) {
            try {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                New-ItemProperty -Path $regPath -Name $valueName -Value $Notepad `
                    -PropertyType String -Force | Out-Null
                Write-Host "  [+] $path" -ForegroundColor Green
                $added++
            } catch {
                Write-Warning "  [!] Failed: $path - $($_.Exception.Message)"
            }
        }
    }

    # --- RunOnceEx (value written under our dedicated section subkey) -------
    foreach ($base in $runOnceExBases) {
        $sectionPath = "$base\$SyntheticSection"
        $regPath     = "Registry::$sectionPath"
        if ($PSCmdlet.ShouldProcess($sectionPath, "Add value '$valueName'")) {
            try {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                New-ItemProperty -Path $regPath -Name $valueName -Value $Notepad `
                    -PropertyType String -Force | Out-Null
                Write-Host "  [+] $sectionPath" -ForegroundColor Green
                $added++
            } catch {
                Write-Warning "  [!] Failed: $sectionPath - $($_.Exception.Message)"
            }
        }
    }

    Write-Host "[+] Added $added synthetic entries." -ForegroundColor Cyan
    Write-Host "    Run/RunOnce entries point to Notepad and may launch it at next logon." -ForegroundColor DarkGray
    Write-Host "    Remove when finished:  .\synthetic_runkey_test_V_01.ps1 -Remove" -ForegroundColor DarkGray
    return
}

# ===========================================================================
# REMOVE
# ===========================================================================
if ($Remove) {
    Write-Host "[*] Removing synthetic entries ('$NamePrefix *')..." -ForegroundColor Yellow
    $removed = 0

    # --- flat Run keys -----------------------------------------------------
    foreach ($path in $flatRunKeys) {
        $regPath = "Registry::$path"
        if (-not (Test-Path $regPath)) { continue }
        $key = Get-Item -Path $regPath -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        foreach ($valueName in @($key.Property)) {
            if ($valueName -like "$NamePrefix*") {
                if ($PSCmdlet.ShouldProcess("$path :: $valueName", "Remove value")) {
                    try {
                        Remove-ItemProperty -Path $regPath -Name $valueName -Force
                        Write-Host "  [-] $path :: $valueName" -ForegroundColor Green
                        $removed++
                    } catch {
                        Write-Warning "  [!] Failed: $path :: $valueName - $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    # --- RunOnceEx: sweep every section for matching values, then drop the
    #     dedicated 'SyntheticTest' section we create ------------------------
    foreach ($base in $runOnceExBases) {
        $baseReg = "Registry::$base"
        if (Test-Path $baseReg) {
            foreach ($section in (Get-ChildItem -Path $baseReg -ErrorAction SilentlyContinue)) {
                $sectionShort = "$base\$($section.PSChildName)"
                $sectionReg   = "Registry::$sectionShort"
                $sectionKey   = Get-Item -Path $sectionReg -ErrorAction SilentlyContinue
                if ($sectionKey) {
                    foreach ($valueName in @($sectionKey.Property)) {
                        if ($valueName -like "$NamePrefix*") {
                            if ($PSCmdlet.ShouldProcess("$sectionShort :: $valueName", "Remove value")) {
                                try {
                                    Remove-ItemProperty -Path $sectionReg -Name $valueName -Force
                                    Write-Host "  [-] $sectionShort :: $valueName" -ForegroundColor Green
                                    $removed++
                                } catch {
                                    Write-Warning "  [!] Failed: $sectionShort :: $valueName - $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
            }

            # Remove our owned section subkey outright (safe - we created it).
            $ourSectionReg = "Registry::$base\$SyntheticSection"
            if (Test-Path $ourSectionReg) {
                if ($PSCmdlet.ShouldProcess("$base\$SyntheticSection", "Remove section subkey")) {
                    try {
                        Remove-Item -Path $ourSectionReg -Recurse -Force
                        Write-Host "  [-] $base\$SyntheticSection (section removed)" -ForegroundColor Green
                    } catch {
                        Write-Warning "  [!] Failed to remove section: $base\$SyntheticSection - $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    Write-Host "[+] Removed $removed synthetic value(s)." -ForegroundColor Cyan
    return
}
