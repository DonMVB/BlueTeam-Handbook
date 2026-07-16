#Requires -RunAsAdministrator

# ***************************************************************************
# *  Script      : create_test_wmi_subscription_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-15 15:40 EST
# *  Purpose     : Creates (or removes) a single, deliberately harmless
# *                permanent WMI event subscription so you can verify that
# *                asep_analyzer detects the full __EventFilter /
# *                __EventConsumer / __FilterToConsumerBinding trio.
# *
# *  IMPORTANT   : This script uses the classic WMI cmdlets (Set-WmiInstance,
# *                Get-WmiObject, Remove-WmiObject). Those exist ONLY in
# *                Windows PowerShell 5.1 (powershell.exe) - NOT in
# *                PowerShell 7 (pwsh). Run this in powershell.exe, elevated.
# *
# *  Command-line options:
# *     (no switch)   Create the test subscription.
# *     -Remove       Delete the test subscription (filter, consumer, binding).
# *     -WhatIf       Show what would happen without making changes.
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Remove
)

# ---------------------------------------------------------------------------
# WHAT A PERMANENT WMI SUBSCRIPTION IS (and why we create three objects)
# ---------------------------------------------------------------------------
# A permanent WMI subscription is a classic persistence mechanism. It is made
# of THREE cooperating objects, all living in the root\subscription namespace:
#
#   1. __EventFilter             - the TRIGGER. A WQL query describing the
#                                  condition that should fire the action.
#   2. <consumer class>          - the ACTION. Here we use LogFileEventConsumer,
#                                  the most benign consumer: it just appends a
#                                  line of text to a file. (Real malware often
#                                  uses CommandLineEventConsumer or
#                                  ActiveScriptEventConsumer to run code.)
#   3. __FilterToConsumerBinding - the LINK that ties the filter to the
#                                  consumer and makes the pair ACTIVE.
#
# The analyzer must see all three and join them to report a real subscription.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONFIG - clearly-named test artifacts so they are easy to spot and remove
# ---------------------------------------------------------------------------
$Namespace    = 'root\subscription'
$FilterName   = 'ASEP_Test_Filter'
$ConsumerName = 'ASEP_Test_Consumer'
$LogFile      = Join-Path $env:TEMP 'ASEP_Test_WMI.log'

# The trigger query intentionally references an IMPOSSIBLE condition
# (a clock Hour of 25, which never occurs). The subscription therefore fully
# EXISTS - so the analyzer can enumerate it - but the consumer action will
# never actually fire. That keeps this test completely inert.
$FilterQuery  = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 " +
                "WHERE TargetInstance ISA 'Win32_LocalTime' " +
                "AND TargetInstance.Hour = 25"

# ---------------------------------------------------------------------------
# GUARD: make sure we are on Windows PowerShell 5.1, not PowerShell 7
# ---------------------------------------------------------------------------
if (-not (Get-Command Set-WmiInstance -ErrorAction SilentlyContinue)) {
    Write-Error ("The classic WMI cmdlets are not available in this host. " +
                 "Re-run this script in Windows PowerShell 5.1 (powershell.exe), elevated.")
    return
}

# ===========================================================================
# REMOVE MODE
# ===========================================================================
if ($Remove) {
    Write-Host "[*] Removing test WMI subscription ($FilterName / $ConsumerName)..." -ForegroundColor Yellow

    # Order does not strictly matter, but remove the binding first so nothing
    # is left "active" mid-cleanup, then the filter and the consumer.
    $binding = Get-WmiObject -Namespace $Namespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
               Where-Object { $_.Filter -match [regex]::Escape($FilterName) }
    if ($binding) {
        if ($PSCmdlet.ShouldProcess("__FilterToConsumerBinding for $FilterName", "Remove")) {
            $binding | Remove-WmiObject
            Write-Host "  [+] Removed binding" -ForegroundColor Green
        }
    } else {
        Write-Host "  [-] No matching binding found" -ForegroundColor Gray
    }

    $filter = Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue
    if ($filter) {
        if ($PSCmdlet.ShouldProcess("__EventFilter '$FilterName'", "Remove")) {
            $filter | Remove-WmiObject
            Write-Host "  [+] Removed filter" -ForegroundColor Green
        }
    } else {
        Write-Host "  [-] No matching filter found" -ForegroundColor Gray
    }

    $consumer = Get-WmiObject -Namespace $Namespace -Class LogFileEventConsumer -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue
    if ($consumer) {
        if ($PSCmdlet.ShouldProcess("LogFileEventConsumer '$ConsumerName'", "Remove")) {
            $consumer | Remove-WmiObject
            Write-Host "  [+] Removed consumer" -ForegroundColor Green
        }
    } else {
        Write-Host "  [-] No matching consumer found" -ForegroundColor Gray
    }

    Write-Host "[+] Cleanup complete." -ForegroundColor Cyan
    return
}

# ===========================================================================
# CREATE MODE
# ===========================================================================
Write-Host "[*] Creating test WMI subscription..." -ForegroundColor Yellow

# Refuse to stack duplicates if the test filter already exists.
$existing = Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warning "A filter named '$FilterName' already exists. Run with -Remove first if you want a clean re-create."
    return
}

if (-not $PSCmdlet.ShouldProcess("root\subscription", "Create test filter, consumer, and binding")) {
    return
}

# --- 1. The TRIGGER: __EventFilter -----------------------------------------
$Filter = Set-WmiInstance -Namespace $Namespace -Class __EventFilter -Arguments @{
    Name           = $FilterName
    EventNamespace = 'root\cimv2'   # namespace the WQL query runs against
    QueryLanguage  = 'WQL'
    Query          = $FilterQuery
}
Write-Host "  [+] Created __EventFilter        : $FilterName" -ForegroundColor Green

# --- 2. The ACTION: LogFileEventConsumer (benign - just writes text) -------
$Consumer = Set-WmiInstance -Namespace $Namespace -Class LogFileEventConsumer -Arguments @{
    Name     = $ConsumerName
    Filename = $LogFile
    Text     = 'ASEP test WMI subscription fired (this line should never appear).'
}
Write-Host "  [+] Created LogFileEventConsumer : $ConsumerName" -ForegroundColor Green

# --- 3. The LINK: __FilterToConsumerBinding --------------------------------
# Passing the WMI objects themselves lets the cmdlet fill in the reference
# paths (__RELPATH) that the binding stores for Filter and Consumer.
$null = Set-WmiInstance -Namespace $Namespace -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $Filter
    Consumer = $Consumer
}
Write-Host "  [+] Created __FilterToConsumerBinding (filter -> consumer)" -ForegroundColor Green

# --- Read back so you can confirm it is really there -----------------------
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow
Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='$FilterName'" |
    Select-Object Name, Query | Format-List
Get-WmiObject -Namespace $Namespace -Class LogFileEventConsumer -Filter "Name='$ConsumerName'" |
    Select-Object Name, Filename | Format-List

Write-Host "[+] Done. Now run asep_analyzer at -Level 3 to confirm it detects the pair." -ForegroundColor Cyan
Write-Host "    When finished testing, remove it with:" -ForegroundColor DarkGray
Write-Host "      .\create_test_wmi_subscription_V_01.ps1 -Remove" -ForegroundColor DarkGray
