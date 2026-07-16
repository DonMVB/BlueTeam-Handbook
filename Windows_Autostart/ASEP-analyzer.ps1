#Requires -Version 3.0

# ***************************************************************************
# *  Script      : asep_analyzer_2_0.ps1
# *  Version     : 2.0
# *  Last Update : 2026-07-16 08:09 EST
# *  Purpose     : Windows Auto Start Extensibility Points (ASEP) Analyzer.
# *                Command-line options are documented in the .SYNOPSIS /
# *                param() block immediately below (OutputPath, ExportFormat,
# *                Level, PassThru).
# *
# *  v2.0 change : Added Winsock provider collection (Get-WinsockLSP) as a
# *                distinct category from Network Providers. Get-NetworkProviders
# *                only reads the NetworkProvider ProviderOrder precedence list.
# *                Layered Service Providers and name-space providers - the
# *                actual Winsock injection point Autoruns tracks in its
# *                "Winsock Providers" tab - live under the WinSock2 catalog
# *                and were previously not collected at all. Now both the
# *                Protocol_Catalog9 (protocol / LSP chain) entries and the
# *                NameSpace_Catalog5 (name-space provider) entries are parsed.
# ***************************************************************************

<#
.SYNOPSIS
Windows Auto Start Extensibility Points (ASEP) Analyzer

.DESCRIPTION
Examines Windows 10/11 systems for Auto Start Extensibility Points.
Supports three analysis levels:
  Level 1 - Run keys, scheduled tasks, services
  Level 2 - Level 1 plus startup folders and Winlogon entries
  Level 3 - Full analysis (all ASEP categories)

.PARAMETER OutputPath
Path where the analysis report will be saved (default: current directory)

.PARAMETER ExportFormat
Output format: TXT, CSV, or JSON (default: TXT)

.PARAMETER Level
Analysis depth: 1, 2, or 3 (default: prompts if omitted)

.EXAMPLE
.\ASEP-Analyzer.ps1 -Level 1
.\ASEP-Analyzer.ps1 -Level 3 -OutputPath "C:\Analysis" -ExportFormat "CSV"
#>

param(
    [string]$OutputPath = (Get-Location).Path,
    [ValidateSet("TXT","CSV","JSON")]
    [string]$ExportFormat = "TXT",
    [ValidateSet("0","1","2","3","")]
    [string]$Level = "",
    [switch]$PassThru
)

# ---------------------------------------------------------------------------
# LEVEL SELECTION
# ---------------------------------------------------------------------------
if ($Level -eq "") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows ASEP Analyzer - Level Select  " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Level 1 - Core:     Run keys, Scheduled Tasks, Services"
    Write-Host "  Level 2 - Standard: Level 1 + Startup Folders, Winlogon"
    Write-Host "  Level 3 - Full:     Everything (all ASEP categories)"
    Write-Host ""

    do {
        $input = Read-Host "Enter analysis level (1, 2, or 3)"
        $input = $input.Trim()
    } while ($input -notin @("0","1","2","3"))

    $Level = $input
}

$AnalysisLevel = [int]$Level

# ---------------------------------------------------------------------------
# VERSION STAMP - update this when the script changes
# ---------------------------------------------------------------------------
$ScriptVersion  = "2.0"
$ScriptDate     = "2026-07-16"
$ScriptFile     = $MyInvocation.MyCommand.Path
Write-Host ""
Write-Host "  Script : $ScriptFile" -ForegroundColor DarkGray
Write-Host "  Version: $ScriptVersion  ($ScriptDate)" -ForegroundColor DarkGray
Write-Host ""

# ---------------------------------------------------------------------------
# PRIVILEGE CHECK
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some results may be incomplete."
}

# ---------------------------------------------------------------------------
# RESULTS CONTAINER
# ---------------------------------------------------------------------------
$Results = [ordered]@{
    "SystemInfo"         = @{}
    "RunKeys"            = [System.Collections.Generic.List[object]]::new()
    "Services"           = [System.Collections.Generic.List[object]]::new()
    "ScheduledTasks"     = [System.Collections.Generic.List[object]]::new()
    "StartupFolders"     = [System.Collections.Generic.List[object]]::new()
    "Winlogon"           = [System.Collections.Generic.List[object]]::new()
    "AppInit"            = [System.Collections.Generic.List[object]]::new()
    "WMISubscriptions"   = [System.Collections.Generic.List[object]]::new()
    "ShellExtensions"    = [System.Collections.Generic.List[object]]::new()
    "BrowserHelperObjects" = [System.Collections.Generic.List[object]]::new()
    "SessionManager"     = [System.Collections.Generic.List[object]]::new()
    "LSA"                = [System.Collections.Generic.List[object]]::new()
    "ActiveSetup"        = [System.Collections.Generic.List[object]]::new()
    "ImageFileExecution" = [System.Collections.Generic.List[object]]::new()
    "PowerShellProfiles" = [System.Collections.Generic.List[object]]::new()
    "Drivers"            = [System.Collections.Generic.List[object]]::new()
    "NetworkProviders"   = [System.Collections.Generic.List[object]]::new()
    "WinsockProviders"   = [System.Collections.Generic.List[object]]::new()
    "COM"                = [System.Collections.Generic.List[object]]::new()
    "BootExecute"        = [System.Collections.Generic.List[object]]::new()
    "KnownDLLs"          = [System.Collections.Generic.List[object]]::new()
    "ModernApps"         = [System.Collections.Generic.List[object]]::new()
}

# ---------------------------------------------------------------------------
# HELPER: Convert binary registry data to readable text
# ---------------------------------------------------------------------------
function Convert-RegistryData {
    param([object]$Data, [string]$ValueType)

    if ($null -eq $Data) { return "" }

    switch ($ValueType) {
        "Binary" {
            if ($Data -is [byte[]]) {
                $text = [System.Text.Encoding]::Unicode.GetString($Data) -replace '[^\x20-\x7E]', ''
                if ([string]::IsNullOrWhiteSpace($text)) {
                    $text = [System.Text.Encoding]::ASCII.GetString($Data) -replace '[^\x20-\x7E]', ''
                }
                if ($text.Length -gt 10) { return $text.Trim() }
                return "0x" + ([BitConverter]::ToString($Data) -replace '-','')
            }
            return $Data.ToString()
        }
        "MultiString" {
            if ($Data -is [array]) { return ($Data -join '; ') }
            return $Data
        }
        "ExpandString" {
            try { return [Environment]::ExpandEnvironmentVariables($Data) }
            catch { return $Data }
        }
        default { return $Data.ToString() }
    }
}

# ---------------------------------------------------------------------------
# HELPER: Read all named values from a registry key in a single open.
#   Returns a list of hashtables: Name, ConvertedValue, Type, Path
#   Returns empty list if the key does not exist.
# ---------------------------------------------------------------------------
function Get-RegistryKeyValues {
    param([string]$Path)

    $results = @()
    try {
        $key = Get-Item -Path "Registry::$Path" -ErrorAction Stop
        foreach ($valueName in $key.Property) {
            try {
                $raw  = $key.GetValue($valueName, $null)
                $kind = $key.GetValueKind($valueName).ToString()
                $results += @{
                    Name           = $valueName
                    Value          = $raw
                    Type           = $kind
                    ConvertedValue = Convert-RegistryData -Data $raw -ValueType $kind
                    Path           = $Path
                }
            } catch {
                # skip unreadable values
            }
        }
    } catch {
        # key does not exist or access denied
    }
    return $results
}

# ---------------------------------------------------------------------------
# HELPER: Read a single named value from a registry key.
#   Returns hashtable with Value, Type, ConvertedValue or $null.
# ---------------------------------------------------------------------------
function Get-RegistryValue {
    param([string]$Path, [string]$Name)

    try {
        $key = Get-Item -Path "Registry::$Path" -ErrorAction Stop
        if ($key.Property -contains $Name) {
            $raw  = $key.GetValue($Name, $null)
            $kind = $key.GetValueKind($Name).ToString()
            return @{
                Value          = $raw
                Type           = $kind
                ConvertedValue = Convert-RegistryData -Data $raw -ValueType $kind
            }
        }
    } catch { }
    return $null
}

# ---------------------------------------------------------------------------
# HELPER: List child key names under a registry path (one open, no recursion).
# ---------------------------------------------------------------------------
function Get-RegistryChildKeys {
    param([string]$Path)

    try {
        return Get-ChildItem -Path "Registry::$Path" -ErrorAction Stop
    } catch {
        return @()
    }
}

# ===========================================================================
# COLLECTION FUNCTIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# LEVEL 1: Run Keys
# All known HKLM/HKCU run-related keys, including 32-bit and policy variants.
#   v1.7: RunOnceEx handled separately. Unlike the other Run keys, RunOnceEx
#         does NOT store commands as direct values of the key. Windows stores
#         them under numbered "section" subkeys (0001, 0002, ...), and each
#         section holds the command values. A flat value read of the RunOnceEx
#         key therefore finds nothing even when it is populated, so those paths
#         now get a child-key enumeration pass (same pattern as Active Setup /
#         IFEO): enumerate the section subkeys, then read the values in each.
# ---------------------------------------------------------------------------
function Get-RunKeys {
    Write-Host "[*] Analyzing Run Keys..." -ForegroundColor Yellow

    $runKeyPaths = @(
        # Standard 64-bit HKLM run keys
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",

        # Standard 64-bit HKCU run keys
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",

        # 32-bit (WOW6432Node) run keys under HKLM
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",

        # 32-bit run keys under HKCU
        "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",

        # Policy-based run keys (can override or supplement user run keys)
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",

        # Logon script via environment variable (UserInitMprLogonScript)
        "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "HKCU\Environment"
    )

    # Logon script keys - only look for the UserInitMprLogonScript value
    $logonScriptKeys = @(
        "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "HKCU\Environment"
    )

    # RunOnceEx base keys - handled via section-subkey enumeration below,
    # NOT via the flat value read above (which would always miss them).
    $runOnceExPaths = @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
    )

    $found = 0

    # --- Flat run keys (direct values of the key) --------------------------
    foreach ($path in $runKeyPaths) {
        if ($path -in $logonScriptKeys) {
            # Only extract the logon script value, not every env var
            $val = Get-RegistryValue -Path $path -Name "UserInitMprLogonScript"
            if ($val -and $val.ConvertedValue) {
                $Results.RunKeys.Add([PSCustomObject]@{
                    Category = "Run Keys"
                    Name     = "UserInitMprLogonScript"
                    Path     = $path
                    Value    = $val.ConvertedValue
                    Type     = $val.Type
                })
                $found++
            }
        } else {
            $values = Get-RegistryKeyValues -Path $path
            foreach ($v in $values) {
                $Results.RunKeys.Add([PSCustomObject]@{
                    Category = "Run Keys"
                    Name     = $v.Name
                    Path     = $v.Path
                    Value    = $v.ConvertedValue
                    Type     = $v.Type
                })
                $found++
            }
        }
    }

    # --- RunOnceEx (numbered section subkeys, each holding command values) -
    foreach ($basePath in $runOnceExPaths) {
        foreach ($section in (Get-RegistryChildKeys -Path $basePath)) {
            # Normalize the child's full hive name back to the short form used
            # elsewhere (covers both HKLM and HKCU RunOnceEx sections).
            $sectionPath = $section.Name -replace 'HKEY_LOCAL_MACHINE','HKLM' `
                                         -replace 'HKEY_CURRENT_USER','HKCU'
            foreach ($v in (Get-RegistryKeyValues -Path $sectionPath)) {
                $Results.RunKeys.Add([PSCustomObject]@{
                    Category = "Run Keys"
                    Name     = $v.Name
                    Path     = $v.Path      # includes the \NNNN section subkey
                    Value    = $v.ConvertedValue
                    Type     = $v.Type
                })
                $found++
            }
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found run key entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No run key entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 1: Services
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# LEVEL 1: Services
#   v1.8: Lists ALL services regardless of StartMode (was Auto-only). The old
#         filter Where-Object { $_.StartMode -in @("Auto","Automatic") } hid
#         Manual/Disabled services - critically, a Manual service that is
#         TRIGGER-STARTED (ETW, device arrival, group policy, IP address
#         available, etc.) auto-launches yet never reports StartMode "Auto",
#         so it was invisible. For Autoruns-style parity we now list every
#         service and annotate the two things Win32_Service does NOT expose:
#           - Delayed auto-start : registry ...\<svc>\DelayedAutostart = 1
#           - Trigger-start      : registry ...\<svc>\TriggerInfo subkey exists
#         Each row keeps the raw StartMode and adds a derived StartType label,
#         plus DelayedAutoStart / HasTrigger / TriggerCount for filtering.
#
# ---------------------------------------------------------------------------
function Get-AutoStartServices {
    Write-Host "[*] Analyzing Services..." -ForegroundColor Yellow
    try {
        # No StartMode filter - collect EVERY service. @() so .Count is safe.
        $services = @(Get-CimInstance -ClassName Win32_Service `
            -Property Name,DisplayName,PathName,StartMode,StartName,State,ServiceType `
            -ErrorAction Stop)

        $triggerCount = 0
        $delayedCount = 0

        foreach ($svc in $services) {
            $svcKey = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)"

            # Delayed auto-start is not exposed by Win32_Service (it reports
            # plain "Auto"); the flag lives in the registry and only applies
            # to Auto services.
            $delayed = $false
            if ($svc.StartMode -in @("Auto","Automatic")) {
                $das = Get-RegistryValue -Path $svcKey -Name "DelayedAutostart"
                if ($das -and "$($das.ConvertedValue)" -eq "1") { $delayed = $true }
            }

            # Trigger-start services carry a TriggerInfo subkey with one numbered
            # child per trigger. This is the case the old Auto-only filter missed.
            $triggers   = @(Get-RegistryChildKeys -Path "$svcKey\TriggerInfo")
            $hasTrigger = ($triggers.Count -gt 0)

            # Derived, human-readable start type.
            if ($svc.StartMode -in @("Auto","Automatic")) {
                $startType = if ($delayed) { "Automatic (Delayed Start)" } else { "Automatic" }
            } elseif ($svc.StartMode -eq "Manual") {
                # Disabled overrides triggers, so only flag trigger-start here.
                $startType = if ($hasTrigger) { "Manual (Trigger Start)" } else { "Manual" }
            } elseif ($svc.StartMode -eq "Disabled") {
                $startType = "Disabled"
            } elseif ($svc.StartMode -eq "Boot") {
                $startType = "Boot (driver)"
            } elseif ($svc.StartMode -eq "System") {
                $startType = "System (driver)"
            } else {
                $startType = "$($svc.StartMode)"
            }

            if ($hasTrigger) { $triggerCount++ }
            if ($delayed)    { $delayedCount++ }

            $Results.Services.Add([PSCustomObject]@{
                Category         = "Services"
                Name             = $svc.Name
                DisplayName      = $svc.DisplayName
                PathName         = $svc.PathName
                StartMode        = $svc.StartMode          # raw CIM value
                StartType        = $startType              # derived label
                DelayedAutoStart = $delayed
                HasTrigger       = $hasTrigger
                TriggerCount     = $triggers.Count
                StartName        = $svc.StartName
                State            = $svc.State
                ServiceType      = $svc.ServiceType
            })
        }

        Write-Host ("  [+] Found {0} services  ({1} trigger-start, {2} delayed-auto)" -f `
            $services.Count, $triggerCount, $delayedCount) -ForegroundColor Green
    } catch {
        Write-Warning "Error collecting services: $($_.Exception.Message)"
    }
}


# ---------------------------------------------------------------------------
# LEVEL 1: Scheduled Tasks
#   Performance fix: retrieve all tasks in ONE call with Get-ScheduledTask,
#   then pipeline into Get-ScheduledTaskInfo via the task objects directly.
#   The original code called Get-ScheduledTask AGAIN inside the loop for each
#   task and also called Get-ScheduledTaskInfo separately - causing 2-3x the
#   COM/WMI round trips for every task on the system.
# ---------------------------------------------------------------------------
function Get-AutoStartTasks {
    Write-Host "[*] Analyzing Scheduled Tasks..." -ForegroundColor Yellow
    try {
        # Retrieve all tasks regardless of state.
        # State integer values: 0=Unknown, 1=Disabled, 2=Queued, 3=Ready, 4=Running.
        # State is recorded in the output so the analyst can filter as needed.
        # Force into an array so .Count is always available even with 0 or 1 result.
        $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

        # Attempt bulk pipeline fetch of TaskInfo (fastest path).
        # On some Windows/PS versions Get-ScheduledTaskInfo does not accept
        # pipeline input from task objects and throws on null TaskPath.
        # The catch sets $bulkFailed so the per-task loop knows to query individually.
        $taskInfoMap = @{}
        $bulkFailed  = $false
        try {
            $tasks | Get-ScheduledTaskInfo -ErrorAction Stop | ForEach-Object {
                $key = "$($_.TaskPath)$($_.TaskName)"
                $taskInfoMap[$key] = $_
            }
        } catch {
            $bulkFailed = $true
        }

        # Map State enum integer to a readable label
        $stateLabel = @{ 0="Unknown"; 1="Disabled"; 2="Queued"; 3="Ready"; 4="Running" }

        $taskCount  = 0
        $errorCount = 0
        foreach ($task in $tasks) {
            # Wrap each task individually so one bad task cannot abort the entire collection
            try {
                if (-not $task.TaskName) { continue }

                $key      = "$($task.TaskPath)$($task.TaskName)"
                $taskInfo = $taskInfoMap[$key]
                $stateStr = if ($stateLabel.ContainsKey([int]$task.State)) { $stateLabel[[int]$task.State] } else { "$($task.State)" }

                # Per-task fallback for Get-ScheduledTaskInfo is intentionally omitted.
                # On this system it throws for most tasks, which caused 215 of 271
                # tasks to be skipped. LastRunTime/NextRunTime show "Unknown" when
                # the bulk fetch failed, but all tasks are recorded.
                $actions = @($task.Actions)
                if ($actions.Count -eq 0) {
                    $Results.ScheduledTasks.Add([PSCustomObject]@{
                        Category    = "Scheduled Tasks"
                        TaskName    = $task.TaskName
                        TaskPath    = $task.TaskPath
                        State       = $stateStr
                        LastRunTime = if ($taskInfo -and $taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString() } else { "Unknown" }
                        NextRunTime = if ($taskInfo -and $taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString() } else { "Unknown" }
                        Action      = "(no executable action)"
                        Author      = if ($task.Author) { $task.Author } else { "" }
                    })
                    $taskCount++
                    continue
                }

                foreach ($action in $actions) {
                    if ($null -eq $action) { continue }

                    $actionStr = ""
                    if ($action.Execute) {
                        $actionStr = $action.Execute
                        if ($action.Arguments) { $actionStr += " $($action.Arguments)" }
                    }

                    $Results.ScheduledTasks.Add([PSCustomObject]@{
                        Category    = "Scheduled Tasks"
                        TaskName    = $task.TaskName
                        TaskPath    = $task.TaskPath
                        State       = $stateStr
                        LastRunTime = if ($taskInfo -and $taskInfo.LastRunTime) { $taskInfo.LastRunTime.ToString() } else { "Unknown" }
                        NextRunTime = if ($taskInfo -and $taskInfo.NextRunTime) { $taskInfo.NextRunTime.ToString() } else { "Unknown" }
                        Action      = $actionStr
                        Author      = if ($task.Author) { $task.Author } else { "" }
                    })
                    $taskCount++
                }
            } catch {
                $errorCount++
                Write-Verbose "Skipped task '$($task.TaskName)': $($_.Exception.Message)"
            }
        }
        $msg = "  [+] Found $taskCount scheduled task actions ($($tasks.Count) tasks total)"
        if ($errorCount -gt 0) { $msg += " [$errorCount skipped due to errors]" }
        Write-Host $msg -ForegroundColor Green
    } catch {
        Write-Warning "Error collecting scheduled tasks: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# LEVEL 2: Startup Folders
# ---------------------------------------------------------------------------
function Get-StartupFolderItems {
    Write-Host "[*] Analyzing Startup Folders..." -ForegroundColor Yellow

    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    $shell = $null
    $found = 0
    foreach ($path in $startupPaths) {
        if (-not (Test-Path $path)) { continue }

        $items = Get-ChildItem $path -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $target = ""
            if ($item.Extension -eq ".lnk") {
                try {
                    if (-not $shell) { $shell = New-Object -ComObject WScript.Shell }
                    $target = $shell.CreateShortcut($item.FullName).TargetPath
                } catch {
                    $target = "Unable to resolve"
                }
            }

            $Results.StartupFolders.Add([PSCustomObject]@{
                Category      = "Startup Folders"
                Name          = $item.Name
                Path          = $item.FullName
                Target        = $target
                Type          = if ($item.PSIsContainer) { "Folder" } else { $item.Extension }
                LastWriteTime = $item.LastWriteTime.ToString()
                Size          = if (-not $item.PSIsContainer) { $item.Length } else { 0 }
            })
            $found++
        }
    }
    if ($shell) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found startup folder items" -ForegroundColor Green
    } else {
        Write-Host "  [-] No startup folder items found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 2: Winlogon / AppInit
# ---------------------------------------------------------------------------
function Get-WinlogonEntries {
    Write-Host "[*] Analyzing Winlogon entries..." -ForegroundColor Yellow

    $winlogonValues = @("Userinit","Shell","System","TaskMan","VmApplet")
    $winlogonPaths  = @(
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )

    $found = 0
    foreach ($path in $winlogonPaths) {
        $allVals = Get-RegistryKeyValues -Path $path
        foreach ($v in $allVals) {
            if ($v.Name -in $winlogonValues -and $v.ConvertedValue) {
                $Results.Winlogon.Add([PSCustomObject]@{
                    Category = "Winlogon"
                    Name     = $v.Name
                    Path     = $path
                    Value    = $v.ConvertedValue
                    Type     = $v.Type
                })
                $found++
            }
        }
    }

    # Winlogon Notify subkeys
    $notifyPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
    foreach ($child in (Get-RegistryChildKeys -Path $notifyPath)) {
        $childPath = $child.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'
        $dllVal    = Get-RegistryValue -Path $childPath -Name "DllName"
        if ($dllVal -and $dllVal.ConvertedValue) {
            $Results.Winlogon.Add([PSCustomObject]@{
                Category = "Winlogon"
                Name     = "Notify\$($child.PSChildName)"
                Path     = $notifyPath
                Value    = $dllVal.ConvertedValue
                Type     = $dllVal.Type
            })
            $found++
        }
    }

    # AppInit_DLLs
    $appInitPaths = @(
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    foreach ($path in $appInitPaths) {
        $v = Get-RegistryValue -Path $path -Name "AppInit_DLLs"
        if ($v -and $v.ConvertedValue) {
            $Results.AppInit.Add([PSCustomObject]@{
                Category = "AppInit DLLs"
                Name     = "AppInit_DLLs"
                Path     = $path
                Value    = $v.ConvertedValue
                Type     = $v.Type
            })
            $found++
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found Winlogon/AppInit entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No notable Winlogon entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: WMI Event Subscriptions
#   Collects all THREE WMI persistence classes and joins each binding to its
#   filter + consumer on the CIM __RELPATH reference, then surfaces any unbound
#   (orphan) filters/consumers.
#     __EventFilter             - the trigger condition (a WQL query)
#     __EventConsumer           - the action (concrete subclasses handled below)
#     __FilterToConsumerBinding - the linkage that makes the pair ACTIVE
#   v1.6: CreatorSID comes back from WMI as a raw binary SID (byte array).
#         ConvertFrom-CreatorSid now renders it as "S-1-... (DOMAIN\Account)".
# ---------------------------------------------------------------------------
function Get-WMISubscriptions {
    Write-Host "[*] Analyzing WMI Event Subscriptions..." -ForegroundColor Yellow

    # Normalize a CIM reference / __RELPATH to a comparable key.
    #   "\\.\root\subscription:__EventFilter.Name=\"x\""  -> '__eventfilter.name="x"'
    #   "CommandLineEventConsumer.Name=\"x\""             -> 'commandlineeventconsumer.name="x"'
    # Everything is lower-cased so the join is case-insensitive.
    function ConvertTo-WmiRefKey {
        param([string]$Reference)
        if ([string]::IsNullOrWhiteSpace($Reference)) { return "" }
        $key = $Reference
        $colon = $key.LastIndexOf(':')   # strip any \\host\namespace: prefix
        if ($colon -ge 0) { $key = $key.Substring($colon + 1) }
        return $key.Trim().ToLowerInvariant()
    }

    # A binding's Filter/Consumer property may come back as a path string or,
    # on some systems, as an embedded CimInstance. Handle both.
    function Get-RefKeyFromValue {
        param($Value)
        if ($null -eq $Value) { return "" }
        if ($Value -is [Microsoft.Management.Infrastructure.CimInstance]) {
            return ConvertTo-WmiRefKey $Value.CimSystemProperties.RelPath
        }
        return ConvertTo-WmiRefKey ([string]$Value)
    }

    # CreatorSID is stored as a raw binary SID (byte array). Convert it to a
    # readable "S-1-... (DOMAIN\Account)" string. Falls back gracefully if the
    # value is already a string, cannot be parsed, or cannot be resolved.
    function ConvertFrom-CreatorSid {
        param($SidValue)
        if ($null -eq $SidValue) { return "" }
        try {
            # WMI/CIM typically returns this as byte[] (uint8[]).
            $bytes = @($SidValue)
            if ($bytes.Count -gt 0 -and ($bytes[0] -is [byte] -or $bytes[0] -is [int])) {
                $byteArray = [byte[]]($bytes | ForEach-Object { [byte]$_ })
                $sid = New-Object System.Security.Principal.SecurityIdentifier($byteArray, 0)
                $sidStr = $sid.Value
                try {
                    $acct = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    return "$sidStr ($acct)"
                } catch {
                    return $sidStr    # valid SID, just not resolvable to a name
                }
            }
            return [string]$SidValue
        } catch {
            return [string]$SidValue
        }
    }

    # Build a readable "action" summary from a consumer. The interesting
    # properties differ by concrete consumer class.
    function Get-ConsumerAction {
        param($Consumer)
        switch ($Consumer.CimClass.CimClassName) {
            "CommandLineEventConsumer" {
                $parts = @()
                if ($Consumer.ExecutablePath)     { $parts += "Exe=$($Consumer.ExecutablePath)" }
                if ($Consumer.CommandLineTemplate){ $parts += "Cmd=$($Consumer.CommandLineTemplate)" }
                if ($Consumer.WorkingDirectory)   { $parts += "WorkDir=$($Consumer.WorkingDirectory)" }
                return ($parts -join " | ")
            }
            "ActiveScriptEventConsumer" {
                if ($Consumer.ScriptFileName) {
                    return "Engine=$($Consumer.ScriptingEngine); File=$($Consumer.ScriptFileName)"
                }
                return "Engine=$($Consumer.ScriptingEngine); InlineScript=$($Consumer.ScriptText)"
            }
            "LogFileEventConsumer"    { return "LogFile=$($Consumer.FileName); Text=$($Consumer.Text)" }
            "NTEventLogEventConsumer" { return "EventLog Name=$($Consumer.Name)" }
            "SMTPEventConsumer"       { return "SMTP Server=$($Consumer.SMTPServer); To=$($Consumer.ToLine)" }
            default                   { return "" }
        }
    }

    try {
        $ns = "root\subscription"

        # @(...) guarantees an array so .Count is reliable even for 0 or 1 result.
        $filters   = @(Get-CimInstance -Namespace $ns -ClassName "__EventFilter"             -ErrorAction SilentlyContinue)
        $consumers = @(Get-CimInstance -Namespace $ns -ClassName "__EventConsumer"           -ErrorAction SilentlyContinue)
        $bindings  = @(Get-CimInstance -Namespace $ns -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue)

        # Index filters and consumers by their normalized __RELPATH so bindings
        # can be resolved without extra WMI round trips.
        $filterByKey = @{}
        foreach ($f in $filters) {
            $filterByKey[(ConvertTo-WmiRefKey $f.CimSystemProperties.RelPath)] = $f
        }
        $consumerByKey = @{}
        foreach ($c in $consumers) {
            $consumerByKey[(ConvertTo-WmiRefKey $c.CimSystemProperties.RelPath)] = $c
        }

        # Track which filters/consumers were referenced by a binding so the
        # leftovers can be reported as orphans afterward.
        $boundFilterKeys   = @{}
        $boundConsumerKeys = @{}

        # --- Bound pairs: the actually-active persistence entries -----------
        foreach ($b in $bindings) {
            $fKey = Get-RefKeyFromValue $b.Filter
            $cKey = Get-RefKeyFromValue $b.Consumer

            $boundFilterKeys[$fKey]   = $true
            $boundConsumerKeys[$cKey] = $true

            $f = $filterByKey[$fKey]
            $c = $consumerByKey[$cKey]

            $sidSource = if ($c) { $c.CreatorSID } elseif ($f) { $f.CreatorSID } else { $null }

            $Results.WMISubscriptions.Add([PSCustomObject]@{
                Category       = "WMI Subscriptions"
                State          = "ACTIVE (bound)"
                FilterName     = if ($f) { $f.Name }  else { "<missing filter: $($b.Filter)>" }
                FilterQuery    = if ($f) { $f.Query } else { "" }
                ConsumerName   = if ($c) { $c.Name }  else { "<missing consumer: $($b.Consumer)>" }
                ConsumerType   = if ($c) { $c.CimClass.CimClassName } else { "" }
                ConsumerAction = if ($c) { Get-ConsumerAction -Consumer $c } else { "" }
                CreatorSID     = ConvertFrom-CreatorSid $sidSource
            })
        }

        # --- Orphan filters: a trigger defined with nothing bound to it -----
        foreach ($f in $filters) {
            $key = ConvertTo-WmiRefKey $f.CimSystemProperties.RelPath
            if (-not $boundFilterKeys.ContainsKey($key)) {
                $Results.WMISubscriptions.Add([PSCustomObject]@{
                    Category       = "WMI Subscriptions"
                    State          = "orphan filter (unbound)"
                    FilterName     = $f.Name
                    FilterQuery    = $f.Query
                    ConsumerName   = ""
                    ConsumerType   = ""
                    ConsumerAction = ""
                    CreatorSID     = ConvertFrom-CreatorSid $f.CreatorSID
                })
            }
        }

        # --- Orphan consumers: an action defined with nothing bound to it ---
        foreach ($c in $consumers) {
            $key = ConvertTo-WmiRefKey $c.CimSystemProperties.RelPath
            if (-not $boundConsumerKeys.ContainsKey($key)) {
                $Results.WMISubscriptions.Add([PSCustomObject]@{
                    Category       = "WMI Subscriptions"
                    State          = "orphan consumer (unbound)"
                    FilterName     = ""
                    FilterQuery    = ""
                    ConsumerName   = $c.Name
                    ConsumerType   = $c.CimClass.CimClassName
                    ConsumerAction = Get-ConsumerAction -Consumer $c
                    CreatorSID     = ConvertFrom-CreatorSid $c.CreatorSID
                })
            }
        }

        Write-Host ("  [+] Filters: {0}  Consumers: {1}  Bindings: {2}" -f `
            $filters.Count, $consumers.Count, $bindings.Count) -ForegroundColor Green
        if ($bindings.Count -gt 0) {
            Write-Host ("  [+] {0} active (bound) subscription(s)" -f $bindings.Count) -ForegroundColor Green
        }
        if (($filters.Count + $consumers.Count + $bindings.Count) -eq 0) {
            Write-Host "  [-] No WMI event subscription objects found" -ForegroundColor Gray
        }
    } catch {
        Write-Verbose "Error collecting WMI subscriptions: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Browser Helper Objects
#   Performance fix: open each CLSID key ONCE and read all needed values in
#   that single open rather than calling Get-SafeRegistryValue 3+ times per BHO.
# ---------------------------------------------------------------------------
function Get-BrowserHelperObjects {
    Write-Host "[*] Analyzing Browser Helper Objects..." -ForegroundColor Yellow

    $bhoPaths = @(
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    )

    $found = 0
    foreach ($bhoRoot in $bhoPaths) {
        foreach ($child in (Get-RegistryChildKeys -Path $bhoRoot)) {
            $clsid = $child.PSChildName

            $description = ""
            $dllPath     = ""

            $clsidRoots = @(
                "HKLM\SOFTWARE\Classes\CLSID\$clsid",
                "HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\$clsid",
                "HKCU\SOFTWARE\Classes\CLSID\$clsid"
            )

            foreach ($cr in $clsidRoots) {
                if (-not $description) {
                    $v = Get-RegistryValue -Path $cr -Name "(default)"
                    if ($v -and $v.ConvertedValue) { $description = $v.ConvertedValue }
                }
                if (-not $dllPath) {
                    $v = Get-RegistryValue -Path "$cr\InProcServer32" -Name "(default)"
                    if ($v -and $v.ConvertedValue) { $dllPath = $v.ConvertedValue }
                }
                if ($description -and $dllPath) { break }
            }

            $Results.BrowserHelperObjects.Add([PSCustomObject]@{
                Category     = "Browser Helper Objects"
                CLSID        = $clsid
                Description  = if ($description) { $description } else { "Unknown" }
                DLLPath      = if ($dllPath)     { $dllPath }     else { "Unknown" }
                RegistryPath = $bhoRoot
            })
            $found++
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found BHOs" -ForegroundColor Green
    } else {
        Write-Host "  [-] No BHOs found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Shell Extensions
# ---------------------------------------------------------------------------
function Get-ShellExtensions {
    Write-Host "[*] Analyzing Shell Extensions..." -ForegroundColor Yellow

    $shellExtPaths = @(
        "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
        "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
        "HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers"
    )

    $found = 0
    foreach ($path in $shellExtPaths) {
        foreach ($handler in (Get-RegistryChildKeys -Path $path)) {
            $handlerPath = $handler.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'
            $clsidVal    = Get-RegistryValue -Path $handlerPath -Name "(default)"

            $Results.ShellExtensions.Add([PSCustomObject]@{
                Category     = "Shell Extensions"
                HandlerName  = $handler.PSChildName
                CLSID        = if ($clsidVal) { $clsidVal.ConvertedValue } else { "Unknown" }
                Type         = ($path -split '\\')[-2]
                RegistryPath = $path
            })
            $found++
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found shell extensions" -ForegroundColor Green
    } else {
        Write-Host "  [-] No shell extensions found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Active Setup
# ---------------------------------------------------------------------------
function Get-ActiveSetupEntries {
    Write-Host "[*] Analyzing Active Setup..." -ForegroundColor Yellow

    $activeSetupPaths = @(
        "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
    )

    $found = 0
    foreach ($path in $activeSetupPaths) {
        foreach ($child in (Get-RegistryChildKeys -Path $path)) {
            $childPath = $child.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'
            $stub      = Get-RegistryValue -Path $childPath -Name "StubPath"
            if ($stub -and $stub.ConvertedValue) {
                $Results.ActiveSetup.Add([PSCustomObject]@{
                    Category     = "Active Setup"
                    ComponentID  = $child.PSChildName
                    StubPath     = $stub.ConvertedValue
                    RegistryPath = $path
                })
                $found++
            }
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found Active Setup entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No Active Setup entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Image File Execution Options (debugger hijacking)
# ---------------------------------------------------------------------------
function Get-IFEOEntries {
    Write-Host "[*] Analyzing Image File Execution Options..." -ForegroundColor Yellow

    $ifeoPaths = @(
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )

    $found = 0
    foreach ($path in $ifeoPaths) {
        foreach ($exe in (Get-RegistryChildKeys -Path $path)) {
            $exePath  = $exe.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'
            $debugger = Get-RegistryValue -Path $exePath -Name "Debugger"
            if ($debugger -and $debugger.ConvertedValue) {
                $Results.ImageFileExecution.Add([PSCustomObject]@{
                    Category     = "Image File Execution Options"
                    Executable   = $exe.PSChildName
                    Debugger     = $debugger.ConvertedValue
                    RegistryPath = $path
                })
                $found++
            }
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found IFEO entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No IFEO debugger entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Boot Execute
# ---------------------------------------------------------------------------
function Get-BootExecuteEntries {
    Write-Host "[*] Analyzing Boot Execute..." -ForegroundColor Yellow

    $v = Get-RegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute"
    if ($v -and $v.ConvertedValue) {
        $Results.BootExecute.Add([PSCustomObject]@{
            Category = "Boot Execute"
            Name     = "BootExecute"
            Value    = $v.ConvertedValue
            Path     = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
        })
        Write-Host "  [+] Found BootExecute entry" -ForegroundColor Green
    } else {
        Write-Host "  [-] BootExecute is default (autocheck)" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: PowerShell Profiles
# ---------------------------------------------------------------------------
function Get-PowerShellProfileEntries {
    Write-Host "[*] Analyzing PowerShell Profiles..." -ForegroundColor Yellow

    $profilePaths = @(
        $PROFILE.CurrentUserCurrentHost,
        $PROFILE.CurrentUserAllHosts,
        $PROFILE.AllUsersCurrentHost,
        $PROFILE.AllUsersAllHosts
    )

    $found = 0
    foreach ($profilePath in $profilePaths) {
        if (-not $profilePath) { continue }
        if (-not (Test-Path $profilePath -ErrorAction SilentlyContinue)) { continue }
        try {
            $content = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
            $preview = if ($content.Length -gt 200) { $content.Substring(0,200) + "..." } else { $content }
            $Results.PowerShellProfiles.Add([PSCustomObject]@{
                Category     = "PowerShell Profiles"
                ProfilePath  = $profilePath
                LastModified = (Get-Item $profilePath).LastWriteTime.ToString()
                SizeBytes    = (Get-Item $profilePath).Length
                Preview      = $preview
            })
            Write-Host "  [+] Found profile: $profilePath" -ForegroundColor Green
            $found++
        } catch {
            Write-Verbose "Error reading profile $profilePath"
        }
    }
    if ($found -eq 0) {
        Write-Host "  [-] No PowerShell profiles found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Drivers
# ---------------------------------------------------------------------------
function Get-AutoStartDrivers {
    Write-Host "[*] Analyzing Drivers..." -ForegroundColor Yellow
    try {
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver `
            -Property Name,DisplayName,PathName,StartMode,State,ServiceType `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.StartMode -in @("Auto","System","Boot") }

        foreach ($d in $drivers) {
            $Results.Drivers.Add([PSCustomObject]@{
                Category    = "Drivers"
                Name        = $d.Name
                DisplayName = $d.DisplayName
                PathName    = $d.PathName
                StartMode   = $d.StartMode
                State       = $d.State
                ServiceType = $d.ServiceType
            })
        }
        Write-Host "  [+] Found $($drivers.Count) auto-start drivers" -ForegroundColor Green
    } catch {
        Write-Warning "Error collecting drivers: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: LSA providers
# ---------------------------------------------------------------------------
function Get-LSAProviders {
    Write-Host "[*] Analyzing LSA Providers..." -ForegroundColor Yellow

    $lsaPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $lsaValues = @("Authentication Packages","Security Packages","Notification Packages")
    $found = 0

    foreach ($vname in $lsaValues) {
        $v = Get-RegistryValue -Path $lsaPath -Name $vname
        if ($v -and $v.ConvertedValue) {
            $Results.LSA.Add([PSCustomObject]@{
                Category = "LSA Providers"
                Name     = $vname
                Path     = $lsaPath
                Value    = $v.ConvertedValue
                Type     = $v.Type
            })
            $found++
        }
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found LSA provider entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No non-default LSA provider entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Network Providers
# ---------------------------------------------------------------------------
function Get-NetworkProviders {
    Write-Host "[*] Analyzing Network Providers..." -ForegroundColor Yellow

    $npPath = "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"
    $v = Get-RegistryValue -Path $npPath -Name "ProviderOrder"
    if ($v -and $v.ConvertedValue) {
        $Results.NetworkProviders.Add([PSCustomObject]@{
            Category = "Network Providers"
            Name     = "ProviderOrder"
            Path     = $npPath
            Value    = $v.ConvertedValue
            Type     = $v.Type
        })
        Write-Host "  [+] Found network provider order" -ForegroundColor Green
    } else {
        Write-Host "  [-] No network provider order found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 3: Winsock Providers (LSPs + Name Space Providers)
#   DISTINCT from Network Providers. Get-NetworkProviders reads the
#   NetworkProvider ProviderOrder precedence list; this reads the Winsock2
#   catalog Autoruns tracks in its "Winsock Providers" tab:
#     Protocol_Catalog9\Catalog_Entries  - protocol/LSP entries (binary
#         PackedCatalogItem = WSAPROTOCOL_INFOW; ChainLen > 1 => layered LSP).
#     NameSpace_Catalog5\Catalog_Entries - name-space providers (LibraryPath,
#         DisplayString, ProviderID, Enabled).
#
#   v2.01: ProviderId in the NameSpace catalog is a REG_BINARY holding the raw
#          16-byte GUID. It was being read via .ConvertedValue, which pushed the
#          bytes through the text-decode path and produced garbled output. Both
#          catalogs now build the GUID from raw bytes via ConvertTo-GuidString,
#          giving a proper {xxxxxxxx-xxxx-...} string (hex fallback if not 16 B).
#
#   NOTE: base "MSAFD ..." providers use the in-box mswsock.dll and store no DLL
#   path; a non-standard LAYERED chain or unexpected DLL is the red flag. All
#   entries are listed so an analyst can spot it. (64-bit catalog only.)
# ---------------------------------------------------------------------------
function Get-WinsockLSP {
    Write-Host "[*] Analyzing Winsock Providers (LSPs / name space)..." -ForegroundColor Yellow

    $wsBase = "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters"

    # Extract a null-terminated Unicode string from a byte[] at a given offset.
    function Get-UnicodeStringAt {
        param([byte[]]$Bytes, [int]$Offset, [int]$MaxBytes)
        if ($null -eq $Bytes -or $Offset -ge $Bytes.Length) { return "" }
        $end   = [Math]::Min($Offset + $MaxBytes, $Bytes.Length)
        $slice = $Bytes[$Offset..($end - 1)]
        $s     = [System.Text.Encoding]::Unicode.GetString($slice)
        $nul   = $s.IndexOf([char]0)
        if ($nul -ge 0) { $s = $s.Substring(0, $nul) }
        return $s.Trim()
    }

    # Turn a raw 16-byte GUID (REG_BINARY) into a proper {..} string. Falls back
    # to hex for odd lengths, or returns an existing string GUID unchanged.
    function ConvertTo-GuidString {
        param($Value)
        if ($null -eq $Value) { return "" }
        if ($Value -is [byte[]]) {
            if ($Value.Length -eq 16) {
                try { return ([System.Guid]::new([byte[]]$Value)).ToString('B') } catch { }
            }
            return "0x" + ([BitConverter]::ToString([byte[]]$Value) -replace '-','')
        }
        return ([string]$Value).Trim()
    }

    $found = 0

    # --- Protocol_Catalog9 : protocol / Layered Service Provider entries ---
    $protoEntries = "$wsBase\Protocol_Catalog9\Catalog_Entries"
    foreach ($entry in (Get-RegistryChildKeys -Path $protoEntries)) {
        $entryPath = $entry.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'
        $packed    = Get-RegistryValue -Path $entryPath -Name "PackedCatalogItem"
        if (-not $packed -or -not ($packed.Value -is [byte[]])) { continue }

        $bytes = [byte[]]$packed.Value

        # WSAPROTOCOL_INFOW offsets: ProviderId GUID @20 (16 B),
        # ProtocolChain.ChainLen (int) @40, szProtocol (WCHAR[256]) @116.
        $providerGuid = ""
        if ($bytes.Length -ge 36) { $providerGuid = ConvertTo-GuidString ([byte[]]($bytes[20..35])) }
        $chainLen = $null
        if ($bytes.Length -ge 44) { $chainLen = [BitConverter]::ToInt32($bytes, 40) }
        $desc = Get-UnicodeStringAt -Bytes $bytes -Offset 116 -MaxBytes 512

        # Chain length > 1 => layered (a real LSP).
        $type = if ($chainLen -gt 1) { "Layered Service Provider (LSP)" } else { "Base protocol" }

        # Best-effort: surface any DLL path embedded anywhere in the blob.
        $dll = ""
        $tokens = ([System.Text.Encoding]::Unicode.GetString($bytes) -split "`0") |
                  Where-Object { $_ -match '\.dll' }
        if ($tokens) { $dll = ($tokens | Select-Object -First 1).Trim() }

        $Results.WinsockProviders.Add([PSCustomObject]@{
            Category     = "Winsock Providers"
            Catalog      = "Protocol_Catalog9"
            Entry        = $entry.PSChildName
            Description  = $desc
            Type         = $type
            ChainLength  = $chainLen
            ProviderId   = $providerGuid
            LibraryPath  = $dll
            RegistryPath = $entryPath
        })
        $found++
    }

    # --- NameSpace_Catalog5 : name-space provider entries ------------------
    $nsEntries = "$wsBase\NameSpace_Catalog5\Catalog_Entries"
    foreach ($entry in (Get-RegistryChildKeys -Path $nsEntries)) {
        $entryPath = $entry.Name -replace 'HKEY_LOCAL_MACHINE','HKLM'

        $lib     = Get-RegistryValue -Path $entryPath -Name "LibraryPath"
        $disp    = Get-RegistryValue -Path $entryPath -Name "DisplayString"
        $provId  = Get-RegistryValue -Path $entryPath -Name "ProviderID"
        $enabled = Get-RegistryValue -Path $entryPath -Name "Enabled"

        $Results.WinsockProviders.Add([PSCustomObject]@{
            Category     = "Winsock Providers"
            Catalog      = "NameSpace_Catalog5"
            Entry        = $entry.PSChildName
            Description  = if ($disp) { $disp.ConvertedValue } else { "" }
            Type         = "Name Space Provider"
            Enabled      = if ($enabled) { $enabled.ConvertedValue } else { "" }
            ProviderId   = if ($provId) { ConvertTo-GuidString $provId.Value } else { "" }
            LibraryPath  = if ($lib) { $lib.ConvertedValue } else { "" }
            RegistryPath = $entryPath
        })
        $found++
    }

    if ($found -gt 0) {
        Write-Host "  [+] Found $found Winsock provider entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No Winsock provider entries found" -ForegroundColor Gray
    }
}


# ---------------------------------------------------------------------------
# LEVEL 3: Known DLLs
# ---------------------------------------------------------------------------
function Get-KnownDLLs {
    Write-Host "[*] Analyzing Known DLLs..." -ForegroundColor Yellow

    $kdPath = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
    $values = Get-RegistryKeyValues -Path $kdPath
    foreach ($v in $values) {
        $Results.KnownDLLs.Add([PSCustomObject]@{
            Category = "Known DLLs"
            Name     = $v.Name
            Path     = $kdPath
            Value    = $v.ConvertedValue
            Type     = $v.Type
        })
    }
    if ($values.Count -gt 0) {
        Write-Host "  [+] Found $($values.Count) Known DLL entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No Known DLL entries found" -ForegroundColor Gray
    }
}

# ===========================================================================
# REPORT GENERATION
# ===========================================================================
function Write-TxtReport {
    param([string]$FilePath)

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("================================================================")
    $null = $sb.AppendLine("WINDOWS AUTO START EXTENSIBILITY POINTS (ASEP) ANALYSIS REPORT")
    $null = $sb.AppendLine("================================================================")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("System Information:")
    $null = $sb.AppendLine("------------------")
    $null = $sb.AppendLine("Computer:      $($Results.SystemInfo.ComputerName)")
    $null = $sb.AppendLine("OS:            $($Results.SystemInfo.OSVersion)")
    $null = $sb.AppendLine("Build:         $($Results.SystemInfo.OSBuild)")
    $null = $sb.AppendLine("Architecture:  $($Results.SystemInfo.Architecture)")
    $null = $sb.AppendLine("User:          $($Results.SystemInfo.CurrentUser)")
    $null = $sb.AppendLine("Domain:        $($Results.SystemInfo.Domain)")
    $null = $sb.AppendLine("Scan Date:     $($Results.SystemInfo.ScanDate)")
    $null = $sb.AppendLine("Analysis Level:$($Results.SystemInfo.AnalysisLevel)")
    $null = $sb.AppendLine("PowerShell:    $($Results.SystemInfo.PSVersion)")
    $null = $sb.AppendLine("Admin Rights:  $($Results.SystemInfo.IsAdmin)")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("================================================================")

    foreach ($category in $Results.Keys | Sort-Object) {
        if ($category -eq "SystemInfo") { continue }
        $items = $Results[$category]
        if ($items.Count -eq 0) { continue }

        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("$($category.ToUpper()) - $($items.Count) item(s)")
        $null = $sb.AppendLine(("=" * 70))

        foreach ($item in $items) {
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -ne "Category") {
                    $null = $sb.AppendLine("$($prop.Name): $($prop.Value)")
                }
            }
            $null = $sb.AppendLine(("-" * 70))
        }
    }

    $sb.ToString() | Out-File -FilePath $FilePath -Encoding UTF8
}

function Write-CsvReport {
    param([string]$FilePath)

    $allResults = [System.Collections.Generic.List[object]]::new()
    foreach ($category in $Results.Keys) {
        if ($category -ne "SystemInfo" -and $Results[$category].Count -gt 0) {
            foreach ($item in $Results[$category]) { $allResults.Add($item) }
        }
    }

    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    } else {
        Write-Warning "No data to export."
    }
}

function Write-JsonReport {
    param([string]$FilePath)

    $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
}

# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Windows ASEP Analysis Tool (Level $AnalysisLevel)  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Collect system info
Write-Host "[*] Collecting system information..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem -Property Caption,BuildNumber,OSArchitecture
$Results.SystemInfo = @{
    ComputerName  = $env:COMPUTERNAME
    OSVersion     = $os.Caption
    OSBuild       = $os.BuildNumber
    Architecture  = $os.OSArchitecture
    CurrentUser   = $env:USERNAME
    Domain        = $env:USERDOMAIN
    ScanDate      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    AnalysisLevel = $AnalysisLevel
    PSVersion     = $PSVersionTable.PSVersion.ToString()
    IsAdmin       = $isAdmin
}

# Level 0 is the semi hidden "test a function" level.

if ($AnalysisLevel -ge 0) {

	# Get-WMISubscriptions # fixed 7/16
	# Get-RunKeys # Fixed 7/16
	# Get-AutoStartServices # Fixed 7/16
	# Get-WinsockLSP # Fixed 7/16
}

# Level 1
if ($AnalysisLevel -ge 1) {
	Get-RunKeys
	Get-AutoStartServices
	Get-AutoStartTasks
}

# Level 2
if ($AnalysisLevel -ge 2) {
    Get-StartupFolderItems
    Get-WinlogonEntries
}

# Level 3
if ($AnalysisLevel -ge 3) {
    Get-WMISubscriptions
    Get-BrowserHelperObjects
    Get-ShellExtensions
    Get-ActiveSetupEntries
    Get-IFEOEntries
    Get-BootExecuteEntries
    Get-PowerShellProfileEntries
    Get-AutoStartDrivers
    Get-LSAProviders
    Get-NetworkProviders
    Get-WinsockLSP
    Get-KnownDLLs
}

# Generate report
Write-Host ""
Write-Host "[*] Generating report..." -ForegroundColor Green

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $OutputPath "ASEP_L${AnalysisLevel}_$($env:COMPUTERNAME)_$timestamp"

switch ($ExportFormat) {
    "CSV"  {
        $outputFile += ".csv"
        Write-CsvReport -FilePath $outputFile
    }
    "JSON" {
        $outputFile += ".json"
        Write-JsonReport -FilePath $outputFile
    }
    default {
        $outputFile += ".txt"
        Write-TxtReport -FilePath $outputFile
    }
}

Write-Host "[+] Report saved to: $outputFile" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# CONSOLE SUMMARY
# Only show categories that were collected at the chosen level.
# Categories not collected at this level are labeled "not collected".
# ---------------------------------------------------------------------------

# Map each category to the minimum level required to collect it.
$levelMap = [ordered]@{
    "RunKeys"              = 1
    "Services"             = 1
    "ScheduledTasks"       = 1
    "StartupFolders"       = 2
    "Winlogon"             = 2
    "AppInit"              = 2
    "ActiveSetup"          = 3
    "BootExecute"          = 3
    "BrowserHelperObjects" = 3
    "Drivers"              = 3
    "ImageFileExecution"   = 3
    "KnownDLLs"            = 3
    "LSA"                  = 3
    "NetworkProviders"     = 3
    "WinsockProviders"     = 3
    "PowerShellProfiles"   = 3
    "ShellExtensions"      = 3
    "WMISubscriptions"     = 3
}

$divider = "-" * 42

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ("  ASEP SUMMARY  (Level $AnalysisLevel - $($Results.SystemInfo.ComputerName))") -ForegroundColor Cyan
Write-Host "  $($Results.SystemInfo.ScanDate)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ("{0,-28}  {1,6}  {2}" -f "Category", "Count", "Status") -ForegroundColor DarkGray
Write-Host $divider -ForegroundColor DarkGray

$totalItems = 0
$lastLevel  = 0

foreach ($category in $levelMap.Keys) {
    $requiredLevel = $levelMap[$category]

    # Print a blank separator line between level groups
    if ($requiredLevel -ne $lastLevel) {
        if ($lastLevel -ne 0) { Write-Host "" }
        Write-Host ("  -- Level $requiredLevel --") -ForegroundColor DarkGray
        $lastLevel = $requiredLevel
    }

    if ($requiredLevel -gt $AnalysisLevel) {
        # Not collected at this run level
        Write-Host ("{0,-28}  {1,6}  {2}" -f $category, "-", "not collected (level $requiredLevel)") -ForegroundColor DarkGray
    } else {
        $count = $Results[$category].Count
        $totalItems += $count
        if ($count -gt 0) {
            Write-Host ("{0,-28}  {1,6}" -f $category, $count) -ForegroundColor White
        } else {
            Write-Host ("{0,-28}  {1,6}  {2}" -f $category, "0", "none found") -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host $divider -ForegroundColor Cyan
Write-Host ("{0,-28}  {1,6}" -f "TOTAL", $totalItems) -ForegroundColor Green
Write-Host ""

if ($AnalysisLevel -lt 3) {
    Write-Host "  Re-run with -Level 3 for full analysis." -ForegroundColor DarkGray
    Write-Host ""
}

if ($Host.Name -eq 'ConsoleHost') {
    Write-Host "To access results in PowerShell:" -ForegroundColor Yellow
    Write-Host "  `$r = .\ASEP-Analyzer.ps1 -Level $AnalysisLevel -PassThru" -ForegroundColor Cyan
    Write-Host "  `$r.RunKeys | Format-Table -AutoSize" -ForegroundColor Cyan
    Write-Host "  `$r.Services | Format-Table -AutoSize" -ForegroundColor Cyan
    Write-Host "  `$r.ScheduledTasks | Format-List" -ForegroundColor Cyan
    Write-Host ""
}

# Only emit the results object when -PassThru is specified.
# Emitting it unconditionally (via return or Write-Output) causes PowerShell
# to dump the raw hashtable to the console on every interactive run.
if ($PassThru) {
    Write-Output $Results
}
