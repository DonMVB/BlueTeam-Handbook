#Requires -Version 3.0

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
    [ValidateSet("1","2","3","")]
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
    } while ($input -notin @("1","2","3"))

    $Level = $input
}

$AnalysisLevel = [int]$Level

# ---------------------------------------------------------------------------
# VERSION STAMP - update this when the script changes
# ---------------------------------------------------------------------------
$ScriptVersion  = "1.4"
$ScriptDate     = "2026-06-28"
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
# ---------------------------------------------------------------------------
function Get-RunKeys {
    Write-Host "[*] Analyzing Run Keys..." -ForegroundColor Yellow

    $runKeyPaths = @(
        # Standard 64-bit HKLM run keys
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",

        # Standard 64-bit HKCU run keys
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",

        # 32-bit (WOW6432Node) run keys under HKLM
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",

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

    $found = 0
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

    if ($found -gt 0) {
        Write-Host "  [+] Found $found run key entries" -ForegroundColor Green
    } else {
        Write-Host "  [-] No run key entries found" -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# LEVEL 1: Services
# ---------------------------------------------------------------------------
function Get-AutoStartServices {
    Write-Host "[*] Analyzing Services..." -ForegroundColor Yellow
    try {
        # Select only the properties we need to reduce data transfer
        $services = Get-CimInstance -ClassName Win32_Service `
            -Property Name,DisplayName,PathName,StartMode,StartName,State,ServiceType `
            -ErrorAction Stop |
            Where-Object { $_.StartMode -in @("Auto","Automatic") }

        foreach ($svc in $services) {
            $Results.Services.Add([PSCustomObject]@{
                Category    = "Services"
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                PathName    = $svc.PathName
                StartMode   = $svc.StartMode
                StartName   = $svc.StartName
                State       = $svc.State
                ServiceType = $svc.ServiceType
            })
        }
        Write-Host "  [+] Found $($services.Count) auto-start services" -ForegroundColor Green
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
# ---------------------------------------------------------------------------
function Get-WMISubscriptions {
    Write-Host "[*] Analyzing WMI Event Subscriptions..." -ForegroundColor Yellow
    try {
        $consumers = Get-CimInstance -Namespace "root\subscription" `
            -ClassName "__EventConsumer" -ErrorAction SilentlyContinue
        foreach ($c in $consumers) {
            $Results.WMISubscriptions.Add([PSCustomObject]@{
                Category   = "WMI Subscriptions"
                Name       = $c.Name
                Class      = $c.CimClass.CimClassName
                CreatorSID = $c.CreatorSID
            })
        }
        if ($consumers.Count -gt 0) {
            Write-Host "  [+] Found $($consumers.Count) WMI consumers" -ForegroundColor Green
        } else {
            Write-Host "  [-] No WMI event consumers found" -ForegroundColor Gray
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

# Level 1
Get-RunKeys
Get-AutoStartServices
Get-AutoStartTasks

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
