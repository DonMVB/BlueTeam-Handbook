#Requires -Version 3.0

<#
.SYNOPSIS
Windows Auto Start Extensibility Points (ASEP) Analyzer
Extracts and analyzes startup persistence mechanisms for forensic review

.DESCRIPTION
This script comprehensively examines Windows 10/11 systems for all known 
Auto Start Extensibility Points, extracting readable information for analysis.

.PARAMETER OutputPath
Path where the analysis report will be saved (default: current directory)

.PARAMETER ExportFormat
Output format: TXT, CSV, or JSON (default: TXT)

.EXAMPLE
.\ASEP-Analyzer.ps1 -OutputPath "C:\Analysis" -ExportFormat "CSV"
#>

param(
    [string]$OutputPath = (Get-Location).Path,
    [ValidateSet("TXT","CSV","JSON")]
    [string]$ExportFormat = "TXT"
)

# Initialize results collection
$Results = @{
    "SystemInfo" = @{}
    "RunKeys" = @()
    "Services" = @()
    "ScheduledTasks" = @()
    "StartupFolders" = @()
    "WMISubscriptions" = @()
    "ShellExtensions" = @()
    "BrowserHelperObjects" = @()
    "Winlogon" = @()
    "SessionManager" = @()
    "LSA" = @()
    "ActiveSetup" = @()
    "ImageFileExecution" = @()
    "ModernApps" = @()
    "PowerShellProfiles" = @()
    "Drivers" = @()
    "NetworkProviders" = @()
    "COM" = @()
}

# Helper function to convert binary registry data to readable text
function Convert-RegistryData {
    param([object]$Data, [string]$ValueType)
    
    if ($null -eq $Data) { return $null }
    
    switch ($ValueType) {
        "Binary" {
            if ($Data -is [byte[]]) {
                $text = [System.Text.Encoding]::ASCII.GetString($Data) -replace '[^\x20-\x7E]', '.'
                return "Binary: $text (Hex: $([BitConverter]::ToString($Data) -replace '-',''))"
            }
            return $Data.ToString()
        }
        "DWord" { return "DWord: $Data" }
        "QWord" { return "QWord: $Data" }
        "MultiString" { return "MultiString: $($Data -join '; ')" }
        "ExpandString" { return "ExpandString: $Data" }
        default { return $Data.ToString() }
    }
}

# Helper function to safely get registry values
function Get-SafeRegistryValue {
    param([string]$Path, [string]$Name = $null)
    
    try {
        if (Test-Path -Path "Registry::$Path" -ErrorAction SilentlyContinue) {
            $key = Get-Item -Path "Registry::$Path" -ErrorAction SilentlyContinue
            if ($key) {
                if ($Name) {
                    $value = $key.GetValue($Name, $null)
                    $valueType = $key.GetValueKind($Name)
                    return @{
                        Value = $value
                        Type = $valueType.ToString()
                        ConvertedValue = Convert-RegistryData -Data $value -ValueType $valueType.ToString()
                    }
                } else {
                    $values = @()
                    foreach ($valueName in $key.GetValueNames()) {
                        $value = $key.GetValue($valueName, $null)
                        $valueType = $key.GetValueKind($valueName)
                        $values += @{
                            Name = $valueName
                            Value = $value
                            Type = $valueType.ToString()
                            ConvertedValue = Convert-RegistryData -Data $value -ValueType $valueType.ToString()
                            Path = $Path
                        }
                    }
                    return $values
                }
            }
        }
    }
    catch {
        Write-Warning "Error accessing registry path: $Path - $($_.Exception.Message)"
    }
    return $null
}

Write-Host "Starting Windows ASEP Analysis..." -ForegroundColor Green

# Collect System Information
Write-Host "Collecting system information..." -ForegroundColor Yellow
$Results.SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    OSBuild = (Get-WmiObject Win32_OperatingSystem).BuildNumber
    Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    CurrentUser = $env:USERNAME
    Domain = $env:USERDOMAIN
    ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PSVersion = $PSVersionTable.PSVersion.ToString()
}

# 1. RUN KEYS
Write-Host "Analyzing Run Keys..." -ForegroundColor Yellow
$RunKeyPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($path in $RunKeyPaths) {
    $values = Get-SafeRegistryValue -Path $path
    if ($values) {
        $Results.RunKeys += $values | ForEach-Object { 
            $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Run Keys"
            $_
        }
    }
}

# 2. WINLOGON ENTRIES
Write-Host "Analyzing Winlogon entries..." -ForegroundColor Yellow
$WinlogonKeys = @(
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="Userinit"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="Shell"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="System"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="TaskMan"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Value="AppInit_DLLs"}
)

foreach ($item in $WinlogonKeys) {
    $value = Get-SafeRegistryValue -Path $item.Path -Name $item.Value
    if ($value -and $value.Value) {
        $Results.Winlogon += @{
            Name = $item.Value
            Path = $item.Path
            Value = $value.Value
            Type = $value.Type
            ConvertedValue = $value.ConvertedValue
            Category = "Winlogon"
        }
    }
}

# 3. SERVICES
Write-Host "Analyzing Services..." -ForegroundColor Yellow
try {
    $services = Get-WmiObject Win32_Service | Where-Object { 
        $_.StartMode -eq "Auto" -or $_.StartMode -eq "Automatic"
    } | Select-Object Name, DisplayName, PathName, StartMode, StartName, State, ServiceType
    
    foreach ($service in $services) {
        $Results.Services += @{
            Name = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartMode = $service.StartMode
            StartName = $service.StartName
            State = $service.State
            ServiceType = $service.ServiceType
            Category = "Services"
        }
    }
}
catch {
    Write-Warning "Error collecting services: $($_.Exception.Message)"
}

# 4. SCHEDULED TASKS
Write-Host "Analyzing Scheduled Tasks..." -ForegroundColor Yellow
try {
    $tasks = Get-ScheduledTask | Where-Object { 
        $_.State -eq "Ready" -and $_.Settings.Enabled -eq $true 
    } | Select-Object TaskName, TaskPath, State
    
    foreach ($task in $tasks) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $action = (Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath).Actions | Select-Object -First 1
            
            $Results.ScheduledTasks += @{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                LastRunTime = if($taskInfo) { $taskInfo.LastRunTime } else { "Unknown" }
                NextRunTime = if($taskInfo) { $taskInfo.NextRunTime } else { "Unknown" }
                Action = if($action) { "$($action.Execute) $($action.Arguments)" } else { "Unknown" }
                Category = "Scheduled Tasks"
            }
        }
        catch {
            $Results.ScheduledTasks += @{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Error = $_.Exception.Message
                Category = "Scheduled Tasks"
            }
        }
    }
}
catch {
    Write-Warning "Error collecting scheduled tasks: $($_.Exception.Message)"
}

# 5. STARTUP FOLDERS
Write-Host "Analyzing Startup Folders..." -ForegroundColor Yellow
$StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $StartupPaths) {
    if (Test-Path $path) {
        $items = Get-ChildItem $path -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            $Results.StartupFolders += @{
                Name = $item.Name
                Path = $item.FullName
                Type = if($item.PSIsContainer) { "Folder" } else { "File" }
                LastWriteTime = $item.LastWriteTime
                Size = if(-not $item.PSIsContainer) { $item.Length } else { 0 }
                Category = "Startup Folders"
            }
        }
    }
}

# 6. BROWSER HELPER OBJECTS
Write-Host "Analyzing Browser Helper Objects..." -ForegroundColor Yellow
$BHOPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
)

foreach ($path in $BHOPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $bhos = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($bho in $bhos) {
                $name = $bho.PSChildName
                $clsidPath = "HKLM\SOFTWARE\Classes\CLSID\$name"
                $description = Get-SafeRegistryValue -Path $clsidPath -Name "(Default)"
                $inProcServer = Get-SafeRegistryValue -Path "$clsidPath\InProcServer32" -Name "(Default)"
                
                $Results.BrowserHelperObjects += @{
                    CLSID = $name
                    Description = if($description) { $description.ConvertedValue } else { "Unknown" }
                    DLLPath = if($inProcServer) { $inProcServer.ConvertedValue } else { "Unknown" }
                    RegistryPath = $path
                    Category = "Browser Helper Objects"
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing BHOs at $path`: $($_.Exception.Message)"
    }
}

# 7. SHELL EXTENSIONS (Sample of common ones)
Write-Host "Analyzing Shell Extensions..." -ForegroundColor Yellow
$ShellExtPaths = @(
    "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
    "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
    "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers"
)

foreach ($path in $ShellExtPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $handlers = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($handler in $handlers) {
                $clsid = Get-SafeRegistryValue -Path $handler.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "") -Name "(Default)"
                $Results.ShellExtensions += @{
                    HandlerName = $handler.PSChildName
                    CLSID = if($clsid) { $clsid.ConvertedValue } else { "Unknown" }
                    Type = $path.Split('\')[-1]
                    RegistryPath = $path
                    Category = "Shell Extensions"
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing shell extensions at $path`: $($_.Exception.Message)"
    }
}

# 8. WMI EVENT SUBSCRIPTIONS
Write-Host "Analyzing WMI Event Subscriptions..." -ForegroundColor Yellow
try {
    $wmiConsumers = Get-WmiObject -Namespace "root\subscription" -Class "__EventConsumer" -ErrorAction SilentlyContinue
    foreach ($consumer in $wmiConsumers) {
        $Results.WMISubscriptions += @{
            Name = $consumer.Name
            Class = $consumer.__CLASS
            CreatorSID = $consumer.CreatorSID
            MachineName = $consumer.MachineName
            Category = "WMI Subscriptions"
        }
    }
}
catch {
    Write-Warning "Error collecting WMI subscriptions: $($_.Exception.Message)"
}

# 9. ACTIVE SETUP
Write-Host "Analyzing Active Setup..." -ForegroundColor Yellow
$ActiveSetupPaths = @(
    "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
)

foreach ($path in $ActiveSetupPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $components = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($component in $components) {
                $stubPath = Get-SafeRegistryValue -Path $component.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "") -Name "StubPath"
                if ($stubPath -and $stubPath.Value) {
                    $Results.ActiveSetup += @{
                        ComponentID = $component.PSChildName
                        StubPath = $stubPath.ConvertedValue
                        RegistryPath = $path
                        Category = "Active Setup"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing Active Setup at $path`: $($_.Exception.Message)"
    }
}

# 10. IMAGE FILE EXECUTION OPTIONS
Write-Host "Analyzing Image File Execution Options..." -ForegroundColor Yellow
$IFEOPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

foreach ($path in $IFEOPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $executables = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($exe in $executables) {
                $debugger = Get-SafeRegistryValue -Path $exe.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "") -Name "Debugger"
                if ($debugger -and $debugger.Value) {
                    $Results.ImageFileExecution += @{
                        Executable = $exe.PSChildName
                        Debugger = $debugger.ConvertedValue
                        RegistryPath = $path
                        Category = "Image File Execution Options"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error analyzing IFEO at $path`: $($_.Exception.Message)"
    }
}

# 11. POWERSHELL PROFILES
Write-Host "Analyzing PowerShell Profiles..." -ForegroundColor Yellow
$ProfilePaths = @(
    $PROFILE.CurrentUserCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.AllUsersAllHosts
)

foreach ($profilePath in $ProfilePaths) {
    if ($profilePath -and (Test-Path $profilePath -ErrorAction SilentlyContinue)) {
        try {
            $content = Get-Content $profilePath -ErrorAction SilentlyContinue | Select-Object -First 10
            $Results.PowerShellProfiles += @{
                ProfilePath = $profilePath
                Exists = $true
                FirstLines = $content -join "`n"
                LastModified = (Get-Item $profilePath).LastWriteTime
                Category = "PowerShell Profiles"
            }
        }
        catch {
            $Results.PowerShellProfiles += @{
                ProfilePath = $profilePath
                Exists = $true
                Error = $_.Exception.Message
                Category = "PowerShell Profiles"
            }
        }
    }
}

# 12. DRIVERS (Sample of suspicious locations)
Write-Host "Analyzing Drivers..." -ForegroundColor Yellow
try {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object { 
        $_.StartMode -eq "Auto" -or $_.StartMode -eq "System" -or $_.StartMode -eq "Boot"
    } | Select-Object Name, DisplayName, PathName, StartMode, State, ServiceType
    
    foreach ($driver in $drivers) {
        $Results.Drivers += @{
            Name = $driver.Name
            DisplayName = $driver.DisplayName
            PathName = $driver.PathName
            StartMode = $driver.StartMode
            State = $driver.State
            ServiceType = $driver.ServiceType
            Category = "Drivers"
        }
    }
}
catch {
    Write-Warning "Error collecting drivers: $($_.Exception.Message)"
}

Write-Host "Analysis complete. Generating report..." -ForegroundColor Green

# Generate Output
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $OutputPath "ASEP_Analysis_$($env:COMPUTERNAME)_$timestamp"

switch ($ExportFormat) {
    "CSV" {
        $outputFile += ".csv"
        $allResults = @()
        foreach ($category in $Results.Keys) {
            if ($category -ne "SystemInfo" -and $Results[$category].Count -gt 0) {
                $allResults += $Results[$category]
            }
        }
        $allResults | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    }
    "JSON" {
        $outputFile += ".json"
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    }
    default {
        $outputFile += ".txt"
        $report = @"
WINDOWS AUTO START EXTENSIBILITY POINTS (ASEP) ANALYSIS REPORT
================================================================

System Information:
- Computer: $($Results.SystemInfo.ComputerName)
- OS: $($Results.SystemInfo.OSVersion)
- Build: $($Results.SystemInfo.OSBuild)
- Architecture: $($Results.SystemInfo.Architecture)
- User: $($Results.SystemInfo.CurrentUser)
- Domain: $($Results.SystemInfo.Domain)
- Scan Date: $($Results.SystemInfo.ScanDate)
- PowerShell: $($Results.SystemInfo.PSVersion)

================================================================

"@
        
        foreach ($category in $Results.Keys) {
            if ($category -eq "SystemInfo") { continue }
            
            $items = $Results[$category]
            if ($items.Count -gt 0) {
                $report += "`n$($category.ToUpper()) ($($items.Count) items):`n"
                $report += "=" * ($category.Length + 20) + "`n"
                
                foreach ($item in $items) {
                    $report += "`nName: $($item.Name)"
                    if ($item.Path) { $report += "`nPath: $($item.Path)" }
                    if ($item.ConvertedValue) { $report += "`nValue: $($item.ConvertedValue)" }
                    elseif ($item.Value) { $report += "`nValue: $($item.Value)" }
                    if ($item.Type) { $report += "`nType: $($item.Type)" }
                    if ($item.LastWriteTime) { $report += "`nLast Modified: $($item.LastWriteTime)" }
                    if ($item.State) { $report += "`nState: $($item.State)" }
                    if ($item.StartMode) { $report += "`nStart Mode: $($item.StartMode)" }
                    $report += "`n" + "-" * 50 + "`n"
                }
            }
        }
        
        $report | Out-File -FilePath $outputFile -Encoding UTF8
    }
}

Write-Host "Report saved to: $outputFile" -ForegroundColor Cyan
Write-Host "Analysis Summary:" -ForegroundColor Green
foreach ($category in $Results.Keys) {
    if ($category -ne "SystemInfo") {
        $count = $Results[$category].Count
        if ($count -gt 0) {
            Write-Host "  $category`: $count items" -ForegroundColor White
        }
    }
}

# Return results for further processing if needed
return $Results
