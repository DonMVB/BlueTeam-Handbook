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

# Ensure running with appropriate privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator. Some information may be unavailable."
}

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
    "AppInit" = @()
    "BootExecute" = @()
    "KnownDLLs" = @()
}

# Helper function to convert binary registry data to readable text
function Convert-RegistryData {
    param([object]$Data, [string]$ValueType)
    
    if ($null -eq $Data) { return "" }
    
    switch ($ValueType) {
        "Binary" {
            if ($Data -is [byte[]]) {
                # Try to extract readable strings
                $text = [System.Text.Encoding]::Unicode.GetString($Data) -replace '[^\x20-\x7E]', ''
                if ([string]::IsNullOrWhiteSpace($text)) {
                    $text = [System.Text.Encoding]::ASCII.GetString($Data) -replace '[^\x20-\x7E]', ''
                }
                $hex = [BitConverter]::ToString($Data) -replace '-',''
                if ($text.Length -gt 10) {
                    return $text.Trim()
                } else {
                    return "0x$hex"
                }
            }
            return $Data.ToString()
        }
        "DWord" { return $Data }
        "QWord" { return $Data }
        "MultiString" { 
            if ($Data -is [array]) {
                return ($Data -join '; ')
            }
            return $Data 
        }
        "ExpandString" { 
            try {
                return [Environment]::ExpandEnvironmentVariables($Data)
            } catch {
                return $Data
            }
        }
        default { return $Data.ToString() }
    }
}

# Helper function to safely get registry values - FIXED VERSION
function Get-SafeRegistryValue {
    param(
        [string]$Path, 
        [string]$Name = $null,
        [switch]$AllValues
    )
    
    try {
        # Remove any "Registry::" prefix if present
        $cleanPath = $Path -replace '^Registry::', ''
        
        # Test if the path exists
        if (-not (Test-Path -Path "Registry::$cleanPath" -ErrorAction SilentlyContinue)) {
            return $null
        }
        
        $key = Get-Item -Path "Registry::$cleanPath" -ErrorAction Stop
        
        if ($Name) {
            # Get specific value
            if ($key.Property -contains $Name) {
                $value = $key.GetValue($Name, $null)
                $valueType = $key.GetValueKind($Name)
                return @{
                    Value = $value
                    Type = $valueType.ToString()
                    ConvertedValue = Convert-RegistryData -Data $value -ValueType $valueType.ToString()
                }
            }
            return $null
        } else {
            # Get all values
            $values = @()
            foreach ($valueName in $key.Property) {
                try {
                    $value = $key.GetValue($valueName, $null)
                    $valueType = $key.GetValueKind($valueName)
                    $converted = Convert-RegistryData -Data $value -ValueType $valueType.ToString()
                    
                    $values += @{
                        Name = $valueName
                        Value = $value
                        Type = $valueType.ToString()
                        ConvertedValue = $converted
                        Path = $cleanPath
                    }
                } catch {
                    Write-Verbose "Error reading value '$valueName' from $cleanPath"
                }
            }
            return $values
        }
    }
    catch {
        Write-Verbose "Error accessing registry path $Path - $($_.Exception.Message)"
        return $null
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows ASEP Analysis Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Collect System Information
Write-Host "[*] Collecting system information..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$Results.SystemInfo = @{
    ComputerName = $env:COMPUTERNAME
    OSVersion = $os.Caption
    OSBuild = $os.BuildNumber
    Architecture = $os.OSArchitecture
    CurrentUser = $env:USERNAME
    Domain = $env:USERDOMAIN
    ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PSVersion = $PSVersionTable.PSVersion.ToString()
    IsAdmin = $isAdmin
}

# 1. RUN KEYS - FIXED
Write-Host "[*] Analyzing Run Keys..." -ForegroundColor Yellow
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
    if ($values -and $values.Count -gt 0) {
        foreach ($val in $values) {
            $Results.RunKeys += [PSCustomObject]@{
                Category = "Run Keys"
                Name = $val.Name
                Path = $val.Path
                Value = $val.ConvertedValue
                Type = $val.Type
            }
        }
        Write-Host "  [+] Found $($values.Count) entries in $path" -ForegroundColor Green
    }
}

# 2. WINLOGON ENTRIES - FIXED
Write-Host "[*] Analyzing Winlogon entries..." -ForegroundColor Yellow
$WinlogonKeys = @(
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="Userinit"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="Shell"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="System"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="TaskMan"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="VmApplet"},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"; Value=$null},
    @{Path="HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Value="Shell"}
)

foreach ($item in $WinlogonKeys) {
    $value = Get-SafeRegistryValue -Path $item.Path -Name $item.Value
    if ($value -and $value.ConvertedValue) {
        $Results.Winlogon += [PSCustomObject]@{
            Category = "Winlogon"
            Name = $item.Value
            Path = $item.Path
            Value = $value.ConvertedValue
            Type = $value.Type
        }
        Write-Host "  [+] Found: $($item.Value)" -ForegroundColor Green
    }
}

# AppInit_DLLs
$appInitPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
)
foreach ($path in $appInitPaths) {
    $value = Get-SafeRegistryValue -Path $path -Name "AppInit_DLLs"
    if ($value -and $value.ConvertedValue) {
        $Results.AppInit += [PSCustomObject]@{
            Category = "AppInit DLLs"
            Name = "AppInit_DLLs"
            Path = $path
            Value = $value.ConvertedValue
            Type = $value.Type
        }
        Write-Host "  [+] Found AppInit_DLLs" -ForegroundColor Green
    }
}

# 3. SERVICES - FIXED
Write-Host "[*] Analyzing Services..." -ForegroundColor Yellow
try {
    $services = Get-CimInstance Win32_Service | Where-Object { 
        $_.StartMode -in @("Auto", "Automatic")
    }
    
    foreach ($service in $services) {
        $Results.Services += [PSCustomObject]@{
            Category = "Services"
            Name = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartMode = $service.StartMode
            StartName = $service.StartName
            State = $service.State
            ServiceType = $service.ServiceType
        }
    }
    Write-Host "  [+] Found $($services.Count) auto-start services" -ForegroundColor Green
}
catch {
    Write-Warning "Error collecting services: $($_.Exception.Message)"
}

# 4. SCHEDULED TASKS - FIXED
Write-Host "[*] Analyzing Scheduled Tasks..." -ForegroundColor Yellow
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
        $_.State -eq "Ready" -and $_.Settings.Enabled -eq $true 
    }
    
    $taskCount = 0
    foreach ($task in $tasks) {
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            $actions = (Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue).Actions
            
            foreach ($action in $actions) {
                $actionStr = ""
                if ($action.Execute) {
                    $actionStr = "$($action.Execute)"
                    if ($action.Arguments) {
                        $actionStr += " $($action.Arguments)"
                    }
                }
                
                $Results.ScheduledTasks += [PSCustomObject]@{
                    Category = "Scheduled Tasks"
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    State = $task.State
                    LastRunTime = if($taskInfo) { $taskInfo.LastRunTime.ToString() } else { "Unknown" }
                    NextRunTime = if($taskInfo) { $taskInfo.NextRunTime.ToString() } else { "Unknown" }
                    Action = $actionStr
                    Author = $task.Author
                }
                $taskCount++
            }
        }
        catch {
            Write-Verbose "Error processing task $($task.TaskName) - $($_.Exception.Message)"
        }
    }
    Write-Host "  [+] Found $taskCount enabled tasks" -ForegroundColor Green
}
catch {
    Write-Warning "Error collecting scheduled tasks: $($_.Exception.Message)"
}

# 5. STARTUP FOLDERS - FIXED
Write-Host "[*] Analyzing Startup Folders..." -ForegroundColor Yellow
$StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $StartupPaths) {
    if (Test-Path $path) {
        $items = Get-ChildItem $path -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            # For shortcuts, try to get target
            $target = ""
            if ($item.Extension -eq ".lnk") {
                try {
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($item.FullName)
                    $target = $shortcut.TargetPath
                } catch {
                    $target = "Unable to resolve"
                }
            }
            
            $Results.StartupFolders += [PSCustomObject]@{
                Category = "Startup Folders"
                Name = $item.Name
                Path = $item.FullName
                Target = $target
                Type = if($item.PSIsContainer) { "Folder" } else { $item.Extension }
                LastWriteTime = $item.LastWriteTime.ToString()
                Size = if(-not $item.PSIsContainer) { $item.Length } else { 0 }
            }
        }
        if ($items.Count -gt 0) {
            Write-Host "  [+] Found $($items.Count) items in $path" -ForegroundColor Green
        }
    }
}

# 6. BROWSER HELPER OBJECTS - FIXED
Write-Host "[*] Analyzing Browser Helper Objects..." -ForegroundColor Yellow
$BHOPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
)

$bhoCount = 0
foreach ($path in $BHOPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $bhos = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($bho in $bhos) {
                $clsid = $bho.PSChildName
                
                # Try multiple locations for CLSID info
                $clsidPaths = @(
                    "HKLM\SOFTWARE\Classes\CLSID\$clsid",
                    "HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\$clsid",
                    "HKCU\SOFTWARE\Classes\CLSID\$clsid"
                )
                
                $description = ""
                $dllPath = ""
                
                foreach ($clsidPath in $clsidPaths) {
                    if (-not $description) {
                        $desc = Get-SafeRegistryValue -Path $clsidPath -Name "(Default)"
                        if ($desc -and $desc.ConvertedValue) { $description = $desc.ConvertedValue }
                    }
                    if (-not $dllPath) {
                        $dll = Get-SafeRegistryValue -Path "$clsidPath\InProcServer32" -Name "(Default)"
                        if ($dll -and $dll.ConvertedValue) { $dllPath = $dll.ConvertedValue }
                    }
                }
                
                $Results.BrowserHelperObjects += [PSCustomObject]@{
                    Category = "Browser Helper Objects"
                    CLSID = $clsid
                    Description = if($description) { $description } else { "Unknown" }
                    DLLPath = if($dllPath) { $dllPath } else { "Unknown" }
                    RegistryPath = $path
                }
                $bhoCount++
            }
        }
    }
    catch {
        Write-Verbose "Error analyzing BHOs at $path - $($_.Exception.Message)"
    }
}
if ($bhoCount -gt 0) {
    Write-Host "  [+] Found $bhoCount BHOs" -ForegroundColor Green
}

# 7. SHELL EXTENSIONS - Sample
Write-Host "[*] Analyzing Shell Extensions..." -ForegroundColor Yellow
$ShellExtPaths = @(
    "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
    "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
    "HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers"
)

$shellExtCount = 0
foreach ($path in $ShellExtPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $handlers = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($handler in $handlers) {
                $handlerPath = $handler.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
                $clsidVal = Get-SafeRegistryValue -Path $handlerPath -Name "(Default)"
                
                $Results.ShellExtensions += [PSCustomObject]@{
                    Category = "Shell Extensions"
                    HandlerName = $handler.PSChildName
                    CLSID = if($clsidVal) { $clsidVal.ConvertedValue } else { "Unknown" }
                    Type = $path.Split('\')[-2]
                    RegistryPath = $path
                }
                $shellExtCount++
            }
        }
    }
    catch {
        Write-Verbose "Error analyzing shell extensions at $path"
    }
}
if ($shellExtCount -gt 0) {
    Write-Host "  [+] Found $shellExtCount shell extensions" -ForegroundColor Green
}

# 8. WMI EVENT SUBSCRIPTIONS - FIXED
Write-Host "[*] Analyzing WMI Event Subscriptions..." -ForegroundColor Yellow
try {
    $wmiConsumers = Get-CimInstance -Namespace "root\subscription" -ClassName "__EventConsumer" -ErrorAction SilentlyContinue
    foreach ($consumer in $wmiConsumers) {
        $Results.WMISubscriptions += [PSCustomObject]@{
            Category = "WMI Subscriptions"
            Name = $consumer.Name
            Class = $consumer.CimClass.CimClassName
            CreatorSID = $consumer.CreatorSID
        }
    }
    if ($wmiConsumers.Count -gt 0) {
        Write-Host "  [+] Found $($wmiConsumers.Count) WMI consumers" -ForegroundColor Green
    }
}
catch {
    Write-Verbose "Error collecting WMI subscriptions: $($_.Exception.Message)"
}

# 9. ACTIVE SETUP - FIXED
Write-Host "[*] Analyzing Active Setup..." -ForegroundColor Yellow
$ActiveSetupPaths = @(
    "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components"
)

$activeSetupCount = 0
foreach ($path in $ActiveSetupPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $components = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($component in $components) {
                $compPath = $component.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
                $stubPath = Get-SafeRegistryValue -Path $compPath -Name "StubPath"
                
                if ($stubPath -and $stubPath.ConvertedValue) {
                    $Results.ActiveSetup += [PSCustomObject]@{
                        Category = "Active Setup"
                        ComponentID = $component.PSChildName
                        StubPath = $stubPath.ConvertedValue
                        RegistryPath = $path
                    }
                    $activeSetupCount++
                }
            }
        }
    }
    catch {
        Write-Verbose "Error analyzing Active Setup at $path"
    }
}
if ($activeSetupCount -gt 0) {
    Write-Host "  [+] Found $activeSetupCount Active Setup entries" -ForegroundColor Green
}

# 10. IMAGE FILE EXECUTION OPTIONS - FIXED
Write-Host "[*] Analyzing Image File Execution Options..." -ForegroundColor Yellow
$IFEOPaths = @(
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
)

$ifeoCount = 0
foreach ($path in $IFEOPaths) {
    try {
        if (Test-Path "Registry::$path") {
            $executables = Get-ChildItem "Registry::$path" -ErrorAction SilentlyContinue
            foreach ($exe in $executables) {
                $exePath = $exe.Name -replace 'HKEY_LOCAL_MACHINE', 'HKLM'
                $debugger = Get-SafeRegistryValue -Path $exePath -Name "Debugger"
                
                if ($debugger -and $debugger.ConvertedValue) {
                    $Results.ImageFileExecution += [PSCustomObject]@{
                        Category = "Image File Execution Options"
                        Executable = $exe.PSChildName
                        Debugger = $debugger.ConvertedValue
                        RegistryPath = $path
                    }
                    $ifeoCount++
                }
            }
        }
    }
    catch {
        Write-Verbose "Error analyzing IFEO at $path"
    }
}
if ($ifeoCount -gt 0) {
    Write-Host "  [+] Found $ifeoCount IFEO entries" -ForegroundColor Green
}

# 11. BOOT EXECUTE
Write-Host "[*] Analyzing Boot Execute..." -ForegroundColor Yellow
$bootExec = Get-SafeRegistryValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute"
if ($bootExec -and $bootExec.ConvertedValue) {
    $Results.BootExecute += [PSCustomObject]@{
        Category = "Boot Execute"
        Name = "BootExecute"
        Value = $bootExec.ConvertedValue
        Path = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"
    }
    Write-Host "  [+] Found BootExecute entry" -ForegroundColor Green
}

# 12. POWERSHELL PROFILES
Write-Host "[*] Analyzing PowerShell Profiles..." -ForegroundColor Yellow
$ProfilePaths = @(
    $PROFILE.CurrentUserCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.AllUsersAllHosts
)

foreach ($profilePath in $ProfilePaths) {
    if ($profilePath -and (Test-Path $profilePath -ErrorAction SilentlyContinue)) {
        try {
            $content = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
            $preview = if ($content.Length -gt 200) { $content.Substring(0, 200) + "..." } else { $content }
            
            $Results.PowerShellProfiles += [PSCustomObject]@{
                Category = "PowerShell Profiles"
                ProfilePath = $profilePath
                LastModified = (Get-Item $profilePath).LastWriteTime.ToString()
                SizeBytes = (Get-Item $profilePath).Length
                Preview = $preview
            }
            Write-Host "  [+] Found profile: $profilePath" -ForegroundColor Green
        }
        catch {
            Write-Verbose "Error reading profile $profilePath"
        }
    }
}

# 13. DRIVERS - FIXED
Write-Host "[*] Analyzing Drivers..." -ForegroundColor Yellow
try {
    $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { 
        $_.StartMode -in @("Auto", "System", "Boot")
    }
    
    foreach ($driver in $drivers) {
        $Results.Drivers += [PSCustomObject]@{
            Category = "Drivers"
            Name = $driver.Name
            DisplayName = $driver.DisplayName
            PathName = $driver.PathName
            StartMode = $driver.StartMode
            State = $driver.State
            ServiceType = $driver.ServiceType
        }
    }
    Write-Host "  [+] Found $($drivers.Count) auto-start drivers" -ForegroundColor Green
}
catch {
    Write-Warning "Error collecting drivers: $($_.Exception.Message)"
}

Write-Host "`n[*] Analysis complete. Generating report..." -ForegroundColor Green

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
        if ($allResults.Count -gt 0) {
            $allResults | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        } else {
            Write-Warning "No data to export!"
        }
    }
    "JSON" {
        $outputFile += ".json"
        $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    }
    default {
        $outputFile += ".txt"
        $report = @"
================================================================
WINDOWS AUTO START EXTENSIBILITY POINTS (ASEP) ANALYSIS REPORT
================================================================

System Information:
------------------
Computer:      $($Results.SystemInfo.ComputerName)
OS:            $($Results.SystemInfo.OSVersion)
Build:         $($Results.SystemInfo.OSBuild)
Architecture:  $($Results.SystemInfo.Architecture)
User:          $($Results.SystemInfo.CurrentUser)
Domain:        $($Results.SystemInfo.Domain)
Scan Date:     $($Results.SystemInfo.ScanDate)
PowerShell:    $($Results.SystemInfo.PSVersion)
Admin Rights:  $($Results.SystemInfo.IsAdmin)

================================================================

"@
        
        foreach ($category in $Results.Keys | Sort-Object) {
            if ($category -eq "SystemInfo") { continue }
            
            $items = $Results[$category]
            if ($items.Count -gt 0) {
                $report += "`n$($category.ToUpper()) - $($items.Count) item(s)`n"
                $report += "=" * 70 + "`n"
                
                foreach ($item in $items) {
                    foreach ($prop in $item.PSObject.Properties) {
                        if ($prop.Value -and $prop.Name -ne "Category") {
                            $report += "$($prop.Name): $($prop.Value)`n"
                        }
                    }
                    $report += "-" * 70 + "`n"
                }
            }
        }
        
        $report | Out-File -FilePath $outputFile -Encoding UTF8
    }
}

Write-Host "`n[+] Report saved to: $outputFile" -ForegroundColor Cyan

# Display summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalItems = 0
foreach ($category in $Results.Keys | Sort-Object) {
    if ($category -ne "SystemInfo") {
        $count = $Results[$category].Count
        if ($count -gt 0) {
            Write-Host ("{0,-30} : {1,5}" -f $category, $count) -ForegroundColor White
            $totalItems += $count
        }
    }
}
Write-Host ("=" * 40) -ForegroundColor Cyan
Write-Host ("{0,-30} : {1,5}" -f "TOTAL ITEMS", $totalItems) -ForegroundColor Green
Write-Host "`n"

return $Results
