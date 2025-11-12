$RunKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($path in $RunKeyPaths) {
    Write-Host "Analyzing: $path"     
    if (Test-Path $path) {
        try {
            $regItems = Get-ItemProperty -Path $path -ErrorAction Stop            
            # Get all property names except the default PowerShell properties
            $propertyNames = $regItems.PSObject.Properties.Name | Where-Object {
                $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
            }
            
            if ($propertyNames.Count -gt 0) {
                foreach ($propertyName in $propertyNames) {
                    $value = $regItems.$propertyName
                    $dataType = $value.GetType().Name                    
                    Write-Host "  Name: $propertyName" 
                    Write-Host "  Data: $value"
                }
            } else {
                Write-Host "  No startup entries found in this key" 
            }
        }
        catch {
            Write-Host "  Error reading registry key: $($_.Exception.Message)"
        }
    } else {
        Write-Host "  Path does not exist: $path"     
    }
    Write-Host "-----"
}
