# Drive and Partition Inventory Script
# Gets detailed information about physical drives and their partitions

function Get-DriveInventory {
    Write-Host "=== PHYSICAL DRIVE AND PARTITION INVENTORY ===" -ForegroundColor Green
    Write-Host "Generated: $(Get-Date)" -ForegroundColor Gray
    Write-Host ""
    
    try {
        # Get all physical disks
        $physicalDisks = Get-WmiObject -Class Win32_DiskDrive | Sort-Object Index
        
        foreach ($disk in $physicalDisks) {
            Write-Host "Physical Drive $($disk.Index): $($disk.Model)" -ForegroundColor Yellow
            Write-Host "  Size: $([math]::Round($disk.Size / 1GB, 2)) GB ($([math]::Round($disk.Size / 1TB, 2)) TB)" -ForegroundColor White
            Write-Host "  Interface: $($disk.InterfaceType)" -ForegroundColor White
            Write-Host "  Serial: $($disk.SerialNumber)" -ForegroundColor White
            Write-Host ""
            
            # Get partitions for this physical disk
            $partitions = Get-WmiObject -Class Win32_DiskPartition | Where-Object { $_.DiskIndex -eq $disk.Index } | Sort-Object Index
            
            if ($partitions) {
                Write-Host "  Partitions:" -ForegroundColor Cyan
                
                foreach ($partition in $partitions) {
                    $sizeGB = [math]::Round($partition.Size / 1GB, 2)
                    $startOffset = [math]::Round($partition.StartingOffset / 1GB, 2)
                    
                    # Determine if partition is hidden - only if explicitly marked as hidden
                    $isHidden = $false
                    $hiddenIndicator = ""
                    
                    # Only mark as hidden if the type specifically contains "Hidden"
                    if ($partition.Type -match "Hidden") {
                        $isHidden = $true
                        $hiddenIndicator = " [HIDDEN]"
                    }
                    
                    # Check if it's a recovery partition by name or type
                    if ($partition.Type -match "Recovery|WINRE") {
                        $hiddenIndicator = " [RECOVERY]"
                        $isHidden = $true
                    }
                    
                    Write-Host "    Partition $($partition.Index): $($partition.Type)$hiddenIndicator" -ForegroundColor White
                    Write-Host "      Size: $sizeGB GB" -ForegroundColor Gray
                    Write-Host "      Start Offset: $startOffset GB" -ForegroundColor Gray
                    Write-Host "      Bootable: $($partition.BootPartition)" -ForegroundColor Gray
                    Write-Host "      Primary: $($partition.PrimaryPartition)" -ForegroundColor Gray
                    
                    # Try to get logical disk (drive letter) associated with this partition
                    $logicalDisks = Get-WmiObject -Class Win32_LogicalDiskToPartition | Where-Object { $_.Antecedent -like "*$($partition.DeviceID.Replace('\', '\\'))*" }
                    
                    if ($logicalDisks) {
                        foreach ($logicalDiskRel in $logicalDisks) {
                            $driveLetter = ($logicalDiskRel.Dependent -split '"')[1]
                            $logicalDisk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $driveLetter }
                            
                            if ($logicalDisk) {
                                $freeSpaceGB = [math]::Round($logicalDisk.FreeSpace / 1GB, 2)
                                $usedSpaceGB = [math]::Round(($logicalDisk.Size - $logicalDisk.FreeSpace) / 1GB, 2)
                                
                                Write-Host "        Mounted as: $($logicalDisk.DeviceID) [$($logicalDisk.FileSystem)]" -ForegroundColor Green
                                Write-Host "        Label: '$($logicalDisk.VolumeName)'" -ForegroundColor Green
                                Write-Host "        Used: $usedSpaceGB GB | Free: $freeSpaceGB GB" -ForegroundColor Green
                            }
                        }
                    } else {
                        if (-not $isHidden) {
                            Write-Host "        Not mounted (no drive letter)" -ForegroundColor Red
                        } else {
                            Write-Host "        Hidden partition (not accessible)" -ForegroundColor Magenta
                        }
                    }
                    Write-Host ""
                }
            } else {
                Write-Host "  No partitions found or disk not initialized" -ForegroundColor Red
                Write-Host ""
            }
            
            Write-Host "  " + ("-" * 60) -ForegroundColor DarkGray
            Write-Host ""
        }
        
        # Additional system information
        Write-Host "=== ADDITIONAL VOLUME INFORMATION ===" -ForegroundColor Green
        
        # Get all volumes including hidden ones using Get-Volume (requires PowerShell 3.0+)
        try {
            $volumes = Get-Volume | Sort-Object DriveLetter
            Write-Host "All Volumes (including hidden):" -ForegroundColor Cyan
            
            foreach ($volume in $volumes) {
                $sizeGB = [math]::Round($volume.Size / 1GB, 2)
                $freeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $driveLetter = if ($volume.DriveLetter) { "$($volume.DriveLetter):" } else { "No Letter" }
                
                Write-Host "  $driveLetter - '$($volume.FileSystemLabel)' [$($volume.FileSystem)] - $sizeGB GB" -ForegroundColor White
                Write-Host "    Health: $($volume.HealthStatus) | Operational: $($volume.OperationalStatus)" -ForegroundColor Gray
                
                if ($volume.DriveLetter -eq $null -and $volume.FileSystem) {
                    Write-Host "      Hidden/System Volume" -ForegroundColor Magenta
                }
                Write-Host ""
            }
        } catch {
            Write-Host "Get-Volume cmdlet not available (PowerShell version < 3.0)" -ForegroundColor Yellow
        }
        
        # Show EFI System Partitions and Recovery partitions specifically
        Write-Host "=== SPECIAL PARTITIONS DETECTED ===" -ForegroundColor Green
        
        # Look for common special partition types
        $allPartitions = Get-WmiObject -Class Win32_DiskPartition
        $specialPartitions = $allPartitions | Where-Object { 
            $_.Type -match "EFI|Recovery|System|Hidden" -or 
            $_.Size -lt 1GB -and $_.BootPartition -eq $true 
        }
        
        if ($specialPartitions) {
            foreach ($special in $specialPartitions) {
                $sizeGB = [math]::Round($special.Size / 1GB, 2)
                Write-Host "  Disk $($special.DiskIndex), Partition $($special.Index): $($special.Type) ($sizeGB GB)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "  No special system partitions detected" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to export results to file
function Export-DriveInventory {
    param(
        [string]$OutputPath = ".\DriveInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    )
    
    Start-Transcript -Path $OutputPath -Append
    Get-DriveInventory
    Stop-Transcript
    
    Write-Host "Inventory exported to: $OutputPath" -ForegroundColor Green
}

# Main execution
Write-Host "Drive Inventory Script" -ForegroundColor Green
Write-Host "Choose an option:" -ForegroundColor Yellow
Write-Host "1. Display inventory on screen" -ForegroundColor White
Write-Host "2. Export inventory to file" -ForegroundColor White
Write-Host "3. Both display and export" -ForegroundColor White

$choice = Read-Host "Enter choice (1-3)"

switch ($choice) {
    "1" { Get-DriveInventory }
    "2" { 
        $outputPath = Read-Host "Enter output file path (or press Enter for default)"
        if ([string]::IsNullOrWhiteSpace($outputPath)) {
            Export-DriveInventory
        } else {
            Export-DriveInventory -OutputPath $outputPath
        }
    }
    "3" {
        Get-DriveInventory
        Write-Host ""
        Write-Host "Also exporting to file..." -ForegroundColor Yellow
        Export-DriveInventory
    }
    default {
        Write-Host "Invalid choice. Running default inventory display." -ForegroundColor Yellow
        Get-DriveInventory
    }
}
