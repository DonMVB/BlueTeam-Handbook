# Sysmon Event Log to JSON Converter
# Extracts Sysmon events and converts XML structure to JSON

# Configuration
$maxEvents = 1000
$outputFile = "Method_02_sysmon_events.json"
$logName = "Microsoft-Windows-Sysmon/Operational"

# Event IDs to skip - these are 'about sysmon', not end user data 
$skipEventIDs = @(4, 5, 16)

Write-Host "Starting Sysmon event extraction..." -ForegroundColor Cyan
Write-Host "Log: $logName" -ForegroundColor Gray
Write-Host "Max Events: $maxEvents" -ForegroundColor Gray
Write-Host "Output File: $outputFile" -ForegroundColor Gray
Write-Host "Skipping Event IDs: $($skipEventIDs -join ', ')" -ForegroundColor Gray
Write-Host ""

try {
    # Get Sysmon events (limited to $maxEvents Variable)
    Write-Host "Retrieving events from Sysmon log..." -ForegroundColor Yellow
    $events = Get-WinEvent -LogName $logName -MaxEvents $maxEvents -ErrorAction Stop
    
    Write-Host "Found $($events.Count) events" -ForegroundColor Green
    Write-Host "Converting events to JSON..." -ForegroundColor Yellow
    
    # Array to hold all converted events
    $jsonEvents = @()
    
    # Counter for progress
    $counter = 0
    $skippedCount = 0
    
    foreach ($event in $events) {
        $counter++
        if ($counter % 10 -eq 0) {
            Write-Host "  Processed $counter/$($events.Count) events..." -ForegroundColor Gray
        }
        
        # Convert the event to XML
        [xml]$eventXml = $event.ToXml()
        
        # Get Event ID
        $eventID = [int]$eventXml.Event.System.EventID
        
        # Skip if Event ID is in the skip list
        if ($skipEventIDs -contains $eventID) {
            $skippedCount++
            continue
        }
        
        # Create a custom object that preserves the XML hierarchy
        $eventObject = [PSCustomObject]@{
            System = [PSCustomObject]@{
                Provider = [PSCustomObject]@{
                    Name = $eventXml.Event.System.Provider.Name
                    Guid = $eventXml.Event.System.Provider.Guid
                }
                EventID = $eventXml.Event.System.EventID
                Version = $eventXml.Event.System.Version
                Level = $eventXml.Event.System.Level
                Task = $eventXml.Event.System.Task
                Opcode = $eventXml.Event.System.Opcode
                Keywords = $eventXml.Event.System.Keywords
                TimeCreated = [PSCustomObject]@{
                    SystemTime = $eventXml.Event.System.TimeCreated.SystemTime
                }
                EventRecordID = $eventXml.Event.System.EventRecordID
                Correlation = $eventXml.Event.System.Correlation
                Execution = [PSCustomObject]@{
                    ProcessID = $eventXml.Event.System.Execution.ProcessID
                    ThreadID = $eventXml.Event.System.Execution.ThreadID
                }
                Channel = $eventXml.Event.System.Channel
                Computer = $eventXml.Event.System.Computer
                Security = [PSCustomObject]@{
                    UserID = $eventXml.Event.System.Security.UserID
                }
            }
            EventData = @{}
        }       
        # Process EventData elements
        if ($eventXml.Event.EventData) {
            $dataNodes = $eventXml.Event.EventData.Data            
            if ($dataNodes) {
                foreach ($data in $dataNodes) {
                    $name = $data.Name
                    $value = $data.'#text'
                    
                    # Add to EventData dictionary
                    if ($name) {
                        $eventObject.EventData[$name] = $value
                    }
                }
            }
        }        
        # Add to array
        $jsonEvents += $eventObject
    }
    
    Write-Host ""
    Write-Host "Converting to JSON and writing to file..." -ForegroundColor Yellow
    
    # Convert to JSON with good formatting (depth 10 to ensure all nested objects are captured)
    $jsonOutput = $jsonEvents | ConvertTo-Json -Depth 10
    
    # Write to file
    $jsonOutput | Out-File -FilePath $outputFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "SUCCESS!" -ForegroundColor Green
    Write-Host "Exported $($jsonEvents.Count) events to $outputFile" -ForegroundColor Green
    if ($skippedCount -gt 0) {
        Write-Host "Skipped $skippedCount events (Event IDs: $($skipEventIDs -join ', '))" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Sample jq commands you can use:" -ForegroundColor Cyan
    Write-Host "  jq '.[].EventData.Image' $outputFile" -ForegroundColor Gray
    Write-Host "  jq '.[].System.EventID' $outputFile" -ForegroundColor Gray
    Write-Host "  jq '.[] | select(.System.EventID == \"1\")' $outputFile" -ForegroundColor Gray
    Write-Host "  jq '.[] | {EventID: .System.EventID, Image: .EventData.Image, Time: .System.TimeCreated.SystemTime}' $outputFile" -ForegroundColor Gray
    
} catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    if ($_.Exception.Message -like "*No events were found*") {
        Write-Host "HINT: Make sure Sysmon is installed and has logged events." -ForegroundColor Yellow
        Write-Host "You can check available event logs with: Get-WinEvent -ListLog *Sysmon*" -ForegroundColor Yellow
    }
    
    if ($_.Exception.Message -like "*does not exist*") {
        Write-Host "HINT: The Sysmon log was not found. Available Sysmon logs:" -ForegroundColor Yellow
        Get-WinEvent -ListLog *Sysmon* -ErrorAction SilentlyContinue | Select-Object LogName, RecordCount
    }
}
