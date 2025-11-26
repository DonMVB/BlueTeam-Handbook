# Also - SAC does write to an event log, IF the event log is enabled. It is! But .. alas .. no 3076 events. 
# CoPilot gave me this code. I'll see if I can enable the log as a first action. Code below (can't be tested though, sad face)
# For audit mode - [[ this is completely untested, but it looks like it might work ... ]]

# Import the ConfigCI module
Import-Module ConfigCI

# Create a default policy in Audit mode
New-CIPolicy -Level FilePublisher -Fallback Hash -UserPEs -Audit -FilePath "C:\Temp\SACAudit.xml"

# Deploy the policy
Set-RuleOption -FilePath "C:\Temp\SACAudit.xml" -Option 3 # Option 3 is Audit Mode

# Convert the policy to binary and deploy
ConvertFrom-CIPolicy -XmlFilePath "C:\Temp\SACAudit.xml" -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SACAudit.bin"

Then to get logs

# Extract Smart App Control block events for 'Stag Lord.docx' using XML overlay

$logName = 'Microsoft-Windows-CodeIntegrity/Operational'
$eventId = 3076  # Adjust if your SAC block events use a different Event ID

Get-WinEvent -LogName $logName -FilterXPath "*[System/EventID=$eventId]" | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $fileName = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'FileName' } | Select-Object -ExpandProperty '#text'
    if ($fileName -like '*Stag Lord.docx*') {
        [PSCustomObject]@{
            Date      = $xml.Event.System.TimeCreated.SystemTime
            FileName  = $fileName
            Action    = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Action' } | Select-Object -ExpandProperty '#text'
            User      = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'User' } | Select-Object -ExpandProperty '#text'
        }
    }
}
