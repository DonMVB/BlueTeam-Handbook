<#
.SYNOPSIS
  Export Sysmon events to JSON (preserve full XML hierarchy).

.DESCRIPTION
  - Default extracts up to 1000 events from Microsoft-Windows-Sysmon/Operational.
  - Converts the full event XML into a nested object (attributes under '@attributes').
  - Writes either a single JSON array or NDJSON (one JSON object per line).
#>

param(
  [string]$OutputPath = ".\Method_01_sysmon_events.json",
  [switch]$UseNdjson,                # If set, write NDJSON (one JSON object per line)
  [int]$MaxEvents = 1000             # Default to 1000 for quick testing
)

$logName = "Microsoft-Windows-Sysmon/Operational"

# Fetch events (limited)
Write-Host "Reading up to $MaxEvents events from $logName..."
$filter = @{ LogName = $logName }
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -Oldest

# Recursive XML -> PS object converter
function Convert-XmlNodeToObject {
  param([System.Xml.XmlNode]$node)

  if ($node.NodeType -eq [System.Xml.XmlNodeType]::Text -or $node.NodeType -eq [System.Xml.XmlNodeType]::CData) {
    return $node.Value
  }

  $childElements = @($node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
  $textChildren  = @($node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Text -or $_.NodeType -eq [System.Xml.XmlNodeType]::CData })

  if ($childElements.Count -eq 0 -and $textChildren.Count -gt 0) {
    return ($textChildren | ForEach-Object { $_.Value }) -join ""
  }

  $obj = [ordered]@{}

  if ($node.Attributes -and $node.Attributes.Count -gt 0) {
    $attr = [ordered]@{}
    foreach ($a in $node.Attributes) { $attr[$a.Name] = $a.Value }
    $obj['@attributes'] = $attr
  }

  foreach ($child in $childElements) {
    $childName = $child.Name
    $childValue = Convert-XmlNodeToObject -node $child

    # Use Contains for OrderedDictionary
    if ($obj.Contains($childName)) {
      # If existing value is an IList, add to it
      if ($obj[$childName] -is [System.Collections.IList]) {
        $obj[$childName].Add($childValue) | Out-Null
      } else {
        # Convert existing scalar to ArrayList and add new value
        $existing = $obj[$childName]
        $arr = New-Object System.Collections.ArrayList
        [void]$arr.Add($existing)
        [void]$arr.Add($childValue)
        $obj[$childName] = $arr
      }
    } else {
      $obj[$childName] = $childValue
    }
  }

  return $obj
}

function Convert-EventToObject {
  param($evt)

  try {
    $xml = [xml]$evt.ToXml()
  } catch {
    $xml = $null
  }

  $xmlHierarchy = $null
  if ($xml) {
    $xmlHierarchy = Convert-XmlNodeToObject -node $xml.Event
  }

  [PSCustomObject]@{
    TimeCreated      = $evt.TimeCreated
    RecordId         = $evt.RecordId
    ProviderName     = $evt.ProviderName
    Id               = $evt.Id
    LevelDisplayName = $evt.LevelDisplayName
    Message          = $evt.Message
    XmlHierarchy     = $xmlHierarchy
  }
}

# Ensure output directory exists
$resolvedOut = Resolve-Path -LiteralPath (Split-Path -Path $OutputPath -Parent) -ErrorAction SilentlyContinue
if (-not $resolvedOut) {
  $dir = Split-Path -Path $OutputPath -Parent
  if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

if ($UseNdjson) {
  $outPath = (Resolve-Path -LiteralPath $OutputPath).Path
  $outStream = [System.IO.StreamWriter]::new($outPath, $false, [System.Text.Encoding]::UTF8)
  try {
    foreach ($e in $events) {
      $obj = Convert-EventToObject -evt $e
      $json = $obj | ConvertTo-Json -Depth 20 -Compress
      $outStream.WriteLine($json)
    }
  } finally {
    $outStream.Close()
  }
  Write-Host "Wrote NDJSON to $outPath"
} else {
  $list = foreach ($e in $events) { Convert-EventToObject -evt $e }
  $json = $list | ConvertTo-Json -Depth 20
  $json | Out-File -FilePath $OutputPath -Encoding UTF8
  Write-Host "Wrote JSON array to $OutputPath"
}
