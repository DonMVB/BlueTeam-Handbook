<#
.SYNOPSIS
    actually-get-sysmon-events.ps1
    Reads Sysmon events in chronological order and prints a clean,
    meaningful summary line per event.

.DESCRIPTION
    Columns printed:
        Time        - Event timestamp (local time, yyyy-MM-dd HH:mm:ss)
        ID          - Sysmon Event ID
        Type        - Human-readable event type name
        Process     - The EXE that caused the event (basename only)
        Detail      - The most meaningful field(s) for that event type

.PARAMETER MaxEvents
    Maximum total events to display across all requested event IDs.
    When filtering by -EventIds, each ID is fetched separately and the
    results are merged and sorted before the limit is applied, so you
    get the most recent N events across all requested types in true
    time order.
    Default: 0 (all events).
    E.g.  .\get-sysmon-events-merged.ps1 -MaxEvents 500

.PARAMETER EventIds
    One or more Sysmon Event IDs to filter on. Accepts a comma-separated
    list or repeated values. When multiple IDs are given, events are
    fetched per-ID, merged, and sorted into true chronological order.
    Default: all event IDs.
    E.g.  .\get-sysmon-events-merged.ps1 -EventIds 1
          .\get-sysmon-events-merged.ps1 -EventIds 1,3,22
          .\get-sysmon-events-merged.ps1 -EventIds 1 -EventIds 3 -EventIds 22

.PARAMETER Since
    Only show events at or after this datetime.
    E.g.  .\get-sysmon-events-merged.ps1 -Since "2026-06-09 08:00:00"

.PARAMETER ProcessName
    Filter to events where the process name contains this string (case-insensitive).
    Applied after fetching, so does not affect -MaxEvents counting.
    E.g.  .\get-sysmon-events-merged.ps11 -ProcessName powershell

.EXAMPLE
    # All events
    .\get-sysmon-events-merged.ps1

    # Last 200 process-create events
    .\get-sysmon-events-merged.ps1 -EventIds 1 -MaxEvents 200

    # Last 500 events that are either process-create, network, or DNS — intermingled in time order
    .\get-sysmon-events-merged.ps1 -EventIds 1,3,22 -MaxEvents 500

    # Everything since this morning involving PowerShell
    .\get-sysmon-events-merged.ps1 -Since "2026-06-09 08:00:00" -ProcessName powershell

    # Injection-focused view: remote thread + process access
    .\get-sysmon-events-merged.ps1-EventIds 8,10 -MaxEvents 100
#>

[CmdletBinding()]
param(
    [int]    $MaxEvents   = 0,
    [int[]]  $EventIds    = @(),
    [string] $Since       = "",
    [string] $ProcessName = ""
)

# ---------------------------------------------------------------------------
# Helper: pull a named field out of Sysmon's EventData XML
# ---------------------------------------------------------------------------
function Get-Field {
    param($DataNodes, [string]$Name)
    $node = $DataNodes | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { return $node.'#text' } else { return "" }
}

# ---------------------------------------------------------------------------
# Helper: return just the EXE basename from a full path
# ---------------------------------------------------------------------------
function Get-ExeName {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return "(unknown)" }
    return [System.IO.Path]::GetFileName($Path)
}

# ---------------------------------------------------------------------------
# Per-event-ID logic: returns the "Process" column and the "Detail" string
# ---------------------------------------------------------------------------
function Get-EventSummary {
    param($DataNodes, [int]$Id)

    $exe    = ""
    $detail = ""

    switch ($Id) {

        1 {  # Process Create
            $image   = Get-Field $DataNodes "Image"
            $cmdline = Get-Field $DataNodes "CommandLine"
            $parent  = Get-Field $DataNodes "ParentImage"
            $user    = Get-Field $DataNodes "User"
            $exe     = Get-ExeName $image
            $detail  = "CMD=[$cmdline]  Parent=$(Get-ExeName $parent)  User=$user"
        }

        2 {  # File Creation Time Changed
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $newt   = Get-Field $DataNodes "CreationUtcTime"
            $oldt   = Get-Field $DataNodes "PreviousCreationUtcTime"
            $exe    = Get-ExeName $image
            $detail = "File=$target  NewTime=$newt  OldTime=$oldt"
        }

        3 {  # Network Connection
            $image   = Get-Field $DataNodes "Image"
            $dstIp   = Get-Field $DataNodes "DestinationIp"
            $dstPort = Get-Field $DataNodes "DestinationPort"
            $srcIp   = Get-Field $DataNodes "SourceIp"
            $srcPort = Get-Field $DataNodes "SourcePort"
            $proto   = Get-Field $DataNodes "Protocol"
            $dstHost = Get-Field $DataNodes "DestinationHostname"
            $user    = Get-Field $DataNodes "User"
            $exe     = Get-ExeName $image
            $dest    = if ($dstHost) { "$dstHost ($dstIp)" } else { $dstIp }
            $detail  = "$proto  $srcIp`:$srcPort -> $dest`:$dstPort  User=$user"
        }

        4 {  # Sysmon Service State Changed
            $state   = Get-Field $DataNodes "State"
            $version = Get-Field $DataNodes "Version"
            $exe     = "Sysmon"
            $detail  = "State=$state  Version=$version"
        }

        5 {  # Process Terminated
            $image = Get-Field $DataNodes "Image"
            $pid   = Get-Field $DataNodes "ProcessId"
            $exe   = Get-ExeName $image
            $detail = "PID=$pid  Path=$image"
        }

        6 {  # Driver Loaded
            $img     = Get-Field $DataNodes "ImageLoaded"
            $signed  = Get-Field $DataNodes "Signed"
            $sig     = Get-Field $DataNodes "Signature"
            $hashes  = Get-Field $DataNodes "Hashes"
            $exe     = Get-ExeName $img
            $detail  = "Driver=$img  Signed=$signed  Signer=$sig  $hashes"
        }

        7 {  # Image (DLL) Loaded
            $image  = Get-Field $DataNodes "Image"
            $loaded = Get-Field $DataNodes "ImageLoaded"
            $signed = Get-Field $DataNodes "Signed"
            $sig    = Get-Field $DataNodes "Signature"
            $exe    = Get-ExeName $image
            $detail = "DLL=$(Get-ExeName $loaded)  Signed=$signed  Signer=$sig  FullPath=$loaded"
        }

        8 {  # CreateRemoteThread
            $src   = Get-Field $DataNodes "SourceImage"
            $tgt   = Get-Field $DataNodes "TargetImage"
            $tid   = Get-Field $DataNodes "NewThreadId"
            $addr  = Get-Field $DataNodes "StartAddress"
            $exe   = Get-ExeName $src
            $detail = "Source=$(Get-ExeName $src) -> Target=$(Get-ExeName $tgt)  TID=$tid  StartAddr=$addr"
        }

        9 {  # RawAccessRead
            $image  = Get-Field $DataNodes "Image"
            $device = Get-Field $DataNodes "Device"
            $exe    = Get-ExeName $image
            $detail = "Device=$device"
        }

        10 {  # ProcessAccess
            $src    = Get-Field $DataNodes "SourceImage"
            $tgt    = Get-Field $DataNodes "TargetImage"
            $access = Get-Field $DataNodes "GrantedAccess"
            $trace  = Get-Field $DataNodes "CallTrace"
            $exe    = Get-ExeName $src
            $detail = "Source=$(Get-ExeName $src) -> Target=$(Get-ExeName $tgt)  Access=$access  Trace=$trace"
        }

        11 {  # FileCreate
            $image   = Get-Field $DataNodes "Image"
            $target  = Get-Field $DataNodes "TargetFilename"
            $created = Get-Field $DataNodes "CreationUtcTime"
            $exe     = Get-ExeName $image
            $detail  = "File=$target  Created=$created"
        }

        12 {  # Registry Object Create/Delete
            $image  = Get-Field $DataNodes "Image"
            $evtype = Get-Field $DataNodes "EventType"
            $target = Get-Field $DataNodes "TargetObject"
            $exe    = Get-ExeName $image
            $detail = "Op=$evtype  Key=$target"
        }

        13 {  # Registry Value Set
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetObject"
            $deets  = Get-Field $DataNodes "Details"
            $exe    = Get-ExeName $image
            $detail = "Key=$target  Value=$deets"
        }

        14 {  # Registry Key/Value Renamed
            $image   = Get-Field $DataNodes "Image"
            $target  = Get-Field $DataNodes "TargetObject"
            $newname = Get-Field $DataNodes "NewName"
            $exe     = Get-ExeName $image
            $detail  = "OldKey=$target  NewKey=$newname"
        }

        15 {  # FileCreateStreamHash (ADS)
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $hashes = Get-Field $DataNodes "Hash"
            $exe    = Get-ExeName $image
            $detail = "ADS=$target  Hashes=$hashes"
        }

        16 {  # Sysmon Config State Changed
            $config = Get-Field $DataNodes "Configuration"
            $hash   = Get-Field $DataNodes "ConfigurationFileHash"
            $exe    = "Sysmon"
            $detail = "Config=$config  Hash=$hash"
        }

        17 {  # Pipe Created
            $image = Get-Field $DataNodes "Image"
            $pipe  = Get-Field $DataNodes "PipeName"
            $exe   = Get-ExeName $image
            $detail = "Pipe=$pipe"
        }

        18 {  # Pipe Connected
            $image = Get-Field $DataNodes "Image"
            $pipe  = Get-Field $DataNodes "PipeName"
            $exe   = Get-ExeName $image
            $detail = "Pipe=$pipe"
        }

        19 {  # WMI EventFilter
            $op    = Get-Field $DataNodes "Operation"
            $ns    = Get-Field $DataNodes "EventNamespace"
            $name  = Get-Field $DataNodes "Name"
            $query = Get-Field $DataNodes "Query"
            $exe   = "WMI"
            $detail = "Op=$op  NS=$ns  Filter=$name  Query=$query"
        }

        20 {  # WMI EventConsumer
            $op   = Get-Field $DataNodes "Operation"
            $name = Get-Field $DataNodes "Name"
            $type = Get-Field $DataNodes "Type"
            $dest = Get-Field $DataNodes "Destination"
            $exe  = "WMI"
            $detail = "Op=$op  Consumer=$name  Type=$type  Dest=$dest"
        }

        21 {  # WMI ConsumerToFilter binding
            $op       = Get-Field $DataNodes "Operation"
            $consumer = Get-Field $DataNodes "Consumer"
            $filter   = Get-Field $DataNodes "Filter"
            $exe      = "WMI"
            $detail   = "Op=$op  Consumer=$consumer  Filter=$filter"
        }

        22 {  # DNS Query
            $image   = Get-Field $DataNodes "Image"
            $query   = Get-Field $DataNodes "QueryName"
            $status  = Get-Field $DataNodes "QueryStatus"
            $results = Get-Field $DataNodes "QueryResults"
            $exe     = Get-ExeName $image
            $detail  = "Query=$query  Status=$status  Results=$results"
        }

        23 {  # FileDelete (archived)
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $hashes = Get-Field $DataNodes "Hashes"
            $arch   = Get-Field $DataNodes "IsExecutable"
            $exe    = Get-ExeName $image
            $detail = "File=$target  Executable=$arch  Hashes=$hashes"
        }

        24 {  # ClipboardChange
            $image  = Get-Field $DataNodes "Image"
            $sess   = Get-Field $DataNodes "Session"
            $client = Get-Field $DataNodes "ClientInfo"
            $hash   = Get-Field $DataNodes "Hashes"
            $exe    = Get-ExeName $image
            $detail = "Session=$sess  Client=$client  Hashes=$hash"
        }

        25 {  # ProcessTampering
            $image  = Get-Field $DataNodes "Image"
            $type   = Get-Field $DataNodes "Type"
            $exe    = Get-ExeName $image
            $detail = "TamperType=$type  Path=$image"
        }

        26 {  # FileDeleteDetected
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $hashes = Get-Field $DataNodes "Hashes"
            $exe    = Get-ExeName $image
            $detail = "File=$target  Hashes=$hashes"
        }

        27 {  # FileBlockExecutable
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $hashes = Get-Field $DataNodes "Hashes"
            $exe    = Get-ExeName $image
            $detail = "BlockedFile=$target  Hashes=$hashes"
        }

        28 {  # FileBlockShredding
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $exe    = Get-ExeName $image
            $detail = "ShreddedFile=$target"
        }

        29 {  # FileExecutableDetected
            $image  = Get-Field $DataNodes "Image"
            $target = Get-Field $DataNodes "TargetFilename"
            $hashes = Get-Field $DataNodes "Hashes"
            $type   = Get-Field $DataNodes "Type"
            $exe    = Get-ExeName $image
            $detail = "File=$target  Type=$type  Hashes=$hashes"
        }

        default {
            $exe    = "(ID $Id)"
            $detail = "(no summary defined for this event ID)"
        }
    }

    return [PSCustomObject]@{ Exe = $exe; Detail = $detail }
}

# ---------------------------------------------------------------------------
# Validate log access
# ---------------------------------------------------------------------------
$logName = "Microsoft-Windows-Sysmon/Operational"

try {
    $null = Get-WinEvent -ListLog $logName -ErrorAction Stop
} catch {
    Write-Error "Cannot access Sysmon event log '$logName'. Is Sysmon installed and running?"
    exit 1
}

# ---------------------------------------------------------------------------
# Parse -Since
# ---------------------------------------------------------------------------
$sinceDate = $null
if ($Since -ne "") {
    try {
        $sinceDate = [datetime]::Parse($Since)
    } catch {
        Write-Error "Could not parse -Since value '$Since'. Use format: 'yyyy-MM-dd HH:mm:ss'"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Fetch events
#
# Strategy:
#   No -EventIds specified  → single query, no ID filter, optional MaxEvents
#   One -EventId specified  → single query with ID filter, optional MaxEvents
#   Multiple -EventIds      → one query per ID (Get-WinEvent only accepts a
#                             single ID in FilterHashtable), results merged
#                             and sorted, then MaxEvents applied to the merged
#                             set so the limit is across all types in true
#                             time order.
#
# Note: Get-WinEvent returns newest-first by default. We always sort oldest-
# first after fetching so the final output is chronological.
# ---------------------------------------------------------------------------

$idLabel = if ($EventIds.Count -gt 0) { "IDs $($EventIds -join ',')" } else { "all IDs" }
Write-Host "Reading Sysmon events ($idLabel) from '$logName'..." -ForegroundColor DarkGray

$rawEvents = @()

if ($EventIds.Count -le 1) {
    # ── Single query path ─────────────────────────────────────────────────
    $filterHash = @{ LogName = $logName }
    if ($sinceDate)          { $filterHash["StartTime"] = $sinceDate }
    if ($EventIds.Count -eq 1) { $filterHash["Id"] = $EventIds[0] }

    $getParams = @{ FilterHashtable = $filterHash; ErrorAction = "SilentlyContinue" }
    if ($MaxEvents -gt 0) { $getParams["MaxEvents"] = $MaxEvents }

    $rawEvents = @(Get-WinEvent @getParams)

} else {
    # ── Multi-ID path: fetch per ID, merge, sort, then cap ───────────────
    # We do NOT pass -MaxEvents to individual queries here — if we asked for
    # 500 events across IDs 1,3,22 and capped each fetch at 500, we'd get up
    # to 1500 events and then discard most of them. Instead we fetch all
    # matching events for each ID (within the time window) and apply the cap
    # after merging. For very large logs with no -Since, add a -Since to
    # limit the fetch window rather than relying on -MaxEvents alone.

    foreach ($id in $EventIds) {
        $filterHash = @{ LogName = $logName; Id = $id }
        if ($sinceDate) { $filterHash["StartTime"] = $sinceDate }

        $batch = @(Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue)
        if ($batch.Count -gt 0) {
            Write-Host ("  ID {0,2}: {1} events" -f $id, $batch.Count) -ForegroundColor DarkGray
            $rawEvents += $batch
        } else {
            Write-Host ("  ID {0,2}: (none)" -f $id) -ForegroundColor DarkGray
        }
    }
}

# Sort into true chronological order across all IDs
$rawEvents = $rawEvents | Sort-Object TimeCreated

# Apply MaxEvents cap AFTER merge+sort so the limit is meaningful across types
if ($MaxEvents -gt 0 -and $rawEvents.Count -gt $MaxEvents) {
    Write-Host ("Capping at $MaxEvents events (fetched {0} total across all IDs)." -f $rawEvents.Count) -ForegroundColor DarkGray
    $rawEvents = $rawEvents | Select-Object -Last $MaxEvents
}

if (-not $rawEvents -or $rawEvents.Count -eq 0) {
    Write-Host "No Sysmon events found matching your criteria." -ForegroundColor Yellow
    exit 0
}

Write-Host ("Found {0} events. Rendering...`n" -f $rawEvents.Count) -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Column widths
# ---------------------------------------------------------------------------
$colTime  = 19
$colId    = 4
$colType  = 26
$colExe   = 22

$header = "{0,-$colTime}  {1,-$colId}  {2,-$colType}  {3,-$colExe}  {4}" -f `
          "Time", "ID", "Type", "Process", "Detail"
$sep    = "-" * $header.Length

Write-Host $header -ForegroundColor White
Write-Host $sep    -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Event type name lookup
# ---------------------------------------------------------------------------
$eventTypeName = @{
    1="Process Create";      2="File Time Changed";   3="Network Connect";
    4="Sysmon State";        5="Process Exit";         6="Driver Load";
    7="Image/DLL Load";      8="Remote Thread";        9="Raw Disk Read";
    10="Process Access";     11="File Create";          12="Registry Obj Chg";
    13="Registry Value Set"; 14="Registry Rename";      15="ADS Create";
    16="Config Change";      17="Pipe Created";         18="Pipe Connected";
    19="WMI Filter";         20="WMI Consumer";         21="WMI Binding";
    22="DNS Query";          23="File Delete (arch)";   24="Clipboard Change";
    25="Process Tampering";  26="File Delete Detect";   27="Exec Blocked";
    28="Shred Blocked";      29="Executable Detected"
}

# ---------------------------------------------------------------------------
# Color map
# ---------------------------------------------------------------------------
function Get-EventColor([int]$Id) {
    switch ($Id) {
        1  { return "Green" }
        3  { return "Cyan" }
        7  { return "DarkCyan" }
        8  { return "Red" }
        10 { return "Red" }
        12 { return "Yellow" }
        13 { return "Yellow" }
        14 { return "Yellow" }
        22 { return "Cyan" }
        25 { return "Red" }
        27 { return "Red" }
        28 { return "Red" }
        default { return "Gray" }
    }
}

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
$skipped = 0

foreach ($evt in $rawEvents) {

    $id       = $evt.Id
    $time     = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    $typeName = if ($eventTypeName.ContainsKey($id)) { $eventTypeName[$id] } else { "Unknown ($id)" }

    $xml       = [xml]$evt.ToXml()
    $dataNodes = $xml.Event.EventData.Data

    $summary = Get-EventSummary -DataNodes $dataNodes -Id $id

    if ($ProcessName -ne "" -and $summary.Exe -notmatch [regex]::Escape($ProcessName)) {
        $skipped++
        continue
    }

    $exeDisplay  = if ($summary.Exe.Length -gt $colExe) { $summary.Exe.Substring(0, $colExe-1) + "~" } else { $summary.Exe }
    $typeDisplay = if ($typeName.Length   -gt $colType)  { $typeName.Substring(0, $colType-1)  + "~" } else { $typeName }

    $line = "{0,-$colTime}  {1,-$colId}  {2,-$colType}  {3,-$colExe}  {4}" -f `
            $time, $id, $typeDisplay, $exeDisplay, $summary.Detail

    Write-Host $line -ForegroundColor (Get-EventColor $id)
}

if ($skipped -gt 0) {
    Write-Host "`n($skipped events filtered out by -ProcessName '$ProcessName')" -ForegroundColor DarkGray
}

Write-Host "`nDone. $($rawEvents.Count - $skipped) events displayed." -ForegroundColor DarkGray
