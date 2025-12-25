# =====================================================================
# Configuration
# =====================================================================
$MinutesBack = 30   # Pull last N minutes of Sysmon data
$Cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$MinutesBack)

Write-Host "=== Unified Sysmon Timeline (Event ID 1, 3, 22) ==="
Write-Host "=== Time Window: Last $MinutesBack minutes ==="
Write-Host ""

# =====================================================================
# Helper: Extract XML field safely
# =====================================================================
function Get-Field($data, $name) {
    return ($data | Where-Object { $_.Name -eq $name }).'#text'
}

# =====================================================================
# Helper: Normalize IP addresses
# =====================================================================
function Normalize-IP($ip) {
    if (-not $ip) { return $null }

    # Strip IPv4-mapped IPv6 prefix
    $clean = $ip -replace '^::ffff:', ''

    return $clean
}

# =====================================================================
# Helper: Normalize IPs inside DNS QueryResults
# =====================================================================
function Normalize-QueryResults($qr) {
    if (-not $qr) { return $qr }

    $parts = $qr -split ';'

    $normalizedParts = foreach ($p in $parts) {

        $trim = $p.Trim()
        if (-not $trim) { continue }

        # If this looks like IPv4 or ::ffff:IPv4, normalize it
        if ($trim -match '^::ffff:' -or $trim -match '^\d{1,3}(\.\d{1,3}){3}$') {
            Normalize-IP $trim
        } else {
            $trim
        }
    }

    return ($normalizedParts -join ';')
}

# =====================================================================
# Track full image paths
# =====================================================================
$imagePaths = @{}

# =====================================================================
# Collect Sysmon Event ID 1 (Process Create)
# =====================================================================
$procEvents = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    ID      = 1
} | Where-Object { $_.TimeCreated.ToUniversalTime() -ge $Cutoff }

$procParsed = foreach ($event in $procEvents) {

    $xml  = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data
    $timeUTC = $event.TimeCreated.ToUniversalTime()

    $imageFull = Get-Field $data 'Image'
    $imageShort = Split-Path $imageFull -Leaf
    if ($imageFull -and -not $imagePaths.ContainsKey($imageShort)) {
        $imagePaths[$imageShort] = $imageFull
    }

    [PSCustomObject]@{
        TimeUTC     = $timeUTC
        EventID     = 1
        EventType   = "ProcessCreate"
        ProcessId   = Get-Field $data 'ProcessId'
        User        = Get-Field $data 'User'
        Image       = $imageShort
        CommandLine = Get-Field $data 'CommandLine'
        SourceIp    = $null
        SourcePort  = $null
        DestIp      = $null
        DestPort    = $null
        DestPortName= $null
        QueryName   = $null
        QueryResults= $null
    }
}

# =====================================================================
# Collect Sysmon Event ID 3 (NetworkConnect)
# =====================================================================
$netEvents = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    ID      = 3
} | Where-Object { $_.TimeCreated.ToUniversalTime() -ge $Cutoff }

$netParsed = foreach ($event in $netEvents) {

    $xml  = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data
    $timeUTC = $event.TimeCreated.ToUniversalTime()

    $imageFull = Get-Field $data 'Image'
    $imageShort = Split-Path $imageFull -Leaf
    if ($imageFull -and -not $imagePaths.ContainsKey($imageShort)) {
        $imagePaths[$imageShort] = $imageFull
    }

    $sourceIp = Normalize-IP (Get-Field $data 'SourceIp')
    $destIp   = Normalize-IP (Get-Field $data 'DestinationIp')

    $destPortName = Get-Field $data 'DestinationPortName'
    if ([string]::IsNullOrWhiteSpace($destPortName)) { $destPortName = $null }

    [PSCustomObject]@{
        TimeUTC     = $timeUTC
        EventID     = 3
        EventType   = "NetworkConnect"
        ProcessId   = Get-Field $data 'ProcessId'
        User        = Get-Field $data 'User'
        Image       = $imageShort
        CommandLine = $null
        SourceIp    = $sourceIp
        SourcePort  = Get-Field $data 'SourcePort'
        DestIp      = $destIp
        DestPort    = Get-Field $data 'DestinationPort'
        DestPortName= $destPortName
        QueryName   = $null
        QueryResults= $null
    }
}

# =====================================================================
# Collect Sysmon Event ID 22 (DNS Query)
# =====================================================================
$dnsEvents = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    ID      = 22
} | Where-Object { $_.TimeCreated.ToUniversalTime() -ge $Cutoff }

$dnsParsed = foreach ($event in $dnsEvents) {

    $xml  = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data
    $timeUTC = $event.TimeCreated.ToUniversalTime()

    $imageFull = Get-Field $data 'Image'
    $imageShort = Split-Path $imageFull -Leaf
    if ($imageFull -and -not $imagePaths.ContainsKey($imageShort)) {
        $imagePaths[$imageShort] = $imageFull
    }

    $queryResultsRaw = Get-Field $data 'QueryResults'
    $queryResultsNorm = Normalize-QueryResults $queryResultsRaw

    [PSCustomObject]@{
        TimeUTC     = $timeUTC
        EventID     = 22
        EventType   = "DNSQuery"
        ProcessId   = Get-Field $data 'ProcessId'
        User        = Get-Field $data 'User'
        Image       = $imageShort
        CommandLine = $null
        SourceIp    = $null
        SourcePort  = $null
        DestIp      = $null
        DestPort    = $null
        DestPortName= $null
        QueryName   = Get-Field $data 'QueryName'
        QueryResults= $queryResultsNorm
    }
}

# =====================================================================
# Combine + Sort Chronologically
# =====================================================================
$timeline = $procParsed + $netParsed + $dnsParsed | Sort-Object TimeUTC

# =====================================================================
# Output Unified Timeline
# =====================================================================
Write-Host "=== Unified Timeline ==="
Write-Host ""

foreach ($row in $timeline) {

    $t = $row.TimeUTC.ToString("yyyy-MM-dd HH:mm:ssZ")

    switch ($row.EventType) {

        "ProcessCreate" {
            # Event ID 1: Time | EventID | ProcessID | User | Image | Command Line
            Write-Host "$t | $($row.EventID) | $($row.ProcessId) | $($row.User) | $($row.Image) | $($row.CommandLine)"
        }

        "NetworkConnect" {
            # Event ID 3: Time | EventID | ProcessID | User | Image | SrcIP:SrcPort DstIP:DstPort[:DestPortName]
            $src = "$($row.SourceIp):$($row.SourcePort)"
            $dst = "$($row.DestIp):$($row.DestPort)"
            if ($row.DestPortName) { $dst += ":$($row.DestPortName)" }
            Write-Host "$t | $($row.EventID) | $($row.ProcessId) | $($row.User) | $($row.Image) | $src $dst"
        }

        "DNSQuery" {
            # Event ID 22: Time | EventID | ProcessID | User | Image | QueryName - QueryResults
            Write-Host "$t | $($row.EventID) | $($row.ProcessId) | $($row.User) | $($row.Image) | $($row.QueryName) - $($row.QueryResults)"
        }
    }
}

# =====================================================================
# Output Image Path Mapping
# =====================================================================
Write-Host ""
Write-Host "=== Image Name → Full Path Mapping ==="

$imagePaths.GetEnumerator() |
    Sort-Object Name |
    ForEach-Object {
        Write-Host "$($_.Key) = $($_.Value)"
    }
