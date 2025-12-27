param(
    [switch]$ShowProgress
)

# Load the structured Sysmon JSON
$events = Get-Content -Raw sysmon_structured.json | ConvertFrom-Json

# Filter EventID 1, 3, 22 and sort by TimeUtc
$filtered = $events |
    Where-Object { $_.EventID -in 1,3,22 } |
    Sort-Object TimeUtc

$counter = 0

foreach ($e in $filtered) {

    $counter++

    if ($ShowProgress -and ($counter % 1000 -eq 0)) {
        Write-Host "Processed $counter events..."
    }

    switch ($e.EventID) {

        1 {
            # Process Create
            $image = Split-Path $e.Image -Leaf

            $fields = @(
                $e.TimeUtc
                "1"
                $e.User
                $e.Computer
                $e.EventData.ProcessId
                $image
                $e.EventData.CommandLine
            )

            ($fields -join " | ")
        }

        3 {
            # NetworkConnect
            $image = Split-Path $e.Image -Leaf

            # Normalize IPv4-mapped IPv6 (::ffff:)
            $srcIp = $e.EventData.SourceIp -replace '^::ffff:',''
            $dstIp = $e.EventData.DestinationIp -replace '^::ffff:',''

            # Build endpoints (must use ${} to avoid drive-qualified variable parsing)
            $src = "${srcIp}:$($e.EventData.SourcePort)"

            if ($e.EventData.DestinationPortName) {
                $dst = "${dstIp}:$($e.EventData.DestinationPort):$($e.EventData.DestinationPortName)"
            }
            else {
                $dst = "${dstIp}:$($e.EventData.DestinationPort)"
            }

            $fields = @(
                $e.TimeUtc
                "3"
                $e.User
                $e.EventData.ProcessId
                $image
                $src
                $dst
            )

            ($fields -join " | ")
        }

        22 {
            # DNS Query
            $image = Split-Path $e.Image -Leaf

            # Normalize IPv4-mapped IPv6 in QueryResults
            $results = (
                $e.EventData.QueryResults -split ';' |
                ForEach-Object { $_ -replace '^::ffff:' } |
                Where-Object { $_ -ne "" }
            ) -join ';'

            $fields = @(
                $e.TimeUtc
                "22"
                $e.User
                $e.EventData.ProcessId
                $image
                $e.EventData.QueryName
                $results
            )

            ($fields -join " | ")
        }
    }
}
