param (
    [Parameter(Mandatory=$true)]
    [string]$PathA,

    [Parameter(Mandatory=$true)]
    [string]$PathB
)

function Get-FileSizeTable {
    param ([string]$Path)
    $files = Get-ChildItem -Path $Path -Recurse -File
    $sizeTable = @{}
    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($Path.Length).TrimStart('\')
        $sizeTable[$relativePath] = $file.Length
    }
    return @{ Table = $sizeTable; Count = $files.Count }
}

$resultsA = Get-FileSizeTable -Path $PathA
$resultsB = Get-FileSizeTable -Path $PathB

$sizeA = $resultsA.Table
$sizeB = $resultsB.Table

$allKeys = $sizeA.Keys + $sizeB.Keys | Sort-Object -Unique

foreach ($key in $allKeys) {
    if (-not $sizeA.ContainsKey($key)) {
        Write-Host "Only in ${PathB}: $key" -ForegroundColor Yellow
    } elseif (-not $sizeB.ContainsKey($key)) {
        Write-Host "Only in ${PathA}: $key" -ForegroundColor Yellow
    } elseif ($sizeA[$key] -ne $sizeB[$key]) {
        Write-Host "Size mismatch: $key" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "Files in ${PathA}: $($resultsA.Count)"
Write-Host "Files in ${PathB}: $($resultsB.Count)"
