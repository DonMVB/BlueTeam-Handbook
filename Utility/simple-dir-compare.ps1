param (
    [string]$PathA,
    [string]$PathB,
    [switch]$h
)

function Show-Help {
    Write-Host "Compare-Directories.ps1 -PathA <Directory1> -PathB <Directory2>" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Compares two directories recursively by file name and size." -ForegroundColor Gray
    Write-Host "Reports files missing from either directory or with size mismatches." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Usage Example:" -ForegroundColor Yellow
    Write-Host "  .\Compare-Directories.ps1 -PathA 'C:\Source' -PathB 'D:\Backup'" -ForegroundColor White
    Write-Host ""
    Write-Host "Optional Flags:"
    Write-Host "  -h or /h     Show this help message" -ForegroundColor Gray
    exit
}

if ($h -or $args -contains "-h" -or $args -contains "/h") {
    Show-Help
}

if (-not $PathA -or -not $PathB) {
    Write-Host "Error: Both -PathA and -PathB are required." -ForegroundColor Red
    Write-Host ""
    Show-Help
}

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
