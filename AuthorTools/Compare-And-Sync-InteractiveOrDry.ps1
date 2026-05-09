<#
.SYNOPSIS
  Compare files between Source and Target by metadata and hash; run as Dry Run or Interactive Update.

.DESCRIPTION
  - Collects metadata: Hash (MD5 default), Size, CreationTimeUtc, LastWriteTimeUtc.
  - For Word documents (.doc, .docx) attempts to collect page and word counts via Word COM.
  - Compares by relative path under each root.
  - Dry Run: performs analysis and prints results only.
  - Interactive Update: prompts per mismatch and can execute copy operations after explicit confirmation.
  - No global "always" choices; every mismatch requires a decision.
  - Optionally export decisions to CSV with -ExportCsv.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Source = "C:\Users\dmurdoch\OneDrive\BlueTeamHandbook\SOC_SIEM_and_Logging\By_Chapter_SOCTH _Revised",

    [Parameter(Mandatory=$false)]
    [string]$Target = "S:\Data\Blue Team Handbook\SOC_SIEM_and_Logging\By_Chapter_SOCTH _Revised",

    [ValidateSet("MD5","SHA256")]
    [string]$HashAlgorithm = "MD5",

    [switch]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Helper: Word stats
# -------------------------
function Get-WordStats {
    param([string]$Path)

    $stats = @{ Pages = $null; Words = $null }

    try {
        # Use Word COM for accurate counts when available
        $word = New-Object -ComObject Word.Application -ErrorAction Stop
        $word.Visible = $false
        $doc = $word.Documents.Open($Path, [ref]$false, [ref]$true, [ref]$false)
        $stats.Words = $doc.ComputeStatistics(0)   # wdStatisticWords = 0
        $stats.Pages = $doc.ComputeStatistics(2)   # wdStatisticPages = 2
        $doc.Close([ref]$false)
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($doc) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    }
    catch {
        # If Word COM not available or fails, leave stats null
    }

    return $stats
}

# -------------------------
# Helper: File metadata
# -------------------------
function Get-FileMeta {
    param([string]$FullPath, [string]$HashAlgorithm)

    $meta = [ordered]@{
        FullPath = $FullPath
        Relative = $null
        Size = $null
        CreationTimeUtc = $null
        LastWriteTimeUtc = $null
        Hash = $null
        IsWord = $false
        WordPages = $null
        WordWords = $null
    }

    if (-not (Test-Path $FullPath)) { return $meta }

    $fi = Get-Item -LiteralPath $FullPath -ErrorAction Stop
    $meta.Size = $fi.Length
    $meta.CreationTimeUtc = $fi.CreationTimeUtc
    $meta.LastWriteTimeUtc = $fi.LastWriteTimeUtc

    try {
        $hashObj = Get-FileHash -Algorithm $HashAlgorithm -Path $FullPath -ErrorAction Stop
        $meta.Hash = $hashObj.Hash
    }
    catch {
        $meta.Hash = "ERROR"
    }

    if ($FullPath -match '\.docx?$') {
        $meta.IsWord = $true
        $w = Get-WordStats -Path $FullPath
        $meta.WordPages = $w.Pages
        $meta.WordWords = $w.Words
    }

    return $meta
}

# -------------------------
# Helper: Build file map
# -------------------------
function Build-FileMap {
    param([string]$Root, [string]$HashAlgorithm)

    $map = @{}
    try {
        $rootResolved = (Resolve-Path -LiteralPath $Root).ProviderPath
    } catch {
        throw "Root path not found: $Root"
    }

    $files = Get-ChildItem -LiteralPath $rootResolved -Recurse -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($rootResolved.Length).TrimStart('\','/')
        $meta = Get-FileMeta -FullPath $f.FullName -HashAlgorithm $HashAlgorithm
        $meta.Relative = $rel
        $map[$rel] = $meta
    }
    return @{ Root = $rootResolved; Map = $map }
}

# -------------------------
# Helper: Prompt per mismatch
# -------------------------
function Prompt-UserAction {
    param([string]$RelPath, [hashtable]$SrcMeta, [hashtable]$DstMeta)

    Write-Host ""
    Write-Host "Mismatch: $RelPath" -ForegroundColor Yellow
    Write-Host "Source: $($SrcMeta.FullPath)"
    Write-Host "  Size: $($SrcMeta.Size) bytes"
    Write-Host "  Created: $($SrcMeta.CreationTimeUtc)"
    Write-Host "  Modified: $($SrcMeta.LastWriteTimeUtc)"
    Write-Host "  Hash: $($SrcMeta.Hash)"
    if ($SrcMeta.IsWord) { Write-Host "  Word Pages: $($SrcMeta.WordPages)  Words: $($SrcMeta.WordWords)" }

    Write-Host "Target: $($DstMeta.FullPath)"
    Write-Host "  Size: $($DstMeta.Size) bytes"
    Write-Host "  Created: $($DstMeta.CreationTimeUtc)"
    Write-Host "  Modified: $($DstMeta.LastWriteTimeUtc)"
    Write-Host "  Hash: $($DstMeta.Hash)"
    if ($DstMeta.IsWord) { Write-Host "  Word Pages: $($DstMeta.WordPages)  Words: $($DstMeta.WordWords)" }

    Write-Host ""
    Write-Host "Choose action:"
    Write-Host "  [1] Show copy command (dry-run) Source -> Target"
    Write-Host "  [2] Show copy command (dry-run) Target -> Source"
    Write-Host "  [3] Execute copy Source -> Target now (requires confirmation)"
    Write-Host "  [4] Execute copy Target -> Source now (requires confirmation)"
    Write-Host "  [5] Skip"
    Write-Host "  [6] View timestamps and sizes only"

    while ($true) {
        $choice = Read-Host "Enter choice (1/2/3/4/5/6)"
        switch ($choice) {
            '1' { return 'SHOW_S2T' }
            '2' { return 'SHOW_T2S' }
            '3' { return 'EXEC_S2T' }
            '4' { return 'EXEC_T2S' }
            '5' { return 'SKIP' }
            '6' { return 'DIFF' }
            default { Write-Host "Invalid choice. Try again." }
        }
    }
}

# -------------------------
# Start: Mode selection
# -------------------------
Write-Host "Source: $Source"
Write-Host "Target: $Target"
Write-Host "Hash Algorithm: $HashAlgorithm"
Write-Host ""

# Ask user for mode
$mode = $null
while ($null -eq $mode) {
    Write-Host "Select mode:"
    Write-Host "  [D] Dry Run - analyze and report only (no prompts for changes)"
    Write-Host "  [I] Interactive Update - analyze, then prompt per mismatch and allow copy execution"
    $m = Read-Host "Enter D or I"
    switch ($m.ToUpper()) {
        'D' { $mode = 'Dry' }
        'I' { $mode = 'Interactive' }
        default { Write-Host "Invalid selection. Enter D or I." }
    }
}
Write-Host "Mode selected: $mode"
Write-Host ""

# -------------------------
# Build maps
# -------------------------
Write-Host "Scanning Source..."
$srcResult = Build-FileMap -Root $Source -HashAlgorithm $HashAlgorithm
Write-Host "Scanning Target..."
$dstResult = Build-FileMap -Root $Target -HashAlgorithm $HashAlgorithm

$srcMap = $srcResult.Map
$dstMap = $dstResult.Map

$onlyInSource = New-Object System.Collections.Generic.List[string]
$onlyInTarget = New-Object System.Collections.Generic.List[string]
$matches = New-Object System.Collections.Generic.List[string]
$mismatches = New-Object System.Collections.Generic.List[string]

foreach ($key in $srcMap.Keys) {
    if (-not $dstMap.ContainsKey($key)) {
        $onlyInSource.Add($key) | Out-Null
    } else {
        $s = $srcMap[$key]
        $d = $dstMap[$key]
        if ($s.Hash -and $d.Hash -and ($s.Hash -eq $d.Hash)) {
            $matches.Add($key) | Out-Null
        } else {
            $mismatches.Add($key) | Out-Null
        }
    }
}

foreach ($key in $dstMap.Keys) {
    if (-not $srcMap.ContainsKey($key)) {
        $onlyInTarget.Add($key) | Out-Null
    }
}

# -------------------------
# Summary report
# -------------------------
Write-Host ""
Write-Host "=== Summary ==="
Write-Host "Files only in Source: $($onlyInSource.Count)"
Write-Host "Files only in Target: $($onlyInTarget.Count)"
Write-Host "Files matching (hash): $($matches.Count)"
Write-Host "Files mismatched: $($mismatches.Count)"
Write-Host ""

if ($onlyInSource.Count -gt 0) {
    Write-Host "=== Only in Source ==="
    $onlyInSource | Sort-Object | ForEach-Object { Write-Host " - $_" }
    Write-Host ""
}
if ($onlyInTarget.Count -gt 0) {
    Write-Host "=== Only in Target ==="
    $onlyInTarget | Sort-Object | ForEach-Object { Write-Host " - $_" }
    Write-Host ""
}
if ($matches.Count -gt 0) {
    Write-Host "=== Matches ==="
    $matches | Sort-Object | ForEach-Object { Write-Host " - $_" }
    Write-Host ""
}

# -------------------------
# Dry Run behavior
# -------------------------
$decisions = @()
if ($mode -eq 'Dry') {
    Write-Host "Dry Run mode: analysis complete. No prompts for changes will be made."
    # For mismatches, provide reasons why (hash mismatch, size/timestamp differences, Word stats differences)
    if ($mismatches.Count -gt 0) {
        Write-Host "`n=== Mismatches and Reasons ==="
        foreach ($rel in $mismatches | Sort-Object) {
            $s = $srcMap[$rel]
            $d = $dstMap[$rel]
            Write-Host ""
            Write-Host "File: $rel" -ForegroundColor Yellow
            Write-Host "  Source Hash: $($s.Hash)"
            Write-Host "  Target Hash: $($d.Hash)"
            if ($s.Hash -ne $d.Hash) { Write-Host "  Reason: Hash mismatch" }
            if ($s.Size -ne $d.Size) { Write-Host "  Reason: Size differs (Source: $($s.Size) bytes, Target: $($d.Size) bytes)" }
            if ($s.LastWriteTimeUtc -ne $d.LastWriteTimeUtc) { Write-Host "  Reason: LastWriteTime differs (Source: $($s.LastWriteTimeUtc), Target: $($d.LastWriteTimeUtc))" }
            if ($s.IsWord -or $d.IsWord) {
                Write-Host "  Word stats:"
                Write-Host "    Source Pages: $($s.WordPages) Words: $($s.WordWords)"
                Write-Host "    Target Pages: $($d.WordPages) Words: $($d.WordWords)"
                if ($s.WordPages -ne $d.WordPages -or $s.WordWords -ne $d.WordWords) {
                    Write-Host "    Reason: Word page/word counts differ"
                }
            }
        }
    } else {
        Write-Host "No mismatches found."
    }

    # Also list only-in-source and only-in-target as candidates
    if ($onlyInSource.Count -gt 0) {
        Write-Host "`n=== Candidate files only in Source (not in Target) ==="
        $onlyInSource | Sort-Object | ForEach-Object { Write-Host " - $_" }
    }
    if ($onlyInTarget.Count -gt 0) {
        Write-Host "`n=== Candidate files only in Target (not in Source) ==="
        $onlyInTarget | Sort-Object | ForEach-Object { Write-Host " - $_" }
    }

    # Optionally export CSV of the analysis (metadata)
    if ($ExportCsv) {
        $out = @()
        foreach ($k in ($srcMap.Keys + $dstMap.Keys | Sort-Object -Unique)) {
            $s = $null; $d = $null
            if ($srcMap.ContainsKey($k)) { $s = $srcMap[$k] }
            if ($dstMap.ContainsKey($k)) { $d = $dstMap[$k] }
            $out += [PSCustomObject]@{
                RelativePath = $k
                SourcePath = if ($s) { $s.FullPath } else { "" }
                SourceSize = if ($s) { $s.Size } else { "" }
                SourceHash = if ($s) { $s.Hash } else { "" }
                SourceLastWriteUtc = if ($s) { $s.LastWriteTimeUtc } else { "" }
                SourceIsWord = if ($s) { $s.IsWord } else { "" }
                SourceWordPages = if ($s) { $s.WordPages } else { "" }
                SourceWordWords = if ($s) { $s.WordWords } else { "" }
                TargetPath = if ($d) { $d.FullPath } else { "" }
                TargetSize = if ($d) { $d.Size } else { "" }
                TargetHash = if ($d) { $d.Hash } else { "" }
                TargetLastWriteUtc = if ($d) { $d.LastWriteTimeUtc } else { "" }
                TargetIsWord = if ($d) { $d.IsWord } else { "" }
                TargetWordPages = if ($d) { $d.WordPages } else { "" }
                TargetWordWords = if ($d) { $d.WordWords } else { "" }
            }
        }
        $csvPath = Join-Path -Path (Get-Location) -ChildPath "CompareAnalysis_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
        $out | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-Host "`nAnalysis exported to: $csvPath"
    }

    Write-Host "`nDry Run complete."
    return
}

# -------------------------
# Interactive Update behavior
# -------------------------
Write-Host "Interactive Update mode: you will be prompted for each mismatch. Copies will only occur after you explicitly confirm per-file."
if ($mismatches.Count -eq 0) {
    Write-Host "No mismatches to resolve. Exiting."
    return
}

foreach ($rel in $mismatches | Sort-Object) {
    $sMeta = $srcMap[$rel]
    $dMeta = $dstMap[$rel]

    $action = Prompt-UserAction -RelPath $rel -SrcMeta $sMeta -DstMeta $dMeta

    switch ($action) {
        'SHOW_S2T' {
            $dstFull = Join-Path $dstResult.Root $rel
            $copyCmd = "Copy-Item -LiteralPath `"$($sMeta.FullPath)`" -Destination `"$dstFull`" -Force"
            Write-Host "DRY RUN: To copy Source -> Target run:" -ForegroundColor Cyan
            Write-Host "  $copyCmd"
            $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="Show Source->Target"; CopyCommand=$copyCmd }
        }
        'SHOW_T2S' {
            $srcFull = Join-Path $srcResult.Root $rel
            $copyCmd = "Copy-Item -LiteralPath `"$($dMeta.FullPath)`" -Destination `"$srcFull`" -Force"
            Write-Host "DRY RUN: To copy Target -> Source run:" -ForegroundColor Cyan
            Write-Host "  $copyCmd"
            $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="Show Target->Source"; CopyCommand=$copyCmd }
        }
        'EXEC_S2T' {
            $dstFull = Join-Path $dstResult.Root $rel
            $copyCmd = "Copy-Item -LiteralPath `"$($sMeta.FullPath)`" -Destination `"$dstFull`" -Force"
            Write-Host "About to execute: $copyCmd" -ForegroundColor Magenta
            $confirm = Read-Host "Type Y to confirm and execute the copy, anything else to cancel"
            if ($confirm.ToUpper() -eq 'Y') {
                $dstDir = Split-Path -Path $dstFull -Parent
                if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
                Copy-Item -LiteralPath $sMeta.FullPath -Destination $dstFull -Force
                Write-Host "Copied Source -> Target: $rel" -ForegroundColor Green
                # refresh metadata
                $newMeta = Get-FileMeta -FullPath $dstFull -HashAlgorithm $HashAlgorithm
                $newMeta.Relative = $rel
                $dstMap[$rel] = $newMeta
                $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="Executed Source->Target"; CopyCommand=$copyCmd }
            } else {
                Write-Host "Execution cancelled by user." -ForegroundColor Yellow
                $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="ExecutionCancelled Source->Target"; CopyCommand=$copyCmd }
            }
        }
        'EXEC_T2S' {
            $srcFull = Join-Path $srcResult.Root $rel
            $copyCmd = "Copy-Item -LiteralPath `"$($dMeta.FullPath)`" -Destination `"$srcFull`" -Force"
            Write-Host "About to execute: $copyCmd" -ForegroundColor Magenta
            $confirm = Read-Host "Type Y to confirm and execute the copy, anything else to cancel"
            if ($confirm.ToUpper() -eq 'Y') {
                $srcDir = Split-Path -Path $srcFull -Parent
                if (-not (Test-Path $srcDir)) { New-Item -ItemType Directory -Path $srcDir -Force | Out-Null }
                Copy-Item -LiteralPath $dMeta.FullPath -Destination $srcFull -Force
                Write-Host "Copied Target -> Source: $rel" -ForegroundColor Green
                $newMeta = Get-FileMeta -FullPath $srcFull -HashAlgorithm $HashAlgorithm
                $newMeta.Relative = $rel
                $srcMap[$rel] = $newMeta
                $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="Executed Target->Source"; CopyCommand=$copyCmd }
            } else {
                Write-Host "Execution cancelled by user." -ForegroundColor Yellow
                $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="ExecutionCancelled Target->Source"; CopyCommand=$copyCmd }
            }
        }
        'SKIP' {
            Write-Host "Skipped: $rel" -ForegroundColor Yellow
            $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="Skipped"; CopyCommand="" }
        }
        'DIFF' {
            Write-Host "Timestamps / Sizes diff for: $rel" -ForegroundColor Gray
            Write-Host "  Source Size: $($sMeta.Size)  Target Size: $($dMeta.Size)"
            Write-Host "  Source Modified: $($sMeta.LastWriteTimeUtc)  Target Modified: $($dMeta.LastWriteTimeUtc)"
            $decisions += [PSCustomObject]@{ RelativePath=$rel; Decision="ViewedDiff"; CopyCommand="" }
        }
    }
}

# -------------------------
# Export decisions if requested
# -------------------------
if ($ExportCsv) {
    $outPath = Join-Path -Path (Get-Location) -ChildPath "CompareDecisions_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    $decisions | Export-Csv -Path $outPath -NoTypeInformation -Force
    Write-Host ""
    Write-Host "Decisions exported to: $outPath"
}

Write-Host ""
Write-Host "=== End of session ==="
Write-Host "Interactive Update complete. Review decisions or re-run the script for another pass."
