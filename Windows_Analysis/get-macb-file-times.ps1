<#
.SYNOPSIS
  Print NTFS MACB times (Modified, Accessed, Changed, Birth) for a file or directory in a two-column (label/value) format,
  and show a compact human-readable difference from Birth plus a right-aligned seconds field on the following line.

.SYNTAX
  .\Get-File-Macb-Times.ps1 -Path "C:\path\to\file_or_dir"

.NOTES
  - Run PowerShell elevated if you encounter permission errors.
  - Use -Verbose to see Win32 error details when ChangeTime retrieval fails.
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

# Resolve path and validate
$resolvedPathInfo = Resolve-Path -LiteralPath $Path -ErrorAction Stop
$targetPath = $resolvedPathInfo.Path
$item = Get-Item -LiteralPath $targetPath -ErrorAction Stop

# Basic times via .NET FileInfo (UTC)
$birthTimeUtc    = $item.CreationTimeUtc
$modifiedTimeUtc = $item.LastWriteTimeUtc
$accessedTimeUtc = $item.LastAccessTimeUtc

# Prepare to call Win32 APIs to get the MFT metadata ChangeTime (FILE_BASIC_INFO.ChangeTime)
$changeTimeUtc = $null
$handle = $null

$csSource = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[StructLayout(LayoutKind.Sequential)]
public struct FILE_BASIC_INFO {
    public long CreationTime;
    public long LastAccessTime;
    public long LastWriteTime;
    public long ChangeTime;
    public uint FileAttributes;
}

public static class Win32 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int FileInformationClass,
        out FILE_BASIC_INFO lpFileInformation,
        uint dwBufferSize);

    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_READ_ATTRIBUTES = 0x80;
    public const uint FILE_SHARE_READ = 1;
    public const uint FILE_SHARE_WRITE = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
}
"@

# Add the CLR type if not already loaded; tolerate "already exists" in the same session.
try {
    Add-Type -TypeDefinition $csSource -ErrorAction Stop
}
catch {
    $msg = $_.Exception.Message
    if ($msg -match 'already exists') {
        Write-Verbose "CLR type FILE_BASIC_INFO already loaded; continuing."
    }
    else {
        throw
    }
}

try {
    # Locate the FILE_BASIC_INFO Type object from loaded assemblies
    $fileBasicInfoType = [AppDomain]::CurrentDomain.GetAssemblies() |
        ForEach-Object { $_.GetType("FILE_BASIC_INFO", $false, $false) } |
        Where-Object { $_ -ne $null } |
        Select-Object -First 1

    if (-not $fileBasicInfoType) {
        throw "Unable to locate CLR type FILE_BASIC_INFO after Add-Type."
    }

    # Create an instance of the struct via Activator to ensure a proper unmanaged instance
    $fileInfo = [System.Activator]::CreateInstance($fileBasicInfoType)

    # Use Marshal.SizeOf(object) overload to compute size from the instance (avoids Type marshaling issues)
    $fileInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf($fileInfo)

    # Prepare Win32 parameters
    $desiredAccess = [Win32]::FILE_READ_ATTRIBUTES
    $shareMode = [Win32]::FILE_SHARE_READ -bor [Win32]::FILE_SHARE_WRITE
    $creationDisposition = [Win32]::OPEN_EXISTING
    $flagsAndAttributes = [Win32]::FILE_FLAG_BACKUP_SEMANTICS

    # Try opening with FILE_READ_ATTRIBUTES first; if that fails, try GENERIC_READ
    $handle = [Win32]::CreateFile($targetPath, $desiredAccess, $shareMode, [IntPtr]::Zero, $creationDisposition, $flagsAndAttributes, [IntPtr]::Zero)
    if ($handle -eq $null -or $handle.IsInvalid) {
        Write-Verbose "CreateFile with FILE_READ_ATTRIBUTES failed, trying GENERIC_READ..."
        $desiredAccess = [Win32]::GENERIC_READ
        $handle = [Win32]::CreateFile($targetPath, $desiredAccess, $shareMode, [IntPtr]::Zero, $creationDisposition, $flagsAndAttributes, [IntPtr]::Zero)
    }

    if ($handle -eq $null -or $handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open handle to path. Win32 error $err."
    }

    # Call GetFileInformationByHandleEx; use a typed reference by boxing the struct instance into a ref
    $refBox = [ref]$fileInfo
    $ok = [Win32]::GetFileInformationByHandleEx($handle, 0, $refBox, [uint32]$fileInfoSize)
    if (-not $ok) {
        $win32Error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "GetFileInformationByHandleEx failed with Win32 error $win32Error."
    }

    # After successful call, $refBox.Value contains the populated struct instance
    $populated = $refBox.Value
    # Extract ChangeTime (FILETIME 100-ns intervals since 1601)
    $changeTimeUtc = [DateTime]::FromFileTimeUtc($populated.ChangeTime)
}
catch {
    $errMsg = $_.Exception.Message
    Write-Verbose "Unable to retrieve ChangeTime via Win32 API: $errMsg"
}
finally {
    if ($handle -ne $null -and -not $handle.IsInvalid) {
        $handle.Close()
        $handle.Dispose()
    }
}

# -------------------------
# Offset formatting helpers
# -------------------------
function Format-ShortTimeSpan {
    param([TimeSpan]$ts)
    $days = [int]$ts.TotalDays
    $hours = [int]$ts.Hours
    $minutes = [int]$ts.Minutes
    $seconds = [int]$ts.Seconds
    return ("{0} d, {1} h, {2} m, {3} s" -f $days, $hours, $minutes, $seconds)
}

function Get-OffsetInfo {
    param(
        [DateTime]$timeUtc,
        [DateTime]$birthUtc
    )

    if ($null -eq $timeUtc) {
        return @{
            Human = "<unavailable - permission or API error>";
            SecondsField = ("<unavailable>").PadLeft(20);
        }
    }

    $diff = $timeUtc - $birthUtc
    $isBefore = $diff.TotalSeconds -lt 0

    if ($isBefore) {
        $absDiff = [TimeSpan]::FromSeconds([math]::Round([math]::Abs($diff.TotalSeconds)))
        $human = (Format-ShortTimeSpan -ts $absDiff) + " (BEFORE Birth)"
        $secondsStr = ("-{0}" -f ([math]::Round([math]::Abs($diff.TotalSeconds))))
    }
    else {
        $human = Format-ShortTimeSpan -ts $diff
        $secondsStr = ("{0}" -f ([math]::Round($diff.TotalSeconds)))
    }

    $secondsField = $secondsStr.PadLeft(20)

    return @{
        Human = $human;
        SecondsField = $secondsField;
    }
}

# Compute offsets
$modifiedInfo = Get-OffsetInfo -timeUtc $modifiedTimeUtc -birthUtc $birthTimeUtc
$accessedInfo = Get-OffsetInfo -timeUtc $accessedTimeUtc -birthUtc $birthTimeUtc
if ($changeTimeUtc -ne $null) {
    $changedInfo = Get-OffsetInfo -timeUtc $changeTimeUtc -birthUtc $birthTimeUtc
}
else {
    $changedInfo = @{
        Human = "<unavailable - permission or API error>";
        SecondsField = ("<unavailable>").PadLeft(20);
    }
}

# -------------------------
# Output: first line contains label, UTC time, "Diff " + compact human text
# second line contains the right-aligned seconds field (20 chars) preceded by two spaces
# -------------------------
$fmtLine = "{0,-10} {1}  Diff {2}"
Write-Output ($fmtLine -f 'Modified', ($modifiedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")), $modifiedInfo.Human)
Write-Output ("Modified:  " + $modifiedInfo.SecondsField)
Write-Output ($fmtLine -f 'Accessed', ($accessedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")), $accessedInfo.Human)
Write-Output ("Accessed:  " + $accessedInfo.SecondsField)
if ($changeTimeUtc -ne $null) {
    Write-Output ($fmtLine -f 'Changed', ($changeTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")), $changedInfo.Human)
    Write-Output ("Changed:  " + $changedInfo.SecondsField)
}
else {
    Write-Output ($fmtLine -f 'Changed', "<unavailable - permission or API error>", $changedInfo.Human)
    Write-Output ("changed:  " + $changedInfo.SecondsField)
}
# Birth line: Diff is zero; seconds field is 0 right-aligned
$birthHuman = "0 d, 0 h, 0 m, 0 s"
$birthSecondsField = ("0").PadLeft(20)
Write-Output ($fmtLine -f 'Birth', ($birthTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")), $birthHuman)
Write-Output ("Birth:  " + $birthSecondsField)
