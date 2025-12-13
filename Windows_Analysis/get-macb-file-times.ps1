<#
.SYNOPSIS
  Print NTFS MACB times (Modified, Accessed, Changed, Birth) for a file or directory in a two-column (label/value) format.

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

# Output in two-column (label/value) format (not a table)
$fmt = "{0,-10} {1}"
Write-Output ($fmt -f 'Modified',  ($modifiedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")))
Write-Output ($fmt -f 'Accessed',  ($accessedTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")))
if ($changeTimeUtc -ne $null) {
    Write-Output ($fmt -f 'Changed',   ($changeTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")))
}
else {
    Write-Output ($fmt -f 'Changed',   "<unavailable - permission or API error; run with -Verbose to see details>")
}
Write-Output ($fmt -f 'Birth',     ($birthTimeUtc.ToString("yyyy-MM-dd HH:mm:ss.fffffff 'UTC'")))
