# Isolated OS contract probe. It operates only inside a fresh runner-temporary
# directory; it is not an application storage implementation or release proof.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class StorageFlushProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access,
        uint sharing, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    public static int DirectoryFlush(string path)
    {
        // GENERIC_READ | GENERIC_WRITE; FILE_FLAG_BACKUP_SEMANTICS |
        // FILE_FLAG_OPEN_REPARSE_POINT. This requests metadata write access.
        using (var directory = CreateFileW(path, 0xc0000000, 7, IntPtr.Zero, 3,
            0x02200000, IntPtr.Zero))
        {
            if (directory.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            return FlushFileBuffers(directory) ? 0 : Marshal.GetLastWin32Error();
        }
    }
}
'@

if (-not $IsWindows) { throw 'This contract requires Windows.' }
if (-not $env:RUNNER_TEMP) { throw 'A runner-owned temporary directory is required.' }
$root = Join-Path $env:RUNNER_TEMP ("cfw-storage-contract-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
try {
    $file = Join-Path $root 'settings.json'
    $stream = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"revision":1}')
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    $beforeRename = [StorageFlushProbe]::DirectoryFlush($root)
    Move-Item -LiteralPath $file -Destination (Join-Path $root 'renamed.json') -ErrorAction Stop
    $afterRename = [StorageFlushProbe]::DirectoryFlush($root)
    Remove-Item -LiteralPath (Join-Path $root 'renamed.json') -ErrorAction Stop
    $afterDelete = [StorageFlushProbe]::DirectoryFlush($root)
    [ordered]@{
        os = [Environment]::OSVersion.VersionString
        directory_flush_before_rename = $beforeRename
        directory_flush_after_rename = $afterRename
        directory_flush_after_delete = $afterDelete
    } | ConvertTo-Json
    if ($beforeRename -ne 0 -or $afterRename -ne 0 -or $afterDelete -ne 0) {
        throw 'Windows did not satisfy the required directory metadata flush contract.'
    }
} finally {
    Remove-Item -LiteralPath $root -Recurse -ErrorAction Stop
}
