param(
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$Payload,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$Source
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:CFW_NATIVE_TUN_MUTATION_TESTS -cne '1') {
    throw 'Wintun lifecycle validation requires an opted-in disposable Windows runner'
}
if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
    throw 'Wintun validation source mismatch'
}
$outputRoot = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $outputRoot -ErrorAction Stop | Out-Null
$dll = Join-Path ([IO.Path]::GetFullPath($Payload)) 'wintun.dll'
$staged = Get-Content -LiteralPath (Join-Path $Payload 'staging.json') -Raw | ConvertFrom-Json
if ((Get-FileHash $dll -Algorithm SHA256).Hash.ToLowerInvariant() -cne $staged.dll_sha256) { throw 'Staged Wintun DLL changed' }
$signature = Get-AuthenticodeSignature -FilePath $dll
if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { throw "Official Wintun signature is not valid: $($signature.Status)" }
[ordered]@{ source=$Source; dll_sha256=$staged.dll_sha256; status=$signature.Status.ToString();
    signer_subject=$signature.SignerCertificate.Subject; signer_thumbprint=$signature.SignerCertificate.Thumbprint;
    temporary_trust_added=$false; release_accepted=$false } | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $outputRoot 'authenticode.json') -Encoding utf8NoBOM
$start = [Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($Probe))
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.ArgumentList.Add($dll)
$start.ArgumentList.Add((Join-Path $outputRoot 'native'))
$start.Environment['CFW_NATIVE_TUN_SOURCE'] = $Source
$process = [Diagnostics.Process]::Start($start)
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
try {
    if (-not $process.WaitForExit(180000)) { throw 'Wintun probe exceeded its lifecycle deadline' }
    if ($process.ExitCode -ne 0) { throw "Wintun native lifecycle failed ($($process.ExitCode)); inspect retained observations" }
    $receipt = Get-Content -LiteralPath (Join-Path $outputRoot 'native/result.json') -Raw | ConvertFrom-Json
    if ($receipt.source -cne $Source -or -not $receipt.success -or $null -ne $receipt.failure -or
        -not $receipt.normal_and_forced_owner_exit_exercised -or $receipt.explicit_route_dns_firewall_writes -or
        $receipt.packet_traffic_verified -or $receipt.product_tunnel_backend_exercised -or $receipt.release_accepted) {
        throw 'Wintun lifecycle receipt is invalid or overstates its scope'
    }
} catch {
    $primaryFailure = $_.Exception.ToString()
} finally {
    try {
        if (-not $process.HasExited) {
            # This retained fixture and its one deliberately parked owner child
            # belong to this disposable test. Never target a product process.
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) { throw 'Timed-out Wintun fixture did not retire' }
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Wintun fixture output did not drain' }
        [IO.File]::WriteAllText((Join-Path $outputRoot 'stdout.log'), $stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $outputRoot 'stderr.log'), $stderr.GetAwaiter().GetResult())
    } catch {
        $cleanupFailures.Add($_.Exception.ToString())
    } finally { $process.Dispose() }
}
if ($null -ne $primaryFailure -or $cleanupFailures.Count -ne 0) {
    $failure = [ordered]@{ source=$Source; primary_failure=$primaryFailure; cleanup_failures=$cleanupFailures.ToArray(); release_accepted=$false }
    try {
        $failure | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputRoot 'failure.json') -Encoding utf8NoBOM
    } catch {
        $cleanupFailures.Add("Failure receipt: $($_.Exception)")
    }
    throw (($primaryFailure, ($cleanupFailures -join '; ')) -join '; ')
}
