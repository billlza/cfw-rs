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
function Invoke-OwnedProbe([string[]]$Arguments, [string]$Prefix) {
    $start = [Diagnostics.ProcessStartInfo]::new([IO.Path]::GetFullPath($Probe))
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.Environment['CFW_NATIVE_TUN_SOURCE'] = $Source
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $operationFailure = $null
    $cleanupFailures = [Collections.Generic.List[string]]::new()
    $observed = [ordered]@{ source=$Source; process_id=$process.Id; process_creation_time=$process.StartTime.ToFileTimeUtc()
        exit_code=$null; exit_observed=$false; release_accepted=$false }
    try {
        if (-not $process.WaitForExit(180000)) { throw 'Wintun probe exceeded its lifecycle deadline' }
        $observed.exit_observed = $true
        $observed.exit_code = $process.ExitCode
        if ($process.ExitCode -ne 0) { throw "Wintun native probe failed ($($process.ExitCode)); inspect retained observations" }
    } catch { $operationFailure = $_.Exception.ToString() }
    finally {
        try {
            if (-not $process.HasExited) {
                # This retained process and its deliberately parked child are
                # this disposable fixture, never a product process.
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) { throw 'Timed-out Wintun fixture did not retire' }
            }
            if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Wintun fixture output did not drain' }
            [IO.File]::WriteAllText((Join-Path $outputRoot "${Prefix}stdout.log"), $stdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText((Join-Path $outputRoot "${Prefix}stderr.log"), $stderr.GetAwaiter().GetResult())
            $observed | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot "${Prefix}process.json") -Encoding utf8NoBOM
        } catch { $cleanupFailures.Add($_.Exception.ToString()) }
        finally { $process.Dispose() }
    }
    if ($null -ne $operationFailure -or $cleanupFailures.Count -ne 0) {
        throw (($operationFailure, ($cleanupFailures -join '; ')) -join '; ')
    }
    return [pscustomobject]$observed
}

try {
    $lifecycleProcess = Invoke-OwnedProbe @($dll, (Join-Path $outputRoot 'native')) ''
    $initial = Get-Content -LiteralPath (Join-Path $outputRoot 'native/initial.json') -Raw | ConvertFrom-Json
    if ($initial.process_id -ne $lifecycleProcess.process_id -or $initial.process_creation_time -ne $lifecycleProcess.process_creation_time) {
        throw 'Lifecycle receipt is not from the retained native process'
    }
    $receipt = Get-Content -LiteralPath (Join-Path $outputRoot 'native/result.json') -Raw | ConvertFrom-Json
    if ($receipt.source -cne $Source -or -not $receipt.success -or $null -ne $receipt.failure -or
        -not $receipt.normal_and_forced_owner_exit_exercised -or $receipt.explicit_route_dns_firewall_writes -or
        $receipt.crash_recovery_strategy -cne 'retained_device_instance' -or $receipt.service_restart_recovery_exercised -or
        $receipt.packet_traffic_verified -or $receipt.product_tunnel_backend_exercised -or $receipt.release_accepted) {
        throw 'Wintun lifecycle receipt is invalid or overstates its scope'
    }
    $binding = Get-Content -LiteralPath (Join-Path $outputRoot 'native/abrupt-device-binding.json') -Raw | ConvertFrom-Json
    $retired = Get-Content -LiteralPath (Join-Path $outputRoot 'native/abrupt-retired.json') -Raw | ConvertFrom-Json
    $control = Get-Content -LiteralPath (Join-Path $outputRoot 'native/recovery-control-preserved.json') -Raw | ConvertFrom-Json
    if ($binding.source -cne $Source -or $retired.source -cne $Source -or $control.source -cne $Source -or
        -not $binding.live_owner_removal_rejected -or -not $binding.foreign_guid_rejected -or
        $binding.luid -ne $retired.luid -or $binding.name -cne $retired.name -or
        -not $retired.adapter_absence_observed -or -not $control.live_control_preserved -or
        $control.interface_guid -ceq $binding.interface_guid -or
        $retired.explicit_owned_device_removal -eq $retired.automatic_absence_observed) {
        throw 'Wintun owned recovery or live control observation is incomplete'
    }

    $packetProcess = Invoke-OwnedProbe @('--packet-roundtrip', $dll, (Join-Path $outputRoot 'packet-native')) 'packet-'
    $initial = Get-Content -LiteralPath (Join-Path $outputRoot 'packet-native/initial.json') -Raw | ConvertFrom-Json
    if ($initial.process_id -ne $packetProcess.process_id -or $initial.process_creation_time -ne $packetProcess.process_creation_time) {
        throw 'Packet receipt is not from the retained native process'
    }
    $packets = Get-Content -LiteralPath (Join-Path $outputRoot 'packet-native/result.json') -Raw | ConvertFrom-Json
    if ($packets.source -cne $Source -or -not $packets.success -or $null -ne $packets.failure -or
        -not $packets.packet_traffic_verified -or ($packets.ip_families -join ',') -cne 'ipv4' -or
        $packets.owned_host_route -cne '192.0.2.123/32' -or $packets.owned_address -cne '192.0.2.10/32' -or
        $packets.default_routes_modified -or $packets.dns_modified -or $packets.firewall_modified -or
        $packets.engine_forwarding_verified -or $packets.product_tunnel_backend_exercised -or $packets.release_accepted -or
        ($packets.cases.mtu -join ',') -cne '1280,1500,9000') {
        throw 'Wintun packet receipt is incomplete or overstates its scope'
    }
    foreach ($case in $packets.cases) {
        if ($case.source -cne $Source -or $case.luid -le 0 -or $case.name -cne "CFW-TUN-$($case.interface_guid)" -or
            $case.request_packet_bytes -ne $case.mtu -or $case.response_packet_bytes -ne $case.mtu -or
            $case.payload_bytes -ne ($case.mtu - 28) -or $case.received_payload_bytes -ne $case.payload_bytes -or
            -not $case.windows_udp_to_wintun_verified -or -not $case.wintun_to_windows_udp_verified -or
            -not $case.request_response_payloads_differ -or -not $case.owned_route_address_mtu_restored -or
            -not $case.adapter_absence_observed -or -not $case.fixture_addresses_and_host_route_absent -or $case.release_accepted) {
            throw 'Wintun full-MTU roundtrip or cleanup was not observed'
        }
        foreach ($direction in @('request','response')) {
            $path = Join-Path $outputRoot "packet-native/mtu-$($case.mtu)-$direction.bin"
            if ((Get-Item -LiteralPath $path).Length -ne $case.mtu -or
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $case."${direction}_sha256") {
                throw 'Wintun packet bytes differ from their native receipt'
            }
        }
    }
} catch {
    $primaryFailure = $_.Exception.ToString()
    [ordered]@{ source=$Source; primary_failure=$primaryFailure; release_accepted=$false } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'failure.json') -Encoding utf8NoBOM
    throw
}
