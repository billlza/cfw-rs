# The native probes of one installed GUI session and what each receipt must
# say before the session goes on. A probe is one run of the fixture launcher
# in the session of the GUI and outside its process. The session imports this
# module with its launcher, source and receipt directory.
param(
    [Parameter(Mandatory)][string]$Launcher,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Receipts
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# One native probe of the fixture, run in this session; returns its receipt.
function Invoke-NativeProbe([string]$Name, [string[]]$Arguments, [int]$TimeoutMs = 30000) {
    $start = [Diagnostics.ProcessStartInfo]::new($Launcher)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.Environment['CFW_NATIVE_SERVICE_SOURCE'] = $Source
    $start.Environment['CFW_NATIVE_SERVICE_RECEIPTS'] = $Receipts
    $process = [Diagnostics.Process]::Start($start)
    $probeStdout = $process.StandardOutput.ReadToEndAsync()
    $probeStderr = $process.StandardError.ReadToEndAsync()
    try {
        if (-not $process.WaitForExit($TimeoutMs)) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw "Timed-out native GUI $Name probe did not retire" }
            throw "Native GUI $Name probe exceeded its observation deadline"
        }
        if ($process.ExitCode -ne 0) { throw "Native GUI $Name probe failed; see its retained stderr" }
        return Get-Content -LiteralPath (Join-Path $Receipts "$Name-probe.json") -Raw | ConvertFrom-Json
    } finally {
        if ($process.HasExited) {
            [IO.File]::WriteAllText((Join-Path $Receipts "$Name-probe-stdout.log"), $probeStdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText((Join-Path $Receipts "$Name-probe-stderr.log"), $probeStderr.GetAwaiter().GetResult())
        }
        $process.Dispose()
    }
}
function Invoke-NativeNetworkProbe([ValidateSet('http', 'closed', 'system-http')][string]$Operation, [int]$Port, $LaunchReceipt) {
    $record = Invoke-NativeProbe $Operation @('--installed-gui-network-probe', $Operation, $Port.ToString([Globalization.CultureInfo]::InvariantCulture)) 20000
    if ($record.document -cne 'cfw-installed-gui-network-probe-v1' -or $record.source -cne $Source -or
        $record.operation -cne $Operation -or $record.gui_process_id -ne $LaunchReceipt.process_id -or
        $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
        -not $record.gui_same_user_session -or $record.proxy_address -cne "127.0.0.1:$Port" -or
        $record.original_user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or
        $record.http_forwarding_verified -ne ($Operation -cne 'closed') -or
        $record.listener_refused -ne ($Operation -ceq 'closed') -or $record.release_accepted) {
        throw 'Native network proof differs from the UI-owned runtime and original user proxy'
    }
    if ($Operation -ceq 'system-http') {
        if (-not $record.system_proxy_applied -or -not $record.applied_user_proxy_unchanged -or
            -not $record.wininet_via_proxy_verified -or ($record.wininet_request_flags -band 4) -ne 4 -or
            $record.user_proxy_unchanged -or $record.user_proxy_sha256 -ceq $LaunchReceipt.user_proxy_before_sha256) {
            throw 'WinINet did not observe the GUI-owned system proxy'
        }
    } elseif ($record.user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or -not $record.user_proxy_unchanged) {
        throw 'The native user proxy differs from the original'
    }
    return $record
}
# One real press of the shortcut the automation session entered, sent through
# Windows on the GUI's input desktop. The product is not addressed.
function Invoke-NativeShortcutProbe([ValidateSet('shortcut-stop', 'shortcut-start', 'shortcut-removed')][string]$Operation, $LaunchReceipt) {
    $record = Invoke-NativeProbe $Operation @('--installed-gui-shortcut-probe', $Operation) 20000
    if ($record.document -cne 'cfw-installed-gui-shortcut-probe-v1' -or $record.source -cne $Source -or
        $record.operation -cne $Operation -or $record.gui_process_id -ne $LaunchReceipt.process_id -or
        $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
        -not $record.gui_same_user_session -or $record.shortcut -cne 'Control+Alt+Shift+F9' -or
        $record.keyboard_events_sent -ne 8 -or $record.keyboard_events_accepted -ne 8 -or
        -not $record.desktop_observation.input_desktop_observed -or $record.product_addressed -or $record.release_accepted) {
        throw 'The native shortcut press differs from the launched GUI and its input desktop'
    }
    return $record
}
function Invoke-NativeTunnelProbe([ValidateSet('tunnel-http', 'tunnel-closed')][string]$Operation, [string]$Installation, $LaunchReceipt) {
    $record = Invoke-NativeProbe $Operation @('--installed-gui-tunnel-probe', $Operation, $Installation)
    $on = $Operation -ceq 'tunnel-http'
    if ($record.document -cne 'cfw-installed-gui-tunnel-probe-v1' -or $record.source -cne $Source -or
        $record.operation -cne $Operation -or $record.gui_process_id -ne $LaunchReceipt.process_id -or
        $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
        -not $record.gui_same_user_session -or $record.installation_id -cne $Installation -or
        $record.adapter_absent -eq $on -or $record.route_entered_tunnel -ne $on -or
        $record.http_through_tunnel_verified -ne $on -or
        ($on -and ($record.route_luid -ne $record.adapter_luid -or $record.local_address -cnotlike '198.18.64.1:*')) -or
        -not $record.user_proxy_unchanged -or $record.user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or
        $record.release_accepted) {
        throw 'Native tunnel proof differs from the UI-owned TUN runtime and the original user proxy'
    }
    return $record
}
function Invoke-NativeCombinedProbe([string]$Installation, [int]$Port, $LaunchReceipt) {
    $record = Invoke-NativeProbe 'combined-http' @('--installed-gui-combined-probe', $Installation, $Port.ToString([Globalization.CultureInfo]::InvariantCulture))
    $ports = @($record.native_user_proxy.ports)
    if ($record.document -cne 'cfw-installed-gui-combined-probe-v1' -or $record.source -cne $Source -or
        $record.gui_process_id -ne $LaunchReceipt.process_id -or
        $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
        -not $record.gui_same_user_session -or $record.installation_id -cne $Installation -or
        -not $record.route_entered_tunnel -or $record.route_luid -ne $record.adapter_luid -or
        $record.local_address -cnotlike '198.18.64.1:*' -or -not $record.http_through_tunnel_verified -or
        $record.proxy_address -cne "127.0.0.1:$Port" -or -not $record.http_forwarding_verified -or
        -not $record.system_proxy_applied -or -not $record.native_user_proxy.manual_proxy_enabled -or
        $record.native_user_proxy.auto_config_enabled -or $record.native_user_proxy.auto_detect_enabled -or
        $ports.Count -ne 1 -or $ports[0] -ne $Port -or
        $record.original_user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or
        $record.user_proxy_sha256 -ceq $LaunchReceipt.user_proxy_before_sha256 -or $record.release_accepted) {
        throw 'Native combined proof differs from the UI-owned runtime, its tunnel and its proxy listener'
    }
    return $record
}
function Invoke-NativeLeakProtectionProbe([ValidateSet('leak-open', 'leak-refused', 'leak-reopened')][string]$Operation, [string]$Installation, [string]$Resolver, [string]$StunServer, $LaunchReceipt) {
    $record = Invoke-NativeProbe $Operation @('--installed-gui-leak-protection-probe', $Operation, $Installation, $Resolver, $StunServer)
    $protected = $Operation -ceq 'leak-refused'
    $flow = if ($protected) { 'refused' } else { 'connected' }
    $last = @($record.encrypted_dns_attempts)[-1]
    if ($record.document -cne 'cfw-installed-gui-leak-protection-probe-v1' -or $record.source -cne $Source -or
        $record.operation -cne $Operation -or $record.gui_process_id -ne $LaunchReceipt.process_id -or
        $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
        -not $record.gui_same_user_session -or $record.installation_id -cne $Installation -or
        -not $record.route_entered_tunnel -or ($Resolver -cne 'any' -and $record.resolver -cne $Resolver) -or
        $record.encrypted_dns_tcp -cne $flow -or $last.outcome -cne $flow -or $last.target -cne "$($record.resolver):853" -or
        ($StunServer -cne 'any' -and $record.stun.target -cne $StunServer) -or ($record.stun.outcome -ceq 'answered') -eq $protected -or
        $record.http_through_tunnel_verified -ne $protected -or
        ($protected -and $record.http_local_address -cnotlike '198.18.64.1:*') -or
        -not $record.user_proxy_unchanged -or $record.user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or
        $record.release_accepted) {
        throw "Native leak protection proof differs from the UI-owned TUN runtime with both switches $(if ($protected) { 'on' } else { 'off' })"
    }
    return $record
}

Export-ModuleMember -Function Invoke-NativeNetworkProbe, Invoke-NativeShortcutProbe, Invoke-NativeTunnelProbe,
    Invoke-NativeCombinedProbe, Invoke-NativeLeakProtectionProbe
