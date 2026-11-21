# The tunnel session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# TUN Mode on the LocalProxy profile. System Proxy joins the running tunnel
# and leaves it, both leak protection switches go on and off, and TUN Mode off
# hands over to a local core, which Stop retires.
$started = (Invoke-GuiScenario 'tunnel-start') | ConvertFrom-Json
$started | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'tunnel-start.json') -Encoding utf8NoBOM
if (-not $started.controller_verified -or -not $started.combined_mode_offered) {
    throw 'TUN GUI did not verify its controller and the offered combined mode'
}
$receipt.controller_verified = $true
$receipt.native_gui_exercised = $true
$receipt.imported_profile_id = $started.before.profiles.profiles[0].id
$installation = [string]$started.active.snapshot.state.runtime.context.installation_id
# System Proxy joins the running tunnel and leaves it again.
$combined = (Invoke-GuiScenario 'combined-start') | ConvertFrom-Json
$combined | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'combined-start.json') -Encoding utf8NoBOM
$startedIdentity = $started.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$joinedIdentity = $combined.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($startedIdentity -cne $joinedIdentity -or -not $combined.controller_verified) {
    throw 'System Proxy did not join the TUN runtime started by this scenario'
}
$proxyPort = [int]$combined.settings.effective.mixed_port
if ($proxyPort -lt 1 -or $proxyPort -gt 65535) { throw 'GUI combined proxy port is invalid' }
$receipt.proxy_port = $proxyPort
$receipt.combined_runtime = $combined.active.snapshot.state.runtime
$combinedHttp = Invoke-NativeCombinedProbe $installation $proxyPort $launch
$receipt.http_forwarding_verified = $true
$left = (Invoke-GuiScenario 'combined-stop') | ConvertFrom-Json
$left | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'combined-stop.json') -Encoding utf8NoBOM
$combinedIdentity = $combined.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$leftIdentity = $left.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($combinedIdentity -cne $leftIdentity) { throw 'System Proxy off did not retire the combined runtime started by this scenario' }
# The combined run is over: its listener is gone and this user's proxy
# options are as they were, while the tunnel that replaced it carries traffic.
$closed = Invoke-NativeNetworkProbe 'closed' $proxyPort $launch
$receipt.listener_released = $true
$receipt.active_runtime = $left.tunnel.snapshot.state.runtime
$receipt.tunnel_runtime = $left.tunnel.snapshot.state.runtime
$tunnelHttp = Invoke-NativeTunnelProbe 'tunnel-http' $installation $launch
if ($tunnelHttp.adapter -cne $combinedHttp.adapter -or $closed.user_proxy_sha256 -cne $tunnelHttp.user_proxy_sha256) {
    throw 'The tunnel after the combined mode differs from the installation adapter or the restored user proxy'
}
$receipt.http_through_tunnel_verified = $true
$receipt.combined_mode_exercised = $true
# Both leak protection switches go on and off again while the tunnel
# runs. Each change replaces the engine, and sockets of this session
# see what the running engine refuses.
$open = Invoke-NativeLeakProtectionProbe 'leak-open' $installation 'any' 'any' $launch
$protected = (Invoke-GuiScenario 'leak-protection-on') | ConvertFrom-Json
$protected | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'leak-protection-on.json') -Encoding utf8NoBOM
$tunnelIdentity = $left.tunnel.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$protectedIdentity = $protected.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($tunnelIdentity -cne $protectedIdentity -or $protected.leak_protection -ne $true -or @($protected.changes).Count -ne 2 -or
    $protected.active.snapshot.generation -le $left.tunnel.snapshot.generation) {
    throw 'Leak protection was not turned on in the TUN runtime that followed the combined mode'
}
$refused = Invoke-NativeLeakProtectionProbe 'leak-refused' $installation $open.resolver $open.stun.target $launch
$unprotected = (Invoke-GuiScenario 'leak-protection-off') | ConvertFrom-Json
$unprotected | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'leak-protection-off.json') -Encoding utf8NoBOM
$refusingIdentity = $protected.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$unprotectedIdentity = $unprotected.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($refusingIdentity -cne $unprotectedIdentity -or $unprotected.leak_protection -ne $false -or @($unprotected.changes).Count -ne 2 -or
    $unprotected.active.snapshot.generation -le $protected.active.snapshot.generation) {
    throw 'Leak protection was not turned off in the TUN runtime that refused the named flows'
}
$reopened = Invoke-NativeLeakProtectionProbe 'leak-reopened' $installation $open.resolver $open.stun.target $launch
if ($open.adapter -cne $tunnelHttp.adapter -or $refused.adapter -cne $tunnelHttp.adapter -or $reopened.adapter -cne $tunnelHttp.adapter) {
    throw 'The leak protection probes observed another adapter than the installation tunnel'
}
$receipt.leak_protection_exercised = $true
$handover = (Invoke-GuiScenario 'tunnel-stop') | ConvertFrom-Json
$handover | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'tunnel-stop.json') -Encoding utf8NoBOM
$tunnelIdentity = $unprotected.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$handoverIdentity = $handover.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($tunnelIdentity -cne $handoverIdentity -or $handover.local.snapshot.state.state -cne 'local_proxy_active' -or
    $handover.local.snapshot.generation -le $unprotected.active.snapshot.generation) {
    throw 'TUN Mode off did not retire the TUN runtime that followed the leak protection changes'
}
$receipt.core_preserved_after_tunnel = $true
$tunnelClosed = Invoke-NativeTunnelProbe 'tunnel-closed' $installation $launch
if ($tunnelClosed.adapter -cne $tunnelHttp.adapter -or $tunnelClosed.route_luid -eq $tunnelHttp.adapter_luid) {
    throw 'The system route still enters the retired tunnel adapter'
}
$receipt.tunnel_adapter_retired = $true
$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$localIdentity = $handover.local.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($localIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the local core that replaced TUN Mode'
}
$receipt.engine_stopped = $true
$receipt.network_mode_exercised = $true
