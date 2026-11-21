# The local-proxy session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# The first profile is imported and started as a local proxy: native HTTP
# through its listener, the connection diagnostics on the same core, and the
# listener's release after Stop.
$started = (Invoke-GuiScenario 'network-start') | ConvertFrom-Json
$started | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-start.json') -Encoding utf8NoBOM
if (-not $started.controller_verified) { throw 'GUI network case did not verify its real controller' }
$receipt.controller_verified = $true
$proxyPort = [int]$started.settings.effective.mixed_port
if ($proxyPort -lt 1 -or $proxyPort -gt 65535) { throw 'GUI proxy port is invalid' }
$receipt.native_gui_exercised = $true
$receipt.imported_profile_id = $started.selected.profiles[0].id
$receipt.proxy_port = $proxyPort
$receipt.active_runtime = $started.active.snapshot.state.runtime
$http = Invoke-NativeNetworkProbe 'http' $proxyPort $launch
$receipt.http_forwarding_verified = $true
# The diagnostics' routed checks pass through this same core.
$diagnostics = (Invoke-GuiScenario 'connection-diagnostics') | ConvertFrom-Json
$diagnostics | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'connection-diagnostics.json') -Encoding utf8NoBOM
$diagnosedIdentity = $diagnostics.before.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($diagnosedIdentity -cne ($started.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress) -or
    -not $diagnostics.connection_diagnostics_exercised -or $diagnostics.release_accepted) {
    throw 'Connection diagnostics did not run on the LocalProxy core started by this scenario'
}
$receipt.connection_diagnostics_exercised = $true
$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$startedIdentity = $started.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($startedIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off' -or
    $stopped.stopped.snapshot.generation -lt $started.active.snapshot.generation) {
    throw 'GUI stop did not retire the runtime started by this scenario'
}
$closed = Invoke-NativeNetworkProbe 'closed' $proxyPort $launch
if ($http.user_proxy_sha256 -cne $closed.user_proxy_sha256) { throw 'User proxy options changed between GUI traffic and stop' }
$receipt.engine_stopped = $true
$receipt.listener_released = $true
$receipt.network_mode_exercised = $true
