# The runtime-settings session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# The Network settings dialog and the General page's own controls, with the
# LocalProxy profile alone. A core started on the automatic port is replaced
# by one on a port of this session's choosing that shares it with one trusted
# source, this machine's private address: a request from that address passes
# and one from the loopback address is refused. The application refuses a
# public source range and leaves the core and the saved settings as they were.
# The log level and the Allow LAN switch of the General page each replace the
# core again. With the core stopped an MTU is saved; TUN Mode starts with it
# and takes another while it runs, and Windows reports each on the adapter.
# The session ends with the settings it began with, so the next one begins as
# this one did.
#
# Not observed: whether another device reaches the LAN port. The Windows
# firewall decides that, and the product writes no firewall rule.

# Two ports nothing is bound to, held together so that they differ. They are
# bound and never listened on.
$held = [Collections.Generic.List[Net.Sockets.Socket]]::new()
try {
    foreach ($address in [Net.IPAddress]::Loopback, [Net.IPAddress]::Any) {
        $socket = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
        $held.Add($socket)
        $socket.Bind([Net.IPEndPoint]::new($address, 0))
    }
    $proxyPort = ([Net.IPEndPoint]$held[0].LocalEndPoint).Port
    $lanPort = ([Net.IPEndPoint]$held[1].LocalEndPoint).Port
} finally { foreach ($socket in $held) { $socket.Dispose() } }
if ($proxyPort -eq $lanPort) { throw 'The runtime settings session could not choose two different ports' }
# The address Windows routes from. Route selection sends no datagram.
$route = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
try {
    $route.Connect('192.0.2.1', 9)
    $trustedSource = ([Net.IPEndPoint]$route.Client.LocalEndPoint).Address.ToString()
} finally { $route.Dispose() }
$sessionInput = [ordered]@{ port=$proxyPort; lan_port=$lanPort; trusted_source=$trustedSource }

$applied = (Invoke-GuiScenario 'runtime-settings-apply') | ConvertFrom-Json
$applied | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-apply.json') -Encoding utf8NoBOM
$defaultPort = [int]$applied.default_port
if (-not $applied.controller_verified -or $applied.release_accepted -or $defaultPort -lt 1 -or $defaultPort -gt 65535 -or
    $defaultPort -eq $proxyPort -or $defaultPort -eq $lanPort) {
    throw 'The runtime settings GUI did not verify its controller on a core that left the automatic port'
}
$receipt.controller_verified = $true
$receipt.native_gui_exercised = $true
$receipt.kept_profile_id = $applied.profile
$receipt.proxy_port = $proxyPort
$receipt.active_runtime = $applied.active.engine.snapshot.state.runtime
# The replacement forwards on the configured port and left nothing on the
# automatic one. Every probe also requires the user proxy options the GUI was
# launched with.
Invoke-NativeNetworkProbe 'http' $proxyPort $launch | Out-Null
Invoke-NativeNetworkProbe 'closed' $defaultPort $launch 'automatic-closed' | Out-Null
$receipt.http_forwarding_verified = $true
Invoke-NativeLanProbe 'lan-shared' $trustedSource $lanPort $launch | Out-Null

$refused = (Invoke-GuiScenario 'runtime-settings-refused') | ConvertFrom-Json
$refused | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-refused.json') -Encoding utf8NoBOM
$appliedIdentity = $applied.active.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$keptIdentity = $refused.kept.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($appliedIdentity -cne $keptIdentity -or $refused.release_accepted) {
    throw 'The refused public source range did not leave the core this session configured'
}

$general = (Invoke-GuiScenario 'runtime-settings-general') | ConvertFrom-Json
$general | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-general.json') -Encoding utf8NoBOM
$generalIdentity = $general.before.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($appliedIdentity -cne $generalIdentity -or $general.reported.log_level -cne 'debug' -or $general.release_accepted -or
    $general.active.engine.snapshot.generation -le $applied.active.engine.snapshot.generation) {
    throw 'The General page did not change the log level and LAN sharing of the core this session configured'
}
# Nothing listens on the LAN port any more, and the core still forwards.
Invoke-NativeLanProbe 'lan-closed' $trustedSource $lanPort $launch | Out-Null
Invoke-NativeNetworkProbe 'http' $proxyPort $launch 'unshared-http' | Out-Null

$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$unsharedIdentity = $general.active.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($unsharedIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the core the General page left running'
}
Invoke-NativeNetworkProbe 'closed' $proxyPort $launch | Out-Null
$receipt.listener_released = $true

# The MTU is saved while nothing runs, and TUN Mode starts with it.
$mtu = (Invoke-GuiScenario 'runtime-settings-mtu') | ConvertFrom-Json
$mtu | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-mtu.json') -Encoding utf8NoBOM
if ($mtu.release_accepted -or $mtu.saved_mtu -eq $applied.before.settings.settings.tunnel_mtu) {
    throw 'The MTU saved with the core off is not a changed one'
}
$tunnelStarted = (Invoke-GuiScenario 'tunnel-start') | ConvertFrom-Json
$tunnelStarted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'tunnel-start.json') -Encoding utf8NoBOM
if (-not $tunnelStarted.controller_verified) { throw 'TUN GUI did not verify its controller with the saved MTU' }
$installation = [string]$tunnelStarted.active.snapshot.state.runtime.context.installation_id
$tunnelHttp = Invoke-NativeTunnelProbe 'tunnel-http' $installation $launch
if ($tunnelHttp.adapter_mtu -ne $mtu.saved_mtu) {
    throw "Windows reports MTU $($tunnelHttp.adapter_mtu) on the tunnel adapter, not the saved $($mtu.saved_mtu)"
}
$live = (Invoke-GuiScenario 'runtime-settings-live-mtu') | ConvertFrom-Json
$live | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-live-mtu.json') -Encoding utf8NoBOM
$tunnelIdentity = $tunnelStarted.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$liveIdentity = $live.before.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($tunnelIdentity -cne $liveIdentity -or $live.release_accepted -or $live.live_mtu -eq $mtu.saved_mtu) {
    throw 'The MTU was not changed in the TUN runtime that started with the saved one'
}
$tunnelChanged = Invoke-NativeTunnelProbe 'tunnel-http' $installation $launch 'tunnel-mtu-changed'
if ($tunnelChanged.adapter_mtu -ne $live.live_mtu -or $tunnelChanged.adapter -cne $tunnelHttp.adapter) {
    throw "Windows reports MTU $($tunnelChanged.adapter_mtu) on the installation's tunnel adapter, not the changed $($live.live_mtu)"
}
$receipt.tunnel_runtime = $live.active.engine.snapshot.state.runtime
$receipt.http_through_tunnel_verified = $true

$handover = (Invoke-GuiScenario 'tunnel-stop') | ConvertFrom-Json
$handover | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'tunnel-stop.json') -Encoding utf8NoBOM
$changedIdentity = $live.active.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$handoverIdentity = $handover.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($changedIdentity -cne $handoverIdentity -or $handover.local.snapshot.state.state -cne 'local_proxy_active') {
    throw 'TUN Mode off did not retire the TUN runtime with the changed MTU'
}
$tunnelClosed = Invoke-NativeTunnelProbe 'tunnel-closed' $installation $launch
if ($tunnelClosed.adapter -cne $tunnelHttp.adapter -or $tunnelClosed.route_luid -eq $tunnelHttp.adapter_luid) {
    throw 'The system route still enters the retired tunnel adapter'
}
$receipt.tunnel_adapter_retired = $true
$halted = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$halted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop-after-tunnel.json') -Encoding utf8NoBOM
$localIdentity = $handover.local.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$haltedIdentity = $halted.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($localIdentity -cne $haltedIdentity -or $halted.stopped.snapshot.state.state -cne 'off' -or
    $halted.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the local core that replaced TUN Mode'
}
$receipt.engine_stopped = $true

# The last step is told what the session began with and puts it back.
$sessionInput.initial = $applied.before.settings
$defaults = (Invoke-GuiScenario 'runtime-settings-defaults') | ConvertFrom-Json
$defaults | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'runtime-settings-defaults.json') -Encoding utf8NoBOM
if ($defaults.release_accepted) { throw 'The runtime settings defaults receipt is invalid' }
$receipt.runtime_settings_exercised = $true
$receipt.network_mode_exercised = $true
