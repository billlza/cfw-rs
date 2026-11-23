# The port-conflict session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# Local ports another program holds, with the LocalProxy profile alone. The
# session listens on the automatic proxy and controller ports before the core
# starts: the core starts on the next port of each kind, and the session's
# listeners keep theirs. A third port the session holds, entered in the Network
# settings while the core runs, cannot be bound: the application restores the
# core it ran and saves nothing. LAN sharing on a fourth port the session holds
# on every address is no endpoint the application moves: the engine cannot
# start, and the application restores the core it ran, as macOS does.
# Configured with the core off, the third port makes a start end with the
# application's reason and the core off. The session ends with the automatic
# port, the core off and its own ports released.

$ports = (Invoke-GuiScenario 'port-conflict-ports') | ConvertFrom-Json
$ports | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'port-conflict-ports.json') -Encoding utf8NoBOM
$heldMixed = [int]$ports.mixed
$heldController = [int]$ports.controller
if ($ports.release_accepted -or $heldMixed -lt 1024 -or $heldMixed -gt 65534 -or $heldController -lt 1024 -or
    $heldController -gt 65534 -or [Math]::Abs($heldMixed - $heldController) -lt 2) {
    throw 'The port conflict session did not read two separate automatic ports'
}
# The ports the core is to move to are free here; another program on them
# would move the core further and is not this case.
foreach ($next in ($heldMixed + 1), ($heldController + 1)) {
    $probe = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
    try { $probe.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $next)) }
    catch { throw "Port $next is not free on this runner, so the core could not move to it" }
    finally { $probe.Dispose() }
}

# A connection to a port the session holds reaches the session's listener,
# not the core.
function Test-SessionHeldPort([Net.Sockets.TcpListener]$Holder, [int]$HeldPort) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect([Net.IPAddress]::Loopback, $HeldPort)
        $waited = [Diagnostics.Stopwatch]::StartNew()
        while (-not $Holder.Pending()) {
            if ($waited.ElapsedMilliseconds -gt 5000) { return $false }
            Start-Sleep -Milliseconds 50
        }
        $Holder.AcceptTcpClient().Dispose()
        return $true
    } finally { $client.Dispose() }
}

# The session's listeners, on the loopback address as another program would
# hold them; the third port is the one it configures. The fourth, for LAN
# sharing, listens on every address.
$holders = [ordered]@{}
try {
    $wanted = [ordered]@{ mixed=$heldMixed; controller=$heldController; configured=0; lan=0 }
    foreach ($name in $wanted.Keys) {
        $address = if ($name -ceq 'lan') { [Net.IPAddress]::Any } else { [Net.IPAddress]::Loopback }
        $holders[$name] = [Net.Sockets.TcpListener]::new($address, [int]$wanted[$name])
        $holders[$name].Start()
    }
    $heldConfigured = ([Net.IPEndPoint]$holders.configured.LocalEndpoint).Port
    $heldLan = ([Net.IPEndPoint]$holders.lan.LocalEndpoint).Port
    if ($heldLan -in ($heldMixed + 1), ($heldController + 1)) {
        throw 'The LAN port the session holds is a port the core moved to'
    }
    $sessionInput = [ordered]@{ mixed=$heldMixed; controller=$heldController; configured=$heldConfigured; lan=$heldLan }

    $conflictStart = (Invoke-GuiScenario 'port-conflict-start') | ConvertFrom-Json
    $conflictStart | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'port-conflict-start.json') -Encoding utf8NoBOM
    if (-not $conflictStart.controller_verified -or $conflictStart.release_accepted) {
        throw 'The port conflict GUI did not verify its controller on the ports it moved to'
    }
    $movedPort = $heldMixed + 1
    $receipt.controller_verified = $true
    $receipt.native_gui_exercised = $true
    $receipt.kept_profile_id = $ports.profile
    $receipt.proxy_port = $movedPort
    $receipt.active_runtime = $conflictStart.active.engine.snapshot.state.runtime
    Invoke-NativeNetworkProbe 'http' $movedPort $launch | Out-Null
    $receipt.http_forwarding_verified = $true
    if (-not (Test-SessionHeldPort $holders.mixed $heldMixed) -or -not (Test-SessionHeldPort $holders.controller $heldController)) {
        throw 'The core took a port the session holds'
    }
    # From here only the proxy port the session configures is held.
    $holders.controller.Stop()

    $settingsChange = (Invoke-GuiScenario 'port-conflict-settings') | ConvertFrom-Json
    $settingsChange | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'port-conflict-settings.json') -Encoding utf8NoBOM
    $startedIdentity = $conflictStart.active.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    $changeIdentity = $settingsChange.before.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    if ($startedIdentity -cne $changeIdentity -or $settingsChange.release_accepted) {
        throw 'The refused port change did not begin from the core that moved past the held ports'
    }
    # The restored core forwards on the port it ran on before the change.
    Invoke-NativeNetworkProbe 'http' $movedPort $launch 'restored-http' | Out-Null

    $lanChange = (Invoke-GuiScenario 'port-conflict-lan') | ConvertFrom-Json
    $lanChange | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'port-conflict-lan.json') -Encoding utf8NoBOM
    $settingsIdentity = $settingsChange.restored.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    $lanIdentity = $lanChange.before.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    if ($settingsIdentity -cne $lanIdentity -or $lanChange.release_accepted) {
        throw 'The refused LAN change did not begin from the core the refused port change restored'
    }
    Invoke-NativeNetworkProbe 'http' $movedPort $launch 'lan-restored-http' | Out-Null
    if (-not (Test-SessionHeldPort $holders.lan $heldLan)) { throw 'The core took the LAN port the session holds' }

    $conflictStopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
    $conflictStopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
    $restoredIdentity = $lanChange.restored.engine.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    $retiredIdentity = $conflictStopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
    if ($restoredIdentity -cne $retiredIdentity -or $conflictStopped.stopped.snapshot.state.state -cne 'off' -or
        $conflictStopped.stopped.snapshot.desired_mode -cne 'off') {
        throw 'GUI stop did not retire the restored core'
    }
    Invoke-NativeNetworkProbe 'closed' $movedPort $launch | Out-Null
    $receipt.listener_released = $true
    $receipt.engine_stopped = $true

    $configuredStart = (Invoke-GuiScenario 'port-conflict-configured') | ConvertFrom-Json
    $configuredStart | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'port-conflict-configured.json') -Encoding utf8NoBOM
    if ($configuredStart.release_accepted -or $configuredStart.outcome.refused.snapshot.generation -le $conflictStopped.stopped.snapshot.generation) {
        throw 'The start on the configured port did not follow the stopped core'
    }
    if (-not (Test-SessionHeldPort $holders.configured $heldConfigured)) { throw 'The core took the configured port the session holds' }
    $receipt.port_conflict_exercised = $true
    $receipt.network_mode_exercised = $true
} finally {
    foreach ($holder in $holders.Values) { $holder.Stop() }
}
