param(
    [Parameter(Mandatory)][string]$Launcher,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][ValidateSet('fresh-off', 'local-proxy', 'tunnel', 'system-proxy-quit')][string]$Scenario,
    [Parameter(Mandatory)][ref]$SessionResult
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:CFW_NATIVE_SERVICE_MUTATION_TESTS -cne '1') {
    throw 'Installed GUI sessions require an opted-in disposable Windows CI runner'
}
if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
    throw 'Installed GUI session source identity mismatch'
}
$outputRoot = (Resolve-Path -LiteralPath $Output).Path
$userState = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Clash for Windows'
$playwrightOutput = Join-Path $outputRoot 'output/playwright'
New-Item -ItemType Directory -Path $playwrightOutput -ErrorAction Stop | Out-Null
$cli = Join-Path $PSScriptRoot 'gui/node_modules/@playwright/cli/playwright-cli.js'
$pagesScript = Join-Path $PSScriptRoot 'gui/pages.js'
Import-Module (Join-Path $PSScriptRoot '../node_runtime.psm1') -Force
$node = Get-CfwPinnedNode
[ordered]@{ executable=$node; version=(& $node --version) } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'node-runtime.json') -Encoding utf8NoBOM
$session = 'cfw-installed-' + [guid]::NewGuid().ToString('N')
$receipt = [ordered]@{
    source=$Source; scenario=$Scenario; process_id=$null; process_creation_time=$null
    native_gui_exercised=$false; ordinary_user=$false; page_count=0; graceful_exit_observed=$false
    debugger_detach_preserved_gui=$false; debugger_detached_before_exit_wait=$false
    imported_profile_id=$null; active_runtime=$null; proxy_port=$null
    http_forwarding_verified=$false; listener_released=$false; engine_stopped=$false; user_proxy_unchanged=$false
    wininet_proxy_verified=$false; active_quit_exercised=$false; original_user_proxy_restored=$false
    tunnel_runtime=$null; http_through_tunnel_verified=$false
    combined_runtime=$null; combined_mode_exercised=$false; leak_protection_exercised=$false
    tunnel_adapter_retired=$false; core_preserved_after_tunnel=$false
    startup_registration_exercised=$false; settings_controls_exercised=$false; actual_sign_in_exercised=$false
    physical_display_exercised=$false; network_mode_exercised=$false; release_accepted=$false
}
$SessionResult.Value = $receipt
$controller = $null
$guiProcess = $null
$attached = $false
$failure = $null
$probeAttempts = [Collections.Generic.List[object]]::new()

function Save-ApplicationLogs {
    # Bounded copy of the product's own native logs, kept for passing sessions
    # too so the Agent's admission and start timing is retained.
    $logs = Join-Path $userState 'logs'
    if (-not (Test-Path -LiteralPath $logs -PathType Container)) { return }
    $files = @(Get-ChildItem -LiteralPath $logs -File -Recurse)
    if ($files.Count -gt 64) { throw 'GUI diagnostic file count bound exceeded' }
    foreach ($file in $files) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -gt 2MB) {
            throw 'GUI diagnostic file is not a bounded regular log'
        }
        $relative = [IO.Path]::GetRelativePath($logs, $file.FullName)
        $destination = Join-Path (Join-Path $outputRoot 'application-logs') $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -ErrorAction Stop
    }
}

function Invoke-Playwright([string]$Name, [string[]]$Arguments) {
    Push-Location $playwrightOutput
    try {
        $result = & $node $cli "--session=$session" @Arguments 2>&1
        $exit = $LASTEXITCODE
        $result | Set-Content -LiteralPath (Join-Path $playwrightOutput "$Name.log") -Encoding utf8NoBOM
        if ($exit -ne 0) { throw "Playwright $Name failed; see its retained log" }
        return ($result -join "`n")
    } finally { Pop-Location }
}
function Invoke-GuiScenario([ValidateSet('startup-off', 'startup-registration', 'settings-controls', 'network-start', 'network-stop', 'tunnel-start', 'tunnel-stop', 'combined-start', 'combined-stop', 'leak-protection-on', 'leak-protection-off', 'system-proxy-start', 'quit')][string]$Name) {
    $observer = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'gui/observe.js'))
    # Both leak protection steps run one script, which is told its step.
    $scenarioFile = if ($Name -ceq 'quit') { 'quit-with-state' } elseif ($Name -clike 'leak-protection-*') { 'leak-protection' } else { $Name }
    $scenarioCode = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "gui/$scenarioFile.js"))
    $quitInput = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'gui/quit.js'))
    $controllerObserver = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'gui/controller.js'))
    $scenarioName = $Scenario | ConvertTo-Json -Compress
    $stepName = $Name | ConvertTo-Json -Compress
    $path = Join-Path $playwrightOutput "$Name.scenario.js"
    $code = "(async (page) => {`nconst observeNative = (`n" + $observer + "`n);`nconst quitInput = (`n" + $quitInput + "`n);`nconst observeController = (`n" + $controllerObserver + "`n);`nreturn await (`n" + $scenarioCode + "`n)(page, observeNative, " + $scenarioName + ", quitInput, observeController, " + $stepName + ");`n})"
    [IO.File]::WriteAllText($path, $code)
    return Invoke-Playwright $Name @('--raw', 'run-code', "--filename=$path")
}
# One native probe of the fixture, run in this session; returns its receipt.
function Invoke-NativeProbe([string]$Name, [string[]]$Arguments, [int]$TimeoutMs = 30000) {
    $start = [Diagnostics.ProcessStartInfo]::new($Launcher)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.Environment['CFW_NATIVE_SERVICE_SOURCE'] = $Source
    $start.Environment['CFW_NATIVE_SERVICE_RECEIPTS'] = $outputRoot
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
        return Get-Content -LiteralPath (Join-Path $outputRoot "$Name-probe.json") -Raw | ConvertFrom-Json
    } finally {
        if ($process.HasExited) {
            [IO.File]::WriteAllText((Join-Path $outputRoot "$Name-probe-stdout.log"), $probeStdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText((Join-Path $outputRoot "$Name-probe-stderr.log"), $probeStderr.GetAwaiter().GetResult())
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

try {
    # Allocate a loopback-only debugging endpoint. These variables are passed
    # only to this test controller/GUI process tree, never stored in the product.
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { $port = $listener.LocalEndpoint.Port } finally { $listener.Stop() }
    $start = [Diagnostics.ProcessStartInfo]::new($Launcher)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('--installed-gui-validation')
    $start.Environment['CFW_NATIVE_SERVICE_SOURCE'] = $Source
    $start.Environment['CFW_NATIVE_SERVICE_RECEIPTS'] = $outputRoot
    $start.Environment['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS'] = "--remote-debugging-address=127.0.0.1 --remote-debugging-port=$port"
    $start.Environment['WEBVIEW2_USER_DATA_FOLDER'] = Join-Path $env:RUNNER_TEMP ('cfw-webview-' + [guid]::NewGuid().ToString('N'))
    $controller = [Diagnostics.Process]::Start($start)
    $stdout = $controller.StandardOutput.ReadToEndAsync()
    $stderr = $controller.StandardError.ReadToEndAsync()
    $endpoint = "http://127.0.0.1:$port"
    Import-Module (Join-Path $PSScriptRoot 'webview_probe.psm1') -Force
    $version = Wait-CfwWebView2 -Controller $controller -Endpoint $endpoint -ProbeAttempts $probeAttempts
    $version | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'webview-version.json') -Encoding utf8NoBOM
    $launch = Get-Content -LiteralPath (Join-Path $outputRoot 'launch.json') -Raw | ConvertFrom-Json
    if ($launch.source -cne $Source -or $launch.integrity_rid -ne 8192 -or $launch.administrator_member -or $launch.desktop_is_fixture -or
        -not $launch.primary_thread_suspended_for_admission) {
        throw 'GUI did not run as the admitted ordinary-user product image'
    }
    $receipt.ordinary_user = $true
    $receipt.process_id = $launch.process_id
    $receipt.process_creation_time = $launch.process_creation_time
    Invoke-Playwright 'attach' @('attach', "--cdp=$endpoint") | Out-Null
    $attached = $true
    Invoke-Playwright 'initial-snapshot' @('snapshot') | Out-Null
    $initialOff = (Invoke-GuiScenario 'startup-off') | ConvertFrom-Json
    if (-not $initialOff.initial_off_verified -or $initialOff.release_accepted) { throw 'Native startup reconciliation was not observed' }
    $initialOff | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'startup-off.json') -Encoding utf8NoBOM
    if ($Scenario -ceq 'fresh-off') {
        $result = Invoke-Playwright 'pages' @('--raw', 'run-code', "--filename=$pagesScript")
        $pages = $result | ConvertFrom-Json
        if ($pages.pages.Count -ne 9 -or -not $pages.native_gui_exercised) { throw 'Incomplete installed GUI page receipt' }
        $pages | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'pages.json') -Encoding utf8NoBOM
        $receipt.page_count = $pages.pages.Count
        $receipt.native_gui_exercised = $true
        $startup = (Invoke-GuiScenario 'startup-registration') | ConvertFrom-Json
        $startup | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'startup-registration.json') -Encoding utf8NoBOM
        if (-not $startup.startup_registration_exercised -or $startup.actual_sign_in_exercised -or $startup.release_accepted) {
            throw 'The installed GUI did not verify its startup registration transaction'
        }
        $receipt.startup_registration_exercised = $true
        $controls = (Invoke-GuiScenario 'settings-controls') | ConvertFrom-Json
        $controls | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'settings-controls.json') -Encoding utf8NoBOM
        if (-not $controls.settings_controls_exercised -or $controls.languages.Count -ne 3 -or
            $controls.engine.Count -ne 2 -or $controls.scroll.Count -ne 10 -or $controls.release_accepted) {
            throw 'The installed GUI did not keep its display language, update interval, leak protection switches and scroll position'
        }
        $receipt.settings_controls_exercised = $true
    } elseif ($Scenario -ceq 'local-proxy') {
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
    } elseif ($Scenario -ceq 'tunnel') {
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
    } else {
        $started = (Invoke-GuiScenario 'system-proxy-start') | ConvertFrom-Json
        $started | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'system-proxy-start.json') -Encoding utf8NoBOM
        if (-not $started.controller_verified) { throw 'SystemProxy GUI did not verify its actual controller' }
        $receipt.controller_verified = $true
        $proxyPort = [int]$started.settings.effective.mixed_port
        if ($proxyPort -lt 1 -or $proxyPort -gt 65535) { throw 'GUI system proxy port is invalid' }
        $receipt.native_gui_exercised = $true
        $receipt.imported_profile_id = $started.before.profiles.profiles[0].id
        $receipt.proxy_port = $proxyPort
        $receipt.active_runtime = $started.active.snapshot.state.runtime
        $systemHttp = Invoke-NativeNetworkProbe 'system-http' $proxyPort $launch
        $receipt.http_forwarding_verified = $systemHttp.http_forwarding_verified
        $receipt.wininet_proxy_verified = $systemHttp.wininet_via_proxy_verified
        $receipt.network_mode_exercised = $true
        [ordered]@{ source=$Source; gui_process_id=$launch.process_id; gui_process_creation_time=$launch.process_creation_time;
            proxy_port=$proxyPort; mode='system_proxy' } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $outputRoot 'exit-network-expectation.json') -Encoding utf8NoBOM
    }
    Invoke-Playwright 'console' @('console', 'error') | Out-Null
    # CDP attachment is a test-owned resource. First prove that releasing it
    # does not close this exact product process, then reconnect for the actual
    # Quit action. Detach before waiting so the debugger cannot retain WebView2
    # during its shutdown. The original native exit/code checks stay required.
    $guiProcess = [Diagnostics.Process]::GetProcessById([int]$launch.process_id)
    $guiCreated = $guiProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    if ($guiCreated -ne $launch.process_creation_time) { throw 'GUI detach control process identity changed' }
    Invoke-Playwright 'detach-control' @('detach') | Out-Null
    $attached = $false
    if ($guiProcess.WaitForExit(500)) { throw 'Detaching the debugger unexpectedly ended the GUI' }
    [ordered]@{ source=$Source; process_id=$launch.process_id; process_creation_time=$guiCreated; still_running_after_detach=$true; observation_ms=500 } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'debugger-detach-control.json') -Encoding utf8NoBOM
    $receipt.debugger_detach_preserved_gui = $true
    Invoke-Playwright 'reattach-for-quit' @('attach', "--cdp=$endpoint") | Out-Null
    $attached = $true
    $quit = (Invoke-GuiScenario 'quit') | ConvertFrom-Json
    if (-not $quit.quit_click_completed -or $quit.native_exit_verified) { throw 'Quit input receipt is invalid' }
    $quit | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'quit-input.json') -Encoding utf8NoBOM
    if ($Scenario -ceq 'system-proxy-quit') {
        $beforeQuit = $quit.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
        $startedRuntime = $started.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
        if ($beforeQuit -cne $startedRuntime) { throw 'Active Quit did not target the started SystemProxy runtime' }
    }
    Invoke-Playwright 'detach' @('detach') | Out-Null
    $attached = $false
    $receipt.debugger_detached_before_exit_wait = $true
    if (-not $controller.WaitForExit(30000) -or $controller.ExitCode -ne 0) { throw 'Installed GUI graceful exit was not observed' }
    $exit = Get-Content -LiteralPath (Join-Path $outputRoot 'exit.json') -Raw | ConvertFrom-Json
    $resumed = Get-Content -LiteralPath (Join-Path $outputRoot 'resume.json') -Raw | ConvertFrom-Json
    if ($resumed.source -cne $Source -or $resumed.process_id -ne $launch.process_id -or
        $resumed.process_creation_time -ne $launch.process_creation_time -or $resumed.previous_suspend_count -ne 1 -or
        -not $resumed.launch_receipt_published_before_resume) {
        throw 'The GUI did not resume from its admitted suspended launch'
    }
    if ($exit.process_id -ne $launch.process_id -or $exit.process_creation_time -ne $launch.process_creation_time -or
        $exit.exit_code -ne 0 -or -not $exit.retained_process_exit_observed) { throw 'GUI exit identity differs from the launched process' }
    if ($exit.source -cne $Source -or -not $exit.user_proxy_unchanged -or
        $exit.user_proxy_after_sha256 -cne $launch.user_proxy_before_sha256) {
        throw 'GUI exit did not preserve the original native user proxy options'
    }
    $receipt.graceful_exit_observed = $true
    # The TUN session takes System Proxy on beside the tunnel and off again.
    $receipt.user_proxy_unchanged = $Scenario -cne 'system-proxy-quit' -and $Scenario -cne 'tunnel'
    $receipt.original_user_proxy_restored = $true
    if ($Scenario -ceq 'system-proxy-quit') {
        $afterQuit = Get-Content -LiteralPath (Join-Path $outputRoot 'exit-network.json') -Raw | ConvertFrom-Json
        if ($afterQuit.source -cne $Source -or $afterQuit.gui_process_id -ne $launch.process_id -or
            $afterQuit.gui_process_creation_time -ne $launch.process_creation_time -or $afterQuit.mode -cne 'system_proxy' -or
            $afterQuit.proxy_address -cne "127.0.0.1:$proxyPort" -or -not $afterQuit.observed_after_retained_gui_exit -or
            -not $afterQuit.listener_refused -or -not $afterQuit.original_user_proxy_restored -or
            $afterQuit.user_proxy_sha256 -cne $launch.user_proxy_before_sha256 -or $afterQuit.release_accepted) {
            throw 'Active Quit did not prove proxy restoration and listener retirement after native exit'
        }
        $receipt.listener_released = $true
        $receipt.active_quit_exercised = $true
    }
} catch {
    $failure = $_
    ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
        Set-Content -LiteralPath (Join-Path $outputRoot 'failure.txt') -Encoding utf8NoBOM
    if (-not $attached -and $null -ne $guiProcess -and -not $guiProcess.HasExited) {
        try {
            Invoke-Playwright 'reattach-after-failure' @('attach', "--cdp=$endpoint") | Out-Null
            $attached = $true
        } catch {
            ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
                Set-Content -LiteralPath (Join-Path $outputRoot 'reattach-diagnostic-failure.txt') -Encoding utf8NoBOM
        }
    }
    if ($attached) {
        try {
            Invoke-Playwright 'console-after-failure' @('console', 'error') | Out-Null
            Invoke-Playwright 'failed-window' @('--raw', 'run-code', "--filename=$(Join-Path $PSScriptRoot 'gui/failure.js')") |
                Set-Content -LiteralPath (Join-Path $outputRoot 'failed-window.json') -Encoding utf8NoBOM
        } catch {
            ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
                Set-Content -LiteralPath (Join-Path $outputRoot 'window-diagnostic-failure.txt') -Encoding utf8NoBOM
        }
    }
    try {
        $launchPath = Join-Path $outputRoot 'launch.json'
        if (Test-Path -LiteralPath $launchPath -PathType Leaf) {
            $observedLaunch = Get-Content -LiteralPath $launchPath -Raw | ConvertFrom-Json
            if ($observedLaunch.source -cne $Source -or $observedLaunch.integrity_rid -ne 8192 -or
                $observedLaunch.administrator_member -or $observedLaunch.desktop_is_fixture) { throw 'Invalid native launch receipt' }
            $receipt.ordinary_user = $true
            # Preserve only this GUI's descendants. Do not collect unrelated
            # process command lines, environment variables or user data.
            $parents = @([uint32]$observedLaunch.process_id)
            $descendants = [Collections.Generic.List[object]]::new()
            for ($depth = 0; $depth -lt 4 -and $parents.Count -gt 0; $depth++) {
                $next = @()
                foreach ($parentId in $parents) {
                    foreach ($child in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$parentId")) {
                        if ($descendants.Count -ge 128) { throw 'GUI diagnostic process bound exceeded' }
                        $descendants.Add(($child | Select-Object ProcessId, ParentProcessId, CreationDate, Name, ExecutablePath))
                        $next += [uint32]$child.ProcessId
                    }
                }
                $parents = $next
            }
            ConvertTo-Json -InputObject $descendants.ToArray() -Depth 5 |
                Set-Content -LiteralPath (Join-Path $outputRoot 'gui-descendants.json') -Encoding utf8NoBOM
        }
    } catch {
        ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
            Set-Content -LiteralPath (Join-Path $outputRoot 'diagnostic-capture-failure.txt') -Encoding utf8NoBOM
    }
} finally {
    # On failure retain the installation and transaction logs for runner
    # teardown. Never mask a failed/unknown MSI result with manual removal.
    if ($attached) {
        try { Invoke-Playwright 'detach-after-failure' @('detach') | Out-Null }
        catch { $_ | Out-String | Set-Content -LiteralPath (Join-Path $outputRoot 'detach-failure.txt') -Encoding utf8NoBOM; if ($null -eq $failure) { $failure = $_ } }
    }
    if ($null -ne $controller) {
        if (-not $controller.WaitForExit(200000)) {
            'GUI controller remained alive beyond its native child deadline' | Set-Content -LiteralPath (Join-Path $outputRoot 'controller-timeout.txt')
            if ($null -eq $failure) { $failure = [Exception]::new('GUI controller did not terminate') }
        } else {
            $stdout.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $outputRoot 'controller-stdout.log') -Encoding utf8NoBOM
            $stderr.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $outputRoot 'controller-stderr.log') -Encoding utf8NoBOM
        }
        $controller.Dispose()
    }
    if ($null -ne $guiProcess) { $guiProcess.Dispose() }
    try { Save-ApplicationLogs }
    catch {
        ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
            Set-Content -LiteralPath (Join-Path $outputRoot 'application-log-capture-failure.txt') -Encoding utf8NoBOM
        if ($null -eq $failure) { $failure = $_ }
    }
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding utf8NoBOM
    ConvertTo-Json -InputObject $probeAttempts.ToArray() -Depth 5 |
        Set-Content -LiteralPath (Join-Path $outputRoot 'webview-startup-attempts.json') -Encoding utf8NoBOM
}
if ($null -ne $failure) { throw $failure }
