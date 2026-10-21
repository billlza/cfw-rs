param(
    [Parameter(Mandatory)][string]$Launcher,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][ValidateSet('fresh-off', 'local-proxy')][string]$Scenario,
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
    startup_registration_exercised=$false; actual_sign_in_exercised=$false
    physical_display_exercised=$false; network_mode_exercised=$false; release_accepted=$false
}
$SessionResult.Value = $receipt
$controller = $null
$guiProcess = $null
$attached = $false
$failure = $null
$probeAttempts = [Collections.Generic.List[object]]::new()

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
function Invoke-GuiScenario([ValidateSet('startup-registration', 'network-start', 'network-stop', 'quit')][string]$Name) {
    $observer = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'gui/observe.js'))
    $scenario = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "gui/$Name.js"))
    $path = Join-Path $playwrightOutput "$Name.scenario.js"
    $code = "(async (page) => {`nconst observeNative = (`n" + $observer + "`n);`nreturn await (`n" + $scenario + "`n)(page, observeNative);`n})"
    [IO.File]::WriteAllText($path, $code)
    return Invoke-Playwright $Name @('--raw', 'run-code', "--filename=$path")
}
function Invoke-NativeNetworkProbe([ValidateSet('http', 'closed')][string]$Operation, [int]$Port, $LaunchReceipt) {
    $start = [Diagnostics.ProcessStartInfo]::new($Launcher)
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('--installed-gui-network-probe', $Operation, $Port.ToString([Globalization.CultureInfo]::InvariantCulture))) {
        $start.ArgumentList.Add($argument)
    }
    $start.Environment['CFW_NATIVE_SERVICE_SOURCE'] = $Source
    $start.Environment['CFW_NATIVE_SERVICE_RECEIPTS'] = $outputRoot
    $process = [Diagnostics.Process]::Start($start)
    $probeStdout = $process.StandardOutput.ReadToEndAsync()
    $probeStderr = $process.StandardError.ReadToEndAsync()
    try {
        if (-not $process.WaitForExit(20000)) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw 'Timed-out native GUI network probe did not retire' }
            throw "Native GUI $Operation probe exceeded its observation deadline"
        }
        if ($process.ExitCode -ne 0) { throw "Native GUI $Operation probe failed; see its retained stderr" }
        $record = Get-Content -LiteralPath (Join-Path $outputRoot "$Operation-probe.json") -Raw | ConvertFrom-Json
        if ($record.document -cne 'cfw-installed-gui-network-probe-v1' -or $record.source -cne $Source -or
            $record.operation -cne $Operation -or $record.gui_process_id -ne $LaunchReceipt.process_id -or
            $record.gui_process_creation_time -ne $LaunchReceipt.process_creation_time -or
            -not $record.gui_same_user_session -or $record.proxy_address -cne "127.0.0.1:$Port" -or
            $record.user_proxy_sha256 -cne $LaunchReceipt.user_proxy_before_sha256 -or -not $record.user_proxy_unchanged -or
            $record.http_forwarding_verified -ne ($Operation -ceq 'http') -or
            $record.listener_refused -ne ($Operation -ceq 'closed') -or $record.release_accepted) {
            throw 'Native network proof differs from the UI-owned runtime and original user proxy'
        }
        return $record
    } finally {
        if ($process.HasExited) {
            [IO.File]::WriteAllText((Join-Path $outputRoot "$Operation-probe-stdout.log"), $probeStdout.GetAwaiter().GetResult())
            [IO.File]::WriteAllText((Join-Path $outputRoot "$Operation-probe-stderr.log"), $probeStderr.GetAwaiter().GetResult())
        }
        $process.Dispose()
    }
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
    } else {
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
    $quit | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'quit-input.json') -Encoding utf8NoBOM
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
    $receipt.user_proxy_unchanged = $true
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
        $logs = Join-Path $userState 'logs'
        if (Test-Path -LiteralPath $logs -PathType Container) {
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
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding utf8NoBOM
    ConvertTo-Json -InputObject $probeAttempts.ToArray() -Depth 5 |
        Set-Content -LiteralPath (Join-Path $outputRoot 'webview-startup-attempts.json') -Encoding utf8NoBOM
}
if ($null -ne $failure) { throw $failure }
