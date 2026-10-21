param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$Launcher,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Output
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:CFW_NATIVE_SERVICE_MUTATION_TESTS -cne '1') {
    throw 'Installed GUI qualification requires an opted-in disposable Windows CI runner'
}
if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
    throw 'Installed GUI source identity mismatch'
}
$installedDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Clash for Windows'
$machineState = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Clash for Windows'
$userState = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Clash for Windows'
if ((Test-Path -LiteralPath $installedDirectory) -or (Test-Path -LiteralPath $machineState) -or (Test-Path -LiteralPath $userState) -or
    @([ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ 'CFWAuthority').Count -ne 0) {
    throw 'Refusing an existing CFW installation or machine state'
}
$package = Get-Content -LiteralPath (Join-Path $PackageDirectory 'package.json') -Raw | ConvertFrom-Json
$msi = Join-Path $PackageDirectory 'CFW-development-windows-x64.msi'
if ($package.source -cne $Source -or $package.desktop_is_fixture -or $package.signed -or $package.release_accepted -or
    (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $package.package_sha256) {
    throw 'GUI validation package differs from the development build'
}
New-Item -ItemType Directory -Path $Output -ErrorAction Stop | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $Output).Path
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
    source=$Source; package_sha256=$package.package_sha256; installed=$null; uninstalled=$null
    native_gui_exercised=$false; ordinary_user=$false; page_count=0; graceful_exit_observed=$false
    debugger_detach_preserved_gui=$false; debugger_detached_before_exit_wait=$false
    physical_display_exercised=$false; network_mode_exercised=$false; release_accepted=$false
}
$controller = $null
$guiProcess = $null
$attached = $false
$failure = $null
$probeAttempts = [Collections.Generic.List[object]]::new()

function Invoke-Installer([string]$Mode, [string]$Name) {
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'))
    $start.UseShellExecute = $false
    foreach ($argument in @($Mode, $msi, '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*vx', (Join-Path $outputRoot "$Name.log"))) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(180000)) {
            throw 'MSI transaction state is unknown after its observation deadline; no competing cleanup is allowed'
        }
        $result = [ordered]@{ exit_code=$process.ExitCode; completed=$true }
        $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot "$Name.json") -Encoding utf8NoBOM
        if ($process.ExitCode -ne 0) { throw "MSI $Name failed with $($process.ExitCode)" }
        return $result
    } finally { $process.Dispose() }
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
try {
    $receipt.installed = Invoke-Installer '/i' 'install'
    $runtime = Join-Path $installedDirectory 'cfw-windows-runtime.exe'
    $check = & $runtime --check-installation $package.manifest_sha256
    $check | Set-Content -LiteralPath (Join-Path $outputRoot 'installed-runtime.json') -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) { throw 'Installed product manifest admission failed' }
    $admitted = $check | ConvertFrom-Json
    if (-not $admitted.installation_verified -or $admitted.release.product_code -cne $package.product_code -or
        $admitted.release.package_code -cne $package.package_code) { throw 'Installed MSI identity differs from the authored package' }
    $service = Get-CimInstance Win32_Service -Filter "Name='CFWAuthority'"
    if ($service.State -cne 'Running' -or $service.StartMode -cne 'Auto') { throw 'Product service is not running with automatic startup' }
    $service | Select-Object Name, State, StartMode, ProcessId, PathName |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputRoot 'installed-service.json') -Encoding utf8NoBOM
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
    if ($launch.source -cne $Source -or $launch.integrity_rid -ne 8192 -or $launch.administrator_member -or $launch.desktop_is_fixture) {
        throw 'GUI did not run as the admitted ordinary-user product image'
    }
    $receipt.ordinary_user = $true
    Invoke-Playwright 'attach' @('attach', "--cdp=$endpoint") | Out-Null
    $attached = $true
    Invoke-Playwright 'initial-snapshot' @('snapshot') | Out-Null
    $result = Invoke-Playwright 'pages' @('--raw', 'run-code', "--filename=$pagesScript")
    $pages = $result | ConvertFrom-Json
    if ($pages.pages.Count -ne 9 -or -not $pages.native_gui_exercised) { throw 'Incomplete installed GUI page receipt' }
    $pages | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'pages.json') -Encoding utf8NoBOM
    $receipt.page_count = $pages.pages.Count
    $receipt.native_gui_exercised = $true
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
    Invoke-Playwright 'quit' @('click', '[data-action="quit-app"]') | Out-Null
    Invoke-Playwright 'detach' @('detach') | Out-Null
    $attached = $false
    $receipt.debugger_detached_before_exit_wait = $true
    if (-not $controller.WaitForExit(30000) -or $controller.ExitCode -ne 0) { throw 'Installed GUI graceful exit was not observed' }
    $exit = Get-Content -LiteralPath (Join-Path $outputRoot 'exit.json') -Raw | ConvertFrom-Json
    if ($exit.process_id -ne $launch.process_id -or $exit.process_creation_time -ne $launch.process_creation_time -or
        $exit.exit_code -ne 0 -or -not $exit.retained_process_exit_observed) { throw 'GUI exit identity differs from the launched process' }
    $receipt.graceful_exit_observed = $true
    $receipt.uninstalled = Invoke-Installer '/x' 'uninstall'
    if ((Test-Path -LiteralPath $installedDirectory) -or
        @([ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ 'CFWAuthority').Count -ne 0) {
        throw 'MSI uninstall retained package files or the product service'
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
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputRoot 'receipt.json') -Encoding utf8NoBOM
    ConvertTo-Json -InputObject $probeAttempts.ToArray() -Depth 5 |
        Set-Content -LiteralPath (Join-Path $outputRoot 'webview-startup-attempts.json') -Encoding utf8NoBOM
}
if ($null -ne $failure) { throw $failure }
