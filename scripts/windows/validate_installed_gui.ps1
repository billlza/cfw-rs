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
$receipt = [ordered]@{
    source=$Source; package_sha256=$package.package_sha256; installed=$null; uninstalled=$null
    fresh_off_session=$null; local_proxy_session=$null
    native_gui_exercised=$false; ordinary_user=$false; page_count=0; graceful_exit_observed=$false
    startup_registration_exercised=$false; actual_sign_in_exercised=$false
    physical_display_exercised=$false; network_mode_exercised=$false; release_accepted=$false
}
$fresh = $null
$network = $null
$failure = $null

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
    $sessionScript = Join-Path $PSScriptRoot 'run_installed_gui_session.ps1'
    & $sessionScript -Launcher $Launcher -Source $Source -Output $outputRoot -Scenario 'fresh-off' -SessionResult ([ref]$fresh)
    if (-not $fresh.graceful_exit_observed -or $fresh.page_count -ne 9 -or $fresh.network_mode_exercised -or
        -not $fresh.startup_registration_exercised -or $fresh.actual_sign_in_exercised) {
        throw 'The independent fresh-Off GUI case did not pass'
    }
    $networkRoot = Join-Path $outputRoot 'local-proxy'
    New-Item -ItemType Directory -Path $networkRoot -ErrorAction Stop | Out-Null
    & $sessionScript -Launcher $Launcher -Source $Source -Output $networkRoot -Scenario 'local-proxy' -SessionResult ([ref]$network)
    if (-not $network.graceful_exit_observed -or -not $network.network_mode_exercised -or
        -not $network.http_forwarding_verified -or -not $network.engine_stopped -or -not $network.listener_released -or
        ($fresh.process_id -eq $network.process_id -and $fresh.process_creation_time -eq $network.process_creation_time)) {
        throw 'The separate GUI LocalProxy lifecycle did not pass'
    }
    $receipt.uninstalled = Invoke-Installer '/x' 'uninstall'
    if ((Test-Path -LiteralPath $installedDirectory) -or
        @([ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ 'CFWAuthority').Count -ne 0) {
        throw 'MSI uninstall retained package files or the product service'
    }
} catch {
    $failure = $_
    ($_.Exception.ToString() + "`n" + $_.ScriptStackTrace) |
        Set-Content -LiteralPath (Join-Path $outputRoot 'qualification-failure.txt') -Encoding utf8NoBOM
} finally {
    $receipt.fresh_off_session = $fresh
    $receipt.local_proxy_session = $network
    if ($null -ne $fresh) {
        $receipt.native_gui_exercised = $fresh.native_gui_exercised
        $receipt.page_count = $fresh.page_count
        $receipt.startup_registration_exercised = $fresh.startup_registration_exercised
    }
    if ($null -ne $fresh -and $null -ne $network) {
        $receipt.ordinary_user = $fresh.ordinary_user -and $network.ordinary_user
        $receipt.graceful_exit_observed = $fresh.graceful_exit_observed -and $network.graceful_exit_observed
        $receipt.network_mode_exercised = $network.network_mode_exercised
    }
    $receipt | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'receipt.json') -Encoding utf8NoBOM
}
if ($null -ne $failure) { throw $failure }
