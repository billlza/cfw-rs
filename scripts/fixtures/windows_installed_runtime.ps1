param(
    [Parameter(Mandatory)][string]$Runtime,
    [Parameter(Mandatory)][string]$DesktopFixture,
    [Parameter(Mandatory)][string]$Engine,
    [Parameter(Mandatory)][string]$EngineVersion,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Receipts
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:CFW_NATIVE_SERVICE_MUTATION_TESTS -cne '1') { throw 'Installed runtime validation requires disposable CI opt-in' }
if ($Source -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid source identity' }
$package = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Clash for Windows'
$machineState = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Clash for Windows'
$serviceName = 'CFWAuthority'
if ((Test-Path -LiteralPath $package) -or (Test-Path -LiteralPath $machineState)) { throw 'Refusing to overwrite an existing product installation or state' }
if (@([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) { throw 'Product service already exists' }
$runtimePath = Join-Path $package 'cfw-windows-runtime.exe'
$desktopPath = Join-Path $package 'Clash for Windows.exe'
$enginePath = Join-Path $package 'cfw-engine-host.exe'
$manifestPath = Join-Path $package 'runtime-installation-v1.json'
$created = $false
$failure = $null
$teardownFailure = $null
$probes = @()
$cases = [System.Collections.Generic.List[string]]::new()

function Invoke-ServiceCommand([string[]]$Arguments) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM command failed ($LASTEXITCODE): $output" }
}
function Protect-Package([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
    $inherit = if ($Directory) { 'OICI' } else { '' }
    $acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;$inherit;FA;;;SY)(A;$inherit;FA;;;BA)(A;$inherit;0x1200a9;;;BU)")
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Require-Rejected([string]$Case) {
    $output = & $runtimePath --check-installation 2>&1
    if ($LASTEXITCODE -eq 0) { throw "Installation counterexample was accepted: $Case" }
    $output | Set-Content -LiteralPath (Join-Path $Receipts "installed-host-$Case.txt") -Encoding utf8
    $cases.Add($Case)
}
function Stop-Installed {
    $service = [System.ServiceProcess.ServiceController]::new($serviceName)
    try {
        $service.Refresh()
        if ($service.Status -ne 'Stopped') {
            if ($service.Status -ne 'StopPending') { Invoke-ServiceCommand @('stop', $serviceName) }
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(40))
        }
    } finally { $service.Dispose() }
}
try {
    New-Item -ItemType Directory -Path $package | Out-Null
    Protect-Package $package $true
    Copy-Item -LiteralPath $Runtime -Destination $runtimePath
    Copy-Item -LiteralPath $DesktopFixture -Destination $desktopPath
    Copy-Item -LiteralPath $Engine -Destination $enginePath
    foreach ($path in @($runtimePath, $desktopPath, $enginePath)) { Protect-Package $path $false }
    $manifest = [ordered]@{
        schema_version = 1; product_version = '0.5.0'; architecture = 'x86_64'; engine_version = $EngineVersion
        runtime_sha256 = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
        desktop_sha256 = (Get-FileHash -LiteralPath $desktopPath -Algorithm SHA256).Hash.ToLowerInvariant()
        engine_sha256 = (Get-FileHash -LiteralPath $enginePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    Protect-Package $manifestPath $false
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $check = & $runtimePath --check-installation
    if ($LASTEXITCODE -ne 0 -or -not ($check | ConvertFrom-Json).installation_verified) { throw 'Protected package was not admitted' }
    $cases.Add('protected_fixed_location_package_admitted')

    $altered = [ordered]@{}
    foreach ($key in $manifest.Keys) { $altered[$key] = $manifest[$key] }
    $altered['desktop_sha256'] = '00' * 32
    $altered | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    Require-Rejected 'wrong_desktop_digest_rejected'
    [IO.File]::WriteAllBytes($manifestPath, $manifestBytes)
    $safeAcl = Get-Acl -LiteralPath $manifestPath
    $unsafeAcl = Get-Acl -LiteralPath $manifestPath
    $unsafeAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Write', 'Allow'))
    Set-Acl -LiteralPath $manifestPath -AclObject $unsafeAcl
    Require-Rejected 'unprivileged_manifest_writer_rejected'
    Set-Acl -LiteralPath $manifestPath -AclObject $safeAcl

    Invoke-ServiceCommand @('create', $serviceName, 'binPath=', ('"' + $runtimePath + '" --service'), 'type=', 'own', 'start=', 'demand', 'obj=', 'LocalSystem')
    $created = $true
    Invoke-ServiceCommand @('sdset', $serviceName, 'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWLORC;;;AU)')
    for ($iteration = 0; $iteration -lt 2; $iteration++) {
        Invoke-ServiceCommand @('start', $serviceName)
        $service = [System.ServiceProcess.ServiceController]::new($serviceName)
        try { $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) } finally { $service.Dispose() }
        $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($observed.ProcessId -eq 0 -or $observed.StartName -ne 'LocalSystem') { throw 'Installed service has no SYSTEM process' }
        $process = [System.Diagnostics.Process]::GetProcessById($observed.ProcessId)
        $null = $process.Handle
        try {
            $raw = & $desktopPath --installed-host-probe
            if ($LASTEXITCODE -ne 0) { throw 'Authenticated installed Desktop probe failed' }
            $probe = $raw | ConvertFrom-Json
            if ($probe.snapshot.state -cne 'off' -or -not $probe.authenticated_product_service) { throw 'Installed service did not return verified Off' }
            if ($iteration -eq 0) {
                & $desktopPath --installed-host-run
                if ($LASTEXITCODE -ne 0) { throw 'Installed service/Agent traffic and cleanup exercise failed' }
                $raw = & $desktopPath --installed-host-probe
                if ($LASTEXITCODE -ne 0) { throw 'Installed post-runtime probe failed' }
                $probe = $raw | ConvertFrom-Json
                if ($probe.lineage.generation -ne 2) { throw 'Installed runtime did not retain both generations' }
                $cases.Add('product_service_and_agent_run_both_proxy_modes')
            }
            $probes += $probe
            Stop-Installed
            if (-not $process.WaitForExit(10000) -or $process.ExitCode -ne 0) { throw 'Product service process did not retire successfully' }
        } finally { $process.Dispose() }
    }
    if (($probes[0].lineage | ConvertTo-Json -Compress) -cne ($probes[1].lineage | ConvertTo-Json -Compress)) { throw 'Service restart replaced durable installation lineage' }
    $cases.Add('actual_product_scm_entrypoint_started_twice')
    $cases.Add('authenticated_desktop_queries_production_off')
    $cases.Add('service_restart_preserves_durable_lineage')
    $cases.Add('scm_stop_waits_for_off_and_process_exit')
} catch { $failure = $_.ToString() }
finally {
    try {
        if ($created) { Stop-Installed; Invoke-ServiceCommand @('delete', $serviceName) }
        # This intentionally retains protected, nonsecret state until VM teardown.
        # Installed uninstall/migration is a separate product implementation.
        if (Test-Path -LiteralPath $package) { Remove-Item -LiteralPath $package -Recurse -Force }
        if (@([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) { throw 'Temporary product service was not removed' }
    } catch { $teardownFailure = $_.ToString() }
    [ordered]@{ product_source=$Source; cases=$cases.ToArray(); probes=$probes; failure=$failure; teardown_failure=$teardownFailure; desktop_is_fixture=$true; product_service_executable=$true; product_agent_entrypoint_executed=$cases.Contains('product_service_and_agent_run_both_proxy_modes'); protected_state_retained_until_vm_teardown=$true; release_accepted=$false } |
        ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Receipts 'installed-runtime-receipt.json') -Encoding utf8NoBOM
}
if ($null -ne $failure -or $null -ne $teardownFailure) { throw "Installed runtime validation failed: $failure; teardown: $teardownFailure" }
