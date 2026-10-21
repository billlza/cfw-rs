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
$manifestPath = Join-Path $package 'runtime-installation-v2.json'
$msi = $null
$msiInFlight = $null
$msiEvidence = Join-Path $Receipts 'msi'
$msiReport = [ordered]@{
    source=$Source; document='cfw-runtime-msi-qualification-v1'
    failed_fresh_install=$null; installed=$null; failed_maintenance=$null; uninstalled=$null
    fresh_rollback_removed_files_and_service=$false; maintenance_rollback=$null
    uninstall_removed_files_and_service=$false; desktop_is_fixture=$true
    wrong_manifest_expectations_rejected=$false; new_build_manifest_rollback_exercised=$false
    new_version_upgrade_exercised=$false; updater_handoff_exercised=$false; release_accepted=$false
}
$failure = $null
$teardownFailure = $null
$probes = @()
$agentExecuted = $false
$cases = [System.Collections.Generic.List[string]]::new()

function Invoke-ServiceCommand([string[]]$Arguments) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM command failed ($LASTEXITCODE): $output" }
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
    Import-Module (Join-Path $PSScriptRoot 'windows_runtime_msi.psm1') -Force
    if (Test-Path -LiteralPath $msiEvidence) { throw 'MSI qualification evidence directory already exists' }
    New-Item -ItemType Directory -Path $msiEvidence | Out-Null
    $manifest = [ordered]@{
        schema_version = 2; product_version = '0.5.0'; build_number = 1
        msi_product_code = '{E66ACF84-7639-4707-BC01-0A370C9B2E3E}'
        msi_package_code = '{00000000-0000-0000-0000-000000000000}'
        architecture = 'x86_64'; engine_version = $EngineVersion
        runtime_sha256 = (Get-FileHash -LiteralPath $Runtime -Algorithm SHA256).Hash.ToLowerInvariant()
        desktop_sha256 = (Get-FileHash -LiteralPath $DesktopFixture -Algorithm SHA256).Hash.ToLowerInvariant()
        engine_sha256 = (Get-FileHash -LiteralPath $Engine -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifestInput = Join-Path $msiEvidence 'manifest.json'
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestInput -Encoding utf8NoBOM
    $msi = New-RuntimeMsiFixture -Runtime $Runtime -Desktop $DesktopFixture -Engine $Engine -Manifest $manifestInput `
        -ProductCode $manifest.msi_product_code -Source $Source -Evidence $msiEvidence
    $manifest.msi_package_code = $msi.package_code
    $candidateEvidence = Join-Path $msiEvidence 'candidate'
    New-Item -ItemType Directory -Path $candidateEvidence | Out-Null
    $candidateManifest = [ordered]@{}
    foreach ($key in $manifest.Keys) { $candidateManifest[$key] = $manifest[$key] }
    $candidateManifest.build_number = 2
    $candidateManifest.msi_product_code = [guid]::NewGuid().ToString('B').ToUpperInvariant()
    $candidateManifest.msi_package_code = '{00000000-0000-0000-0000-000000000000}'
    $candidateInput = Join-Path $candidateEvidence 'manifest.json'
    $candidateManifest | ConvertTo-Json | Set-Content -LiteralPath $candidateInput -Encoding utf8NoBOM
    $msiCandidate = New-RuntimeMsiFixture -Runtime $Runtime -Desktop $DesktopFixture -Engine $Engine -Manifest $candidateInput `
        -ProductCode $candidateManifest.msi_product_code -Source $Source -Evidence $candidateEvidence
    $msiInFlight = 'failed-install'
    $msiReport.failed_fresh_install = Invoke-RuntimeMsi -Fixture $msi -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    if ((Test-Path -LiteralPath $package) -or (Test-Path -LiteralPath $machineState) -or
        @([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) {
        throw 'Failed fresh MSI installation did not roll back its files/service before any runtime enrollment'
    }
    $msiReport.fresh_rollback_removed_files_and_service = $true
    $msiInFlight = 'install'
    $msiReport.installed = Invoke-RuntimeMsi -Fixture $msi -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $manifestInput -Algorithm SHA256).Hash) {
        throw 'MSI installed a different runtime manifest'
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $check = & $runtimePath --check-installation $msi.manifest_sha256
    if ($LASTEXITCODE -ne 0 -or -not ($check | ConvertFrom-Json).installation_verified) { throw 'Protected package was not admitted' }
    $release = ($check | ConvertFrom-Json).release
    if ($release.version -cne '0.5.0' -or $release.build -ne 1 -or
        $release.product_code -cne $manifest.msi_product_code -or $release.package_code -cne $manifest.msi_package_code) {
        throw 'Installed release observation does not match the protected manifest'
    }
    $cases.Add('protected_fixed_location_package_admitted')
    $cases.Add('protected_release_build_and_msi_identities_observed')
    foreach ($expected in @($msiCandidate.manifest_sha256, 'invalid')) {
        $rejected = & $runtimePath --check-installation $expected 2>&1
        if ($LASTEXITCODE -eq 0) { throw 'Wrong expected installed manifest was accepted' }
    }
    $msiReport.wrong_manifest_expectations_rejected = $true
    foreach ($mode in @('--prepare-maintenance', '--rollback-maintenance')) {
        $rejected = & $runtimePath $mode 'c40a7b13-74b7-4543-a5c0-55de82b9dad6' 2>&1
        if ($LASTEXITCODE -eq 0 -or "$rejected" -notmatch 'requires the SYSTEM primary identity') {
            throw "Ordinary installer caller was not refused before maintenance: $mode; $rejected"
        }
    }
    $cases.Add('non_system_maintenance_entrypoints_rejected')

    foreach ($case in @(
        @('old_manifest_schema_rejected', 'schema_version', 1),
        @('missing_installed_build_rejected', 'build_number', $null),
        @('zero_installed_build_rejected', 'build_number', 0),
        @('invalid_installed_product_code_rejected', 'msi_product_code', 'invalid'),
        @('reused_installed_package_code_rejected', 'msi_package_code', $manifest.msi_product_code)
    )) {
        $altered = [ordered]@{}
        foreach ($key in $manifest.Keys) { $altered[$key] = $manifest[$key] }
        if ($null -eq $case[2]) { $altered.Remove($case[1]) } else { $altered[$case[1]] = $case[2] }
        $altered | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
        Require-Rejected $case[0]
        [IO.File]::WriteAllBytes($manifestPath, $manifestBytes)
    }

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
                [ordered]@{ product_source=$Source; probe=$probe } | ConvertTo-Json -Depth 12 |
                    Set-Content -LiteralPath (Join-Path $Receipts 'installed-host-initial-probe.json') -Encoding utf8NoBOM
                # A failed client leaves execution unknown until native evidence
                # resolves it. Null is not evidence that no Agent was launched.
                $agentExecuted = $null
                & $desktopPath --installed-host-run
                if ($LASTEXITCODE -ne 0) { throw 'Installed service/Agent traffic and cleanup exercise failed' }
                $agentExecuted = $true
                $raw = & $desktopPath --installed-host-probe
                if ($LASTEXITCODE -ne 0) { throw 'Installed post-runtime probe failed' }
                $probe = $raw | ConvertFrom-Json
                if ($probe.lineage.generation -ne 8) { throw 'Installed runtime did not retain the five backend and three application generations' }
                $cases.Add('product_service_and_agent_run_both_proxy_modes')
            }
            $probes += $probe
            if ($iteration -eq 0) {
                & $DesktopFixture --installed-maintenance-validation
                if ($LASTEXITCODE -ne 0) { throw 'Installed SYSTEM service maintenance validation failed' }
                $maintenance = Get-Content -LiteralPath (Join-Path $Receipts 'installed-service-maintenance.json') -Raw | ConvertFrom-Json
                if ($maintenance.source -cne $Source -or -not $maintenance.rollback_restored_startup -or
                    -not $maintenance.maintenance_record_removed -or $maintenance.msi_installation_exercised) {
                    throw 'Installed service maintenance receipt is incomplete'
                }
                $cases.Add('product_service_maintenance_prepare_and_rollback')
            }
            Stop-Installed
            if (-not $process.WaitForExit(10000) -or $process.ExitCode -ne 0) { throw 'Product service process did not retire successfully' }
        } finally { $process.Dispose() }
    }
    if (($probes[0].lineage | ConvertTo-Json -Compress) -cne ($probes[1].lineage | ConvertTo-Json -Compress)) { throw 'Service restart replaced durable installation lineage' }
    $cases.Add('actual_product_scm_entrypoint_started_twice')
    $cases.Add('authenticated_desktop_queries_production_off')
    $cases.Add('service_restart_preserves_durable_lineage')
    $cases.Add('scm_stop_waits_for_off_and_process_exit')

    # Exercise the real deferred SYSTEM preparation and rollback entrypoints
    # inside a failing major-upgrade transaction. The test build has different manifest bytes
    # and package identity. The deferred check requires those exact new bytes
    # before the injected failure; rollback must restore the original bytes.
    Invoke-ServiceCommand @('start', $serviceName)
    $service = [System.ServiceProcess.ServiceController]::new($serviceName)
    try { $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) } finally { $service.Dispose() }
    $before = & $desktopPath --installed-host-probe
    if ($LASTEXITCODE -ne 0) { throw 'Pre-MSI maintenance probe failed' }
    $before = $before | ConvertFrom-Json
    if ($before.snapshot.state -cne 'off' -or -not $before.authenticated_product_service) { throw 'MSI maintenance did not begin from authenticated Off' }
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $oldProcess = [Diagnostics.Process]::GetProcessById($observed.ProcessId)
    $null = $oldProcess.Handle
    try {
        $msiInFlight = 'failed-maintenance'
        $msiReport.failed_maintenance = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence -ExpectedProductCode $msi.product_code -ExpectedPackageCode $msi.package_code
        $msiInFlight = $null
        if (-not $oldProcess.WaitForExit(10000) -or $oldProcess.ExitCode -ne 0) { throw 'MSI maintenance did not retire the original service process cleanly' }
    } finally { $oldProcess.Dispose() }
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($observed.State -cne 'Stopped' -or $observed.StartMode -cne 'Manual') { throw 'MSI rollback did not restore the original stopped, demand-start service' }
    $check = & $runtimePath --check-installation $msi.manifest_sha256
    if ($LASTEXITCODE -ne 0 -or -not ($check | ConvertFrom-Json).installation_verified) { throw 'MSI rollback did not restore an admitted installation' }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $manifestInput -Algorithm SHA256).Hash) { throw 'MSI rollback changed the installed manifest' }
    Invoke-ServiceCommand @('start', $serviceName)
    $service = [System.ServiceProcess.ServiceController]::new($serviceName)
    try { $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) } finally { $service.Dispose() }
    $after = & $desktopPath --installed-host-probe
    if ($LASTEXITCODE -ne 0) { throw 'Product service restart after MSI rollback failed' }
    $after = $after | ConvertFrom-Json
    if ($after.snapshot.state -cne 'off' -or -not $after.authenticated_product_service -or
        ($before.lineage | ConvertTo-Json -Compress) -cne ($after.lineage | ConvertTo-Json -Compress) -or
        $after.snapshot.revision -ne ($before.snapshot.revision + 1)) { throw 'MSI rollback/restart did not preserve authority lineage and exact startup revision' }
    $msiReport.maintenance_rollback = [ordered]@{
        before=$before; after=$after; original_service_process_exited=$true
        original_start_type_restored=$true; original_manifest_restored=$true
        restart_after_rollback=$true; rollback_started_runtime=$false; active_proxy_drain_exercised=$false
    }
    $msiReport.new_build_manifest_rollback_exercised = $true
} catch { $failure = $_.ToString() }
finally {
    try {
        if ($null -ne $msiInFlight) {
            $completionPath = Join-Path $msiEvidence "$msiInFlight.json"
            if (-not (Test-Path -LiteralPath $completionPath) -or -not (Get-Content -LiteralPath $completionPath -Raw | ConvertFrom-Json).completed) {
                throw 'MSI transaction state is unknown; no competing teardown transaction was started'
            }
        }
        if ($null -ne $msi -and (Get-RuntimeMsiProductState $msi.product_code) -eq 5) {
            # This is fixture teardown from an already Off runtime. It does not
            # qualify interactive uninstall while another user's GUI is active.
            Stop-Installed
            $msiReport.uninstalled = Invoke-RuntimeMsi -Fixture $msi -Operation 'uninstall' -Evidence $msiEvidence
            if (Test-Path -LiteralPath $package) { throw 'MSI uninstall left installed files behind' }
            if (@([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) { throw 'MSI uninstall left the service behind' }
            $msiReport.uninstall_removed_files_and_service = $true
        }
        if (@([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) { throw 'Temporary product service was not removed' }
    } catch { $teardownFailure = $_.ToString() }
    $msiReport | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Receipts 'installed-msi-receipt.json') -Encoding utf8NoBOM
    [ordered]@{ product_source=$Source; cases=$cases.ToArray(); probes=$probes; failure=$failure; teardown_failure=$teardownFailure; desktop_is_fixture=$true; product_service_executable=$true; product_agent_entrypoint_executed=$agentExecuted; protected_state_retained_until_vm_teardown=$true; release_accepted=$false } |
        ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Receipts 'installed-runtime-receipt.json') -Encoding utf8NoBOM
}
if ($null -ne $failure -or $null -ne $teardownFailure) { throw "Installed runtime validation failed: $failure; teardown: $teardownFailure" }
