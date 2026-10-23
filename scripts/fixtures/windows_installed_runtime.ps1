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
$wintunPath = Join-Path $package 'wintun.dll'
$manifestPath = Join-Path $package 'runtime-installation-v2.json'
$msi = $null
$msiCandidate = $null
$msiInFlight = $null
$msiEvidence = Join-Path $Receipts 'msi'
$msiReport = [ordered]@{
    source=$Source; document='cfw-runtime-msi-qualification-v3'
    failed_fresh_install=$null; installed=$null; failed_maintenance=$null; uninstalled=$null
    fresh_rollback_removed_files_and_service=$false; maintenance_rollback=$null
    uninstall_removed_files_and_service=$false; desktop_is_fixture=$true
    wrong_manifest_expectations_rejected=$false; new_build_manifest_rollback_exercised=$false
    failed_fresh_commit=$null; fresh_commit_rollback=$null; fresh_activation=$null
    failed_stopped_maintenance=$null; stopped_rollback=$null
    failed_commit=$null; commit_failure_rollback=$null; upgraded=$null; upgrade_commit=$null
    reinstalled=$null; reinstallation=$null; uninstalled_reinstalled=$null
    new_build_upgrade_committed=$false; completed_history_reinstall_exercised=$false
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
function Require-Rejected([string]$Case, [string]$ExpectedError = '') {
    $output = & $runtimePath --check-installation 2>&1
    if ($LASTEXITCODE -eq 0) { throw "Installation counterexample was accepted: $Case" }
    $output | Set-Content -LiteralPath (Join-Path $Receipts "installed-host-$Case.txt") -Encoding utf8
    if ($ExpectedError -and -not ($output -join "`n").Contains($ExpectedError, [StringComparison]::Ordinal)) {
        throw "Installation counterexample failed outside its expected boundary: $Case"
    }
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
function Read-InstalledProbe {
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($observed.State -cne 'Running' -or $observed.ProcessId -eq 0) { throw 'MSI did not leave an already-running service' }
    $raw = & $desktopPath --installed-host-probe
    if ($LASTEXITCODE -ne 0) { throw 'Installed service startup probe failed' }
    $probe = $raw | ConvertFrom-Json
    if ($probe.snapshot.state -cne 'off' -or -not $probe.authenticated_product_service) { throw 'Restarted service did not report authenticated Off' }
    return $probe
}
function Assert-Installation($Fixture, [string]$ExpectedState = 'Running') {
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($observed.State -cne $ExpectedState -or $observed.StartMode -cne 'Manual') { throw 'MSI did not restore the expected service state and startup configuration' }
    $raw = & $runtimePath --check-installation $Fixture.manifest_sha256
    if ($LASTEXITCODE -ne 0) { throw 'MSI result did not admit its exact installed manifest' }
    $check = $raw | ConvertFrom-Json
    if (-not $check.installation_verified -or $check.release.build -ne $Fixture.build_number -or
        $check.release.product_code -cne $Fixture.product_code -or $check.release.package_code -cne $Fixture.package_code -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Fixture.manifest_sha256) {
        throw 'Installed MSI result differs from the expected package identity'
    }
}
function Assert-RestartLineage($Before, $After, [int]$Starts = 1) {
    if (($Before.lineage | ConvertTo-Json -Compress) -cne ($After.lineage | ConvertTo-Json -Compress) -or
        $After.snapshot.revision -ne ($Before.snapshot.revision + $Starts)) { throw 'MSI restart did not preserve lineage and the exact startup revision' }
}
function Read-MsiReport([string]$Operation, [string]$Field) {
    $content = Get-Content -LiteralPath (Join-Path $msiEvidence "$Operation.log") -Raw
    $reports = @([regex]::Matches($content, '(?m)^WixQuietExec64:  (\{.*\})\r?$') | ForEach-Object {
        $value = $_.Groups[1].Value | ConvertFrom-Json
        if ($value.PSObject.Properties.Name -ccontains $Field) { $value }
    })
    if ($reports.Count -ne 1) { throw "Missing or ambiguous native MSI receipt: $Operation / $Field" }
    return $reports[0]
}
function Assert-ActivatedProcessRetired($Activation, $Retirement) {
    if (-not $Activation.started_by_action -or -not $Retirement.retained_process_exit_observed -or
        $Activation.process_id -ne $Retirement.retired_service.process_id -or
        $Activation.process_creation_time -ne $Retirement.retired_service.process_creation_time -or
        $Retirement.authority.state -cne 'off') { throw 'MSI did not retire the exact activated service process into Off' }
}
function Assert-RunningReceipt($Service, $Probe) {
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $process = [Diagnostics.Process]::GetProcessById($observed.ProcessId)
    try {
        if (-not $Service.started_by_action -or $Service.process_id -ne $observed.ProcessId -or
            $Service.process_creation_time -ne $process.StartTime.ToUniversalTime().ToFileTimeUtc() -or
            $Probe.snapshot.state -cne 'off') { throw 'Running SCM process differs from the MSI activation receipt' }
    } finally { $process.Dispose() }
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
    # Fail after fresh service activation. Its exact process must retire before
    # MSI removes files; already-enrolled authority data is deliberately retained.
    $msiInFlight = 'failed-fresh-commit'
    $msiReport.failed_fresh_commit = Invoke-RuntimeMsi -Fixture $msi -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    if ((Test-Path -LiteralPath $package) -or
        @([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) {
        throw 'Late fresh-install rollback retained package files or its service'
    }
    $freshStarted = Read-MsiReport 'failed-fresh-commit' 'fresh_service'
    $freshRetired = Read-MsiReport 'failed-fresh-commit' 'fresh_service_retired'
    Assert-ActivatedProcessRetired $freshStarted.fresh_service $freshRetired
    $msiReport.fresh_commit_rollback = [ordered]@{ activation=$freshStarted; retirement=$freshRetired; files_and_service_removed=$true; enrolled_authority_retained=$true }
    $msiInFlight = 'install'
    $msiReport.installed = Invoke-RuntimeMsi -Fixture $msi -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    Assert-Installation $msi
    $freshProbe = Read-InstalledProbe
    $freshActivation = Read-MsiReport 'install' 'fresh_service'
    Assert-RunningReceipt $freshActivation.fresh_service $freshProbe
    $msiReport.fresh_activation = [ordered]@{ activation=$freshActivation; probe=$freshProbe }
    # Before any runtime preparation, the protected genesis remains revision 1.
    # Machine::reconcile verifies fresh Off without appending a runtime record.
    # A retired runtime (exercised below) instead commits a new startup revision.
    if ($freshRetired.authority.revision -ne 1 -or $freshRetired.authority.root.epoch -ne 0 -or
        $freshRetired.authority.root.generation -ne 0 -or
        ($freshProbe.snapshot | ConvertTo-Json -Compress) -cne ($freshRetired.authority | ConvertTo-Json -Compress) -or
        ($freshProbe.snapshot | ConvertTo-Json -Compress) -cne ($freshActivation.authority | ConvertTo-Json -Compress)) {
        throw 'Fresh retry did not preserve the exact unused genesis while independently proving Off'
    }
    Stop-Installed
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $manifestInput -Algorithm SHA256).Hash) {
        throw 'MSI installed a different runtime manifest'
    }
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifestWriteTime = [IO.File]::GetLastWriteTimeUtc($manifestPath)
    $check = & $runtimePath --check-installation $msi.manifest_sha256
    if ($LASTEXITCODE -ne 0 -or -not ($check | ConvertFrom-Json).installation_verified) { throw 'Protected package was not admitted' }
    $release = ($check | ConvertFrom-Json).release
    if ($release.version -cne '0.5.0' -or $release.build -ne 1 -or
        $release.product_code -cne $manifest.msi_product_code -or $release.package_code -cne $manifest.msi_package_code) {
        throw 'Installed release observation does not match the protected manifest'
    }
    $cases.Add('protected_fixed_location_package_admitted')
    $cases.Add('protected_release_build_and_msi_identities_observed')
    if ((Get-Item -LiteralPath $wintunPath).Length -ne $msi.wintun_bytes -or
        (Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $msi.wintun_sha256) {
        throw 'MSI did not install the pinned Wintun image'
    }
    $driverBytes = [IO.File]::ReadAllBytes($wintunPath)
    $driverWriteTime = [IO.File]::GetLastWriteTimeUtc($wintunPath)
    $driverAcl = Get-Acl -LiteralPath $wintunPath
    try {
        $alteredDriver = [byte[]]$driverBytes.Clone()
        $alteredDriver[0] = $alteredDriver[0] -bxor 1
        [IO.File]::WriteAllBytes($wintunPath, $alteredDriver)
        Require-Rejected 'changed_wintun_image_rejected' 'executable does not match the installation identity'
    } finally {
        [IO.File]::WriteAllBytes($wintunPath, $driverBytes)
        [IO.File]::SetLastWriteTimeUtc($wintunPath, $driverWriteTime)
    }
    try {
        $unsafeDriverAcl = Get-Acl -LiteralPath $wintunPath
        $unsafeDriverAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Write', 'Allow'))
        Set-Acl -LiteralPath $wintunPath -AclObject $unsafeDriverAcl
        Require-Rejected 'unprivileged_wintun_writer_rejected' 'installation ownership or write access is unsafe'
    } finally { Set-Acl -LiteralPath $wintunPath -AclObject $driverAcl }
    $driverCheck = & $runtimePath --check-installation $msi.manifest_sha256
    if ($LASTEXITCODE -ne 0 -or -not ($driverCheck | ConvertFrom-Json).installation_verified) {
        throw 'Restored Wintun package was not admitted'
    }
    $cases.Add('protected_official_wintun_image_admitted')
    foreach ($counterexample in @(
        @($msiCandidate.manifest_sha256, 'installed manifest differs from the expected release'),
        @('invalid', 'Windows runtime installation manifest is invalid')
    )) {
        $rejected = & $runtimePath --check-installation $counterexample[0] 2>&1
        if ($LASTEXITCODE -eq 0 -or "$rejected" -notlike "*$($counterexample[1])*") { throw 'Wrong expected installed manifest was not rejected at its identity boundary' }
    }
    $msiReport.wrong_manifest_expectations_rejected = $true
    foreach ($mode in @('--prepare-maintenance', '--rollback-maintenance', '--rollback-update')) {
        $rejected = & $runtimePath $mode 'c40a7b13-74b7-4543-a5c0-55de82b9dad6' 2>&1
        if ($LASTEXITCODE -eq 0 -or "$rejected" -notmatch 'requires the SYSTEM primary identity') {
            throw "Ordinary installer caller was not refused before maintenance: $mode; $rejected"
        }
    }
    foreach ($mode in @('--prepare-update', '--commit-update', '--activate-update', '--retire-update-target')) {
        $rejected = & $runtimePath $mode 'c40a7b13-74b7-4543-a5c0-55de82b9dad6' $msiCandidate.manifest_sha256 2>&1
        if ($LASTEXITCODE -eq 0 -or "$rejected" -notmatch 'requires the SYSTEM primary identity') { throw "Ordinary update-maintenance caller was not refused: $mode" }
    }
    foreach ($mode in @('--fresh-install-maintenance', '--activate-fresh-install', '--retire-fresh-install')) {
        $rejected = & $runtimePath $mode $msi.manifest_sha256 2>&1
        if ($LASTEXITCODE -eq 0 -or "$rejected" -notmatch 'requires the SYSTEM primary identity') { throw "Ordinary fresh-install caller was not refused: $mode" }
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
    # Restore the complete pre-counterexample file state. A deliberately
    # modified timestamp would mark the unversioned MSI file as user-edited.
    [IO.File]::SetLastWriteTimeUtc($manifestPath, $manifestWriteTime)

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
                if ($probe.lineage.generation -ne 9) { throw 'Installed runtime did not retain the five backend, three application and one tunnel generations' }
                $cases.Add('product_service_and_agent_run_both_proxy_modes')
                $cases.Add('product_tunnel_routes_dns_and_traffic_then_retires_its_adapter')
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
        $msiReport.failed_maintenance = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence -ExpectedProductCode $msi.product_code -ExpectedPackageCode $msi.package_code -ExpectedMsiVersion $msi.msi_version
        $msiInFlight = $null
        if (-not $oldProcess.WaitForExit(10000) -or $oldProcess.ExitCode -ne 0) { throw 'MSI maintenance did not retire the original service process cleanly' }
    } finally { $oldProcess.Dispose() }
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($observed.State -cne 'Running' -or $observed.StartMode -cne 'Manual') { throw 'MSI rollback did not restore the originally running service' }
    $check = & $runtimePath --check-installation $msi.manifest_sha256
    if ($LASTEXITCODE -ne 0 -or -not ($check | ConvertFrom-Json).installation_verified) { throw 'MSI rollback did not restore an admitted installation' }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $manifestInput -Algorithm SHA256).Hash) { throw 'MSI rollback changed the installed manifest' }
    $after = Read-InstalledProbe
    $rollback = Read-MsiReport 'failed-maintenance' 'original_service'
    Assert-RunningReceipt $rollback.original_service $after
    if ($after.snapshot.state -cne 'off' -or -not $after.authenticated_product_service -or
        ($before.lineage | ConvertTo-Json -Compress) -cne ($after.lineage | ConvertTo-Json -Compress) -or
        $after.snapshot.revision -ne ($before.snapshot.revision + 1)) { throw 'MSI rollback/restart did not preserve authority lineage and exact startup revision' }
    $msiReport.maintenance_rollback = [ordered]@{
        before=$before; after=$after; original_service_process_exited=$true
        original_start_type_restored=$true; original_manifest_restored=$true
        restart_after_rollback=$true; rollback_started_runtime=$true; active_proxy_drain_exercised=$false
    }
    $msiReport.new_build_manifest_rollback_exercised = $true

    # A later commit action can still fail. The completed marker must retain
    # enough original identity to restore the old service after MSI rollback.
    $beforeLate = $after
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $oldProcess = [Diagnostics.Process]::GetProcessById($observed.ProcessId)
    $null = $oldProcess.Handle
    try {
        $msiInFlight = 'failed-commit'
        $msiReport.failed_commit = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence -ExpectedProductCode $msi.product_code -ExpectedPackageCode $msi.package_code -ExpectedMsiVersion $msi.msi_version
        $msiInFlight = $null
        if (-not $oldProcess.WaitForExit(10000) -or $oldProcess.ExitCode -ne 0) { throw 'Late MSI rollback did not retire the original service cleanly' }
    } finally { $oldProcess.Dispose() }
    Assert-Installation $msi
    $afterLate = Read-InstalledProbe
    Assert-RestartLineage $beforeLate $afterLate 2
    $activated = Read-MsiReport 'failed-commit' 'target_service'
    $retired = Read-MsiReport 'failed-commit' 'target_retired'
    Assert-ActivatedProcessRetired $activated.target_service $retired
    $restored = Read-MsiReport 'failed-commit' 'original_service'
    Assert-RunningReceipt $restored.original_service $afterLate
    $msiReport.commit_failure_rollback = [ordered]@{
        before=$beforeLate; after=$afterLate; original_manifest_restored=$true
        original_start_type_restored=$true; original_service_process_exited=$true
        runtime_started_by_rollback=$true; target_activation=$activated; target_retirement=$retired; original_restoration=$restored
    }

    Stop-Installed
    $msiInFlight = 'failed-stopped-maintenance'
    $msiReport.failed_stopped_maintenance = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence -ExpectedProductCode $msi.product_code -ExpectedPackageCode $msi.package_code -ExpectedMsiVersion $msi.msi_version
    $msiInFlight = $null
    Assert-Installation $msi 'Stopped'
    $stoppedRollback = Read-MsiReport 'failed-stopped-maintenance' 'original_service'
    if ($stoppedRollback.original_running -or $null -ne $stoppedRollback.original_service -or -not $stoppedRollback.startup_restored) {
        throw 'MSI rollback started an originally stopped service'
    }
    $msiReport.stopped_rollback = $stoppedRollback
    Invoke-ServiceCommand @('start', $serviceName)
    $service = [System.ServiceProcess.ServiceController]::new($serviceName)
    try { $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) } finally { $service.Dispose() }
    $beforeUpgrade = Read-InstalledProbe
    Assert-RestartLineage $afterLate $beforeUpgrade
    $observed = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $oldProcess = [Diagnostics.Process]::GetProcessById($observed.ProcessId)
    $null = $oldProcess.Handle
    try {
        $msiInFlight = 'upgrade'
        $msiReport.upgraded = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence -PreviousProductCode $msi.product_code
        $msiInFlight = $null
        if (-not $oldProcess.WaitForExit(10000) -or $oldProcess.ExitCode -ne 0) { throw 'Successful MSI upgrade did not retire the original service cleanly' }
    } finally { $oldProcess.Dispose() }
    Assert-Installation $msiCandidate
    $afterUpgrade = Read-InstalledProbe
    Assert-RestartLineage $beforeUpgrade $afterUpgrade
    $upgradeActivation = Read-MsiReport 'upgrade' 'target_service'
    Assert-RunningReceipt $upgradeActivation.target_service $afterUpgrade
    $msiReport.upgrade_commit = [ordered]@{
        before=$beforeUpgrade; after=$afterUpgrade; target_manifest_installed=$true
        original_start_type_restored=$true; original_service_process_exited=$true
        runtime_started_by_commit=$true; activation=$upgradeActivation; protected_lineage_preserved=$true
    }
    $msiReport.new_build_upgrade_committed = $true

    Stop-Installed
    $msiInFlight = 'uninstall'
    $msiReport.uninstalled = Invoke-RuntimeMsi -Fixture $msiCandidate -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    if (Test-Path -LiteralPath $package) { throw 'Committed MSI uninstall left package files behind' }
    if (@([System.ServiceProcess.ServiceController]::GetServices() | Where-Object ServiceName -CEQ $serviceName).Count -ne 0) { throw 'Committed MSI uninstall left the service behind' }
    $msiReport.uninstall_removed_files_and_service = $true

    # Explicit fresh installation after uninstall has a different manifest.
    # Completed history may retire only while SCM is absent and Authority Off.
    $msiInFlight = 'reinstall'
    $msiReport.reinstalled = Invoke-RuntimeMsi -Fixture $msi -Operation $msiInFlight -Evidence $msiEvidence
    $msiInFlight = $null
    Assert-Installation $msi
    $afterReinstall = Read-InstalledProbe
    Assert-RestartLineage $afterUpgrade $afterReinstall
    $reinstallActivation = Read-MsiReport 'reinstall' 'fresh_service'
    Assert-RunningReceipt $reinstallActivation.fresh_service $afterReinstall
    $msiReport.reinstallation = [ordered]@{ before=$afterUpgrade; after=$afterReinstall; activation=$reinstallActivation; original_manifest_installed=$true; protected_lineage_preserved=$true }
    $msiReport.completed_history_reinstall_exercised = $true
} catch { $failure = $_.ToString() }
finally {
    if ($null -ne $failure) {
        # Failure diagnostics only. The SYSTEM service records its last error
        # in its private directory, which backup semantics can read.
        try {
            $systemDiagnostics = Join-Path $env:ProgramData 'Clash for Windows\authority-v1\diagnostics'
            $null = & robocopy $systemDiagnostics $Receipts 'last-runtime-error.json' /B /R:0 /W:0 /NJH /NJS /NP
            if ($LASTEXITCODE -ge 8) { $failure = "$failure; SYSTEM diagnostics copy exited $LASTEXITCODE" }
        } catch { $failure = "$failure; SYSTEM diagnostics copy: $($_.ToString())" }
    }
    try {
        if ($null -ne $msiInFlight) {
            $completionPath = Join-Path $msiEvidence "$msiInFlight.json"
            if (-not (Test-Path -LiteralPath $completionPath) -or -not (Get-Content -LiteralPath $completionPath -Raw | ConvertFrom-Json).completed) {
                throw 'MSI transaction state is unknown; no competing teardown transaction was started'
            }
        }
        $registered = @(@($msi, $msiCandidate) | Where-Object { $null -ne $_ -and (Get-RuntimeMsiProductState $_.product_code) -eq 5 })
        if ($registered.Count -gt 1) { throw 'Multiple fixture MSI registrations remain; refusing ambiguous teardown' }
        if ($registered.Count -eq 1) {
            # This is fixture teardown from an already Off runtime. It does not
            # qualify interactive uninstall while another user's GUI is active.
            Stop-Installed
            $operation = if ($null -eq $msiReport.uninstalled) { 'uninstall' } else { 'uninstall-reinstalled' }
            $removed = Invoke-RuntimeMsi -Fixture $registered[0] -Operation $operation -Evidence $msiEvidence
            if ($operation -eq 'uninstall') { $msiReport.uninstalled = $removed } else { $msiReport.uninstalled_reinstalled = $removed }
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
