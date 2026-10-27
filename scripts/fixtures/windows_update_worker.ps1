param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Fixtures,
    [Parameter(Mandatory)][string]$Evidence,
    [Parameter(Mandatory)][string]$SignTool,
    [Parameter(Mandatory)][string]$PublisherThumbprint
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:CFW_NATIVE_PACKAGE_TESTS -cne '1' -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Protected update-worker fixtures require explicitly opted-in disposable hosted CI'
}
if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
    throw 'Update-worker fixture source identity mismatch'
}
$package = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Clash for Windows'
if (Test-Path -LiteralPath $package) { throw 'Refusing to replace an existing product installation' }
$created = $false
$failure = $null
$cleanupFailure = $null
$workerPassed = $false
$transportPassed = $false
$mediumPassed = $false
$priorWorker = $env:CFW_NATIVE_PACKAGE_WORKER_FIXTURE
$priorReceipts = $env:CFW_NATIVE_SERVICE_RECEIPTS
$manifest = $null

function Protect-Package([string]$Path, [bool]$Directory) {
    $acl = if ($Directory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
    $inherit = if ($Directory) { 'OICI' } else { '' }
    $acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;$inherit;FA;;;SY)(A;$inherit;FA;;;BA)(A;$inherit;0x1200a9;;;BU)")
    Set-Acl -LiteralPath $Path -AclObject $acl
}

try {
    cargo build --locked -p cfw-windows-engine --bin cfw-windows-runtime --example native-update-worker-fixture --example native-service-fixture --features native-package-validation,native-service-validation 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'worker-build.log')
    if ($LASTEXITCODE -ne 0) { throw 'Update worker build failed' }
    New-Item -ItemType Directory -Path $package -ErrorAction Stop | Out-Null
    $created = $true
    Protect-Package $package $true
    $runtime = Join-Path $package 'cfw-windows-runtime.exe'
    $desktop = Join-Path $package 'Clash for Windows.exe'
    $engine = Join-Path $package 'cfw-engine-host.exe'
    $manifestPath = Join-Path $package 'runtime-installation-v2.json'
    Copy-Item -LiteralPath 'target/debug/cfw-windows-runtime.exe' -Destination $runtime
    Copy-Item -LiteralPath 'target/debug/examples/native-service-fixture.exe' -Destination $desktop
    & $SignTool sign /fd SHA256 /s My /sha1 $PublisherThumbprint $desktop
    if ($LASTEXITCODE -ne 0) { throw 'Disposable installed Desktop signing failed' }
    $signature = Get-AuthenticodeSignature -LiteralPath $desktop
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $PublisherThumbprint) {
        throw 'Disposable installed Desktop publisher mismatch'
    }
    & $SignTool verify /pa /all $desktop
    if ($LASTEXITCODE -ne 0) { throw 'Disposable installed Desktop signature verification failed' }
    # This inspection never launches an engine. A distinct admitted PE fixture
    # satisfies the installation shape without installing or starting services.
    Copy-Item -LiteralPath (Join-Path $Fixtures 'unsigned.exe') -Destination $engine
    # Use the actual pinned DLL even though this lane never loads it. Runtime
    # admission must not require a special exemption for package-worker tests.
    $driverStage = Join-Path $Evidence 'wintun-distribution'
    python scripts/stage_wintun_validation.py --repository "$PWD" --output $driverStage 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'wintun-staging.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Update-worker Wintun staging failed' }
    $wintun = Join-Path $package 'wintun.dll'
    Copy-Item -LiteralPath (Join-Path $driverStage 'payload/wintun.dll') -Destination $wintun -ErrorAction Stop
    foreach ($path in @($runtime, $desktop, $engine, $wintun)) { Protect-Package $path $false }
    $manifest = [ordered]@{
        schema_version=2; product_version=(Get-Content -LiteralPath 'apps/cfw-tauri-shell/tauri.conf.json' -Raw | ConvertFrom-Json).version; build_number=1
        msi_product_code='{6D762E56-384D-4203-8520-A9B83D0F0652}'
        msi_package_code='{C1BB0951-CB20-43FC-8ECA-AC8AC63F0A12}'
        architecture='x86_64'; engine_version='1.14.2'
        runtime_sha256=(Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant()
        desktop_sha256=(Get-FileHash -LiteralPath $desktop -Algorithm SHA256).Hash.ToLowerInvariant()
        engine_sha256=(Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    Protect-Package $manifestPath $false
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $Evidence 'worker-installation.json')
    Copy-Item -LiteralPath $runtime -Destination (Join-Path $Evidence 'worker-runtime.exe')
    Copy-Item -LiteralPath $desktop -Destination (Join-Path $Evidence 'worker-publisher.exe')
    Copy-Item -LiteralPath $engine -Destination (Join-Path $Evidence 'worker-engine-fixture.exe')
    $check = & $runtime --check-installation
    if ($LASTEXITCODE -ne 0) { throw 'The native worker installation was not admitted' }
    $check | Set-Content -LiteralPath (Join-Path $Evidence 'worker-installation-check.json') -Encoding utf8NoBOM
    $check = $check | ConvertFrom-Json
    if (-not $check.installation_verified -or $check.release.build -ne 1 -or
        $check.release.product_code -cne $manifest.msi_product_code -or $check.release.package_code -cne $manifest.msi_package_code) {
        throw 'Native installed release observation mismatch'
    }
    cargo test --locked -p cfw-windows-engine --test native_update_worker --features native-package-validation -- --test-threads=1 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'worker-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Installed update worker native validation failed' }
    $workerPassed = $true

    $env:CFW_NATIVE_PACKAGE_WORKER_FIXTURE = Join-Path $Fixtures 'counterexample-worker.exe'
    Copy-Item -LiteralPath 'target/debug/examples/native-update-worker-fixture.exe' -Destination $env:CFW_NATIVE_PACKAGE_WORKER_FIXTURE
    Copy-Item -LiteralPath $env:CFW_NATIVE_PACKAGE_WORKER_FIXTURE -Destination (Join-Path $Evidence 'worker-counterexample.exe')
    cargo test --locked -p cfw-windows-engine --lib --features native-package-validation process::one_shot::tests -- --test-threads=1 --nocapture 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'worker-transport-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Native worker timeout/cancellation/pipe cleanup failed' }
    $transportPassed = $true

    $medium = Join-Path $Fixtures 'medium-inspection'
    New-Item -ItemType Directory -Path $medium -ErrorAction Stop | Out-Null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $sid = $identity.User.Value } finally { $identity.Dispose() }
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm("O:${sid}G:${sid}D:P(A;OICI;FA;;;${sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    Set-Acl -LiteralPath $medium -AclObject $acl
    $env:CFW_NATIVE_SERVICE_RECEIPTS = $medium
    & $desktop --update-package-validation 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'worker-medium-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'Installed update inspection from an ordinary Desktop failed' }
    $mediumPassed = $true
} catch { $failure = "$($_.Exception.ToString())`n$($_.ScriptStackTrace)" }
finally {
    $env:CFW_NATIVE_PACKAGE_WORKER_FIXTURE = $priorWorker
    $env:CFW_NATIVE_SERVICE_RECEIPTS = $priorReceipts
    try {
        if ($created) {
            Remove-Item -LiteralPath $package -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $package) { throw 'Temporary installed update worker remains' }
        }
    } catch { $cleanupFailure = $_.ToString() }
    [ordered]@{
        source=$Source; failure=$failure; cleanup_failure=$cleanupFailure
        protected_installation_created=$created; installation=$manifest
        native_worker_passed=$workerPassed; native_transport_passed=$transportPassed
        native_medium_worker_passed=$mediumPassed
        installed_product_msi=$false; desktop_is_fixture=$true; engine_is_fixture=$true
        service_started=$false; production_publisher=$false; release_accepted=$false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Evidence 'worker-receipt.json') -Encoding utf8NoBOM
}
if ($null -ne $failure -or $null -ne $cleanupFailure) {
    throw "Native update-worker validation failed: $failure; cleanup: $cleanupFailure"
}
