# Native MSI qualification on an explicitly disposable Windows runner. There
# is no manual file/service cleanup fallback: a failed rollback or uninstall
# remains a failed MSI result, with its logs preserved for VM teardown.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RuntimeMsiOptIn {
    if (-not $IsWindows -or $env:CFW_NATIVE_SERVICE_MUTATION_TESTS -cne '1' -or $env:GITHUB_ACTIONS -cne 'true') {
        throw 'Runtime MSI qualification requires an opted-in disposable Windows CI runner'
    }
}
function Get-RuntimeMsiProductState([string]$ProductCode) {
    Assert-RuntimeMsiOptIn
    if ($null -eq ('CfwRuntimeMsiQualification' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using System.Text;
public static class CfwRuntimeMsiQualification {
    [DllImport("msi.dll", EntryPoint="MsiQueryProductStateW", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern int ProductState(string productCode);
    [DllImport("msi.dll", EntryPoint="MsiGetProductInfoExW", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern uint ProductInfo(string productCode, string userSid, uint context,
                                         string property, StringBuilder value, ref uint length);
}
'@
    }
    return [CfwRuntimeMsiQualification]::ProductState($ProductCode)
}
function Get-RuntimeMsiRegistration([string]$ProductCode) {
    Assert-RuntimeMsiOptIn
    $result = [ordered]@{}
    foreach ($property in @('PackageCode', 'VersionString', 'ProductName', 'AssignmentType')) {
        $value = [Text.StringBuilder]::new(4096)
        [uint32]$length = 4096
        # MSIINSTALLCONTEXT_MACHINE (4), with no user SID. A registration in
        # the current user's context is not a per-machine installation receipt.
        $status = [CfwRuntimeMsiQualification]::ProductInfo($ProductCode, $null, 4, $property, $value, [ref]$length)
        if ($status -ne 0 -or $length -eq 0 -or $length -ge 4096 -or $value.Length -ne $length) {
            throw "Machine MSI property lookup failed: $property (status $status, length $length)"
        }
        $result[$property] = $value.ToString()
    }
    return [pscustomobject]$result
}
function New-RuntimeMsiFixture {
    param([string]$Runtime, [string]$Desktop, [string]$Engine, [string]$Manifest,
          [string]$ProductCode, [string]$Source, [string]$Evidence)
    Assert-RuntimeMsiOptIn
    if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
        throw 'Runtime MSI source identity mismatch'
    }
    if ((Get-RuntimeMsiProductState $ProductCode) -ne -1) { throw 'Refusing an existing MSI product registration' }
    $tools = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'WiX Toolset v3.14/bin'
    $candle = Join-Path $tools 'candle.exe'
    $light = Join-Path $tools 'light.exe'
    $csc = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $wixAssembly = Join-Path $tools 'wix.dll'
    foreach ($path in @($candle, $light, $csc, $wixAssembly, $Runtime, $Desktop, $Engine, $Manifest)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required MSI qualification input missing: $path" }
    }
    $definition = Join-Path $PSScriptRoot 'windows_runtime_installation.wxs'
    $object = Join-Path $Evidence 'runtime-fixture.wixobj'
    $package = Join-Path $Evidence 'runtime-fixture.msi'
    $binder = Join-Path $Evidence 'RuntimeMsiManifestBinder.dll'
    & $csc /nologo /target:library /warnaserror+ "/reference:$wixAssembly" "/out:$binder" (Join-Path $PSScriptRoot 'RuntimeMsiManifestBinder.cs') 2>&1 |
        Tee-Object -FilePath (Join-Path $Evidence 'binder-compile.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI manifest binder compilation failed' }
    $transaction = [guid]::NewGuid().ToString('D')
    $arguments = @('-nologo', '-wx', '-arch', 'x64', '-out', $object,
        "-dRuntime=$Runtime", "-dDesktop=$Desktop", "-dEngine=$Engine", "-dManifest=$Manifest",
        "-dProductCode=$ProductCode", "-dMaintenanceTransaction=$transaction", $definition)
    & $candle @arguments 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'compile.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI fixture compilation failed' }
    & $light -nologo -wx -ext $binder -out $package $object 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'link.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI fixture link or validation failed' }
    $boundManifest = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
    if ($boundManifest.msi_product_code -cne $ProductCode -or $boundManifest.msi_package_code -ceq '{00000000-0000-0000-0000-000000000000}') { throw 'Runtime manifest was not bound to its generated MSI identity' }
    $result = [pscustomobject]@{
        source=$Source; path=$package; product_code=$ProductCode; package_code=$boundManifest.msi_package_code
        package_sha256=(Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
        maintenance_transaction=$transaction; manifest_sha256=(Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
        build_number=$boundManifest.build_number
        desktop_is_fixture=$true; signed=$false; release_accepted=$false
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'package.json') -Encoding utf8NoBOM
    return $result
}
function Invoke-RuntimeMsi {
    param([Parameter(Mandatory)]$Fixture,
          [ValidateSet('failed-install','install','failed-maintenance','uninstall')][string]$Operation,
          [string]$Evidence, [string]$ExpectedProductCode, [string]$ExpectedPackageCode)
    Assert-RuntimeMsiOptIn
    if ((Get-FileHash -LiteralPath $Fixture.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Fixture.package_sha256) {
        throw 'Runtime MSI fixture bytes changed after authoring'
    }
    $log = Join-Path $Evidence "$Operation.log"
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'))
    $start.UseShellExecute = $false
    $mode = if ($Operation -eq 'uninstall') { '/x' } else { '/i' }
    foreach ($arg in @($mode, $Fixture.path, '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*vx', $log)) { $start.ArgumentList.Add($arg) }
    if ($Operation -in @('failed-install', 'failed-maintenance')) { $start.ArgumentList.Add('CFW_FIXTURE_FAIL=1') }
    if ($Operation -eq 'failed-maintenance') { $start.ArgumentList.Add('CFW_FIXTURE_MAINTENANCE=1') }
    $process = [Diagnostics.Process]::Start($start)
    if ([string]::IsNullOrEmpty($ExpectedProductCode)) { $ExpectedProductCode = $Fixture.product_code }
    $result = [ordered]@{ operation=$Operation; exit_code=$null; completed=$false; product_state=$null
        registration_product_code=$ExpectedProductCode; replacement_product_state=$null; registration=$null; log=[IO.Path]::GetFileName($log) }
    try {
        if (-not $process.WaitForExit(180000)) {
            # Killing msiexec's client does not prove the elevated transaction
            # ended. Leave it unknown; never begin a competing cleanup/retry.
            throw 'MSI transaction deadline expired; transaction state is unknown'
        }
        $result.completed = $true
        $result.exit_code = $process.ExitCode
        $result.product_state = Get-RuntimeMsiProductState $ExpectedProductCode
        $expectedCode = if ($Operation -in @('failed-install', 'failed-maintenance')) { 1603 } else { 0 }
        if ($result.exit_code -ne $expectedCode) {
            throw "Unexpected MSI result for ${Operation}: $($result.exit_code), expected $expectedCode (reboot-required is not accepted as completed replacement)"
        }
        $expectedState = if ($Operation -in @('failed-install', 'uninstall')) { -1 } else { 5 }
        if ($result.product_state -ne $expectedState) { throw "Unexpected MSI registration after ${Operation}: $($result.product_state)" }
        if ($expectedState -eq 5) {
            $result.registration = Get-RuntimeMsiRegistration $ExpectedProductCode
            if ([string]::IsNullOrEmpty($ExpectedPackageCode)) { $ExpectedPackageCode = $Fixture.package_code }
            if ($result.registration.PackageCode -cne $ExpectedPackageCode -or
                $result.registration.VersionString -cne '0.5.0' -or
                $result.registration.ProductName -cne 'CFW Runtime Installation Fixture' -or
                $result.registration.AssignmentType -cne '1') { throw 'Machine MSI registration does not match the original installed package' }
        }
        if ($Operation -eq 'failed-maintenance') {
            if ($ExpectedProductCode -ceq $Fixture.product_code) { throw 'MSI rollback fixture did not use a distinct candidate product' }
            $result.replacement_product_state = Get-RuntimeMsiProductState $Fixture.product_code
            if ($result.replacement_product_state -ne -1) { throw 'Failed replacement left a candidate MSI product registered' }
        }
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { throw 'MSI verbose transaction log was not created' }
        if ($expectedCode -eq 1603) {
            $content = Get-Content -LiteralPath $log -Raw
            $validationIndex = $content.IndexOf('Executing op: CustomActionSchedule(Action=ValidateInstalledRuntime,', [StringComparison]::Ordinal)
            $failureIndex = $content.IndexOf('CustomAction FailAfterInstallServices returned actual error code 1', [StringComparison]::Ordinal)
            if ($validationIndex -lt 0 -or $failureIndex -le $validationIndex) {
                throw 'MSI failed outside the injected deferred-action/rollback boundary'
            }
            if ($Operation -eq 'failed-maintenance' -and
                $content.IndexOf('CustomActionRollback(Action=RollbackRuntimeMaintenance,', [StringComparison]::Ordinal) -le $failureIndex) {
                throw 'MSI did not execute the scheduled runtime-maintenance rollback action'
            }
        }
        return [pscustomobject]$result
    } finally {
        $process.Dispose()
        $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence "$Operation.json") -Encoding utf8NoBOM
    }
}
Export-ModuleMember -Function New-RuntimeMsiFixture, Invoke-RuntimeMsi, Get-RuntimeMsiProductState
