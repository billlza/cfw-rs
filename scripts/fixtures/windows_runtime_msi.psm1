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
public static class CfwRuntimeMsiQualification {
    [DllImport("msi.dll", EntryPoint="MsiQueryProductStateW", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern int ProductState(string productCode);
}
'@
    }
    return [CfwRuntimeMsiQualification]::ProductState($ProductCode)
}
function New-RuntimeMsiFixture {
    param([string]$Runtime, [string]$Desktop, [string]$Engine, [string]$Manifest,
          [string]$ProductCode, [string]$PackageCode, [string]$Source, [string]$Evidence)
    Assert-RuntimeMsiOptIn
    if ($Source -cnotmatch '^[0-9a-f]{40}$' -or (git rev-parse HEAD) -cne $Source -or $LASTEXITCODE -ne 0) {
        throw 'Runtime MSI source identity mismatch'
    }
    if ((Get-RuntimeMsiProductState $ProductCode) -ne -1) { throw 'Refusing an existing MSI product registration' }
    $tools = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'WiX Toolset v3.14/bin'
    $candle = Join-Path $tools 'candle.exe'
    $light = Join-Path $tools 'light.exe'
    foreach ($path in @($candle, $light, $Runtime, $Desktop, $Engine, $Manifest)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required MSI qualification input missing: $path" }
    }
    $definition = Join-Path $PSScriptRoot 'windows_runtime_installation.wxs'
    $object = Join-Path $Evidence 'runtime-fixture.wixobj'
    $package = Join-Path $Evidence 'runtime-fixture.msi'
    $transaction = [guid]::NewGuid().ToString('D')
    $arguments = @('-nologo', '-wx', '-arch', 'x64', '-out', $object,
        "-dRuntime=$Runtime", "-dDesktop=$Desktop", "-dEngine=$Engine", "-dManifest=$Manifest",
        "-dProductCode=$ProductCode", "-dPackageCode=$PackageCode", "-dMaintenanceTransaction=$transaction", $definition)
    & $candle @arguments 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'compile.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI fixture compilation failed' }
    & $light -nologo -wx -out $package $object 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'link.log') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Runtime MSI fixture link or validation failed' }
    $result = [pscustomobject]@{
        source=$Source; path=$package; product_code=$ProductCode; package_code=$PackageCode
        package_sha256=(Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
        maintenance_transaction=$transaction; desktop_is_fixture=$true; signed=$false; release_accepted=$false
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'package.json') -Encoding utf8NoBOM
    return $result
}
function Invoke-RuntimeMsi {
    param([Parameter(Mandatory)]$Fixture,
          [ValidateSet('failed-install','install','failed-maintenance','uninstall')][string]$Operation,
          [string]$Evidence)
    Assert-RuntimeMsiOptIn
    if ((Get-FileHash -LiteralPath $Fixture.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Fixture.package_sha256) {
        throw 'Runtime MSI fixture bytes changed after authoring'
    }
    $log = Join-Path $Evidence "$Operation.log"
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'))
    $start.UseShellExecute = $false
    $mode = switch ($Operation) { 'uninstall' { '/x' } 'failed-maintenance' { '/fa' } default { '/i' } }
    foreach ($arg in @($mode, $Fixture.path, '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*vx', $log)) { $start.ArgumentList.Add($arg) }
    if ($Operation -in @('failed-install', 'failed-maintenance')) { $start.ArgumentList.Add('CFW_FIXTURE_FAIL=1') }
    if ($Operation -eq 'failed-maintenance') { $start.ArgumentList.Add('CFW_FIXTURE_MAINTENANCE=1') }
    $process = [Diagnostics.Process]::Start($start)
    $result = [ordered]@{ operation=$Operation; exit_code=$null; completed=$false; product_state=$null; log=[IO.Path]::GetFileName($log) }
    try {
        if (-not $process.WaitForExit(180000)) {
            # Killing msiexec's client does not prove the elevated transaction
            # ended. Leave it unknown; never begin a competing cleanup/retry.
            throw 'MSI transaction deadline expired; transaction state is unknown'
        }
        $result.completed = $true
        $result.exit_code = $process.ExitCode
        $result.product_state = Get-RuntimeMsiProductState $Fixture.product_code
        $expectedCode = if ($Operation -in @('failed-install', 'failed-maintenance')) { 1603 } else { 0 }
        if ($result.exit_code -ne $expectedCode) {
            throw "Unexpected MSI result for ${Operation}: $($result.exit_code), expected $expectedCode (reboot-required is not accepted as completed replacement)"
        }
        $expectedState = if ($Operation -in @('failed-install', 'uninstall')) { -1 } else { 5 }
        if ($result.product_state -ne $expectedState) { throw "Unexpected MSI registration after ${Operation}: $($result.product_state)" }
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { throw 'MSI verbose transaction log was not created' }
        if ($expectedCode -eq 1603) {
            $content = Get-Content -LiteralPath $log -Raw
            if ($content -notmatch 'CustomAction FailAfterInstallServices returned actual error code 1' -or
                $content -notmatch 'Executing op: (ActionStart\(Name=Rollback|CustomActionRollback\()') {
                throw 'MSI failed outside the injected deferred-action/rollback boundary'
            }
            if ($Operation -eq 'failed-maintenance' -and
                $content -notmatch 'CustomActionRollback\(Action=RollbackRuntimeMaintenance,') {
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
