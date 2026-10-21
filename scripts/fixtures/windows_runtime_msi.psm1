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
    private static extern uint ProductInfo(string productCode, string userSid, uint context,
                                          string property, StringBuilder value, ref uint length);
    public static uint MachineProductInfo(string productCode, string property, StringBuilder value, ref uint length) {
        // PowerShell converts $null to String.Empty for a .NET string argument.
        // MSIINSTALLCONTEXT_MACHINE requires an actual null SID pointer.
        return ProductInfo(productCode, null, 4, property, value, ref length);
    }
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
        $status = [CfwRuntimeMsiQualification]::MachineProductInfo($ProductCode, $property, $value, [ref]$length)
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
    if ((Get-RuntimeMsiProductState $ProductCode) -ne -1) { throw 'Refusing an existing MSI product registration' }
    Import-Module (Join-Path $PSScriptRoot '../windows/runtime_msi.psm1') -Force
    New-WindowsRuntimeMsi -Runtime $Runtime -Desktop $Desktop -Engine $Engine -Manifest $Manifest `
        -Wintun (Join-Path (Split-Path -Parent $Engine) 'wintun.dll') `
        -ProductCode $ProductCode -Source $Source -Evidence $Evidence -QualificationFixture
}
function Invoke-RuntimeMsi {
    param([Parameter(Mandatory)]$Fixture,
          [ValidateSet('failed-install','failed-fresh-commit','install','failed-maintenance','failed-stopped-maintenance','failed-commit','upgrade','reinstall','uninstall','uninstall-reinstalled')][string]$Operation,
          [string]$Evidence, [string]$ExpectedProductCode, [string]$ExpectedPackageCode, [string]$ExpectedMsiVersion,
          [string]$PreviousProductCode)
    Assert-RuntimeMsiOptIn
    if ((Get-FileHash -LiteralPath $Fixture.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Fixture.package_sha256) {
        throw 'Runtime MSI fixture bytes changed after authoring'
    }
    $log = Join-Path $Evidence "$Operation.log"
    $start = [Diagnostics.ProcessStartInfo]::new((Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'))
    $start.UseShellExecute = $false
    $mode = if ($Operation -in @('uninstall', 'uninstall-reinstalled')) { '/x' } else { '/i' }
    foreach ($arg in @($mode, $Fixture.path, '/qn', '/norestart', 'REBOOT=ReallySuppress', '/l*vx', $log)) { $start.ArgumentList.Add($arg) }
    if ($Operation -in @('failed-install', 'failed-maintenance', 'failed-stopped-maintenance')) { $start.ArgumentList.Add('CFW_FIXTURE_FAIL=1') }
    if ($Operation -in @('failed-maintenance', 'failed-stopped-maintenance', 'failed-commit', 'upgrade')) { $start.ArgumentList.Add('CFW_FIXTURE_MAINTENANCE=1') }
    if ($Operation -in @('failed-commit', 'failed-fresh-commit')) { $start.ArgumentList.Add('CFW_FIXTURE_FAIL_COMMIT=1') }
    $process = [Diagnostics.Process]::Start($start)
    if ([string]::IsNullOrEmpty($ExpectedProductCode)) { $ExpectedProductCode = $Fixture.product_code }
    $result = [ordered]@{ operation=$Operation; exit_code=$null; completed=$false; product_state=$null
        registration_product_code=$ExpectedProductCode; replacement_product_state=$null; registration=$null
        previous_product_code=$null; previous_product_state=$null; log=[IO.Path]::GetFileName($log) }
    try {
        if (-not $process.WaitForExit(180000)) {
            # Killing msiexec's client does not prove the elevated transaction
            # ended. Leave it unknown; never begin a competing cleanup/retry.
            throw 'MSI transaction deadline expired; transaction state is unknown'
        }
        $result.completed = $true
        $result.exit_code = $process.ExitCode
        $result.product_state = Get-RuntimeMsiProductState $ExpectedProductCode
        $expectedCode = if ($Operation -in @('failed-install', 'failed-fresh-commit', 'failed-maintenance', 'failed-stopped-maintenance', 'failed-commit')) { 1603 } else { 0 }
        if ($result.exit_code -ne $expectedCode) {
            throw "Unexpected MSI result for ${Operation}: $($result.exit_code), expected $expectedCode (reboot-required is not accepted as completed replacement)"
        }
        $expectedState = if ($Operation -in @('failed-install', 'failed-fresh-commit', 'uninstall', 'uninstall-reinstalled')) { -1 } else { 5 }
        if ($result.product_state -ne $expectedState) { throw "Unexpected MSI registration after ${Operation}: $($result.product_state)" }
        if ($expectedState -eq 5) {
            $result.registration = Get-RuntimeMsiRegistration $ExpectedProductCode
            if ([string]::IsNullOrEmpty($ExpectedPackageCode)) { $ExpectedPackageCode = $Fixture.package_code }
            if ([string]::IsNullOrEmpty($ExpectedMsiVersion)) { $ExpectedMsiVersion = $Fixture.msi_version }
            if ($result.registration.PackageCode -cne $ExpectedPackageCode -or
                $result.registration.VersionString -cne $ExpectedMsiVersion -or
                $result.registration.ProductName -cne 'CFW Runtime Installation Fixture' -or
                $result.registration.AssignmentType -cne '1') { throw 'Machine MSI registration does not match the original installed package' }
        }
        if ($Operation -in @('failed-maintenance', 'failed-stopped-maintenance', 'failed-commit')) {
            if ($ExpectedProductCode -ceq $Fixture.product_code) { throw 'MSI rollback fixture did not use a distinct candidate product' }
            $result.replacement_product_state = Get-RuntimeMsiProductState $Fixture.product_code
            if ($result.replacement_product_state -ne -1) { throw 'Failed replacement left a candidate MSI product registered' }
        }
        if ($Operation -eq 'upgrade') {
            if ([string]::IsNullOrEmpty($PreviousProductCode) -or $PreviousProductCode -ceq $Fixture.product_code) {
                throw 'Successful MSI upgrade requires a distinct previous product'
            }
            $result.previous_product_code = $PreviousProductCode
            $result.previous_product_state = Get-RuntimeMsiProductState $PreviousProductCode
            if ($result.previous_product_state -ne -1) { throw 'Successful upgrade retained the previous product registration' }
        }
        if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { throw 'MSI verbose transaction log was not created' }
        if ($expectedCode -eq 1603) {
            $content = Get-Content -LiteralPath $log -Raw
            foreach ($action in @('RollbackRuntimeMaintenance', 'RetireRuntimeTarget', 'RetireFreshRuntime')) {
                if ($content.Contains("CustomAction $action returned actual error code", [StringComparison]::Ordinal)) {
                    throw "MSI rollback action failed: $action; continued rollback is not successful recovery"
                }
            }
            $validationIndex = $content.IndexOf('Executing op: CustomActionSchedule(Action=ValidateInstalledRuntime,', [StringComparison]::Ordinal)
            $faultAction = if ($Operation -in @('failed-commit', 'failed-fresh-commit')) { 'FailAfterCommit' } else { 'FailAfterReplacement' }
            $failureIndex = $content.IndexOf("CustomAction $faultAction returned actual error code 1", [StringComparison]::Ordinal)
            if ($validationIndex -lt 0 -or $failureIndex -le $validationIndex) {
                throw 'MSI failed outside the injected deferred-action/rollback boundary'
            }
            if ($Operation -in @('failed-maintenance', 'failed-stopped-maintenance', 'failed-commit') -and
                $content.IndexOf('CustomActionRollback(Action=RollbackRuntimeMaintenance,', [StringComparison]::Ordinal) -le $failureIndex) {
                throw 'MSI did not execute the scheduled runtime-maintenance rollback action'
            }
            if ($Operation -in @('failed-commit', 'failed-fresh-commit')) {
                $activation = if ($Operation -eq 'failed-commit') { '"target_service":' } else { '"fresh_service":' }
                $commitIndex = $content.IndexOf($activation, [StringComparison]::Ordinal)
                if ($commitIndex -lt 0 -or $commitIndex -ge $failureIndex) { throw 'Late MSI failure did not follow authenticated runtime activation' }
            }
        }
        return [pscustomobject]$result
    } finally {
        $process.Dispose()
        $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence "$Operation.json") -Encoding utf8NoBOM
    }
}
Export-ModuleMember -Function New-RuntimeMsiFixture, Invoke-RuntimeMsi, Get-RuntimeMsiProductState
