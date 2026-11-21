# The subscription session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# A subscription imported by its URL beside the LocalProxy profile, with
# its passwords in Windows protected storage, starts the core. Once the
# core is stopped, the profile is renamed, pointed at the changed
# document and updated. The LocalProxy profile is selected again, the
# subscription profile is deleted and the credentials it leaves are
# cleaned up, so the next session begins as this one did.
$imported = (Invoke-GuiScenario 'subscription-import') | ConvertFrom-Json
$imported | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'subscription-import.json') -Encoding utf8NoBOM
if ($imported.release_accepted -or $imported.profile -ceq $imported.kept -or @($imported.requirements).Count -ne 2) {
    throw 'The subscription import receipt is invalid'
}
$receipt.native_gui_exercised = $true
$receipt.imported_profile_id = $imported.profile
$receipt.kept_profile_id = $imported.kept
$receipt.active_runtime = $imported.active.snapshot.state.runtime
$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$startedIdentity = $imported.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($startedIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the core that ran the subscription'
}
$receipt.engine_stopped = $true
$updated = (Invoke-GuiScenario 'subscription-update') | ConvertFrom-Json
$updated | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'subscription-update.json') -Encoding utf8NoBOM
if ($updated.before.saved.id -cne $receipt.imported_profile_id -or $updated.updated.digest -ceq $imported.imported.digest -or
    @($updated.requirements).Count -ne 2 -or $updated.release_accepted) {
    throw 'The update did not replace the document of the imported subscription'
}
$deleted = (Invoke-GuiScenario 'subscription-delete') | ConvertFrom-Json
$deleted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'subscription-delete.json') -Encoding utf8NoBOM
# The vault keeps the passwords of both documents until the cleanup, so
# it offers exactly the references imported and those of the update.
$expected = (@($imported.requirements) + @($updated.requirements) | ForEach-Object { $_.id } | Sort-Object) -join ','
$offered = (@($deleted.references) | Sort-Object) -join ','
$remaining = @($deleted.deleted.profiles)
if ($deleted.before.saved.id -cne $receipt.imported_profile_id -or $deleted.kept -cne $receipt.kept_profile_id -or
    $remaining.Count -ne 1 -or $remaining[0].id -cne $receipt.kept_profile_id -or -not $remaining[0].active -or
    $offered -cne $expected -or $deleted.release_accepted) {
    throw 'The subscription profile and the credentials it left were not removed through the GUI'
}
$receipt.profile_deleted = $true
$receipt.subscription_exercised = $true
$receipt.network_mode_exercised = $true
