# The node-choice session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# Beside the LocalProxy session's profile, a profile of two remote nodes and
# no group: one choice saved while the core is off, one made on the running
# core. The repository refuses to delete the selected profile, so the
# LocalProxy profile is selected again before the node profile is deleted,
# and the next session begins as this one did.
$offline = (Invoke-GuiScenario 'node-choice-offline') | ConvertFrom-Json
$offline | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'node-choice-offline.json') -Encoding utf8NoBOM
if ($offline.release_accepted -or $offline.profile -ceq $offline.kept) { throw 'The offline node choice receipt is invalid' }
$receipt.native_gui_exercised = $true
$receipt.imported_profile_id = $offline.profile
$receipt.kept_profile_id = $offline.kept
$online = (Invoke-GuiScenario 'node-choice-online') | ConvertFrom-Json
$online | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'node-choice-online.json') -Encoding utf8NoBOM
if ($online.before.saved.id -cne $receipt.imported_profile_id -or $online.release_accepted) {
    throw 'The node choice core did not start the profile chosen while it was off'
}
$receipt.active_runtime = $online.active.snapshot.state.runtime
$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$chosenIdentity = $online.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($chosenIdentity -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the core that carried both node choices'
}
$receipt.engine_stopped = $true
$receipt.node_choice_exercised = $true
$receipt.network_mode_exercised = $true
$deleted = (Invoke-GuiScenario 'profile-delete') | ConvertFrom-Json
$deleted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'profile-delete.json') -Encoding utf8NoBOM
$remaining = @($deleted.deleted.profiles)
if ($deleted.before.saved.id -cne $receipt.imported_profile_id -or $deleted.kept -cne $receipt.kept_profile_id -or
    -not $deleted.refused.disabled -or $remaining.Count -ne 1 -or $remaining[0].id -cne $receipt.kept_profile_id -or
    -not $remaining[0].active -or $deleted.release_accepted) {
    throw 'The node choice profile was not deleted through the GUI once the LocalProxy profile was selected again'
}
$receipt.profile_deleted = $true
