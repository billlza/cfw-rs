# The automation session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# A global shortcut and a network rule entered in Settings, with the
# LocalProxy profile alone. The rule starts the core on the runner's wired
# network. Each press of the shortcut is real keyboard input: the first
# stops that core, the second starts another, and the third, after the
# shortcut is removed, changes nothing. Nothing in this session presses
# Start; the last core is stopped through the GUI.
$ruled = (Invoke-GuiScenario 'automation-rule') | ConvertFrom-Json
$ruled | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'automation-rule.json') -Encoding utf8NoBOM
if (-not $ruled.core_started_by_network_rule -or $ruled.release_accepted) { throw 'The network rule receipt is invalid' }
$receipt.native_gui_exercised = $true
$receipt.kept_profile_id = $ruled.before.profiles.profiles[0].id
$receipt.active_runtime = $ruled.active.snapshot.state.runtime
Invoke-NativeShortcutProbe 'shortcut-stop' $launch | Out-Null
$halted = (Invoke-GuiScenario 'automation-shortcut-stop') | ConvertFrom-Json
$halted | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'automation-shortcut-stop.json') -Encoding utf8NoBOM
if (-not $halted.core_stopped_by_shortcut -or -not $halted.network_rule_left_core_stopped -or
    $halted.held.milliseconds -lt 12000 -or $halted.held.looks -lt 12 -or $halted.release_accepted) {
    throw 'The shortcut did not stop the core the network rule started, or the rule started it again'
}
Invoke-NativeShortcutProbe 'shortcut-start' $launch | Out-Null
$resumed = (Invoke-GuiScenario 'automation-shortcut-start') | ConvertFrom-Json
$resumed | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'automation-shortcut-start.json') -Encoding utf8NoBOM
$ruleRuntime = $ruled.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
$shortcutRuntime = $resumed.active.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if (-not $resumed.core_started_by_shortcut -or -not $resumed.refusal_names_platform_keys -or
    $ruleRuntime -ceq $shortcutRuntime -or $resumed.active.snapshot.generation -le $ruled.active.snapshot.generation -or
    $resumed.release_accepted) {
    throw 'The shortcut did not start a core of its own after the core of the rule had stopped, or the refusal did not name the Windows keys'
}
Invoke-NativeShortcutProbe 'shortcut-removed' $launch | Out-Null
$ignored = (Invoke-GuiScenario 'automation-shortcut-removed') | ConvertFrom-Json
$ignored | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'automation-shortcut-removed.json') -Encoding utf8NoBOM
if (-not $ignored.removed_shortcut_ignored -or $ignored.held.milliseconds -lt 6000 -or $ignored.held.looks -lt 6 -or
    ($ignored.held.last.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress) -cne $shortcutRuntime -or
    $ignored.release_accepted) {
    throw 'The removed shortcut still changed the core'
}
$stopped = (Invoke-GuiScenario 'network-stop') | ConvertFrom-Json
$stopped | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'network-stop.json') -Encoding utf8NoBOM
$stoppedIdentity = $stopped.before.snapshot.state.runtime | ConvertTo-Json -Depth 20 -Compress
if ($shortcutRuntime -cne $stoppedIdentity -or $stopped.stopped.snapshot.state.state -cne 'off' -or
    $stopped.stopped.snapshot.desired_mode -cne 'off') {
    throw 'GUI stop did not retire the core the shortcut started'
}
$receipt.engine_stopped = $true
$receipt.automation_exercised = $true
$receipt.network_mode_exercised = $true
