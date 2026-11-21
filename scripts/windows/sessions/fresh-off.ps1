# The fresh-off session of run_installed_gui_session.ps1, which dot-sources this
# file between its startup check and Quit: the steps run in the runner's scope.
#
# Every page, the startup registration and the Settings controls of an
# installation without a profile. No network mode is started.
$result = Invoke-Playwright 'pages' @('--raw', 'run-code', "--filename=$pagesScript")
$pages = $result | ConvertFrom-Json
if ($pages.pages.Count -ne 9 -or -not $pages.native_gui_exercised) { throw 'Incomplete installed GUI page receipt' }
$pages | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'pages.json') -Encoding utf8NoBOM
$receipt.page_count = $pages.pages.Count
$receipt.native_gui_exercised = $true
$startup = (Invoke-GuiScenario 'startup-registration') | ConvertFrom-Json
$startup | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'startup-registration.json') -Encoding utf8NoBOM
if (-not $startup.startup_registration_exercised -or $startup.actual_sign_in_exercised -or $startup.release_accepted) {
    throw 'The installed GUI did not verify its startup registration transaction'
}
$receipt.startup_registration_exercised = $true
$controls = (Invoke-GuiScenario 'settings-controls') | ConvertFrom-Json
$controls | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $outputRoot 'settings-controls.json') -Encoding utf8NoBOM
if (-not $controls.settings_controls_exercised -or $controls.languages.Count -ne 3 -or
    $controls.engine.Count -ne 2 -or $controls.scroll.Count -ne 10 -or $controls.release_accepted) {
    throw 'The installed GUI did not keep its display language, update interval, leak protection switches and scroll position'
}
$receipt.settings_controls_exercised = $true
