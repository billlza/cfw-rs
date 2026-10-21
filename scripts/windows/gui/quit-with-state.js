// Capture the real pre-Quit state, then use the same snapshot-free visible
// click as the independent last-page-close regression.
(async (page, _observeNative, scenario, quitInput) => {
  if (!['fresh-off', 'local-proxy', 'system-proxy-quit'].includes(scenario)) throw new Error('Unknown Quit scenario');
  const before = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  const activeQuit = scenario === 'system-proxy-quit';
  if (before.unavailable_reason !== null || before.snapshot.state.state !== (activeQuit ? 'proxy_active' : 'off') ||
      before.snapshot.desired_mode !== (activeQuit ? 'system_proxy' : 'off') ||
      (activeQuit && (before.snapshot.state.runtime.ready !== true || before.snapshot.state.runtime.owner !== 'windows_user_agent' ||
        before.snapshot.config_digest !== before.snapshot.state.runtime.config_digest))) {
    throw new Error('Quit scenario does not match the observed runtime state');
  }
  const input = await quitInput(page);
  return { before, ...input };
})
