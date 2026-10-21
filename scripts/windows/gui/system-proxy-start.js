// Reopen the previously imported profile, enable the real Windows user proxy
// through its visible switch, and leave it running for the active Quit case.
(async (page, observeNative, _scenario, _quitInput, observeController) => {
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  });
  if (before.boot.product.operating_system !== 'windows' || before.engine.unavailable_reason !== null ||
      before.engine.snapshot.state.state !== 'off' || before.engine.snapshot.desired_mode !== 'off' ||
      before.engine.capabilities.system_proxy !== true || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 1 || before.profiles.profiles[0].active !== true) {
    throw new Error('SystemProxy GUI case did not reopen the stopped, imported profile');
  }
  await observeNative(page, () => {
    const input = document.querySelector('[data-toggle="systemProxy"]');
    return input && !input.disabled && !input.checked ? { enabled: true, checked: false } : false;
  }, undefined, { name: 'SystemProxy switch readiness', timeoutMs: 15000 });
  const control = page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="systemProxy"]') });
  await control.click();
  const active = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'proxy_active') {
      if (value.snapshot.desired_mode !== 'system_proxy' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_user_agent' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
        throw new Error('SystemProxy activation did not carry the ready Windows runtime identity');
      }
      return value;
    }
    if (!['off', 'proxy_starting'].includes(state)) throw new Error(`Unexpected SystemProxy start result: ${JSON.stringify(value)}`);
    return false;
  }, undefined, { name: 'SystemProxy start', timeoutMs: 30000 });
  const settings = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('read_runtime_settings_snapshot'));
  if (!Number.isInteger(settings.effective.mixed_port) || settings.effective.mixed_port < 1 || settings.effective.mixed_port > 65535) {
    throw new Error('The active GUI did not report a valid SystemProxy listener');
  }
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  const controllerProof = await observeController(page, active, 'system-proxy');
  await page.screenshot({ path: 'system-proxy-active.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { before, active, settings, snapshot, ...controllerProof, mutations: ['systemProxy:on'], release_accepted: false };
})
