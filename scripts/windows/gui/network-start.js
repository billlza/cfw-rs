// All mutations go through visible controls. IPC below only observes the real
// installed application; the imported direct profile contains no credentials.
(async (page) => {
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  });
  if (before.boot.product.operating_system !== 'windows' || before.boot.product.name !== 'Clash for Windows' ||
      before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.engine.capabilities.local_proxy !== true ||
      before.profiles.profiles.length !== 0 || before.profiles.invalid_profiles.length !== 0) {
    throw new Error(`GUI network case did not begin with an empty, stopped installation: ${JSON.stringify(before)}`);
  }
  await page.locator('#nav button[data-page="profiles"]').click();
  await page.locator('[data-profile-url]').fill('{"outbounds":[{"type":"direct","tag":"direct"}]}');
  await page.locator('[data-action="import-profile"]').click();
  const selectedHandle = await page.waitForFunction(async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length > 1) throw new Error('GUI import produced unexpected profiles');
    return value.profiles.length === 1 && value.profiles[0].active ? value : false;
  }, undefined, { timeout: 15000, polling: 250 });
  let selected;
  try { selected = await selectedHandle.jsonValue(); } finally { await selectedHandle.dispose(); }
  const credentials = page.getByRole('dialog', { name: 'Profile credentials', exact: true });
  await credentials.getByText('This profile references no credentials.', { exact: true }).waitFor({ timeout: 15000 });
  await credentials.locator('button[data-glass-dismiss]').click();
  await credentials.waitFor({ state: 'hidden' });
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).click();
  const activeHandle = await page.waitForFunction(async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'local_proxy_active') {
      if (value.snapshot.desired_mode !== 'local_proxy' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
        throw new Error('LocalProxy activation did not carry the ready runtime identity');
      }
      return value;
    }
    if (!['off', 'local_proxy_starting'].includes(state)) throw new Error(`Unexpected start result: ${JSON.stringify(value)}`);
    return false;
  }, undefined, { timeout: 30000, polling: 250 });
  let active;
  try { active = await activeHandle.jsonValue(); } finally { await activeHandle.dispose(); }
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  const settings = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('read_runtime_settings_snapshot'));
  if (!Number.isInteger(settings.effective.mixed_port) || settings.effective.mixed_port < 1 || settings.effective.mixed_port > 65535) {
    throw new Error('The active GUI did not report a valid local proxy listener');
  }
  await page.screenshot({ path: 'local-proxy-active.png' });
  return { before, selected, active, settings, snapshot: await page.locator('body').ariaSnapshot(),
    mutations: ['import-profile', 'toggle-core'], release_accepted: false };
})
