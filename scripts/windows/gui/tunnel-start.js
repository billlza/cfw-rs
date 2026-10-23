// Reopen the previously imported profile and turn TUN Mode on through its
// visible switch. SYSTEM creates and routes the tunnel adapter for the
// UserAgent's engine; the combined mode stays refused with its own reason.
(async (page, observeNative, _scenario, _quitInput, observeController) => {
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  });
  const capabilities = before.engine.capabilities;
  if (before.boot.product.operating_system !== 'windows' || before.engine.unavailable_reason !== null ||
      before.engine.snapshot.state.state !== 'off' || before.engine.snapshot.desired_mode !== 'off' ||
      capabilities.tunnel !== true || capabilities.system_proxy !== true || capabilities.tunnel_system_proxy !== false ||
      before.profiles.invalid_profiles.length !== 0 || before.profiles.profiles.length !== 1 ||
      before.profiles.profiles[0].active !== true) {
    throw new Error(`TUN GUI case did not reopen the stopped, imported profile with TUN alone: ${JSON.stringify(before)}`);
  }
  await observeNative(page, () => {
    const input = document.querySelector('[data-toggle="tunMode"]');
    return input && !input.disabled && !input.checked ? { enabled: true, checked: false } : false;
  }, undefined, { name: 'TUN switch readiness', timeoutMs: 15000 });
  const control = page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="tunMode"]') });
  await control.click();
  // The first adapter of a fresh runner also installs the pinned driver.
  const active = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'tunnel_active') {
      if (value.snapshot.desired_mode !== 'tunnel' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_tunnel_service' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
        throw new Error('TUN activation did not carry the ready Windows tunnel runtime identity');
      }
      return value;
    }
    if (!['off', 'tunnel_installing', 'tunnel_starting'].includes(state)) throw new Error(`Unexpected TUN start result: ${JSON.stringify(value)}`);
    return false;
  }, undefined, { name: 'TUN start', timeoutMs: 75000 });
  const reason = 'TUN Mode and System Proxy cannot run together in this Windows build. Turn one off first.';
  const combined = await observeNative(page, (expected) => {
    const input = document.querySelector('[data-toggle="systemProxy"]');
    const note = input?.closest('.cfw-row-right')?.querySelector('.cfw-row-note');
    return input && input.disabled && !input.checked && note?.getAttribute('title') === expected
      ? { system_proxy_disabled: true, reason: expected } : false;
  }, reason, { name: 'combined-mode refusal', timeoutMs: 15000 });
  const controllerProof = await observeController(page, active, 'tunnel');
  await page.screenshot({ path: 'tunnel-active.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, active, combined, snapshot, ...controllerProof, combined_mode_refused: true,
    mutations: ['tunMode:on'], release_accepted: false };
})
