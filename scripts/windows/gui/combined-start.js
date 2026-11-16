// With TUN Mode on, turn System Proxy on through its visible switch. The
// coordinator retires the Tunnel run and starts one run that owns both:
// SYSTEM routes its adapter again and this user's proxy options name the
// run's own listener.
(async (page, observeNative, _scenario, _quitInput, observeController) => {
  await page.locator('#nav button[data-page="general"]').click();
  const before = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (before.unavailable_reason !== null || before.capabilities.tunnel_system_proxy !== true ||
      before.snapshot.state.state !== 'tunnel_active' || before.snapshot.desired_mode !== 'tunnel' ||
      before.snapshot.state.runtime.ready !== true ||
      before.snapshot.state.runtime.owner !== 'windows_tunnel_service') {
    throw new Error(`The GUI's verified TUN runtime is no longer active: ${JSON.stringify(before)}`);
  }
  const control = page.locator('label.inline-switch').filter({ has: page.locator('[data-toggle="systemProxy"]') });
  await control.click();
  // The observation runs inside the page, so the started generation is
  // passed in rather than captured.
  const active = await observeNative(page, async (startedGeneration) => {
    const value = await window.__TAURI_INTERNALS__.invoke('engine_snapshot');
    if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
    const state = value.snapshot.state.state;
    if (state === 'tunnel_system_proxy_active') {
      if (value.snapshot.desired_mode !== 'tunnel_system_proxy' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_tunnel_service' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest ||
          value.snapshot.generation <= startedGeneration) {
        throw new Error('The combined mode did not start a newer ready Windows tunnel runtime');
      }
      return value;
    }
    // The coordinator publishes Off between retiring TUN and starting both.
    if (!['tunnel_active', 'tunnel_stopping', 'off', 'tunnel_installing', 'tunnel_starting'].includes(state)) {
      throw new Error(`Unexpected combined start result: ${JSON.stringify(value)}`);
    }
    return false;
  }, before.snapshot.generation, { name: 'combined start', timeoutMs: 75000 });
  await observeNative(page, () => {
    const proxy = document.querySelector('[data-toggle="systemProxy"]');
    const tunnel = document.querySelector('[data-toggle="tunMode"]');
    return proxy && tunnel && !proxy.disabled && proxy.checked && !tunnel.disabled && tunnel.checked
      ? { system_proxy_on: true, tunnel_on: true } : false;
  }, undefined, { name: 'both switches on', timeoutMs: 15000 });
  const settings = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('read_runtime_settings_snapshot'));
  if (!Number.isInteger(settings.effective.mixed_port) || settings.effective.mixed_port < 1 || settings.effective.mixed_port > 65535) {
    throw new Error('The active GUI did not report a valid proxy listener for the combined mode');
  }
  const controllerProof = await observeController(page, active, 'combined');
  await page.screenshot({ path: 'combined-active.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, active, settings, snapshot, ...controllerProof, mutations: ['systemProxy:on'], release_accepted: false };
})
