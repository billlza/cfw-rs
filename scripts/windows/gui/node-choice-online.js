// Start the core after the offline choice, then choose the other node on the
// running core. The controller's selector starts on the saved choice and
// reports the new one, the profile keeps the new one, and the core that
// carries both is not replaced. Nothing in this session dials the nodes.
(async (page, observeNative) => {
  const selector = 'cfw-proxy-selector';
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const profiles = await invoke('profiles_snapshot');
    const id = profiles.profiles.find(profile => profile.active)?.id ?? null;
    return { engine: await invoke('engine_snapshot'), profiles, saved: id === null ? null : await invoke('read_profile_text', { id }) };
  });
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.engine.capabilities.local_proxy !== true ||
      before.profiles.invalid_profiles.length !== 0 || before.profiles.profiles.length !== 2 ||
      before.profiles.profiles.filter(profile => profile.active).length !== 1 ||
      before.saved?.proxy_selections[selector] !== 'second') {
    throw new Error(`The node choice case did not keep its stopped profile and offline choice: ${JSON.stringify(before)}`);
  }
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).click();
  const active = await observeNative(page, async () => {
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
  }, undefined, { name: 'LocalProxy start with the offline choice', timeoutMs: 30000 });
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  // The product enables these controls only after its own controller snapshot.
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator('button[data-mode="Rule"]:enabled').waitFor({ timeout: 15000 });
  const started = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('controller_snapshot'));
  const group = started.proxies.groups.find(item => item.name === selector);
  if (group?.kind !== 'Selector' || group.now !== 'second' || JSON.stringify(group.options) !== '["first","second"]') {
    throw new Error(`The running core did not start on the saved choice: ${JSON.stringify(started.proxies.groups)}`);
  }
  await page.locator(`button.cfw-node-card.selected[data-group="${selector}"][data-node="second"]:enabled`).waitFor({ timeout: 15000 });
  await page.locator(`button.cfw-node-card[data-group="${selector}"][data-node="first"]`).click();
  // The product sends the choice, confirms it with the controller and saves it.
  const chosen = await observeNative(page, async ({ id, selector }) => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const controller = await invoke('controller_snapshot');
    const now = controller.proxies.groups.find(item => item.name === selector)?.now;
    if (now !== 'first' && now !== 'second') throw new Error(`The controller reported ${now} for the app's selector`);
    const saved = await invoke('read_profile_text', { id });
    const shown = document.querySelector(`button.cfw-node-card.selected[data-group="${selector}"]`);
    return now === 'first' && saved.proxy_selections[selector] === 'first' && shown?.dataset.node === 'first' && !shown.disabled
      ? { controller, saved, engine: await invoke('engine_snapshot') } : false;
  }, { id: before.saved.id, selector }, { name: 'online node choice', timeoutMs: 15000 });
  if (JSON.stringify(chosen.engine.snapshot.state) !== JSON.stringify(active.snapshot.state) ||
      chosen.engine.snapshot.generation !== active.snapshot.generation ||
      chosen.engine.snapshot.config_digest !== active.snapshot.config_digest) {
    throw new Error('Choosing a node on the running core replaced the core');
  }
  if (chosen.saved.body !== before.saved.body || chosen.saved.digest !== before.saved.digest) {
    throw new Error('Saving the online choice changed the profile document');
  }
  await page.screenshot({ path: 'node-choice-online.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Stop core' }).waitFor();
  return { before, active, started, chosen, snapshot,
    mutations: ['toggle-core', 'select-node:first'], release_accepted: false };
})
