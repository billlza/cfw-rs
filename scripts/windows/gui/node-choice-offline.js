// Import a profile of two remote nodes and no group, then choose its second
// node while the core is off. The core puts the app's own selector in front of
// such a profile; the Proxies page offers that selector from the saved profile
// and saves the choice for the next start. Nothing in this session dials the
// nodes. All mutations go through visible controls; IPC only observes.
(async (page, observeNative) => {
  const selector = 'cfw-proxy-selector';
  const profileDocument = { outbounds: [
    { type: 'socks5', tag: 'first', server: 'first.example.com', server_port: 1080 },
    { type: 'socks5', tag: 'second', server: 'second.example.com', server_port: 1080 },
  ] };
  await page.locator('#nav button[data-page="general"][aria-current="page"]').waitFor();
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { boot: await invoke('boot_payload'), engine: await invoke('engine_snapshot'), profiles: await invoke('profiles_snapshot') };
  });
  if (before.boot.product.operating_system !== 'windows' || before.engine.unavailable_reason !== null ||
      before.engine.snapshot.state.state !== 'off' || before.engine.snapshot.desired_mode !== 'off' ||
      before.engine.capabilities.local_proxy !== true ||
      before.profiles.profiles.length !== 0 || before.profiles.invalid_profiles.length !== 0) {
    throw new Error(`The node choice case did not begin with an empty, stopped installation: ${JSON.stringify(before)}`);
  }
  await page.locator('#nav button[data-page="profiles"]').click();
  await page.locator('[data-profile-url]').fill(JSON.stringify(profileDocument));
  await page.locator('[data-action="import-profile"]').click();
  const selected = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length > 1) throw new Error('GUI import produced unexpected profiles');
    return value.profiles.length === 1 && value.profiles[0].active ? value : false;
  }, undefined, { name: 'node profile import', timeoutMs: 15000 });
  const credentials = page.getByRole('dialog', { name: 'Profile credentials', exact: true });
  await credentials.getByText('This profile references no credentials.', { exact: true }).waitFor({ timeout: 15000 });
  await credentials.locator('button[data-glass-dismiss]').click();
  await credentials.waitFor({ state: 'hidden' });
  const id = selected.profiles[0].id;
  const imported = await page.evaluate(id => window.__TAURI_INTERNALS__.invoke('read_profile_text', { id }), id);
  const offered = imported.app_selector;
  if (offered?.tag !== selector || JSON.stringify(offered.members) !== '["first","second"]' || offered.default !== 'first' ||
      Object.keys(imported.proxy_selections).length !== 0) {
    throw new Error(`The profile without a group did not offer the app's selector: ${JSON.stringify({ offered, selections: imported.proxy_selections })}`);
  }
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator(`button.cfw-node-card.selected[data-group="${selector}"][data-node="first"]:enabled`).waitFor({ timeout: 15000 });
  await page.locator(`button.cfw-node-card[data-group="${selector}"][data-node="second"]`).click();
  // The page saves the choice, reads the profile back and shows it again.
  const saved = await observeNative(page, async ({ id, selector }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('read_profile_text', { id });
    const choice = value.proxy_selections[selector];
    if (choice === undefined) return false;
    if (choice !== 'second') throw new Error(`The offline choice saved ${choice}`);
    const shown = document.querySelector(`button.cfw-node-card.selected[data-group="${selector}"]`);
    return shown?.dataset.node === 'second' && !shown.disabled ? value : false;
  }, { id, selector }, { name: 'offline node choice', timeoutMs: 15000 });
  // The choice is kept beside the profile; the document and its digest stay.
  if (saved.body !== imported.body || saved.digest !== imported.digest || Object.keys(saved.proxy_selections).length !== 1) {
    throw new Error('Saving the offline choice changed the profile document');
  }
  const after = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (after.snapshot.state.state !== 'off' || after.snapshot.desired_mode !== 'off') throw new Error('The offline choice started the core');
  await page.screenshot({ path: 'node-choice-offline.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="general"]').click();
  await page.locator('[data-action="toggle-core"]').filter({ hasText: 'Start core' }).waitFor();
  return { before, selected, imported, saved, snapshot,
    mutations: ['import-profile', 'select-node:second'], release_accepted: false };
})
