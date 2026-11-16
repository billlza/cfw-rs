// After the core has stopped, the Proxies page shows the choice made on the
// running core as the saved one. The profile is then deleted through its
// context menu and confirmation dialog, so the next session again begins with
// an empty installation.
(async (page, observeNative) => {
  const selector = 'cfw-proxy-selector';
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const profiles = await invoke('profiles_snapshot');
    const id = profiles.profiles.length === 1 ? profiles.profiles[0].id : null;
    return { engine: await invoke('engine_snapshot'), profiles, saved: id === null ? null : await invoke('read_profile_text', { id }) };
  });
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 1 || before.profiles.profiles[0].active !== true ||
      before.saved?.proxy_selections[selector] !== 'first') {
    throw new Error(`The stopped node choice case did not keep the online choice: ${JSON.stringify(before)}`);
  }
  const id = before.saved.id;
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator(`button.cfw-node-card.selected[data-group="${selector}"][data-node="first"]:enabled`).waitFor({ timeout: 15000 });
  await page.screenshot({ path: 'node-choice-saved.png' });
  await page.locator('#nav button[data-page="profiles"]').click();
  await page.locator(`[data-profile-card="${id}"]`).click({ button: 'right' });
  await page.locator(`[data-profile-menu="delete"][data-profile-id="${id}"]:enabled`).click();
  const dialog = page.getByRole('dialog', { name: 'Delete profile', exact: true });
  await dialog.locator(`[data-glass-delete-confirm="${id}"]`).click();
  await dialog.waitFor({ state: 'hidden' });
  const deleted = await observeNative(page, async () => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length > 1) throw new Error('Profile deletion left unexpected profiles');
    return value.profiles.length === 0 ? value : false;
  }, undefined, { name: 'profile deletion', timeoutMs: 15000 });
  await page.locator(`[data-profile-card="${id}"]`).waitFor({ state: 'detached' });
  const after = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (after.snapshot.state.state !== 'off' || after.snapshot.desired_mode !== 'off') throw new Error('Deleting the profile changed the stopped core');
  await page.screenshot({ path: 'node-choice-deleted.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { before, deleted, snapshot, mutations: ['delete-profile'], release_accepted: false };
})
