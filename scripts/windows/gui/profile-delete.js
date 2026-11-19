// After the core has stopped, the Proxies page shows the choice made on the
// running core as the saved one. The node profile is still selected, and the
// repository refuses to delete the selected profile, so its Delete is disabled
// with the reason. The LocalProxy session's profile is selected again by
// clicking its card, and the node profile is then deleted through its context
// menu and confirmation dialog, so the next session begins with the LocalProxy
// profile alone, as it did before this one.
(async (page, observeNative) => {
  const selector = 'cfw-proxy-selector';
  const refusal = 'Select another profile before deleting this one.';
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const profiles = await invoke('profiles_snapshot');
    const id = profiles.profiles.find(profile => profile.active)?.id ?? null;
    return { engine: await invoke('engine_snapshot'), profiles, saved: id === null ? null : await invoke('read_profile_text', { id }) };
  });
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 2 || before.profiles.profiles.filter(profile => profile.active).length !== 1 ||
      before.saved?.proxy_selections[selector] !== 'first') {
    throw new Error(`The stopped node choice case did not keep the online choice: ${JSON.stringify(before)}`);
  }
  const id = before.saved.id;
  const kept = before.profiles.profiles.find(profile => profile.id !== id).id;
  await page.locator('#nav button[data-page="proxies"]').click();
  await page.locator(`button.cfw-node-card.selected[data-group="${selector}"][data-node="first"]:enabled`).waitFor({ timeout: 15000 });
  await page.screenshot({ path: 'node-choice-saved.png' });
  await page.locator('#nav button[data-page="profiles"]').click();
  await page.locator(`[data-profile-card="${id}"]`).click({ button: 'right' });
  const offered = page.locator(`[data-profile-menu="delete"][data-profile-id="${id}"]`);
  await offered.waitFor();
  const refused = { disabled: await offered.isDisabled(), title: await offered.getAttribute('title') };
  if (!refused.disabled || refused.title !== refusal) {
    throw new Error(`Delete was offered on the selected profile: ${JSON.stringify(refused)}`);
  }
  await page.keyboard.press('Escape');
  await page.locator('.glass-menu').waitFor({ state: 'detached' });
  await page.locator(`[data-profile-card="${kept}"] h3`).click();
  const reselected = await observeNative(page, async ({ id, kept }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length !== 2 || !value.profiles.some(profile => profile.id === id)) {
      throw new Error('Selecting a profile changed the profiles');
    }
    const active = value.profiles.filter(profile => profile.active);
    return active.length === 1 && active[0].id === kept ? value : false;
  }, { id, kept }, { name: 'LocalProxy profile selection', timeoutMs: 15000 });
  await page.locator(`[data-profile-card="${id}"]`).click({ button: 'right' });
  await page.locator(`[data-profile-menu="delete"][data-profile-id="${id}"]:enabled`).click();
  const dialog = page.getByRole('dialog', { name: 'Delete profile', exact: true });
  await dialog.locator(`[data-glass-delete-confirm="${id}"]`).click();
  await dialog.waitFor({ state: 'hidden' });
  const deleted = await observeNative(page, async ({ id, kept }) => {
    const value = await window.__TAURI_INTERNALS__.invoke('profiles_snapshot');
    if (value.invalid_profiles.length || value.profiles.length > 2) throw new Error('Profile deletion left unexpected profiles');
    if (value.profiles.length === 2 && value.profiles.some(profile => profile.id === id)) return false;
    if (value.profiles.length !== 1 || value.profiles[0].id !== kept || value.profiles[0].active !== true) {
      throw new Error(`Deleting the node profile changed the LocalProxy profile: ${JSON.stringify(value)}`);
    }
    return value;
  }, { id, kept }, { name: 'profile deletion', timeoutMs: 15000 });
  await page.locator(`[data-profile-card="${id}"]`).waitFor({ state: 'detached' });
  const after = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (after.snapshot.state.state !== 'off' || after.snapshot.desired_mode !== 'off') throw new Error('Deleting the profile changed the stopped core');
  await page.screenshot({ path: 'node-choice-deleted.png' });
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { before, kept, refused, reselected, deleted, snapshot,
    mutations: ['select-profile', 'delete-profile'], release_accepted: false };
})
