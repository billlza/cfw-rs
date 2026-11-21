// Delete the subscription profile and the credentials it leaves behind. The
// repository refuses to delete the selected profile, so the LocalProxy
// session's profile is selected again first, and the next session begins as
// this one did. The deleted profile's passwords stay in Windows protected
// storage, those of the imported document as well as those of the update,
// until Settings > Credentials > Unused credentials removes them; the session
// compares the references offered with the ones it imported and updated.
// Afterwards the vault holds no unused credentials. All mutations go through
// visible controls; IPC only observes.
(async (page, observeNative) => {
  const offered = count => `Unused protected credentials: ${count}. Cleanup revalidates the repository snapshot and the vault revision before one atomic deletion.`;
  const reference = /^Shadowsocks Password \u00b7 ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/u;
  // A refusal opens another dialog; whatever opens is read and shown.
  const review = async () => {
    await page.locator('[data-action="preview-credential-gc"]:enabled').click();
    return observeNative(page, () => {
      const dialog = document.querySelector('.glass-dialog[role="dialog"]');
      return dialog ? { label: dialog.getAttribute('aria-label'), copy: dialog.querySelector('.glass-dialog-copy')?.textContent ?? null,
        items: [...dialog.querySelectorAll('.glass-list li')].map(item => item.textContent),
        confirm: dialog.querySelector('[data-glass-credential-gc-confirm]') !== null } : false;
    }, undefined, { name: 'credential cleanup review', timeoutMs: 15000 });
  };
  const before = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const profiles = await invoke('profiles_snapshot');
    const id = profiles.profiles.find(profile => profile.active)?.id ?? null;
    return { engine: await invoke('engine_snapshot'), profiles, saved: id === null ? null : await invoke('read_profile_text', { id }) };
  });
  if (before.engine.unavailable_reason !== null || before.engine.snapshot.state.state !== 'off' ||
      before.engine.snapshot.desired_mode !== 'off' || before.profiles.invalid_profiles.length !== 0 ||
      before.profiles.profiles.length !== 2 || before.profiles.profiles.filter(profile => profile.active).length !== 1 ||
      typeof before.saved?.source_url !== 'string') {
    throw new Error(`The stopped subscription case did not keep its updated profile selected: ${JSON.stringify(before)}`);
  }
  const id = before.saved.id;
  const kept = before.profiles.profiles.find(profile => profile.id !== id).id;
  await page.locator('#nav button[data-page="profiles"]').click();
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
      throw new Error(`Deleting the subscription profile changed the LocalProxy profile: ${JSON.stringify(value)}`);
    }
    return value;
  }, { id, kept }, { name: 'profile deletion', timeoutMs: 15000 });
  await page.locator(`[data-profile-card="${id}"]`).waitFor({ state: 'detached' });
  await page.locator('#nav button[data-page="settings"]').click();
  const unused = await review();
  const references = unused.items.map(item => reference.exec(item)?.[1] ?? null);
  if (unused.label !== 'Credential cleanup' || unused.items.length < 1 || unused.items.length > 12 ||
      unused.copy !== offered(unused.items.length) || references.includes(null) || !unused.confirm) {
    throw new Error(`The deleted profile's credentials were not offered for cleanup: ${JSON.stringify(unused)}`);
  }
  const cleanup = page.getByRole('dialog', { name: 'Credential cleanup', exact: true });
  await cleanup.locator('[data-glass-credential-gc-confirm]').click();
  await cleanup.waitFor({ state: 'hidden' });
  // The cleanup ran: a new review finds nothing.
  const emptied = await review();
  if (emptied.label !== 'Credential cleanup' || emptied.copy !== 'The credential vault has no unused references.' ||
      emptied.items.length !== 0 || emptied.confirm) {
    throw new Error(`The cleanup left unused credentials: ${JSON.stringify(emptied)}`);
  }
  await page.screenshot({ path: 'subscription-cleaned.png' });
  await cleanup.locator('[data-glass-credential-gc-cancel]').click();
  await cleanup.waitFor({ state: 'hidden' });
  const after = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('engine_snapshot'));
  if (after.snapshot.state.state !== 'off' || after.snapshot.desired_mode !== 'off') throw new Error('The cleanup changed the stopped core');
  const snapshot = await page.locator('body').ariaSnapshot();
  await page.locator('[data-action="quit-app"]').waitFor();
  return { before, kept, reselected, deleted, unused, references, emptied, snapshot,
    mutations: ['select-profile', 'delete-profile', 'delete-unused-credentials'], release_accepted: false };
})
