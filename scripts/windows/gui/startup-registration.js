// Exercise the real ordinary-user startup preference transaction. Registration
// is observed independently of the checkbox; this does not simulate sign-in.
(async (page) => {
  await page.locator('#nav button[data-page="settings"]').click();
  const observe = async (enabled) => {
    const handle = await page.waitForFunction(async (expected) => {
      const snapshot = await window.__TAURI_INTERNALS__.invoke('read_settings_snapshot');
      const status = snapshot.launch_at_login;
      if (!['registered', 'not_registered'].includes(status.live_status)) {
        throw new Error(`Unexpected native Windows startup state: ${JSON.stringify(snapshot)}`);
      }
      const input = document.querySelector('[data-toggle="startAtLogin"]');
      const registered = status.live_status === 'registered';
      if (registered !== expected || status.persisted_intent !== expected ||
          snapshot.settings.launch_at_login !== expected || status.matches_persisted_intent !== true ||
          !input || input.disabled || input.checked !== expected) return false;
      const hint = input.closest('label').querySelector('small').textContent;
      if (!hint.includes(expected ? 'registration does not confirm launch' : 'No startup registration for this user')) return false;
      return { snapshot, hint };
    }, enabled, { timeout: 15000, polling: 300 });
    try { return await handle.jsonValue(); } finally { await handle.dispose(); }
  };
  const initial = await observe(false);
  const control = page.locator('label.toggle-row').filter({ has: page.locator('[data-toggle="startAtLogin"]') });
  await control.click();
  const registered = await observe(true);
  await page.screenshot({ path: 'startup-registered.png' });
  await control.click();
  const restored = await observe(false);
  for (const [key, value] of Object.entries(initial.snapshot.settings)) {
    if (restored.snapshot.settings[key] !== value ||
        registered.snapshot.settings[key] !== (key === 'launch_at_login' ? true : value)) {
      throw new Error(`Startup registration unexpectedly changed preference ${key}`);
    }
  }
  if (registered.snapshot.persisted !== true || restored.snapshot.persisted !== true) {
    throw new Error('Startup registration did not persist its requested preference');
  }
  await page.screenshot({ path: 'startup-restored.png' });
  return { initial, registered, restored, snapshot: await page.locator('body').ariaSnapshot(),
    mutations: ['startAtLogin:on', 'startAtLogin:off'], startup_registration_exercised: true,
    actual_sign_in_exercised: false, release_accepted: false };
})
