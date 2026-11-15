// Settings that arrived after the first Windows build, driven through their
// visible controls on the installed application: the display language, the
// automatic subscription update interval, and the two leak protection switches
// of the engine. Each change redraws the page, so the same steps show that a
// scrolled Settings page stays where it was. IPC only observes, and every
// preference returns to its first value.
(async (page, observeNative) => {
  const tunnel = 'Wintun adapter created and routed by the Windows authority service';
  const languageControl = 'select[data-language-setting]';
  const intervalControl = 'select[data-subscription-update-interval]';
  // Kana or Han: what a translated sentence holds in each bundled language.
  const translated = /[\u3040-\u30ff\u3400-\u9fff]/u;
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('#nav button[data-page="settings"][aria-current="page"]').waitFor();
  const shown = () => page.evaluate(() => {
    const text = node => node.textContent.trim();
    const group = [...document.querySelectorAll('section.settings-group')]
      .find(section => text(section.querySelector('h3')) === 'Windows');
    if (!group) throw new Error('The Settings page shows no Windows group');
    return {
      language: document.documentElement.lang,
      title: text(document.querySelector('#page-title')),
      navigation: [...document.querySelectorAll('#nav button[data-page] b')].map(text),
      windows: [...group.querySelectorAll('.setting-row')].map(row => ({
        label: text(row.querySelector('b')), value: text(row.querySelector('strong')),
      })),
    };
  });
  // The architecture of the build is a value; everything else is a sentence
  // or a label of the display language.
  const sentences = view => [view.title, ...view.navigation,
    ...view.windows.map(item => item.label), ...view.windows.slice(1).map(item => item.value)];
  // Bring the control into view on a page that is scrolled away from its top.
  const place = async (control) => {
    const placed = await page.evaluate((query) => {
      const layout = document.querySelector('.settings-layout');
      const field = document.querySelector(query);
      if (!layout || !field || field.disabled) throw new Error(`Settings control is unavailable: ${query}`);
      const room = layout.scrollHeight - layout.clientHeight;
      const offset = field.getBoundingClientRect().top - layout.getBoundingClientRect().top + layout.scrollTop;
      layout.scrollTop = Math.min(room, Math.max(8, Math.round(offset - layout.clientHeight / 2)));
      // Using a control that is out of view would scroll the page by itself.
      const box = layout.getBoundingClientRect();
      const rect = field.getBoundingClientRect();
      return { room, top: layout.scrollTop, in_view: rect.top >= box.top && rect.bottom <= box.bottom };
    }, control);
    if (placed.room < 8 || placed.top < 4 || !placed.in_view) {
      throw new Error(`The Settings page does not scroll ${control} into view: ${JSON.stringify(placed)}`);
    }
    return placed;
  };
  // Use the control, and wait until the page that held it has been replaced.
  const through = async (control, use) => {
    const placed = await place(control);
    const replaced = await page.locator(control).elementHandle();
    await use();
    await page.waitForFunction(node => !node.isConnected, replaced, { timeout: 15000 });
    return placed;
  };
  const change = (control, value) => through(control, () => page.locator(control).selectOption(value));
  const kept = (name, placed, seen) => {
    if (Math.abs(seen.scroll_top - placed.top) > 1) {
      throw new Error(`${name} moved the scrolled Settings page from ${placed.top} to ${seen.scroll_top}`);
    }
    return { change: name, before: placed.top, after: seen.scroll_top };
  };
  const chooseLanguage = async (language, locale) => {
    const placed = await change(languageControl, language);
    const seen = await observeNative(page, async ({ expected, shownAs, control }) => {
      const snapshot = await window.__TAURI_INTERNALS__.invoke('read_settings_snapshot');
      const field = document.querySelector(control);
      if (snapshot.settings.language !== expected || snapshot.persisted !== true ||
          document.documentElement.lang !== shownAs || !field || field.disabled || field.value !== expected) return false;
      return { snapshot, scroll_top: document.querySelector('.settings-layout').scrollTop };
    }, { expected: language, shownAs: locale, control: languageControl },
    { name: `display language ${language}`, timeoutMs: 15000 });
    return { seen, scroll: kept(`display language ${language}`, placed, seen), view: await shown() };
  };
  const chooseInterval = async (interval) => {
    const placed = await change(intervalControl, interval);
    const seen = await observeNative(page, async ({ expected, control }) => {
      const report = await window.__TAURI_INTERNALS__.invoke('subscription_updates');
      const field = document.querySelector(control);
      if (report.interval !== expected || !field || field.disabled || field.value !== expected) return false;
      if (!Array.isArray(report.profiles) || report.profiles.length !== 0) {
        throw new Error(`An installation without profiles reports subscription updates: ${JSON.stringify(report)}`);
      }
      return { report, scroll_top: document.querySelector('.settings-layout').scrollTop };
    }, { expected: interval, control: intervalControl },
    { name: `subscription update interval ${interval}`, timeoutMs: 15000 });
    return { seen, scroll: kept(`subscription update interval ${interval}`, placed, seen) };
  };
  const flip = async (toggle, field, enabled) => {
    const control = `[data-toggle="${toggle}"]`;
    const name = `${toggle} ${enabled ? 'on' : 'off'}`;
    const placed = await through(control, () =>
      page.locator('label.toggle-row').filter({ has: page.locator(control) }).click());
    const seen = await observeNative(page, async ({ expected, key, query }) => {
      const snapshot = await window.__TAURI_INTERNALS__.invoke('read_runtime_settings_snapshot');
      const input = document.querySelector(query);
      if (snapshot.effective[key] !== expected || !input || input.disabled || input.checked !== expected) return false;
      return { effective: snapshot.effective, scroll_top: document.querySelector('.settings-layout').scrollTop };
    }, { expected: enabled, key: field, query: control }, { name, timeoutMs: 15000 });
    return { seen, scroll: kept(name, placed, seen) };
  };

  const first = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { settings: await invoke('read_settings_snapshot'), updates: await invoke('subscription_updates'),
      runtime: await invoke('read_runtime_settings_snapshot') };
  });
  const english = await shown();
  if (english.language !== 'en' || english.navigation.length !== 9 || english.windows.length !== 5 ||
      english.windows[0].label !== 'Architecture' || english.windows[4].label !== 'Tunnel' ||
      english.windows[4].value !== tunnel || first.updates.interval !== 'off' ||
      !Array.isArray(first.updates.profiles) || first.updates.profiles.length !== 0 ||
      first.runtime.effective.dns_leak_protection !== false || first.runtime.effective.webrtc_leak_protection !== false) {
    throw new Error(`Settings did not begin in English with the newer options off: ${JSON.stringify({ english, first })}`);
  }
  const scroll = [];
  const languages = [];
  for (const language of ['zh-Hans', 'zh-Hant', 'ja']) {
    const chosen = await chooseLanguage(language, language);
    const original = sentences(english);
    const now = sentences(chosen.view);
    if (now.length !== original.length || now.some((text, index) => text === original[index] || !translated.test(text))) {
      throw new Error(`Settings kept English text in ${language}: ${JSON.stringify(chosen.view)}`);
    }
    await page.screenshot({ path: `settings-${language}.png` });
    scroll.push(chosen.scroll);
    languages.push({ language, view: chosen.view });
  }
  const restored = await chooseLanguage(first.settings.settings.language, 'en');
  if (JSON.stringify(restored.view) !== JSON.stringify(english)) {
    throw new Error(`Settings did not return to English: ${JSON.stringify(restored.view)}`);
  }
  for (const [key, value] of Object.entries(first.settings.settings)) {
    if (restored.seen.snapshot.settings[key] !== value) throw new Error(`The display language changed preference ${key}`);
  }
  scroll.push(restored.scroll);
  const daily = await chooseInterval('daily');
  await page.screenshot({ path: 'settings-subscription-updates-daily.png' });
  const off = await chooseInterval('off');
  scroll.push(daily.scroll, off.scroll);
  const engine = [];
  for (const [toggle, field] of [['dnsLeakProtection', 'dns_leak_protection'], ['webrtcLeakProtection', 'webrtc_leak_protection']]) {
    const on = await flip(toggle, field, true);
    const other = field === 'dns_leak_protection' ? 'webrtc_leak_protection' : 'dns_leak_protection';
    if (on.seen.effective[other] !== false) throw new Error(`${toggle} also changed ${other}`);
    await page.screenshot({ path: `settings-${toggle}-on.png` });
    const back = await flip(toggle, field, false);
    scroll.push(on.scroll, back.scroll);
    engine.push({ toggle, on: on.seen.effective, off: back.seen.effective });
  }
  const last = await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('read_runtime_settings_snapshot'));
  if (JSON.stringify(last.effective) !== JSON.stringify(first.runtime.effective)) {
    throw new Error(`The engine switches left other runtime settings: ${JSON.stringify(last.effective)}`);
  }
  return { first, english, languages, restored: restored.seen.snapshot, daily: daily.seen.report, off: off.seen.report, engine, scroll,
    snapshot: await page.locator('body').ariaSnapshot(),
    mutations: ['language:zh-Hans', 'language:zh-Hant', 'language:ja', `language:${first.settings.settings.language}`,
      'subscriptionUpdates:daily', 'subscriptionUpdates:off', 'dnsLeakProtection:on', 'dnsLeakProtection:off',
      'webrtcLeakProtection:on', 'webrtcLeakProtection:off'],
    settings_controls_exercised: true, release_accepted: false };
})
