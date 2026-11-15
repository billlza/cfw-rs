// Flip the two leak protection switches of the engine through their visible
// controls while TUN Mode runs. Each flip replaces the running engine with one
// built from the new settings, and the running engine's own rule table shows
// what it refuses afterwards. IPC only observes. The driver names the step:
// both switches on, or both off again.
(async (page, observeNative, _scenario, _quitInput, _observeController, step) => {
  if (step !== 'leak-protection-on' && step !== 'leak-protection-off') {
    throw new Error(`Unknown leak protection step: ${step}`);
  }
  const enabled = step === 'leak-protection-on';
  const switches = [['dnsLeakProtection', 'dns_leak_protection'], ['webrtcLeakProtection', 'webrtc_leak_protection']];
  // What the pinned engine reports for the rules of each switch, in their order.
  const named = {
    dns_leak_protection: [['port=853', 'reject']],
    webrtc_leak_protection: [['network=udp', 'sniff(stun)'], ['protocol=stun', 'reject'],
      ['network=udp port=[25 110 143 465 587 993 995]', 'reject']],
  };
  const observed = () => page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    return { engine: await invoke('engine_snapshot'), settings: await invoke('read_runtime_settings_snapshot'),
      rules: await invoke('rules_snapshot') };
  });
  // The running engine holds the rules of exactly the switches that are on,
  // each once and where it acts: encrypted DNS is refused in every route mode,
  // STUN in every mode but Direct.
  const table = (view) => {
    const rules = view.rules.rules.map(rule => [rule.payload, rule.proxy]);
    const differs = reason => new Error(`The running engine's rules differ: ${reason}: ${JSON.stringify(rules)}`);
    const places = ([payload, proxy]) => rules.flatMap((rule, index) => rule[0] === payload && rule[1] === proxy ? [index] : []);
    const hijack = places(['port=53', 'hijack-dns']);
    const direct = rules.findIndex(rule => rule[0] === 'clash_mode=Direct');
    const global = rules.findIndex(rule => rule[0] === 'clash_mode=Global');
    if (hijack.length !== 1 || direct <= hijack[0] || global <= direct) throw differs('no DNS hijack before the mode rules');
    const found = {};
    for (const [field, expected] of Object.entries(named)) {
      const on = view.settings.effective[field];
      const seen = expected.map(places);
      if (typeof on !== 'boolean' || seen.some(indexes => indexes.length !== (on ? 1 : 0))) {
        throw differs(`${field} is ${on}`);
      }
      found[field] = seen.map(indexes => indexes[0]);
    }
    const [dns] = found.dns_leak_protection;
    const [sniff, stun, unsniffed] = found.webrtc_leak_protection;
    if (dns !== undefined && !(hijack[0] < dns && dns < direct)) throw differs('port 853 is not refused before the mode rules');
    if (sniff !== undefined && !(direct < sniff && sniff < stun && stun < unsniffed && unsniffed < global)) {
      throw differs('STUN is not sniffed and refused between the Direct and Global mode rules');
    }
    return { count: rules.length, dns_hijack: hijack[0], direct_mode: direct, global_mode: global, ...found };
  };
  const flip = async (toggle, field, generation) => {
    const control = `[data-toggle="${toggle}"]`;
    await observeNative(page, ({ query, checked }) => {
      const input = document.querySelector(query);
      return input && !input.disabled && input.checked === checked ? { offered: true } : false;
    }, { query: control, checked: !enabled }, { name: `${toggle} switch readiness`, timeoutMs: 15000 });
    await page.locator('label.toggle-row').filter({ has: page.locator(control) }).click();
    // The observation runs inside the page, so its inputs are passed in.
    return observeNative(page, async ({ started, key, expected, query }) => {
      const invoke = window.__TAURI_INTERNALS__.invoke;
      const value = await invoke('engine_snapshot');
      if (value.unavailable_reason !== null) throw new Error(`Engine observation unavailable: ${value.unavailable_reason}`);
      const state = value.snapshot.state.state;
      // The coordinator publishes Off between retiring the engine and starting its replacement.
      if (!['tunnel_active', 'tunnel_stopping', 'off', 'tunnel_installing', 'tunnel_starting'].includes(state)) {
        throw new Error(`Unexpected result of a settings change in TUN Mode: ${JSON.stringify(value)}`);
      }
      if (state !== 'tunnel_active' || value.snapshot.generation <= started) return false;
      if (value.snapshot.desired_mode !== 'tunnel' || value.snapshot.state.runtime.ready !== true ||
          value.snapshot.state.runtime.owner !== 'windows_tunnel_service' ||
          value.snapshot.config_digest !== value.snapshot.state.runtime.config_digest) {
        throw new Error('The settings change did not start a newer ready Windows tunnel runtime');
      }
      // The page offers the switch again once it has taken the result. A
      // change that failed restores the previous settings under a newer
      // generation, which is a failure here and not a reason to wait.
      const input = document.querySelector(query);
      if (!input || input.disabled) return false;
      const settings = await invoke('read_runtime_settings_snapshot');
      if (settings.effective[key] !== expected || input.checked !== expected) {
        throw new Error(`The engine was replaced without the new setting: ${JSON.stringify(settings.effective)}`);
      }
      return value;
    }, { started: generation, key: field, expected: enabled, query: control },
    { name: `${toggle} ${enabled ? 'on' : 'off'} while TUN Mode runs`, timeoutMs: 75000 });
  };

  await page.locator('#nav button[data-page="general"]').click();
  const first = await observed();
  const before = first.engine;
  if (before.unavailable_reason !== null || before.snapshot.state.state !== 'tunnel_active' ||
      before.snapshot.desired_mode !== 'tunnel' || before.snapshot.state.runtime.ready !== true ||
      before.snapshot.state.runtime.owner !== 'windows_tunnel_service' ||
      switches.some(([, field]) => first.settings.effective[field] !== !enabled)) {
    throw new Error(`The GUI's verified TUN runtime does not run with both switches ${enabled ? 'off' : 'on'}: ${JSON.stringify({
      engine: before, effective: first.settings.effective })}`);
  }
  const began = table(first);
  await page.locator('#nav button[data-page="settings"]').click();
  await page.locator('#nav button[data-page="settings"][aria-current="page"]').waitFor();
  const changes = [];
  let active = before;
  for (const [toggle, field] of switches) {
    const replaced = await flip(toggle, field, active.snapshot.generation);
    const now = await observed();
    if (JSON.stringify(now.engine.snapshot) !== JSON.stringify(replaced.snapshot)) {
      throw new Error(`The engine changed again after ${toggle}: ${JSON.stringify(now.engine)}`);
    }
    changes.push({ toggle, enabled, generation: replaced.snapshot.generation,
      effective: now.settings.effective, rules: table(now) });
    active = replaced;
  }
  await page.screenshot({ path: `${step}.png` });
  await page.locator('#nav button[data-page="general"]').click();
  await observeNative(page, () => {
    const proxy = document.querySelector('[data-toggle="systemProxy"]');
    const tunnel = document.querySelector('[data-toggle="tunMode"]');
    return proxy && tunnel && !proxy.disabled && !proxy.checked && !tunnel.disabled && tunnel.checked
      ? { system_proxy_on: false, tunnel_on: true } : false;
  }, undefined, { name: 'switches after the leak protection change', timeoutMs: 15000 });
  const snapshot = await page.locator('body').ariaSnapshot();
  return { before, began, changes, active, snapshot, leak_protection: enabled,
    mutations: switches.map(([toggle]) => `${toggle}:${enabled ? 'on' : 'off'}`), release_accepted: false };
})
