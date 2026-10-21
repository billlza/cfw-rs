// Run by the Playwright controller, with no state injected into the product.
// waitForFunction treats an async predicate's Promise as truthy before it
// resolves; use evaluate to await each real observation before deciding.
(async (page, read, argument, { name, timeoutMs, pollingMs = 250 }) => {
  if (typeof name !== 'string' || !name.trim() || !Number.isInteger(timeoutMs) ||
      timeoutMs < 1 || timeoutMs > 30000 || !Number.isInteger(pollingMs) || pollingMs < 1 || pollingMs > 1000) {
    throw new Error('Invalid GUI observation bounds');
  }
  let stopped = false;
  let timer;
  let cancelDelay;
  const timeout = new Error(`${name} observation exceeded ${timeoutMs} ms`);
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(timeout), timeoutMs); });
  const poll = async () => {
    while (!stopped) {
      const value = await page.evaluate(read, argument);
      if (stopped) throw timeout;
      if (value !== false) {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) {
          throw new Error(`${name} returned an invalid observation`);
        }
        return value;
      }
      await new Promise(resolve => {
        const delay = setTimeout(resolve, pollingMs);
        cancelDelay = () => { clearTimeout(delay); resolve(); };
      });
      cancelDelay = undefined;
    }
    throw timeout;
  };
  try { return await Promise.race([poll(), deadline]); }
  finally {
    stopped = true;
    clearTimeout(timer);
    cancelDelay?.();
  }
})
