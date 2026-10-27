// Real-browser regression for the test controller; never run on a product page.
(async (page, observeNative) => {
  if (page.url() !== 'about:blank') throw new Error('Observation regression requires its own blank page');
  const reset = () => page.evaluate(() => {
    document.body.dataset.attempts = '0';
    delete document.body.dataset.completed;
  });
  const count = () => page.evaluate(() => Number(document.body.dataset.attempts));
  const check = (condition, message) => { if (!condition) throw new Error(message); };
  await reset();
  const ready = await observeNative(page, async () => {
    const attempt = Number(document.body.dataset.attempts) + 1;
    document.body.dataset.attempts = String(attempt);
    await new Promise(resolve => setTimeout(resolve, 30));
    return attempt === 3 ? { observed: true, attempt } : false;
  }, undefined, { name: 'delayed readiness', timeoutMs: 2000, pollingMs: 20 });
  check(ready.observed === true && ready.attempt === 3 && await count() === 3, 'Async false was accepted before readiness');

  await reset();
  let rejection;
  try {
    await observeNative(page, async () => {
      document.body.dataset.attempts = String(Number(document.body.dataset.attempts) + 1);
      throw new Error('native read rejected');
    }, undefined, { name: 'rejected read', timeoutMs: 1000, pollingMs: 20 });
  } catch (error) { rejection = String(error); }
  check(rejection?.includes('native read rejected') && await count() === 1, 'A rejected read was retried or hidden');

  let invalid;
  try { await observeNative(page, () => true, undefined, { name: 'invalid result', timeoutMs: 1000 }); }
  catch (error) { invalid = String(error); }
  check(invalid?.includes('invalid observation'), 'A scalar was accepted as a complete snapshot');

  await reset();
  let exceeded;
  try {
    await observeNative(page, async () => {
      document.body.dataset.attempts = String(Number(document.body.dataset.attempts) + 1);
      await new Promise(resolve => setTimeout(resolve, 150));
      document.body.dataset.completed = 'yes';
      return false;
    }, undefined, { name: 'slow read', timeoutMs: 40, pollingMs: 20 });
  } catch (error) { exceeded = String(error); }
  check(exceeded?.includes('slow read observation exceeded 40 ms'), 'An in-flight read escaped the overall deadline');
  await page.waitForFunction(() => document.body.dataset.completed === 'yes', undefined, { timeout: 2000 });
  check(await count() === 1, 'Polling continued after the deadline');
  return { delayed_async_false_retried: true, native_rejection_preserved: true,
    invalid_result_refused: true, in_flight_read_deadline_enforced: true,
    no_reads_after_deadline: true, product_behavior_exercised: false };
})
