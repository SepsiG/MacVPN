// Driven by scripts/smoke-manage.sh, in the menu popover (hidden, never reopened). The app's smoke driver fills in
// __MODE__. `lock`: turns "Show “Lock Now”" on in the settings, clicks "Lock Now", waits for the locked menu, checks
// that it shows no connection name, no switch and no settings, and clicks "Unlock…". `change`: "Change Master
// Password…" in the settings. Anything unexpected stops the script, and the driver reports what did not happen.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 20000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    throw new Error('timeout');
  };
  const openSettings = async () => {
    const disclosure = await waitFor(() => document.querySelector('[aria-controls=menu-settings]'));
    if (disclosure.getAttribute('aria-expanded') !== 'true') disclosure.click();
    await sleep(200);
  };
  const mode = '__MODE__';
  if (mode === 'lock') {
    await openSettings();
    const toggle = await waitFor(() => document.querySelector('input.show-lock-now'));
    if (!toggle.checked) toggle.click();
    (await waitFor(() => document.querySelector('button.lock-now'))).click();
    const unlock = await waitFor(() => document.querySelector('.locked .unlock-row'));
    const text = document.body.textContent;
    if (/Seeded|Zz /.test(text)) throw new Error('a name in the locked menu');
    if (document.querySelector('input[type=checkbox], [aria-controls=menu-settings], .card')) throw new Error('a switch in the locked menu');
    unlock.click();
  } else if (mode === 'change') {
    await waitFor(() => !document.querySelector('.locked'));
    await openSettings();
    (await waitFor(() => document.querySelector('button.change-password'))).click();
  }
})();
