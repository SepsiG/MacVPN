// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), the features plan's Task 15: the
// "Connection Notifications" switch in the menu popover's settings. The app's smoke driver connects and drops a
// seeded connection and reads the notices the sandbox recorded; this script only turns the switch to `on` (the
// switch's localized `label` from the driver) and waits for the view model to have it. Writes
// `NOTICES <phase> OK` / `… FAILED <checks>` into the result connection's name.
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const S = window.__smoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 8000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const checks = {};
  try {
    const disclosure = await waitFor(() => document.querySelector('[aria-controls=menu-settings]'));
    if (disclosure && disclosure.getAttribute('aria-expanded') !== 'true') disclosure.click();
    const toggle = await waitFor(() =>
      [...document.querySelectorAll('#menu-settings label.setting')].find((l) => l.textContent.includes(S.label))?.querySelector('input'),
    );
    checks.switch = !!toggle;
    if (toggle && toggle.checked !== S.on) toggle.click();
    checks.stored = !!(await waitFor(async () => (await invoke('get_view_model')).connectionNotifications === S.on));
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const view = await invoke('editor_open', { id: S.result });
  await invoke('editor_save', {
    id: S.result,
    fields: { ...view.fields, name: `${S.section} ${S.phase} ${failed.length === 0 ? 'OK' : `FAILED ${failed.join(',')}`}` },
  });
})();
