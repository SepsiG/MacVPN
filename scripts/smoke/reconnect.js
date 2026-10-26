// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), the features plan's Task 15: the
// "Reconnect Automatically" switch in a connection's detail (Connections window). The app's smoke driver selects
// the seeded connection (`name`, `id`), scripts the network, the sleep, the wake and the drops, and watches the stand-in
// helper; this script only turns the detail's switch to `on` and waits for the view model's row to have it. Writes
// `RECONNECT <phase> OK` / `… FAILED <checks>` into the result connection's name.
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
    // The driver selected it; a click on its row if the detail shows another one.
    if (document.querySelector('.detail h1')?.textContent !== S.name) {
      [...document.querySelectorAll('nav .row.item')].find((b) => b.querySelector('.label')?.textContent === S.name)?.click();
    }
    checks.detail = !!(await waitFor(() => document.querySelector('.detail h1')?.textContent === S.name));
    const toggle = await waitFor(() => document.querySelector('.detail .reconnect input'));
    checks.switch = !!toggle;
    if (toggle && toggle.checked !== S.on) toggle.click();
    checks.stored = !!(await waitFor(async () => (await invoke('get_view_model')).rows.find((r) => r.id === S.id)?.autoReconnect === S.on));
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
