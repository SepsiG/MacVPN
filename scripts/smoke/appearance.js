// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), the features plan's Task 15: the
// Appearance setting. The app's smoke driver sets `window.__smoke` (`phase`, `result`, `mode`, `expected`):
//   initial      – in the menu popover, before any click: the system's value (the setting starts at Match System);
//   menu-<mode>  – in the popover: Settings, the mode's segment (Match System / Light / Dark) clicked, the setting
//                  stored, then `prefers-color-scheme: dark` as expected (`null`: not compared);
//   manage-<mode> – in the Connections window: the same media query, as expected.
// Each phase writes `APPEARANCE <phase> OK dark=<bool>` / `… FAILED <checks> dark=<bool>` into the result
// connection's name.
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
  const dark = () => window.matchMedia('(prefers-color-scheme: dark)').matches;
  const checks = {};
  try {
    if (S.phase.startsWith('menu-')) {
      const disclosure = await waitFor(() => document.querySelector('[aria-controls=menu-settings]'));
      if (disclosure && disclosure.getAttribute('aria-expanded') !== 'true') disclosure.click();
      // The segments in order: Match System, Light, Dark.
      const index = { system: 0, light: 1, dark: 2 }[S.mode];
      const segment = await waitFor(() => document.querySelectorAll('.setting.appearance [role=radio]')[index]);
      checks.segment = !!segment;
      segment?.click();
      checks.checked = !!(await waitFor(() => segment?.getAttribute('aria-checked') === 'true'));
      checks.stored = !!(await waitFor(async () => (await invoke('get_view_model')).appearance === S.mode));
    } else if (!S.phase.startsWith('manage-') && S.phase !== 'initial') {
      checks.phase = false;
    }
    if (S.expected === true || S.expected === false) {
      checks.media = !!(await waitFor(() => dark() === S.expected, 5000));
    }
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  const outcome = failed.length === 0 ? 'OK' : `FAILED ${failed.join(',')}`;
  const view = await invoke('editor_open', { id: S.result });
  await invoke('editor_save', { id: S.result, fields: { ...view.fields, name: `${S.section} ${S.phase} ${outcome} dark=${dark()}` } });
})();
