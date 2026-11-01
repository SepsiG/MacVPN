// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only): the Language setting. The app's
// smoke driver sets `window.__smoke` (`phase`, `result`, `setting`, `language`, `settings`, `search`):
//   menu-<setting>   – in the menu popover: Settings, the setting's segment (Match System / English / Magyar)
//                      clicked, the setting stored, the view model's language as expected, and the popover's
//                      "Settings" in that language without reopening it;
//   manage-<setting> – in the Connections window (open all along): its search field's placeholder in that language.
// Each phase writes `LANGUAGE <phase> OK` / `… FAILED <checks>` into the result connection's name.
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
  const text = (el) => (el?.textContent ?? '').trim();
  const checks = {};
  try {
    if (S.phase.startsWith('menu-')) {
      const disclosure = await waitFor(() => document.querySelector('[aria-controls=menu-settings]'));
      if (disclosure && disclosure.getAttribute('aria-expanded') !== 'true') disclosure.click();
      // The segments in order: Match System, English, Magyar.
      const index = { system: 0, en: 1, hu: 2 }[S.setting];
      const segment = await waitFor(() => document.querySelectorAll('.setting.language [role=radio]')[index]);
      checks.segment = !!segment;
      // The language names are the same in every language.
      checks.names = !!(await waitFor(() => {
        const names = [...document.querySelectorAll('.setting.language [role=radio]')].map(text);
        return names[1] === 'English' && names[2] === 'Magyar';
      }));
      segment?.click();
      checks.checked = !!(await waitFor(() => segment?.getAttribute('aria-checked') === 'true'));
      checks.stored = !!(await waitFor(async () => {
        const vm = await invoke('get_view_model');
        return vm.languageSetting === S.setting && vm.language === S.language;
      }));
      checks.text = !!(await waitFor(() => text(document.querySelector('[aria-controls=menu-settings] .disclosure-label')) === S.settings));
    } else if (S.phase.startsWith('manage-')) {
      checks.text = !!(await waitFor(() => [...document.querySelectorAll('input[placeholder]')].some((i) => i.placeholder === S.search)));
    } else {
      checks.phase = false;
    }
  } catch (e) {
    console.error(e);
    checks.error = false;
  }
  const failed = Object.entries(checks)
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
  // On a failure, what the window showed (the placeholders, the Settings label).
  const seen = failed.length === 0 ? '' : ` seen=${JSON.stringify([...document.querySelectorAll('input[placeholder]')].map((i) => i.placeholder).concat(text(document.querySelector('[aria-controls=menu-settings] .disclosure-label'))))}`;
  const outcome = failed.length === 0 ? 'OK' : `FAILED ${failed.join(',')}${seen}`;
  const view = await invoke('editor_open', { id: S.result });
  await invoke('editor_save', { id: S.result, fields: { ...view.fields, name: `${S.section} ${S.phase} ${outcome}` } });
})();
