// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window: files
// "opened from Finder" – the app's smoke driver simulates the open event (`open_files::receive`, the same path as
// `RunEvent::Opened`) with sandbox fixtures, one phase per run (`window.__smokeOpen`; the expected file names in
// `window.__smokeOpenNames`):
//   one, two, locked – the import's report appears in this window (the "Import" alert naming each opened file); OK
//                      closes it;
//   catalog          – the Team catalogs section with the "Add Team Catalog" dialog, the file source chosen and the
//                      opened file's name shown; the team key and the fingerprint empty and "Check" disabled (they are
//                      still the user's); Cancel closes it.
// Each phase writes its result into the result connection's name (`OPEN <phase> OK` / `… FAILED <checks>`).
(async () => {
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 20000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const $ = (selector) => document.querySelector(selector);
  const RESULT = 'E6111111-2222-4333-8444-555555555555';
  const phase = window.__smokeOpen;
  const names = window.__smokeOpenNames ?? [];
  const vm = await invoke('get_view_model');
  const lang = vm.language;
  const t = (en, hu) => (lang === 'hu' ? hu : en);
  const checks = {};
  try {
    if (phase === 'one' || phase === 'two' || phase === 'locked') {
      const alert = await waitFor(() => {
        const a = $('.alert');
        return a && names.every((n) => a.textContent.includes(n)) ? a : null;
      });
      checks.report = !!alert;
      checks.title = alert?.querySelector('h1')?.textContent.trim() === t('Import', 'Importálás');
      // The report names the files, never their folder.
      checks.noPath = !!alert && !alert.textContent.includes('/');
      alert?.querySelector('.buttons button.primary')?.click();
      checks.closed = !!(await waitFor(() => !$('.alert')));
    } else if (phase === 'catalog') {
      const sheet = await waitFor(() => $('.sheet'));
      checks.section = !!$('.team-catalogs-section');
      checks.dialog = !!sheet && sheet.querySelector('h1')?.textContent.trim() === t('Add Team Catalog', 'Csapatkatalógus hozzáadása');
      checks.fileSource = $('.sheet .source-kind button[aria-checked="true"]')?.textContent.trim() === t('File', 'Fájl');
      checks.fileName = $('.sheet .file-name')?.textContent.trim() === names[0];
      checks.keyEmpty = $('.sheet input.team-key')?.value === '';
      checks.fingerprintEmpty = $('.sheet input.fingerprint')?.value === '';
      checks.checkDisabled = $('.sheet button.check')?.disabled === true;
      checks.noPreview = !$('.sheet [data-preview]');
      $('.sheet button.cancel')?.click();
      checks.closed = !!(await waitFor(() => !$('.sheet')));
      checks.notSubscribed = (await invoke('get_view_model')).catalogs?.length === 0;
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
  const view = await invoke('editor_open', { id: RESULT });
  await invoke('editor_save', {
    id: RESULT,
    fields: { ...view.fields, name: failed.length === 0 ? `OPEN ${phase} OK` : `OPEN ${phase} FAILED ${failed.join(',')}` },
  });
})();
