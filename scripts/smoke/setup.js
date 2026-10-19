// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the System Status window
// over the mock report (a missing tool, root layer 6 installed, 7 bundled). The sandbox runs no brew, no root
// installer and no uninstaller (they answer "cancelled"). The result goes into a seeded connection's name.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const rows = () => document.querySelectorAll('.check-row');
  const checks = {};
  try {
    checks.rows = !!(await waitFor(() => rows().length === 3));
    checks.homebrewOk = !rows()[0].querySelector('.action');
    checks.upgradeNotice = !!(await waitFor(() => document.querySelector('.setup .notice')));
    const tools = rows()[1].querySelector('.action button');
    checks.toolsButton = !!tools && !tools.disabled;
    tools.click();
    checks.brewOutput = !!(await waitFor(() => document.querySelector('.output')?.textContent.includes('sandbox: brew is not run')));
    checks.brewDone = !!(await waitFor(() => document.querySelector('.output')?.textContent.includes('✓')));
    rows()[2].querySelector('.action button').click();
    checks.installError = !!(await waitFor(() => document.querySelector('.setup .error')));
    document.querySelector('.uninstall').click();
    const dialog = await waitFor(() => document.querySelector('[role=alertdialog]'));
    checks.uninstallAsked = !!dialog && !!dialog.querySelector('input[type=checkbox]');
    dialog.querySelector('input[type=checkbox]').click();
    dialog.querySelector('button.destructive').click();
    checks.uninstallFailed = !!(await waitFor(() => {
      const d = document.querySelector('[role=alertdialog]');
      return d && !d.querySelector('input[type=checkbox]') && d.querySelector('button.primary');
    }));
    document.querySelector('[role=alertdialog] button.primary').click();
    checks.closed = !!(await waitFor(() => !document.querySelector('[role=alertdialog]')));
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const id = '41111111-2222-4333-8444-555555555555';
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'SETUP OK' : `SETUP FAILED ${failed.join(',')}` } });
})();
