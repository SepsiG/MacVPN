// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the System Status window
// over the mock report. macOS: a missing tool, root layer 7 installed, 8 bundled; the sandbox runs no brew, no root
// installer and no uninstaller (they answer "cancelled"). Windows (the `platform` the page reports): the engine rows –
// the WinVPN Service green, OpenVPN Community red with "Install" (the sandbox runs no installer), WireGuard green –,
// the green Windows VPN client row under them (WinVPN 2c; no "native VPNs come later" note any more), "Open
// Installed Apps…" and the account clean-up button (G-9: its confirmation opened and cancelled). The result goes into a
// seeded connection's name.
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
  const windows = async () => {
    checks.rows = !!(await waitFor(() => rows().length === 4));
    checks.serviceOk = !rows()[0].querySelector('.action button');
    const install = rows()[1].querySelector('.action button');
    checks.openvpnInstall = !!install && !install.disabled;
    checks.wireguardOk = !rows()[2].querySelector('.action button');
    checks.rasRow = !!rows()[3].querySelector('.mark.ok') && !rows()[3].querySelector('.action');
    checks.noLaterNote = !document.querySelector('.later-note');
    // G-9: "Remove WinVPN from This Account…" in place of MacVPN's uninstaller: its confirmation with "Also delete
    // user data", cancelled (the clean-up is never run here).
    const cleanup = document.querySelector('.card.danger .uninstall');
    checks.accountCleanup = !!cleanup && !cleanup.disabled;
    cleanup?.click();
    const dialog = await waitFor(() => document.querySelector('[role=alertdialog]'));
    checks.cleanupAsked = !!dialog && !!dialog.querySelector('input[type=checkbox]') && !!dialog.querySelector('button.destructive');
    dialog?.querySelector('button.cancel')?.click();
    checks.cleanupCancelled = !!(await waitFor(() => !document.querySelector('[role=alertdialog]'))) && !(await invoke('get_view_model')).setup.uninstalling;
    install.click();
    checks.installerOutput = !!(await waitFor(() => document.querySelector('.output')?.textContent.includes('sandbox: the OpenVPN installer is not run')));
  };
  const macos = async () => {
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
  };
  try {
    if ((await invoke('get_platform')).os === 'windows') await windows();
    else await macos();
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const id = '41111111-2222-4333-8444-555555555555';
  const view = await invoke('editor_open', { id });
  await invoke('editor_save', { id, fields: { ...view.fields, name: failed.length === 0 ? 'SETUP OK' : `SETUP FAILED ${failed.join(',')}` } });
})();
