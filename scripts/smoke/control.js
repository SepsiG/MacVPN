// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in the Connections window,
// after prompt.js: the control API's Paired apps section. Turns "Allow other apps to control VPNs" on with its
// switch, then waits while the shell's test client pairs (pairing.js answers the pairing window), holds the seeded
// connection up and closes its socket: meanwhile the app's card (name, the full executable path, the allowed
// connection ticked) and the "Held by" label in the list must show, and the label must go once the client is
// gone. Last, the switch turns the setting off. The result goes into a seeded connection's name.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(150);
    }
    return null;
  };
  const vm = () => invoke('get_view_model');
  const result = '81111111-2222-4333-8444-555555555555';
  const target = '91111111-2222-4333-8444-555555555555';
  const checks = {};
  try {
    (await waitFor(() => document.querySelector('.sidebar .footer .paired'))).click();
    const toggle = await waitFor(() => document.querySelector('.paired .control-switch'));
    checks.section = !!toggle;
    checks.offByDefault = !!toggle && !toggle.checked && (await vm()).control.enabled === false;
    checks.emptyList = !!document.querySelector('.paired .none');
    toggle.click();
    checks.running = !!(await waitFor(async () => (await vm()).control.running, 15000));
    checks.switchOn = !!(await waitFor(() => document.querySelector('.paired .control-switch')?.checked));

    // The test client pairs and holds the target connection.
    const card = await waitFor(() => document.querySelector('.paired .card.app'), 90000);
    checks.card = !!card;
    const v = await vm();
    const client = v.control.clients[0];
    checks.cardPath = !!client && card?.querySelector('.path')?.textContent === client.executable && client.executable.startsWith('/');
    checks.cardName = card?.querySelector('.app-name')?.textContent === 'smoke-client';
    checks.allowedTicked = !!card?.querySelector(`input[value="${target}"]`)?.checked;
    checks.noSecret = !/token|sha256/i.test(JSON.stringify(v.control));
    const held = await waitFor(() => [...document.querySelectorAll('nav .row .held')].find((el) => el.textContent.includes('smoke-client')), 60000);
    checks.heldLabel = !!held;
    checks.heldInVm = !!(await vm()).rows.find((r) => r.id === target)?.heldBy.includes('smoke-client');
    // The client closes its socket: the label goes.
    checks.heldGone = !!(await waitFor(() => !document.querySelector('nav .row .held'), 60000));
    checks.lastUsed = (await vm()).control.clients[0]?.lastUsed !== null;
    checks.auditSave = !!document.querySelector('.paired .activity .save-audit');

    // Off: the server stops (the socket goes; the shell checks it).
    document.querySelector('.paired .control-switch').click();
    checks.stopped = !!(await waitFor(async () => {
      const x = await vm();
      return !x.control.running && !x.control.enabled;
    }, 30000));
    checks.listKept = (await vm()).control.clients.length === 1;
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const view = await invoke('editor_open', { id: result });
  await invoke('editor_save', { id: result, fields: { ...view.fields, name: failed.length === 0 ? 'CONTROL OK' : `CONTROL FAILED ${failed.join(',')}` } });
})();
