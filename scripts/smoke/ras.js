// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), Windows only (WinVPN 2c), in
// the Connections window; the driver (`platform/smoke/ras.rs`) seeded the connections and put the ids, names and
// expected texts (from strings.json, in the run's language) into `window.__smoke`. Every connect goes to the
// run's stand-ins (no dial, no network). Checks: the New menu offers L2TP and not Cisco IPsec; an IKEv2 PSK
// connection shows the Windows reason and cannot connect; a Cisco IPsec connection shows option A's text and
// "Make an L2TP/IPsec Copy" selects its copy; an IKEv2 (EAP) connection shows the "On Windows: …" summary and
// connects and disconnects, as does an SSTP connection; an L2TP connection's password and PSK typed and saved
// ("Save": the Windows entry is written at once), then it connects and disconnects. Writes `RAS OK` or
// `RAS FAILED <checks>` into the result connection's name.
(async () => {
  const s = window.__smoke;
  const invoke = window.__TAURI_INTERNALS__.invoke;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 10000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = await fn();
      if (value) return value;
      await sleep(150);
    }
    return null;
  };
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const row = (name) => [...document.querySelectorAll('nav .row')].find((b) => b.querySelector('.name .label')?.textContent === name);
  const open = async (name) => {
    const r = await waitFor(() => row(name));
    if (!r) return false;
    r.click();
    return !!(await waitFor(() => document.querySelector('.detail h1')?.textContent === name));
  };
  const reasons = () => [...document.querySelectorAll('.platform-reason')].map((p) => p.textContent);
  const connectButton = () => document.querySelector('.detail .header .actions button');
  const vmRow = async (id) => (await invoke('get_view_model')).rows.find((r) => r.id === id);
  const reaches = (id, state) => waitFor(async () => (await vmRow(id))?.state === state, 15000);
  // Connect → connected → Disconnect → disconnected, through the detail's button.
  const connectAndDisconnect = async (id) => {
    const button = await waitFor(() => (connectButton()?.disabled === false ? connectButton() : null));
    if (!button) return 'noButton';
    button.click();
    if (!(await reaches(id, 'connected'))) return `notConnected(${JSON.stringify(await vmRow(id))})`.slice(0, 120);
    const stop = await waitFor(() => (connectButton()?.classList.contains('primary') === false ? connectButton() : null));
    if (!stop) return 'noDisconnect';
    stop.click();
    return (await reaches(id, 'disconnected')) ? null : 'notDisconnected';
  };
  const checks = {};
  const notes = [];
  try {
    // The New menu: L2TP, no Cisco IPsec (option A).
    document.querySelector('.sidebar .toolbar button').click();
    const items = await waitFor(() => {
      const buttons = [...document.querySelectorAll('.sidebar .menu button')].map((b) => b.textContent.trim());
      return buttons.length > 0 ? buttons : null;
    });
    checks.newL2tp = !!items && items.some((t) => t.includes(s.l2tpLabel));
    checks.newNoCisco = !!items && !items.some((t) => t.includes(s.ciscoLabel));
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await waitFor(() => !document.querySelector('.sidebar .menu'));

    // IKEv2 with a pre-shared key: the Windows reason, no connect.
    checks.pskOpened = await open(s.ikev2PskName);
    checks.pskReason = !!(await waitFor(() => reasons().some((r) => r.includes(s.pskReason))));
    checks.pskNoConnect = connectButton()?.disabled === true;
    checks.pskRow = (await vmRow(s.ikev2Psk))?.unavailableReason?.includes(s.pskReason) === true;

    // Cisco IPsec: option A's text, no connect, the L2TP copy selected.
    checks.ciscoOpened = await open(s.ciscoName);
    checks.ciscoReason = !!(await waitFor(() => reasons().some((r) => r.includes(s.ciscoReason))));
    checks.ciscoNoConnect = connectButton()?.disabled === true;
    const copy = [...document.querySelectorAll('.detail .form button')].find((b) => b.textContent.trim() === s.copyLabel);
    checks.copyButton = !!copy;
    copy?.click();
    checks.copySelected = !!(await waitFor(() => document.querySelector('.detail h1')?.textContent === s.copyName));
    checks.copyNoReason = reasons().length === 0;

    // IKEv2 (EAP): what Windows makes of it, then a connect through the stand-in helper.
    checks.ikev2Opened = await open(s.ikev2Name);
    checks.ikev2Summary = !!(await waitFor(() => [...document.querySelectorAll('.detail .note')].some((n) => n.textContent.startsWith(s.summary))));
    checks.ikev2NoReason = reasons().length === 0;
    const ikev2 = await connectAndDisconnect(s.ikev2);
    checks.ikev2Connect = ikev2 === null;
    if (ikev2) notes.push(`ikev2:${ikev2}`);

    // SSTP the same way.
    checks.sstpOpened = await open(s.sstpName);
    const sstp = await connectAndDisconnect(s.sstp);
    checks.sstpConnect = sstp === null;
    if (sstp) notes.push(`sstp:${sstp}`);

    // L2TP: password and PSK typed, "Save" writes the Windows entry; then connect and disconnect.
    checks.l2tpOpened = await open(s.l2tpName);
    const secrets = await waitFor(() => {
      const fields = document.querySelectorAll('.form input[type=password]');
      return fields.length === 2 ? fields : null;
    });
    checks.l2tpFields = !!secrets;
    if (secrets) {
      setValue(secrets[0], s.password);
      setValue(secrets[1], s.psk);
    }
    await sleep(300);
    const save = document.querySelector('.form .footer button.primary');
    checks.l2tpSaveLabel = save?.textContent.trim() === s.saveLabel;
    save?.click();
    checks.l2tpSaved = !!(await waitFor(async () => {
      const view = await invoke('editor_open', { id: s.l2tp });
      return !view.dirty && view.hasStoredSecret.password && view.hasStoredSecret.psk && !view.error;
    }));
    const l2tp = await connectAndDisconnect(s.l2tp);
    checks.l2tpConnect = l2tp === null;
    if (l2tp) notes.push(`l2tp:${l2tp}`);
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const view = await invoke('editor_open', { id: s.result });
  const name = failed.length === 0 ? 'RAS OK' : `RAS FAILED ${failed.join(',')} ${notes.join(' ')}`.trim();
  await invoke('editor_save', { id: s.result, fields: { ...view.fields, name } });
})();
