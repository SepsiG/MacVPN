// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), Linux only (LinVPN L-b): the
// NetworkManager rows and the VPN rows over the run's stand-ins (no NetworkManager write, no PackageKit, no network).
// The driver (`platform/smoke/linux.rs`) seeded the connections and put the phase, the ids, names and expected texts
// (from strings.json, in the run's language) into `window.__smoke`:
//   setup  – System Status (the stand-in report with SSTP's plugin missing): the NetworkManager row and one row per
//            kind, SSTP red with Install, the rest green, no engine note; Install runs the sandbox's install (its
//            output names that PackageKit is not asked);
//   green  – System Status once the driver flipped the stand-in (SSTP's plugin installed): SSTP green, no Install;
//   manage – the Connections window: an OpenVPN connection with peer-fingerprint is greyed with the Linux reason,
//            its editor shows it, Connect is disabled; an OpenVPN editor's "Send all traffic over VPN": Always adds
//            `redirect-gateway def1` to the config text, Server decides removes it, Always again and Save stores it
//            (the driver reads the stored config); an L2TP connection: "Save" (no profile to approve) with its
//            password and PSK, then Connect → connected through the stand-in native controller → Disconnect; a
//            Cisco IPsec connection is not greyed (unlike Windows); a stand-in helper connection's Log tab shows its
//            lines, "Clear Log…" clears them.
// Each phase writes `NM <phase> OK` / `NM <phase> FAILED <checks>` into the result connection's name.
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
  const checks = {};
  const notes = [];

  // System Status: the NetworkManager row first, then one per kind in the report's order (SSTP last).
  const rows = () => [...document.querySelectorAll('.check-row')];
  const ok = (row) => !!row?.querySelector('.mark.ok');
  const setup = async () => {
    checks.rows = !!(await waitFor(() => rows().length === 7));
    checks.noEngineNote = !document.querySelector('.engine-note');
    checks.networkmanager = ok(rows()[0]) && rows()[0].querySelector('.detail')?.textContent === s.nmDetail;
    checks.othersGreen = rows().slice(0, 6).every(ok);
    const sstp = rows()[6];
    checks.sstpRed = !!sstp && !ok(sstp) && sstp.querySelector('.detail')?.textContent === s.sstpMissing;
    const install = document.querySelector('#nm-install-sstp');
    checks.sstpInstall = !!install && !install.disabled && sstp?.contains(install);
    checks.onlyOneInstall = document.querySelectorAll('.check-row .action button').length === 1;
    install?.click();
    checks.installOutput = !!(await waitFor(() => document.querySelector('.output')?.textContent.includes(s.installOutput), 15000));
    checks.installDone = !!(await waitFor(async () => !(await invoke('get_view_model')).setup.brewRunning, 15000));
  };
  const green = async () => {
    checks.sstpGreen = !!(await waitFor(() => rows().length === 7 && ok(rows()[6]) && rows()[6].querySelector('.detail')?.textContent === s.installed));
    checks.allGreen = rows().every(ok);
    checks.noInstall = !document.querySelector('#nm-install-sstp') && !document.querySelector('.check-row .action button');
  };

  // The Connections window.
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
  const textarea = () => document.querySelector('.editor textarea.config');
  const routingButtons = () => [...document.querySelectorAll('.routing .segmented button[role=radio]')];
  const choose = async (index) => {
    const before = textarea()?.value;
    routingButtons()[index]?.click();
    await waitFor(() => textarea()?.value !== before);
    return !!(await waitFor(() => routingButtons()[index]?.getAttribute('aria-checked') === 'true'));
  };
  const manage = async () => {
    // peer-fingerprint: the Linux reason, no connect.
    checks.fingerprintOpened = await open(s.fingerprintName);
    checks.fingerprintReason = !!(await waitFor(() => reasons().some((r) => r.includes(s.fingerprintReason))));
    checks.fingerprintNoConnect = connectButton()?.disabled === true;
    const fp = await vmRow(s.fingerprint);
    checks.fingerprintRow = !!fp && !fp.available && fp.unavailableReason?.includes(s.fingerprintReason) === true;

    // OpenVPN's "Send all traffic over VPN": the three-way control rewrites the config text.
    checks.routingOpened = await open(s.routingName);
    checks.routingControl = !!(await waitFor(() => routingButtons().length === 3));
    checks.routingLabels = routingButtons().map((b) => b.textContent.trim()).join('|') === s.routingLabels;
    checks.routingServer = routingButtons()[0]?.getAttribute('aria-checked') === 'true';
    checks.alwaysChosen = await choose(1);
    checks.alwaysAdds = /^redirect-gateway def1$/m.test(textarea()?.value ?? '');
    checks.serverChosen = await choose(0);
    checks.serverRemoves = !/redirect-gateway/.test(textarea()?.value ?? '');
    checks.alwaysAgain = await choose(1);
    document.querySelector('.footer button.primary')?.click();
    checks.routingSaved = !!(await waitFor(async () => {
      const view = await invoke('editor_open', { id: s.routing });
      return !view.dirty && /^redirect-gateway def1$/m.test(view.fields.text) && !view.error;
    }));

    // L2TP: "Save" writes the plan record at once (nothing to approve); then connect and disconnect.
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
    checks.l2tpNoApproval = ![...document.querySelectorAll('.form .note')].some((n) => n.textContent.includes(s.approveNote));
    // LinVPN's own note (the plan record, NetworkManager's connection only when connecting), not the Windows text.
    checks.l2tpSaveNote = [...document.querySelectorAll('.form .note')].some((n) => n.textContent.trim() === s.saveNote);
    save?.click();
    checks.l2tpSaved = !!(await waitFor(async () => {
      const view = await invoke('editor_open', { id: s.l2tp });
      return !view.dirty && view.hasStoredSecret.password && view.hasStoredSecret.psk && !view.error && view.platform?.noInstallStep === true;
    }));
    const l2tp = await connectAndDisconnect(s.l2tp);
    checks.l2tpConnect = l2tp === null;
    if (l2tp) notes.push(`l2tp:${l2tp}`);

    // Cisco IPsec: usable on Linux (no reason, Connect enabled).
    checks.ciscoOpened = await open(s.ciscoName);
    await sleep(500);
    checks.ciscoNoReason = reasons().length === 0;
    checks.ciscoConnectable = !!(await waitFor(() => connectButton()?.disabled === false));
    checks.ciscoRow = (await vmRow(s.cisco))?.available === true;

    // The stand-in helper connection's Log tab: its lines, then "Clear Log…" (confirmed) clears them.
    checks.logOpened = await open(s.logName);
    const log = await connectAndDisconnect(s.log);
    checks.logConnect = log === null;
    if (log) notes.push(`log:${log}`);
    document.querySelectorAll('.tabs button')[1]?.click();
    const lines = () => [...document.querySelectorAll('.log .lines .line')].map((l) => l.textContent);
    checks.logLines = !!(await waitFor(() => lines().some((l) => l.includes(s.logLine))));
    const clear = await waitFor(() => document.querySelector('.log .clear-log'));
    clear?.click();
    await waitFor(() => document.querySelector('[role=alertdialog]'));
    document.querySelector('.alert button.destructive')?.click();
    checks.logCleared = !!(await waitFor(() => !document.querySelector('[role=alertdialog]') && lines().length > 0 && !lines().some((l) => l.includes(s.logLine))));
    checks.logNote = lines().some((l) => l.includes(s.clearedNote));
    document.querySelectorAll('.tabs button')[0]?.click();
  };

  try {
    if (s.phase === 'setup') await setup();
    else if (s.phase === 'green') await green();
    else if (s.phase === 'manage') await manage();
    else checks.phase = false;
  } catch (e) {
    checks[`error ${String(e).slice(0, 60)}`] = false;
  }
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  const view = await invoke('editor_open', { id: s.result });
  const name = failed.length === 0 ? `NM ${s.phase} OK` : `NM ${s.phase} FAILED ${failed.join(',')} ${notes.join(' ')}`.trim();
  await invoke('editor_save', { id: s.result, fields: { ...view.fields, name } });
})();
