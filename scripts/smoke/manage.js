// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only): uses the real Connections
// window like a user and writes the result into the first connection's name (saved through the UI, so the
// store proves the round trip). Language independent: only classes and structure are used, except one check that
// the window shows the view model's language (the Save button's English or Hungarian text). The New menu, a
// connection's context menu at the window's corners and its colour picker must lie inside the window (8 pt margin).
// The Log tab's time filter and "Clear Log…" (confirmed after a cancelled question). The search field filters the
// tree as typed (accents and case ignored), Up / Down / Return open a result, the
// empty result names the query (in the window's language), Escape clears it and every row is back. A new WireGuard
// connection's "Generate Key Pair" and its public key. A new IKEv2 connection's client certificate panel.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 8000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    return null;
  };
  const setValue = (el, value) => {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const row = (name) => [...document.querySelectorAll('nav .row')].find((b) => b.textContent.includes(name));
  const save = () => document.querySelector('.footer button.primary').click();
  const shown = (title) => waitFor(() => document.querySelector('.detail h1')?.textContent === title);
  // A popover or context menu lies inside the window, 8 pt from its edges (after its opening animation).
  // The window's real content size (the layout viewport), measured at each use: the window may have been resized
  // since the script started.
  const viewport = () => ({
    width: document.documentElement.clientWidth || innerWidth,
    height: document.documentElement.clientHeight || innerHeight,
  });
  // Where a failed placement check found its popover (for the result: `name[left,top,right,bottom in WxH]`).
  const geometry = [];
  const inside = async (selector, name = selector) => {
    const el = await waitFor(() => document.querySelector(selector));
    if (!el) {
      geometry.push(`${name}[none]`);
      return false;
    }
    await sleep(300);
    // The opening animation (`translateY(-4px) scale(0.98)`) moves the box; a cold first run may still be in it.
    const finite = el.getAnimations({ subtree: true }).filter((a) => a.effect?.getComputedTiming().endTime !== Infinity);
    await Promise.all(finite.map((a) => a.finished.catch(() => {})));
    const r = el.getBoundingClientRect();
    const { width, height } = viewport();
    const ok = r.width > 0 && r.left >= 7.5 && r.top >= 7.5 && r.right <= width - 7.5 && r.bottom <= height - 7.5;
    if (!ok) geometry.push(`${name}[${[r.left, r.top, r.right, r.bottom].map(Math.round).join(',')} in ${width}x${height}]`);
    return ok;
  };
  const escape = () => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  const contextAt = (target, x, y) =>
    target.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: x, clientY: y }));
  const checks = {};
  let name = null;
  try {
    const a = await waitFor(() => row('Seeded A'));
    checks.list = !!a && !!row('Seeded B');
    a.click();
    const text = await waitFor(() => document.querySelector('textarea.config'));
    const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
    const saveText = { en: 'Save', hu: 'Mentés' }[vm.language];
    checks.language = !!saveText && document.querySelector('.footer button.primary')?.textContent === saveText;
    checks.loaded = !!text && text.value.includes('remote vpn.example.com');
    setValue(text, `${text.value}user nobody\n`);
    const panel = await waitFor(() => document.querySelector('.risky'));
    checks.riskyPanel = !!panel;
    checks.dirty = !!(await waitFor(() => document.querySelector('.footer .unsaved')));
    save();
    checks.ackRequired = !!(await waitFor(() => document.querySelector('.issues li')));
    panel.querySelector('input[type=checkbox]').click();
    await sleep(300);
    setValue(document.querySelector('input.wide'), 'Smoke A');
    await sleep(300);
    save();
    checks.saved = !!(await waitFor(() => document.querySelector('.footer .secondary')));
    checks.issuesCleared = !document.querySelector('.issues li');

    // The unsaved-changes question on a selection change; Discard goes on.
    setValue(document.querySelector('input.wide'), 'Dirty A');
    await sleep(400);
    row('Seeded B').click();
    checks.unsavedAsked = !!(await waitFor(() => document.querySelector('[role=alertdialog]')));
    document.querySelector('.alert button.destructive').click();
    checks.switched = !!(await shown('Seeded B'));
    document.querySelectorAll('.tabs button')[1].click();
    checks.logTab = !!(await waitFor(() => document.querySelector('.log .toolbar')));
    // The Log tab's time filter (the presets; "Custom Range" shows From / To) and "Clear Log…" (asked first, with
    // the connection's name; Cancel keeps it; confirmed, the backend clears and the view starts over).
    const time = await waitFor(() => document.querySelector('.log select.time'));
    checks.logTimePresets = !!time && time.options.length === 6;
    if (time) {
      const choose = (value) => {
        time.value = value;
        time.dispatchEvent(new Event('change', { bubbles: true }));
      };
      choose('custom');
      checks.logCustomRange = !!(await waitFor(() => document.querySelector('.log .range input.from[type=datetime-local]') && document.querySelector('.log .range input.to')));
      choose('any');
      checks.logCustomHidden = !!(await waitFor(() => !document.querySelector('.log .range')));
    }
    const clearButton = await waitFor(() => document.querySelector('.log .clear-log'));
    clearButton?.click();
    checks.logClearAsked = !!(await waitFor(() => document.querySelector('[role=alertdialog]')?.textContent.includes('Seeded B')));
    document.querySelector('.alert button.cancel')?.click();
    checks.logClearCancelled = !!(await waitFor(() => !document.querySelector('[role=alertdialog]')));
    clearButton?.click();
    await waitFor(() => document.querySelector('[role=alertdialog]'));
    document.querySelector('.alert button.destructive')?.click();
    await sleep(300);
    checks.logCleared = !!(await waitFor(() => !document.querySelector('[role=alertdialog]') && clearButton && !clearButton.disabled));
    document.querySelectorAll('.tabs button')[0].click();

    // Back to A: the saved name and the stored acknowledgement are there.
    row('Smoke A').click();
    await shown('Smoke A');
    name = await waitFor(() => {
      const input = document.querySelector('input.wide');
      return input && input.value === 'Smoke A' ? input : null;
    });
    checks.reloaded = !!name;
    checks.acknowledged = !!(await waitFor(() => document.querySelector('.risky input[type=checkbox]')?.checked));

    // SSTP form: the port and the user name into the serialized config.
    row('Seeded S').click();
    await shown('Seeded S');
    const port = await waitFor(() => [...document.querySelectorAll('.form .field input')].find((i) => i.value === '443'));
    checks.sstpLoaded = !!port;
    setValue(port, '8443');
    port.dispatchEvent(new Event('change', { bubbles: true }));
    await sleep(300);
    save();
    checks.sstpSaved = !!(await waitFor(() => document.querySelector('.footer .secondary')));

    const invoke = window.__TAURI_INTERNALS__.invoke;
    const { os } = await invoke('get_platform');
    const windows = os === 'windows';
    if (windows) {
      // WinVPN 2c: the L2TP form saves the Windows VPN entry at once ("Save", no profile to approve); it is not
      // saved here (the sandbox's RAS engine would write an entry). SSTP cannot skip the certificate check.
      checks.nativeListed = !!row('Seeded L');
      const sstpView = await invoke('editor_open', { id: '21111111-2222-4333-8444-555555555555' });
      checks.sstpNoVerification = !!sstpView.platform?.insecureCert;
      const insecure = document.querySelector('.form select option[value=insecure]');
      checks.sstpInsecureDisabled = !!insecure && insecure.disabled && insecure.title === sstpView.platform.insecureCert;
      row('Seeded L').click();
      await shown('Seeded L');
      const saveLabel = { en: 'Save', hu: 'Mentés' }[vm.language];
      checks.nativeSaveButton = !!(await waitFor(() => document.querySelector('.form .footer button.primary')?.textContent.trim() === saveLabel));
      const nativeView = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
      checks.nativeNoInstallStep = nativeView.platform?.noInstallStep === true && nativeView.platform.l2tpCopy === false;
    } else if (os === 'linux') {
      // LinVPN L-b: the native form saves at once ("Save": the plan record in the sandbox's data folder, no profile
      // to approve, no NetworkManager connection). The stored password is never sent back.
      row('Seeded L').click();
      await shown('Seeded L');
      const saveLabel = { en: 'Save', hu: 'Mentés' }[vm.language];
      checks.nativeSaveButton = !!(await waitFor(() => document.querySelector('.form .footer button.primary')?.textContent.trim() === saveLabel));
      const password = await waitFor(() => document.querySelector('.form input[type=password]'));
      setValue(password, 'native-secret');
      setValue(document.querySelector('.form .field input[type=text]'), 'Seeded L2');
      await sleep(300);
      save();
      checks.nativeSaved = !!(await waitFor(() => document.querySelector('.footer .ok')));
      const nativeView = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
      checks.nativeStored = nativeView.fields.name === 'Seeded L2' && nativeView.hasStoredSecret.password && nativeView.fields.password === null && !nativeView.dirty;
      checks.nativeNoInstallStep = nativeView.platform?.noInstallStep === true;
      checks.noSecretInView = !JSON.stringify(nativeView).includes('native-secret');
    } else {
      // Native form: the profile is generated and staged (the sandbox does not open it).
      row('Seeded L').click();
      await shown('Seeded L');
      const password = await waitFor(() => document.querySelector('.form input[type=password]'));
      setValue(password, 'native-secret');
      await sleep(300);
      save();
      checks.nativeSaved = !!(await waitFor(() => document.querySelector('.footer .ok')));
      // The stored password is never sent back: the field is empty, marked as saved, with the Remove action.
      checks.secretHidden = !!(await waitFor(() => {
        const field = document.querySelector('.form input[type=password]');
        return field && field.value === '' && document.querySelector('.form .remove');
      }));
      const nativeView = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
      checks.noSecretInView = !JSON.stringify(nativeView).includes('native-secret') && nativeView.hasStoredSecret.password;
      // Saving again with the field untouched keeps the stored password.
      setValue(document.querySelector('.form .field input[type=text]'), 'Seeded L2');
      await sleep(300);
      save();
      await sleep(600);
      const again = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
      checks.secretKept = again.hasStoredSecret.password && again.fields.password === null && !again.dirty;
    }

    // The native connection's name now (renamed by the native form's save above: macOS and Linux; Windows saves none).
    const l2 = windows ? 'Seeded L' : 'Seeded L2';
    // The search: typed with accents the names do not have, by server and by type; Up / Down and Return open a
    // result; the empty result and its Clear; Escape clears, then leaves the field; Cmd+F comes back to it.
    const field = document.querySelector('.sidebar input.query');
    const shownNames = () => [...document.querySelectorAll('nav .row.item .name .label')].map((l) => l.textContent);
    const all = shownNames();
    const showing = (expected) =>
      waitFor(() => {
        const names = shownNames();
        return names.length === expected.length && expected.every((n) => names.includes(n));
      });
    checks.searchField = !!field && all.length >= 10;
    field.focus();
    setValue(field, 'SÉÉDED');
    checks.searchAccents = !!(await showing(['Seeded B', 'Seeded S', l2])) && !!document.querySelector('nav .tree.filtering mark');
    setValue(field, 'l2tp.example');
    checks.searchServer = !!(await showing([l2]));
    // An OpenVPN server comes from the config's `remote` (its host only: the port is not searched).
    setValue(field, 'B-GATEWAY.example');
    checks.searchOpenvpnServer = !!(await showing(['Seeded B']));
    setValue(field, 'b-gateway.example.net 1194');
    checks.searchNoPort = !!(await waitFor(() => document.querySelector('.sidebar .no-match')));
    setValue(field, 'sstp');
    checks.searchType = !!(await showing(['Seeded S']));
    setValue(field, 'seeded');
    await showing(['Seeded B', 'Seeded S', l2]);
    const key = (k, extra = {}) => field.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...extra }));
    const activeName = () => document.querySelector('nav .row.item.active .name .label')?.textContent;
    const first = activeName();
    key('ArrowDown');
    await sleep(150);
    const second = activeName();
    key('ArrowUp');
    await sleep(150);
    checks.searchArrows = !!first && !!second && first !== second && activeName() === first;
    key('ArrowDown');
    await sleep(150);
    key('Enter');
    checks.searchEnter = !!(await shown(second));
    setValue(field, 'zz-nothing-árvíz');
    const empty = await waitFor(() => document.querySelector('.sidebar .no-match'));
    const quoted = { en: '“zz-nothing-árvíz”', hu: '„zz-nothing-árvíz”' }[vm.language];
    const english = !!empty && empty.textContent.includes('No connections match');
    checks.searchEmpty = !!empty && shownNames().length === 0 && empty.textContent.includes(quoted) && english === (vm.language === 'en');
    empty?.querySelector('button.clear-search')?.click();
    checks.searchCleared = !!(await showing(all)) && field.value === '';
    setValue(field, 'seeded');
    await showing(['Seeded B', 'Seeded S', l2]);
    checks.searchNoDrag = !!document.querySelector('nav .tree.filtering');
    key('Escape');
    checks.searchEscape = !!(await showing(all)) && field.value === '' && document.activeElement === field;
    key('Escape');
    checks.searchBlur = document.activeElement !== field;
    // The platform's find shortcut: Cmd+F on macOS, Ctrl+F on Windows and Linux.
    const ctrl = os !== 'macos';
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'f', metaKey: !ctrl, ctrlKey: ctrl, bubbles: true, cancelable: true }));
    checks.searchCmdF = document.activeElement === field;
    field.blur();

    // The New menu (its longest item in the run's language) inside the window, not cut at the left edge.
    document.querySelector('.sidebar .toolbar button').click();
    checks.newMenuInside = await inside('.sidebar .menu', 'newMenuInside');
    checks.newMenuNoOverflow = [...document.querySelectorAll('.sidebar .menu button')].every((b) => b.scrollWidth <= b.clientWidth);
    escape();
    await waitFor(() => !document.querySelector('.sidebar .menu'));
    // A connection's context menu at the window's corners, and its colour picker at the bottom right.
    for (const [corner, name] of [
      [({ width, height }) => [width - 2, height - 2], 'contextBottomRight'],
      [({ width }) => [width - 2, 2], 'contextTopRight'],
      [({ height }) => [1, height - 1], 'contextBottomLeft'],
    ]) {
      const [x, y] = corner(viewport());
      contextAt(row('Seeded B'), x, y);
      checks[name] = await inside('.menu[role=menu]', name);
      if (name === 'contextBottomRight') {
        const colour = document.querySelector('.menu [data-action="colour"]');
        colour?.click();
        checks.pickerInside = !!colour && (await inside('.picker', 'pickerInside'));
      }
      escape();
      await waitFor(() => !document.querySelector('.menu[role=menu], .picker'));
    }

    // New, then delete it.
    document.querySelector('.sidebar .toolbar button').click();
    (await waitFor(() => document.querySelector('.sidebar .menu button'))).click();
    checks.created = !!(await waitFor(() => document.querySelector('.detail h1')?.textContent.includes('OpenVPN')));
    document.querySelector('.header button.icon.destructive').click();
    (await waitFor(() => document.querySelector('.alert button.destructive'))).click();
    checks.deleted = !!(await waitFor(() => document.querySelector('.empty')));
    // WireGuard keys: a new WireGuard connection's "Generate Key Pair" writes a private key into the config and the
    // public key the backend derives appears (both 44 base64 characters, different); the private key field is
    // masked, and so is the key in the config text until "Show secrets"; a second generation asks first
    // (cancelled: the key stays). Nothing is copied (the real clipboard).
    // Then it is deleted unsaved.
    document.querySelector('.sidebar .toolbar button').click();
    (await waitFor(() => document.querySelector('.sidebar .menu button[data-kind=wireguard]'))).click();
    const generate = await waitFor(() => document.querySelector('.wg-keys .generate-key-pair'));
    checks.wgPanel = !!generate && !document.querySelector('.wg-keys [data-public-key]') && !!document.querySelector('.wg-keys .no-key');
    generate?.click();
    const publicKey = await waitFor(() => document.querySelector('.wg-keys [data-public-key]')?.textContent);
    const masked = document.querySelector('.wg-keys input.privateKey');
    const privateKey = masked?.value;
    const wgKey = /^[A-Za-z0-9+/]{43}=$/;
    checks.wgPublicKey = wgKey.test(publicKey ?? '') && wgKey.test(privateKey ?? '') && publicKey !== privateKey;
    checks.wgPrivateMasked = masked?.type === 'password';
    // The config text shows the key masked and read-only (G1 of the client-credential audit) until "Show secrets":
    // then the real key, editable.
    const hidden = await waitFor(() => document.querySelector('textarea.config.masked'));
    checks.wgConfigMasked =
      !!hidden?.readOnly && /^PrivateKey = \u2022{16}$/m.test(hidden.value) && !hidden.value.includes(privateKey ?? '-');
    document.querySelector('.show-secrets input')?.click();
    const plain = await waitFor(() => {
      const area = document.querySelector('textarea.config');
      return area && !area.classList.contains('masked') ? area : null;
    });
    checks.wgShowSecrets = !!plain && !plain.readOnly && plain.value.includes(`PrivateKey = ${privateKey}`);
    document.querySelector('.wg-keys .generate-key-pair')?.click();
    checks.wgReplaceAsked = !!(await waitFor(() => document.querySelector('[role=alertdialog]')));
    document.querySelector('.alert button.cancel')?.click();
    await waitFor(() => !document.querySelector('[role=alertdialog]'));
    checks.wgKeyKept = document.querySelector('.wg-keys [data-public-key]')?.textContent === publicKey;
    document.querySelector('.header button.icon.destructive').click();
    (await waitFor(() => document.querySelector('.alert button.destructive'))).click();
    checks.wgDeleted = !!(await waitFor(() => document.querySelector('.empty')));
    // IKEv2 client certificate (G2/G4): a new IKEv2 connection (EAP template) has no client certificate panel and no
    // key password field; with `auth = pubkey` typed, the panel ("Import Client Certificate…", nothing imported yet,
    // no Remove) and the private key password field appear. The open panel itself is not driven. Deleted unsaved.
    document.querySelector('.sidebar .toolbar button').click();
    (await waitFor(() => document.querySelector('.sidebar .menu button[data-kind=strongswan]'))).click();
    const swanText = await waitFor(() => document.querySelector('textarea.config')?.value.includes('auth = eap-mschapv2') && document.querySelector('textarea.config'));
    const secretsBefore = document.querySelectorAll('.secret input[type=password]').length;
    checks.certPanelHiddenForEap = !!swanText && !document.querySelector('.client-cert');
    setValue(swanText, swanText.value.replace('auth = eap-mschapv2', 'auth = pubkey'));
    const importCert = await waitFor(() => document.querySelector('.client-cert .import-cert'), windows ? 2000 : 8000);
    if (windows) {
      // WinVPN signs with a computer certificate from Windows' store: no panel, no key password, the grey note.
      const note = await waitFor(() => document.querySelector('.platform-notes')?.textContent.includes('.p12'));
      checks.certWindowsNote = !!note && !importCert && !document.querySelector('.client-cert') && document.querySelectorAll('.secret input[type=password]').length === secretsBefore;
    } else {
      checks.certPanel = !!importCert && !importCert.disabled && !!document.querySelector('.client-cert .no-cert') && !document.querySelector('.client-cert .remove-cert');
      checks.certKeyPassword = (await waitFor(() => document.querySelectorAll('.secret input[type=password]').length === secretsBefore + 1)) === true;
    }
    document.querySelector('.header button.icon.destructive').click();
    (await waitFor(() => document.querySelector('.alert button.destructive'))).click();
    checks.certDeleted = !!(await waitFor(() => document.querySelector('.empty')));
    // The navigation allowlist: leaving the app's origin is cancelled. `about:blank` loads without the network,
    // so were it allowed, the page would be replaced and the result below would never be written.
    const origin = window.location.origin;
    window.location.href = 'about:blank';
    await sleep(1000);
    checks.navigationBlocked = window.location.origin === origin && !!document.querySelector('nav .row');
    row('Smoke A').click();
    await shown('Smoke A');
    await waitFor(() => document.querySelector('input.wide')?.value === 'Smoke A');
    const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
    setValue(document.querySelector('input.wide'), failed.length === 0 ? 'SMOKE OK' : `SMOKE FAILED ${failed.join(',')} ${geometry.join(' ')}`.trim());
  } catch (e) {
    const input = document.querySelector('input.wide');
    if (input) setValue(input, `SMOKE ERROR ${String(e).slice(0, 80)}`);
  }
  await sleep(400);
  save();
})();
