// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only): uses the real Connections
// window like a user and writes the result into the first connection's name (saved through the UI, so the
// store proves the round trip). Language independent: only classes and structure are used, except one check that
// the window shows the view model's language (the Save button's English or Hungarian text).
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
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const nativeView = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
    checks.noSecretInView = !JSON.stringify(nativeView).includes('native-secret') && nativeView.hasStoredSecret.password;
    // Saving again with the field untouched keeps the stored password.
    setValue(document.querySelector('.form .field input[type=text]'), 'Seeded L2');
    await sleep(300);
    save();
    await sleep(600);
    const again = await invoke('editor_open', { id: '31111111-2222-4333-8444-555555555555' });
    checks.secretKept = again.hasStoredSecret.password && again.fields.password === null && !again.dirty;

    // New, then delete it.
    document.querySelector('.sidebar .toolbar button').click();
    (await waitFor(() => document.querySelector('.sidebar .menu button'))).click();
    checks.created = !!(await waitFor(() => document.querySelector('.detail h1')?.textContent.includes('OpenVPN')));
    document.querySelector('.header button.icon.destructive').click();
    (await waitFor(() => document.querySelector('.alert button.destructive'))).click();
    checks.deleted = !!(await waitFor(() => document.querySelector('.empty')));
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
    setValue(document.querySelector('input.wide'), failed.length === 0 ? 'SMOKE OK' : `SMOKE FAILED ${failed.join(',')}`);
  } catch (e) {
    const input = document.querySelector('input.wide');
    if (input) setValue(input, `SMOKE ERROR ${String(e).slice(0, 80)}`);
  }
  await sleep(400);
  save();
})();
