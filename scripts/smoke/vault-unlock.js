// Driven by scripts/smoke-manage.sh, in the unlock window (`vault-unlock`). The app's smoke driver fills in
// __MODE__ and the secrets. `wrong-then-right`: a wrong password first – the delay's countdown must show and hold the
// Unlock button – then __PASSWORD__. `recovery`: "Use recovery key", __RECOVERY_KEY__ and __NEW_PASSWORD__ twice.
// `password`: __PASSWORD__. Anything unexpected stops the script, and the driver reports that the vault did not open.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 40000) => {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const value = fn();
      if (value) return value;
      await sleep(100);
    }
    throw new Error('timeout');
  };
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const enabled = (selector) => () => {
    const b = document.querySelector(selector);
    return b && !b.disabled ? b : null;
  };
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  // The product's name (MacVPN, WinVPN) as the platform reports it.
  const product = (await window.__TAURI_INTERNALS__.invoke('get_platform')).productName;
  const texts = {
    en: { locked: `${product} is locked`, reset: 'Reset the master password' },
    hu: { locked: `A ${product} zárolva van`, reset: 'A mesterjelszó visszaállítása' },
  }[vm.language];
  const title = () => document.querySelector('.unlock h1')?.textContent.trim();
  await waitFor(() => title() === texts.locked);
  const password = () => document.querySelector('.unlock input[data-field=password]:not(:disabled)');
  const mode = '__MODE__';

  if (mode === 'wrong-then-right') {
    setValue(await waitFor(password), 'not-the-master-password');
    (await waitFor(enabled('.unlock button.unlock-button'))).click();
    // The countdown, with Unlock held.
    await waitFor(() => document.querySelector('.unlock .wait'));
    setValue(await waitFor(password), '__PASSWORD__');
    if (!document.querySelector('.unlock button.unlock-button')?.disabled) throw new Error('Unlock during the delay');
  } else if (mode === 'recovery') {
    (await waitFor(enabled('.unlock button.use-recovery'))).click();
    await waitFor(() => title() === texts.reset);
    setValue(await waitFor(() => document.querySelector('.unlock input[data-field=recovery]:not(:disabled)')), '__RECOVERY_KEY__'.toLowerCase());
    setValue(document.querySelector('.unlock input[data-field=new]'), '__NEW_PASSWORD__');
    setValue(document.querySelector('.unlock input[data-field=again]'), '__NEW_PASSWORD__');
    (await waitFor(enabled('.unlock button.recover-button'))).click();
    return;
  } else {
    setValue(await waitFor(password), '__PASSWORD__');
  }
  (await waitFor(enabled('.unlock button.unlock-button'))).click();
})();
