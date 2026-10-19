// Driven by scripts/smoke-manage.sh, in the master password window (`vault-password`, mode `change`). The app's
// smoke driver fills in __PASSWORD__ (the current one) and __NEW_PASSWORD__. Types them, waits for "changed" in
// the view model's language, and closes the window. Anything unexpected stops the script.
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (fn, ms = 30000) => {
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
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const done = { en: 'The master password was changed', hu: 'A mesterjelszó megváltozott' }[vm.language];
  if (vm.vault.passwordMode !== 'change') throw new Error('not the change mode');
  setValue(await waitFor(() => document.querySelector('.password input[data-field=current]:not(:disabled)')), '__PASSWORD__');
  setValue(document.querySelector('.password input[data-field=new]'), '__NEW_PASSWORD__');
  setValue(document.querySelector('.password input[data-field=again]'), '__NEW_PASSWORD__');
  (await waitFor(() => {
    const b = document.querySelector('.password button.submit');
    return b && !b.disabled ? b : null;
  })).click();
  await waitFor(() => document.querySelector('.password h1')?.textContent.trim() === done);
  document.querySelector('.password button.close').click();
})();
