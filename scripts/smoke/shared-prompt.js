// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in a credential prompt window
// (`cred-*`) of a connection linked to the shared credential "Smoke Cred", which has a user name and no password.
// The window must ask for the password only and name the credential with its use count ("used by 2"); once the
// input lock passed, it types the password, leaves "Save" ticked (the password goes into the shared credential)
// and clicks Connect. Anything wrong: Cancel, which the backend reports.
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
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const connect = await waitFor(() => document.querySelector('.credentials button.connect'));
  const cancel = document.querySelector('.credentials button.cancel');
  if (!connect || !cancel) return;
  const vm = await window.__TAURI_INTERNALS__.invoke('get_view_model');
  const prompt = vm.credentialPrompts[0];
  const line = {
    en: 'Password for Smoke Cred — used by 2 connections',
    hu: 'A(z) Smoke Cred jelszava — 2 kapcsolat használja',
  }[vm.language];
  const inputs = () => [...document.querySelectorAll('.credentials input[data-field]')];
  const shared = document.querySelector('.credentials .shared')?.textContent.trim() ?? '';
  const ok =
    !!prompt &&
    prompt.credentialName === 'Smoke Cred' &&
    prompt.usedBy === 2 &&
    inputs().map((i) => i.dataset.field).join('+') === 'password' &&
    shared.includes('Smoke Cred') &&
    shared === line &&
    !!document.querySelector('.credentials .save input[type=checkbox]')?.checked;
  if (!ok) {
    cancel.click();
    return;
  }
  await waitFor(() => !inputs()[0].disabled, 5000);
  setValue(inputs()[0], 'smoke-shared-pass');
  await waitFor(() => !connect.disabled, 3000);
  connect.click();
})();
