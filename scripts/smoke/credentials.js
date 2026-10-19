// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in a credential prompt window
// (`cred-*`). The first prompt (nothing stored) must show exactly the user name and password fields, the title in
// the view model's language, "Save" ticked and Connect disabled; once the inputs take input (the 1 s lock), it
// types the smoke user name and password, leaves "Save" ticked and clicks Connect. The re-prompt after a sign-in
// failure must show the retry line, the stored user name pre-filled and only the user name and password; it is
// cancelled. Anything wrong: the opposite answer (Cancel on the first prompt, Connect on the re-prompt), which the
// backend reports.
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
  const title = { en: 'Credentials needed', hu: 'Hitelesítő adatok szükségesek' }[vm.language];
  const inputs = () => [...document.querySelectorAll('.credentials input[data-field]')];
  const fields = inputs().map((i) => i.dataset.field).join('+');
  const save = document.querySelector('.credentials .save input[type=checkbox]');
  const retry = document.querySelector('.credentials .retry')?.textContent.trim() ?? '';
  const common =
    !!prompt &&
    document.querySelector('.credentials h1')?.textContent.trim() === title &&
    fields === 'username+password' &&
    inputs()[0]?.type === 'text' &&
    inputs()[1]?.type === 'password' &&
    !!save?.checked &&
    connect.disabled &&
    !document.querySelector('form, [type=submit], [autofocus]');
  if (prompt?.message) {
    // The re-prompt: the retry line and the stored user name.
    const ok = common && retry === prompt.message && inputs()[0].value === prompt.username;
    await waitFor(() => !inputs()[0].disabled, 5000);
    if (ok) {
      cancel.click();
    } else {
      setValue(inputs()[1], 'wrong');
      await sleep(200);
      connect.click();
    }
    return;
  }
  if (!common || retry !== '' || inputs()[0].value !== '') {
    cancel.click();
    return;
  }
  // The 1 s input lock: the fields take input once it passed.
  await waitFor(() => !inputs()[0].disabled, 5000);
  setValue(inputs()[0], 'smoke-user');
  setValue(inputs()[1], 'smoke-pass-4711');
  await waitFor(() => !connect.disabled, 3000);
  connect.click();
  // The page forgets the typed values once the answer is sent.
  await waitFor(() => inputs().every((i) => i.value === ''), 3000);
})();
