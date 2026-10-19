// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in a credential prompt window
// (`cred-*`) the driver opened with the most content a prompt can have: the retry line, all four fields (user name,
// password, PSK, private key password), "Save" and its hint, and – after Connect with a value the backend refuses
// (a tab: a control character) – the inline error. The window must still fit it all without scrolling. Then
// Cancel; anything wrong: Connect with valid values instead (the driver logs the answer).
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
  // The window fits its content (fit_window): nothing scrolls, and no more than the content's own padding below.
  const fits = () => {
    const page = document.scrollingElement;
    const content = document.getElementById('app')?.getBoundingClientRect().height ?? 0;
    return content > 0 && page.scrollHeight <= page.clientHeight && window.innerHeight - content <= 2;
  };
  const shot = async () => {
    if (window.smokeShot === 'pending') await waitFor(() => window.smokeShot === 'done', 30000);
  };
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const connect = await waitFor(() => document.querySelector('.credentials button.connect'));
  const cancel = document.querySelector('.credentials button.cancel');
  if (!connect || !cancel) return;
  const inputs = () => [...document.querySelectorAll('.credentials input[data-field]')];
  const fields = inputs().map((i) => i.dataset.field).join('+');
  const shape = fields === 'username+password+psk+keyPassword' && !!document.querySelector('.credentials .retry');
  await waitFor(() => !inputs()[0].disabled, 5000);
  for (const input of inputs()) setValue(input, 'x');
  setValue(inputs()[1], 'bad\tvalue');
  await waitFor(() => !connect.disabled, 3000);
  connect.click();
  const refused = !!(await waitFor(() => document.querySelector('.credentials .refused'), 5000));
  const fitted = !!(await waitFor(fits, 5000));
  await shot();
  if (shape && refused && fitted) {
    cancel.click();
  } else {
    for (const input of inputs()) setValue(input, 'valid');
    await waitFor(() => !connect.disabled, 3000);
    connect.click();
  }
})();
