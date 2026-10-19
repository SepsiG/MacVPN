// Driven by scripts/smoke-manage.sh (MACVPN_SMOKE_DIR, debug build, sandbox only), in an MFA prompt window: the
// window must fit its content (no scrolling); the mock code prompt is answered with 123456 once its field takes input (only if the server's text is labelled and
// the field is secure), the mock web sign-in with "Open in Browser" (only if the ASCII host is shown). The
// backend logs the results; the sandbox does not open the URL.
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
  // With screenshots on (the driver sets 'pending'), wait here until it took one.
  const shot = async () => {
    if (window.smokeShot === 'pending') await waitFor(() => window.smokeShot === 'done', 30000);
  };
  const setValue = (el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const target = await waitFor(() => document.querySelector('input.code') || document.querySelector('button.open'));
  if (!target) return;
  const fitted = !!(await waitFor(fits, 5000));
  await shot();
  await waitFor(() => !target.disabled);
  if (target.tagName === 'INPUT') {
    const labelled = !!document.querySelector('.prompt .caption') && document.querySelector('.prompt .text')?.textContent.includes('Smoke');
    setValue(target, fitted && labelled && target.type === 'password' ? '123456' : 'wrong');
    await sleep(200);
    document.querySelector('button.continue').click();
  } else if (fitted && document.querySelector('.prompt .host')?.textContent === 'sso.example.com') {
    target.click();
  } else {
    document.querySelector('.buttons button').click();
  }
})();
