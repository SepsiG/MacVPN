// node --test: OpenVPN's "Send all traffic over VPN" on Linux (L-b Task 23): the three choices in order, shown only
// for OpenVPN on Linux, and the help text that says what each means (with OpenVPN < 2.7, what "Server decides" does
// then). The config rewrite itself is the backend's (`openvpn_routing_read` / `_write`).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { helpText, pushVisible, routingOptions, visible } from './openvpnRouting.ts';

const tr = (key: string, ...args: (string | number)[]) => (args.length ? `<${key}|${args.join('|')}>` : `<${key}>`);

test('the three choices in order: Server decides, Always, Never', () => {
  const options = routingOptions(tr);
  assert.deepEqual(
    options.map((o) => o.id),
    ['server', 'always', 'never'],
  );
  assert.deepEqual(
    options.map((o) => o.label),
    ['<Server decides>', '<Always>', '<Never (split tunnel)>'],
  );
});

test('the control is shown only for OpenVPN on Linux', () => {
  assert.equal(visible('linux', 'openvpn'), true);
  for (const [os, kind] of [
    ['macos', 'openvpn'],
    ['windows', 'openvpn'],
    ['linux', 'wireguard'],
    ['linux', 'strongswan'],
    ['linux', 'l2tp'],
    ['linux', 'cisco'],
    ['linux', 'sstp'],
  ] as const) {
    assert.equal(visible(os, kind), false, `${os} ${kind}`);
  }
});

test('the help text says what each choice means', () => {
  assert.equal(helpText('server', { pushVisible: true }, tr), "<The server's redirect-gateway decides.>");
  assert.equal(helpText('always', { pushVisible: true }, tr), '<All traffic goes through the VPN (redirect-gateway def1).>');
  assert.equal(
    helpText('never', { pushVisible: true }, tr),
    "<Only the VPN's own networks go through it; a redirect-gateway from the server is ignored.>",
  );
});

test('with OpenVPN older than 2.7, "Server decides" says it falls back to the profile', () => {
  const text = helpText('server', { pushVisible: false }, tr);
  assert.match(text, /2\.7/);
  assert.match(text, /profile/);
  // Always and Never mean the same with any OpenVPN.
  assert.equal(helpText('always', { pushVisible: false }, tr), helpText('always', { pushVisible: true }, tr));
  assert.equal(helpText('never', { pushVisible: false }, tr), helpText('never', { pushVisible: true }, tr));
});


test('pushVisible comes from System Status: OpenVPN row flag, assumed before the first check', () => {
  const row = { ok: true, detail: '' };
  assert.equal(pushVisible(undefined), true);
  const nm = (flag?: boolean) => ({
    networkmanager: row,
    kinds: [{ kind: 'openvpn', row, packages: 'network-manager-openvpn', ...(flag === undefined ? {} : { pushVisible: flag }) }],
  });
  assert.equal(pushVisible(nm(true)), true);
  assert.equal(pushVisible(nm()), false, 'absent: OpenVPN older than 2.7');
  assert.equal(pushVisible({ networkmanager: row, kinds: [] }), false, 'no OpenVPN row');
});
