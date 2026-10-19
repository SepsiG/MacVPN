// The control API's test client for scripts/smoke-manage.sh (the full example client is
// examples/macvpn-control-client): pair, hello, list, up the target connection, hold it a moment, close the
// socket. Usage: node control-client.mjs <socket> <connection id> <result.json>. The token stays in memory and is
// never printed; the result file records what happened.
import net from 'node:net';
import { writeFileSync } from 'node:fs';

const [socketPath, target, out] = process.argv.slice(2);
const result = { steps: [] };
const step = (name, ok, extra = {}) => result.steps.push({ name, ok, ...extra });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// One socket connection with a line reader.
function open() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let buffer = '';
    const lines = [];
    const waiters = [];
    let closed = false;
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buffer += chunk;
      let i;
      while ((i = buffer.indexOf('\n')) >= 0) {
        const line = JSON.parse(buffer.slice(0, i));
        buffer = buffer.slice(i + 1);
        lines.push(line);
        waiters.splice(0).forEach((w) => w());
      }
    });
    socket.on('close', () => {
      closed = true;
      waiters.splice(0).forEach((w) => w());
    });
    socket.on('error', reject);
    socket.on('connect', () =>
      resolve({
        send: (obj) => socket.write(`${JSON.stringify(obj)}\n`),
        /// The next line (or null once closed), waiting at most `ms`.
        async next(ms) {
          const deadline = Date.now() + ms;
          while (lines.length === 0 && !closed && Date.now() < deadline) {
            await new Promise((r) => {
              waiters.push(r);
              setTimeout(r, 200);
            });
          }
          return lines.shift() ?? null;
        },
        end: () => socket.end(),
      }),
    );
  });
}

try {
  const pairing = await open();
  pairing.send({ op: 'pair', name: 'smoke-client' });
  const paired = await pairing.next(150000);
  const token = paired?.ok ? paired.token : null;
  step('pair', typeof token === 'string' && token.length === 43 && typeof paired.client_id === 'string', { error: paired?.error ?? null });
  pairing.end();
  if (token) {
    const c = await open();
    c.send({ op: 'hello', token });
    const hello = await c.next(10000);
    step('hello', hello?.ok === true && hello.api === 1);
    c.send({ id: 1, op: 'list' });
    const list = await c.next(10000);
    const ids = list?.connections?.map((x) => x.id) ?? [];
    step('list', list?.id === 1 && list.ok === true && ids.length === 1 && ids[0] === target, { ids });
    c.send({ id: 2, op: 'up', connection: target });
    const events = [];
    let reply = null;
    while (!reply) {
      const line = await c.next(60000);
      if (line === null) break;
      if (line.event === 'state') events.push(line.state);
      else if (line.id === 2) reply = line;
    }
    step('up', reply?.ok === true && reply.state === 'connected', { events, error: reply?.error ?? null });
    // Hold it while the app shows "Held by", then close the socket: the lease ends.
    await sleep(4000);
    c.end();
    step('closed', true);
  }
} catch (e) {
  step('error', false, { error: String(e) });
}
writeFileSync(out, JSON.stringify(result, null, 2));
