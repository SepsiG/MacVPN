// node --test: the Connections window's search – diacritics both ways, the matched fields, folder ancestry (a
// folder stays for a match inside it, its own name match keeps all its contents), catalog names, the empty result,
// the keyboard's steps and the highlighted part of a name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fold, highlight, matches, normalizeQuery, searchTree, step } from './search.ts';
import { folder, item, row, TREE, ROWS } from '../folders/fixtures.ts';
import type { Row } from '../api.ts';

const ids = (rows: { id: string }[] | undefined) => (rows ?? []).map((r) => r.id);
const named = (id: string, name: string, extra: Pick<Partial<Row>, 'typeLabel' | 'kind' | 'server' | 'catalog'> = {}): Row => ({ ...row(id), name, ...extra }) as Row;

test('folding drops case and diacritics, Hungarian ones included', () => {
  assert.equal(fold('ÁRVÍZTŰRŐ tükörfúrógép'), 'arvizturo tukorfurogep');
  assert.equal(normalizeQuery('  Árvíz   tűrő '), 'arviz turo');
  assert.ok(matches('Árvíztűrő iroda', 'arvizturo'));
  assert.ok(matches('Arvizturo iroda', 'árvíztűrő'), 'typed with accents, stored without');
  assert.ok(matches('Győr VPN', 'GYOR'));
  assert.ok(!matches('Győr VPN', 'pécs'));
  assert.ok(!matches('anything', '   '), 'a blank query matches nothing (it is no search)');
});

test('no query: no filtering', () => {
  assert.equal(searchTree(TREE, ROWS, ''), null);
  assert.equal(searchTree(TREE, ROWS, '  '), null);
});

test('a connection matches on its name, type label, server and team catalog', () => {
  const rows = [
    named('a', 'Budapest iroda'),
    named('b', 'Home', { typeLabel: 'WireGuard', kind: 'wireguard' }),
    named('c', 'Branch', { typeLabel: 'L2TP', kind: 'l2tp', server: 'l2tp.szeged.example' }),
    named('d', 'Shared', { catalog: { catalogId: 'k', name: 'Cég katalógus', pendingRemoval: false, profileOutdated: false } }),
    named('e', 'Office', { server: 'ovpn-gw.debrecen.example' }),
  ];
  const tree = rows.map((r) => item(r.id, null, 0));
  assert.deepEqual(searchTree(tree, rows, 'budapest')?.items, ['a']);
  assert.deepEqual(searchTree(tree, rows, 'wireguard')?.items, ['b']);
  assert.deepEqual(searchTree(tree, rows, 'SZEGED')?.items, ['c']);
  assert.deepEqual(searchTree(tree, rows, 'ceg katalogus')?.items, ['d'], 'the catalog name, without its accents');
  assert.deepEqual(searchTree(tree, rows, 'DEBRECEN.example')?.items, ['e'], "an OpenVPN config's remote host");
  assert.deepEqual(searchTree(tree, rows, 'openvpn')?.items, ['a', 'd', 'e'], 'the type label of the fixture rows');
});

test('a folder stays for a match inside it, at any depth, with its ancestors', () => {
  const rows = ROWS.map((r) => (r.id === 'd1' ? named('d1', 'Árvíztűrő gép') : r));
  const result = searchTree(TREE, rows, 'arvizturo');
  assert.deepEqual(ids(result?.tree), ['Work', 'Clients', 'Deep', 'd1']);
  assert.deepEqual(result?.items, ['d1']);
});

test('a folder whose own name matches keeps all its contents; its siblings go', () => {
  const tree = TREE.map((r) => (r.id === 'Clients' ? { ...r, name: 'Ügyfelek' } : r));
  const result = searchTree(tree, ROWS, 'ugyfel');
  assert.deepEqual(ids(result?.tree), ['Work', 'Clients', 'Deep', 'd1', 'c1']);
  assert.deepEqual(result?.items, ['d1', 'c1'], 'w1–w3 are only in the parent folder');
});

test('a collapsed folder does not hide a match (the stored state is not read)', () => {
  const tree = TREE.map((r) => (r.type === 'folder' ? { ...r, collapsed: true } : r));
  assert.deepEqual(ids(searchTree(tree, ROWS, 'c1')?.tree), ['Work', 'Clients', 'c1']);
  assert.ok(tree.every((r) => r.type !== 'folder' || r.collapsed), 'unchanged');
});

test('an empty folder matches by name only; nothing matches: an empty result', () => {
  assert.deepEqual(ids(searchTree(TREE, ROWS, 'archive')?.tree), ['Archive']);
  assert.deepEqual(searchTree(TREE, ROWS, 'archive')?.items, []);
  const none = searchTree(TREE, ROWS, 'no such thing');
  assert.deepEqual(none, { tree: [], items: [] });
  // An item without its row (an older view model) never matches.
  assert.deepEqual(searchTree([folder('F', null, 0), item('ghost', 'F', 1)], [], 'ghost')?.tree, []);
});

test('Up and Down move through the results and stop at the ends', () => {
  const items = ['a', 'b', 'c'];
  assert.equal(step(items, null, 1), 'a');
  assert.equal(step(items, null, -1), 'c');
  assert.equal(step(items, 'a', 1), 'b');
  assert.equal(step(items, 'c', 1), 'c');
  assert.equal(step(items, 'a', -1), 'a');
  assert.equal(step(items, 'gone', 1), 'a');
  assert.equal(step([], 'a', 1), null);
});

test('the matched part of a name is highlighted in the original spelling', () => {
  assert.deepEqual(highlight('Árvíztűrő gép', 'arvizturo'), [
    { text: 'Árvíztűrő', match: true },
    { text: ' gép', match: false },
  ]);
  assert.deepEqual(highlight('Iroda Győr', 'gyor'), [
    { text: 'Iroda ', match: false },
    { text: 'Győr', match: true },
  ]);
  // Decomposed input (NFD, as some pastes are) maps back without cutting a letter from its accent.
  const nfd = 'Győr'.normalize('NFD');
  assert.deepEqual(highlight(nfd, 'gyo'), [
    { text: nfd.slice(0, 4), match: true },
    { text: 'r', match: false },
  ]);
  assert.deepEqual(highlight('Office', ''), [{ text: 'Office', match: false }]);
  assert.deepEqual(highlight('Office', 'xyz'), [{ text: 'Office', match: false }]);
});
