// The Connections window's search (pure, so `node --test` checks it): case- and diacritic-insensitive matching
// ("árvíztűrő" finds "arvizturo" and the other way round), the filtered folder tree, the keyboard's result list and
// the highlighted part of a name.
//
// What a connection matches on: its name, its type label (OpenVPN, WireGuard, …), its server host (the backend's
// sanitized host: never config text), the team catalog's name for a catalog row, and the names of the folders it
// is in. A folder stays when its own name matches (then with all its contents) or anything inside it does.
import type { Row, TreeRow } from '../api.ts';

/// `text` without case and diacritics, with the original index each folded character came from (`starts`) and the
/// index after it (`ends`), so a match in the folded text maps back to the original.
interface Folded {
  text: string;
  starts: number[];
  ends: number[];
}

function foldChar(c: string): string {
  return c.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
}

function foldWithMap(text: string): Folded {
  let out = '';
  const starts: number[] = [];
  const ends: number[] = [];
  let i = 0;
  for (const c of text) {
    const folded = foldChar(c);
    for (const f of folded) {
      out += f;
      for (let k = 0; k < f.length; k += 1) {
        starts.push(i);
        ends.push(i + c.length);
      }
    }
    i += c.length;
  }
  return { text: out, starts, ends };
}

/// Lower case, no diacritics (NFD without the combining marks): "Árvíztűrő" → "arvizturo".
export function fold(text: string): string {
  return foldWithMap(text).text;
}

/// The query as it is matched: folded, trimmed, inner whitespace collapsed ("" : no search).
export function normalizeQuery(query: string): string {
  return fold(query).trim().replace(/\s+/g, ' ');
}

/// `text` contains the (normalized) query.
export function matches(text: string | null | undefined, query: string): boolean {
  const q = normalizeQuery(query);
  return q !== '' && !!text && fold(text).includes(q);
}

export interface Segment {
  text: string;
  match: boolean;
}

/// `text` cut into the parts that match the query and the rest (the first match only; no query: one plain part).
export function highlight(text: string, query: string): Segment[] {
  const q = normalizeQuery(query);
  if (q === '' || text === '') return [{ text, match: false }];
  const folded = foldWithMap(text);
  const at = folded.text.indexOf(q);
  if (at < 0) return [{ text, match: false }];
  const start = folded.starts[at];
  let end = folded.ends[at + q.length - 1];
  // A decomposed letter's accents (combining marks fold to nothing) stay with it.
  const marks = /^\p{M}+/u.exec(text.slice(end));
  if (marks) end += marks[0].length;
  return [
    { text: text.slice(0, start), match: false },
    { text: text.slice(start, end), match: true },
    { text: text.slice(end), match: false },
  ].filter((s) => s.text !== '');
}

/// The searchable texts of a connection row (never a secret: the view model has none).
export function rowTexts(row: Row): string[] {
  return [row.name, row.typeLabel, row.server ?? '', row.catalog?.name ?? ''].filter((t) => t !== '');
}

export interface SearchResult {
  /// The tree rows to show, in display order (every folder in it is shown expanded).
  tree: TreeRow[];
  /// The connections in `tree`, in display order: what Up / Down move through.
  items: string[];
}

/// The tree filtered by `query`; null without a query (the whole tree, with the stored collapsed state).
export function searchTree(tree: readonly TreeRow[], rows: readonly Row[], query: string): SearchResult | null {
  const q = normalizeQuery(query);
  if (q === '') return null;
  const byId = new Map(rows.map((r) => [r.id, r]));
  const has = (text: string) => fold(text).includes(q);
  const keep = new Array<boolean>(tree.length).fill(false);
  // The open folders above the current row: their index and whether the folder or one above it matched by name.
  const stack: { index: number; depth: number; matched: boolean }[] = [];
  tree.forEach((row, index) => {
    while (stack.length > 0 && stack[stack.length - 1].depth >= row.depth) stack.pop();
    const inMatchedFolder = stack.length > 0 && stack[stack.length - 1].matched;
    let hit: boolean;
    if (row.type === 'folder') {
      hit = inMatchedFolder || has(row.name);
      stack.push({ index, depth: row.depth, matched: hit });
    } else {
      const r = byId.get(row.id);
      hit = !!r && (inMatchedFolder || rowTexts(r).some(has));
    }
    if (hit) {
      keep[index] = true;
      // Its folders stay too.
      for (const open of stack) keep[open.index] = true;
    }
  });
  const shown = tree.filter((_, i) => keep[i]);
  return { tree: shown, items: shown.filter((r) => r.type === 'item').map((r) => r.id) };
}

/// The result Up (-1) or Down (+1) moves to from `current` (none or gone: the first, or the last going up).
export function step(items: readonly string[], current: string | null, delta: 1 | -1): string | null {
  if (items.length === 0) return null;
  const at = current === null ? -1 : items.indexOf(current);
  if (at < 0) return delta > 0 ? items[0] : items[items.length - 1];
  return items[Math.min(items.length - 1, Math.max(0, at + delta))];
}
