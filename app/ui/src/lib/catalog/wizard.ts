// The publish wizard's rules (spec 7, plan Task 17), pure so `node --test` checks them: the steps of each flow,
// the folder tree with checkboxes (a ticked folder brings its whole subtree), the ticks of the review (team
// secrets opt-in, credential slots ticked by default, every inline key needs its own tick), the selection sent to
// the backend, and the team key's one-time reveal with the "retype one group" check.
import type { Row, TreeRow } from '../api.ts';
import { formatGroupInput } from '../vault/recovery.ts';
import type { ItemField, PublishPreview, SelectionInput } from './publishApi.ts';

/// A new catalog, a new version of a publication (its saved selection), or a team key rotation (the review of
/// the saved selection first, then the save panel).
export type Mode = 'new' | 'again' | 'rotate';
export type Step = 'select' | 'review' | 'name' | 'done';

const FLOWS: Record<Mode, readonly Step[]> = {
  new: ['select', 'review', 'name', 'done'],
  again: ['select', 'review', 'done'],
  rotate: ['review', 'done'],
};

export function stepsOf(mode: Mode): readonly Step[] {
  return FLOWS[mode];
}

/// Where a flow starts: a new version and a rotation open on the review of the saved selection.
export function firstStep(mode: Mode): Step {
  return mode === 'new' ? 'select' : 'review';
}

/// The step after `step` (`null`: none).
export function nextStep(mode: Mode, step: Step): Step | null {
  const flow = FLOWS[mode];
  const i = flow.indexOf(step);
  return i >= 0 && i + 1 < flow.length ? flow[i + 1] : null;
}

/// The step before `step` (`null`: none; nothing goes back from "done").
export function previousStep(mode: Mode, step: Step): Step | null {
  const flow = FLOWS[mode];
  const i = flow.indexOf(step);
  return step !== 'done' && i > 0 ? flow[i - 1] : null;
}

// MARK: - step 1: the tree with checkboxes

export interface Picked {
  folders: ReadonlySet<string>;
  connections: ReadonlySet<string>;
}

export const NOTHING: Picked = { folders: new Set(), connections: new Set() };

/// The folders above a row, nearest first.
export function ancestorsOf(tree: readonly TreeRow[], id: string): string[] {
  const parents = new Map<string, string | null>();
  for (const r of tree) if (r.type === 'folder') parents.set(r.id, r.parent);
  const start = tree.find((r) => r.id === id);
  const out: string[] = [];
  let parent = start?.parent ?? null;
  while (parent !== null && !out.includes(parent)) {
    out.push(parent);
    parent = parents.get(parent) ?? null;
  }
  return out;
}

/// A ticked folder above the row brings it along (its checkbox shows ticked and cannot be changed).
export function covered(tree: readonly TreeRow[], picked: Picked, id: string): boolean {
  return ancestorsOf(tree, id).some((f) => picked.folders.has(f));
}

/// Ticked: by itself or through a folder above it.
export function isPicked(tree: readonly TreeRow[], picked: Picked, row: TreeRow): boolean {
  const own = row.type === 'folder' ? picked.folders.has(row.id) : picked.connections.has(row.id);
  return own || covered(tree, picked, row.id);
}

/// Ticks or unticks a row. A ticked folder replaces the ticks inside it (the subtree goes with the folder); a row
/// covered by a ticked folder does not change.
export function toggle(tree: readonly TreeRow[], picked: Picked, row: TreeRow, on: boolean): Picked {
  if (covered(tree, picked, row.id)) return picked;
  const folders = new Set(picked.folders);
  const connections = new Set(picked.connections);
  if (row.type === 'item') {
    if (on) connections.add(row.id);
    else connections.delete(row.id);
    return { folders, connections };
  }
  if (!on) {
    folders.delete(row.id);
    return { folders, connections };
  }
  folders.add(row.id);
  for (const r of tree) {
    if (r.id !== row.id && ancestorsOf(tree, r.id).includes(row.id)) {
      folders.delete(r.id);
      connections.delete(r.id);
    }
  }
  return { folders, connections };
}

/// A row of a team catalog (subscribed): never offered. `catalog` is the subscriber side's badge.
type Subscribed = { catalog?: unknown };

/// The rows step 1 offers: the user's own folders and managed connections. System VPNs, team catalog connections
/// and the folders a team catalog owns are left out (the publish would refuse them).
export function offered(tree: readonly TreeRow[], rows: readonly Row[], teamFolders: Readonly<Record<string, string>> = {}): TreeRow[] {
  const byId = new Map(rows.map((r) => [r.id, r]));
  return tree.filter((r) => {
    if (r.type === 'folder') return !(r.id in teamFolders) && !ancestorsOf(tree, r.id).some((f) => f in teamFolders);
    const row = byId.get(r.id) as (Row & Subscribed) | undefined;
    return !!row && row.managed && (row.catalog ?? null) === null && !ancestorsOf(tree, r.id).some((f) => f in teamFolders);
  });
}

/// The connections the selection brings (ticked or inside a ticked folder), among the offered rows.
export function pickedConnections(tree: readonly TreeRow[], shown: readonly TreeRow[], picked: Picked): number {
  return shown.filter((r) => r.type === 'item' && isPicked(tree, picked, r)).length;
}

// MARK: - step 2: the review's ticks

export interface Ticks {
  /// `item|psk`, `item|keypass`: opt-in.
  secrets: ReadonlySet<string>;
  /// `item|wireguardPrivateKey`, …: each one needs its own tick.
  inline: ReadonlySet<string>;
  /// Credential slot ids: ticked by default.
  slots: ReadonlySet<string>;
}

export const NO_TICKS: Ticks = { secrets: new Set(), inline: new Set(), slots: new Set() };

export function fieldKey(f: ItemField): string {
  return `${f.item}|${f.field}`;
}

function split(key: string): ItemField {
  const i = key.indexOf('|');
  return { item: key.slice(0, i), field: key.slice(i + 1) };
}

export function withTick(set: ReadonlySet<string>, key: string, on: boolean): Set<string> {
  const next = new Set(set);
  if (on) next.add(key);
  else next.delete(key);
  return next;
}

/// The saved selection of a publication, as ticks and picks.
export function fromSelection(selection: SelectionInput | undefined): { picked: Picked; ticks: Ticks } {
  if (!selection) return { picked: NOTHING, ticks: NO_TICKS };
  return {
    picked: { folders: new Set(selection.folders), connections: new Set(selection.connections) },
    ticks: {
      secrets: new Set(selection.secrets.map((s) => fieldKey({ item: s.item, field: s.field }))),
      inline: new Set(selection.inlineSecrets.map((s) => fieldKey({ item: s.item, field: s.secret }))),
      slots: new Set(selection.slots),
    },
  };
}

/// Every credential slot the review shows for the first time is ticked ("without user names or passwords"); one
/// the user unticked stays unticked. `seen` collects the slots already shown. In a flow from a saved selection the
/// first review keeps the saved ticks (`tickNew` false).
export function defaultSlots(ticks: Ticks, preview: PublishPreview, seen: Set<string>, tickNew: boolean): Ticks {
  const slots = new Set(ticks.slots);
  for (const slot of preview.availableSlots) {
    if (seen.has(slot.id)) continue;
    seen.add(slot.id);
    if (tickNew) slots.add(slot.id);
  }
  return { ...ticks, slots };
}

/// What the backend gets: the picks without the rows a ticked folder covers, and only the ticks the review
/// offers (once there is a review).
export function selectionOf(tree: readonly TreeRow[], picked: Picked, ticks: Ticks, preview: PublishPreview | null): SelectionInput {
  const offeredKeys = (list: ItemField[] | undefined) => (list ? new Set(list.map(fieldKey)) : null);
  const secretKeys = offeredKeys(preview?.availableSecrets);
  const inlineKeys = offeredKeys(preview?.inlineSecrets);
  const slotIds = preview ? new Set(preview.availableSlots.map((s) => s.id)) : null;
  const keep = (key: string, allowed: Set<string> | null) => allowed === null || allowed.has(key);
  return {
    folders: [...picked.folders].filter((id) => !covered(tree, picked, id)).sort(),
    connections: [...picked.connections].filter((id) => !covered(tree, picked, id)).sort(),
    secrets: [...ticks.secrets].filter((k) => keep(k, secretKeys)).sort().map(split),
    slots: [...ticks.slots].filter((id) => keep(id, slotIds)).sort(),
    inlineSecrets: [...ticks.inline]
      .filter((k) => keep(k, inlineKeys))
      .sort()
      .map(split)
      .map((f) => ({ item: f.item, secret: f.field })),
  };
}

/// Why the review cannot go on: refused connections (fix them first), inline keys without their tick, nothing
/// to publish. Empty: ready.
export type Blocker = 'refused' | 'inline' | 'empty';

export function reviewBlockers(preview: PublishPreview | null, ticks: Ticks): Blocker[] {
  if (!preview) return ['empty'];
  const out: Blocker[] = [];
  if (preview.refused.length > 0) out.push('refused');
  if (preview.inlineSecrets.some((f) => !ticks.inline.has(fieldKey(f)))) out.push('inline');
  if (preview.counts.connections + preview.counts.folders === 0) out.push('empty');
  return out;
}

/// The publications whose next version would stop announcing the successor key their last one announced (the
/// review's warning; empty: none).
export function droppedSuccessorIn(preview: PublishPreview | null): string[] {
  return preview?.successorDroppedIn ?? [];
}

/// "Rotate Team Key" republishes the saved selection without a review: the backend refuses it while a published
/// connection changed since the last publish, so the list offers "Publish New Version" in its place.
export function rotateNeedsReview(publication: { changed: number }): boolean {
  return publication.changed > 0;
}

// MARK: - the team key, shown once

export const TEAM_KEY_PREFIX = 'TEAM-';

/// The key's groups of four, without the `TEAM-` prefix.
export function teamKeyGroups(key: string): string[] {
  const body = key.trim().toUpperCase();
  return (body.startsWith(TEAM_KEY_PREFIX) ? body.slice(TEAM_KEY_PREFIX.length) : body).split('-').filter((g) => g !== '');
}

/// A random group to retype (`random` in [0, 1)).
export function pickGroup(count: number, random: () => number = Math.random): number {
  return Math.min(count - 1, Math.max(0, Math.floor(random() * count)));
}

/// The typed group matches (case and the Crockford look-alikes do not matter, as for the recovery key).
export function groupMatches(expected: string | null, typed: string): boolean {
  return expected !== null && expected !== '' && formatGroupInput(typed) === expected.toUpperCase();
}

/// The reveal: the key shown with Copy and "I Saved It"; then only the asked group is kept (the key is gone from
/// the page and from this state); closed: nothing is kept.
export interface Reveal {
  step: 'key' | 'confirm' | 'closed';
  key: string | null;
  /// The group asked for (0-based).
  group: number | null;
  /// That group's text, for the check.
  expected: string | null;
}

export function reveal(key: string): Reveal {
  return { step: 'key', key, group: null, expected: null };
}

export function savedIt(state: Reveal, random: () => number = Math.random): Reveal {
  const groups = teamKeyGroups(state.key ?? '');
  if (groups.length === 0) return closeReveal();
  const group = pickGroup(groups.length, random);
  return { step: 'confirm', key: null, group, expected: groups[group] };
}

export function closeReveal(): Reveal {
  return { step: 'closed', key: null, group: null, expected: null };
}
