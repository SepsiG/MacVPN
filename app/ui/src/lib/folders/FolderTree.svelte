<script lang="ts">
  // The Connections window's list as a folder tree (spec 3): folders with their colour, collapse chevron and
  // active count; the connections and system VPNs in them (pinned first, then by use), each with its effective
  // colour as a slim bar and a marker when the colour is its own. Drag and drop moves and reorders folders,
  // reorders the pins of a folder and moves items into folders (dnd.ts decides; a drop into itself or a subfolder is
  // refused before the backend is asked). The context menu: New Folder, Rename (inline), Colour, Move to Top Level,
  // Delete (with the two-step dialog); Pin / Unpin on an item.
  // A team catalog's folders and connections (spec 6) carry the "Team" badge and are read-only: they are never
  // dragged and nothing is dropped into them (the ghost says why); their context menu offers only what the user
  // may change – Pin / Unpin, the own colour ("Use team colour"), "Duplicate as personal connection…", and
  // "Install profile" when the catalog changed a native connection.
  // While the sidebar's search filters it (`filtered`, manage/search.ts), the tree shows only the matches and their
  // folders, every folder open (the stored collapsed state is left alone), the matched part of the names marked and
  // the keyboard's result (`active`) highlighted; nothing is dragged then (reordering a filtered tree would confuse).
  import { api, type FolderColor, type FolderTreeRow, type Row, type TreeRow } from '../api';
  import { engineLink } from '../format';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import TypeIcon from '../TypeIcon.svelte';
  import Modal from '../manage/Modal.svelte';
  import ColorPicker, { type ColorChoice } from './ColorPicker.svelte';
  import { pointAnchor, popover } from '../popover';
  import DeleteFolderDialog from './DeleteFolderDialog.svelte';
  import DuplicateDialog from '../catalog/DuplicateDialog.svelte';
  import TeamBadge from '../catalog/TeamBadge.svelte';
  import { catalogApi } from '../catalog/catalogApi';
  import { isTeamRoot, isTeamRow, teamOf } from '../catalog/status';
  import FolderIcon from './FolderIcon.svelte';
  import PublishedBadges from '../catalog/PublishedBadges.svelte';
  import { dropTarget, zoneOf, type DropAction, type Dragged, type Hover, type Drop } from './dnd';
  import { colorToken, descendantFolders, folderBadge, indentLevel, visibleRows } from './tree';
  import type { DeleteMode } from './tree';
  import { highlight, type SearchResult } from '../manage/search';

  let {
    rows,
    tree,
    selected,
    enabled,
    palette,
    teamFolders = {},
    onselect,
    query = '',
    filtered = null,
    active = null,
    onclearfilter = () => {},
  }: {
    rows: Row[];
    tree: TreeRow[];
    selected: string | null;
    /// Folders can be edited (otherwise: the ranked list with Pin / Unpin only).
    enabled: boolean;
    palette: FolderColor[];
    /// The folders team catalogs own: folder id → catalog id (read-only, the root carries the "Team" badge).
    teamFolders?: Record<string, string>;
    onselect: (id: string) => void;
    /// The search's text (its matches are marked in the names).
    query?: string;
    /// The search's result (null: no search, the whole tree).
    filtered?: SearchResult | null;
    /// The search result Up / Down moved to (Return opens it).
    active?: string | null;
    /// Ends the search (a new folder must be seen to be named).
    onclearfilter?: () => void;
  } = $props();

  const byId = $derived(new Map(rows.map((r) => [r.id, r])));

  // The collapsed state is the backend's (persisted, shared with the menu); a toggle shows at once.
  let collapsedNow = $state<Record<string, boolean>>({});
  const isCollapsed = (f: FolderTreeRow) => collapsedNow[f.id] ?? f.collapsed;
  $effect(() => {
    const settled = Object.keys(collapsedNow).filter((id) => tree.some((r) => r.type === 'folder' && r.id === id && r.collapsed === collapsedNow[id]));
    if (settled.length > 0) {
      const next = { ...collapsedNow };
      for (const id of settled) delete next[id];
      collapsedNow = next;
    }
  });
  const visible = $derived(filtered ? filtered.tree : visibleRows(tree, isCollapsed));
  /// A folder is shown open: while searching every folder is (without changing the stored state).
  const isOpen = (f: FolderTreeRow) => filtered !== null || !isCollapsed(f);
  // The keyboard's result stays in view.
  $effect(() => {
    if (!active || !list) return;
    list.querySelector(`[data-id="${CSS.escape(active)}"]`)?.scrollIntoView?.({ block: 'nearest' });
  });

  let context = $state<{ x: number; y: number; row: TreeRow | null } | null>(null);
  let picker = $state<{ x: number; y: number; row: TreeRow } | null>(null);
  let renaming = $state<string | null>(null);
  let renameValue = $state('');
  let pendingRename = $state<string | null>(null);
  let deleting = $state<FolderTreeRow | null>(null);
  let failure = $state<string | null>(null);
  let duplicating = $state<Row | null>(null);

  let list: HTMLElement | undefined = $state();
  let drag = $state<{
    dragged: Dragged;
    label: string;
    startX: number;
    startY: number;
    x: number;
    y: number;
    moved: boolean;
    drop: Drop | null;
    refused: string | null;
    /// Why this drag cannot drop anywhere here (a team catalog's row, or a drop into one), shown on the ghost.
    reason: string | null;
  } | null>(null);
  let suppressClick = false;

  function subtitle(row: Row): string {
    if (!row.managed) return tr('%@ · System VPN', row.typeLabel);
    // An unavailable row says why ("OpenVPN · Not installed: OpenVPN").
    return !row.available && row.unavailableReason ? `${row.typeLabel} · ${row.unavailableReason}` : row.typeLabel;
  }

  /// "System Status" of an unavailable row: opens the window (not the row's selection or a drag).
  function openSetup(event: Event) {
    event.stopPropagation();
    event.preventDefault();
    api.openWindow('setup').catch(console.error);
  }

  async function run(action: () => Promise<unknown>) {
    try {
      await action();
    } catch (e) {
      failure = typeof e === 'string' ? e : String(e);
    }
  }

  function setCollapsed(folder: FolderTreeRow, collapsed: boolean) {
    collapsedNow = { ...collapsedNow, [folder.id]: collapsed };
    run(() => api.folderSetCollapsed(folder.id, collapsed));
  }

  function expand(id: string | null) {
    const f = tree.find((r): r is FolderTreeRow => r.type === 'folder' && r.id === id);
    if (f && isCollapsed(f)) setCollapsed(f, false);
  }

  // MARK: - Drag and drop

  function pointerdown(event: PointerEvent, dragged: Dragged, label: string) {
    if (event.button !== 0 || renaming || filtered || (!enabled && dragged.type === 'folder')) return;
    drag = { dragged, label, startX: event.clientX, startY: event.clientY, x: event.clientX, y: event.clientY, moved: false, drop: null, refused: null, reason: null };
  }

  function hoverAt(x: number, y: number): Hover {
    const element = document.elementFromPoint(x, y);
    if (!list || !element || !list.contains(element)) return null;
    const rowElement = element.closest<HTMLElement>('[data-tree-row]');
    if (!rowElement) return { root: true };
    const rect = rowElement.getBoundingClientRect();
    return { rowId: rowElement.dataset.id ?? '', zone: zoneOf((y - rect.top) / Math.max(1, rect.height), rowElement.dataset.folder === 'true') };
  }

  function pointermove(event: PointerEvent) {
    if (!drag) return;
    if (!drag.moved && Math.hypot(event.clientX - drag.startX, event.clientY - drag.startY) < 5) return;
    // Without folders only the pins can be reordered.
    drag.moved = true;
    drag.x = event.clientX;
    drag.y = event.clientY;
    const hover = hoverAt(event.clientX, event.clientY);
    let drop = dropTarget(tree, rows, drag.dragged, hover);
    if (drop && !enabled && drop.action.type !== 'pinMove') drop = null;
    drag.reason = null;
    const draggedRow = tree.find((r) => r.id === drag?.dragged.id);
    if (draggedRow && isTeamRow(draggedRow, rows, teamFolders)) {
      drop = null;
      drag.reason = tr('Team catalog items cannot be moved.');
    } else if (drop && drop.action.type !== 'pinMove' && teamOf(teamFolders, drop.action.type === 'itemMove' ? drop.action.folder : drop.action.parent)) {
      drop = null;
      drag.reason = tr('Nothing can be moved into a team catalog.');
    }
    drag.drop = drop;
    // A folder over itself or one of its subfolders: shown as refused.
    const over = hover && 'rowId' in hover ? hover.rowId : null;
    drag.refused =
      !drop && over && drag.dragged.type === 'folder' && (over === drag.dragged.id || descendantFolders(tree, drag.dragged.id).has(over)) ? over : null;
    // Near the edges of the scrolling list: scroll.
    const scroller = list?.parentElement;
    if (scroller) {
      const rect = scroller.getBoundingClientRect();
      if (event.clientY < rect.top + 28) scroller.scrollBy(0, -10);
      else if (event.clientY > rect.bottom - 28) scroller.scrollBy(0, 10);
    }
  }

  function pointerup() {
    if (!drag) return;
    const { moved, drop } = drag;
    drag = null;
    if (!moved) return;
    suppressClick = true;
    setTimeout(() => (suppressClick = false), 0);
    if (drop) perform(drop.action);
  }

  function perform(action: DropAction) {
    run(async () => {
      if (action.type === 'folderMove') {
        await api.folderMove(action.id, action.parent, action.position);
        expand(action.parent);
      } else if (action.type === 'itemMove') {
        await api.itemMove(action.key, action.folder);
        expand(action.folder);
      } else {
        await api.movePinned(action.from, action.to);
      }
    });
  }

  function indicator(id: string): 'before' | 'after' | 'into' | null {
    const i = drag?.moved ? drag.drop?.indicator : null;
    return i && i.rowId === id ? i.where : null;
  }

  // MARK: - Context menu and actions

  function openContext(event: MouseEvent, row: TreeRow | null) {
    event.preventDefault();
    event.stopPropagation();
    if (!enabled && (row === null || (row.type === 'folder' && !teamOf(teamFolders, row.id)))) return;
    // At the pointer; `popover` keeps it inside the window (to the left of / above the pointer at an edge).
    context = { x: event.clientX, y: event.clientY, row };
  }

  function clickFolder(folder: FolderTreeRow) {
    if (suppressClick || filtered) return;
    setCollapsed(folder, !isCollapsed(folder));
  }

  function clickItem(id: string) {
    if (suppressClick) return;
    onselect(id);
  }

  /// "New Folder" in `parent` (null: the top level), then its name is edited in place.
  export function newFolder(parent: string | null = null) {
    context = null;
    onclearfilter();
    run(async () => {
      const id = await api.folderCreate(parent, tr('New Folder'));
      expand(parent);
      pendingRename = id;
    });
  }

  $effect(() => {
    const id = pendingRename;
    if (!id) return;
    const created = tree.find((r): r is FolderTreeRow => r.type === 'folder' && r.id === id);
    if (created) {
      pendingRename = null;
      startRename(created);
    }
  });

  function startRename(folder: FolderTreeRow) {
    context = null;
    renaming = folder.id;
    renameValue = folder.name;
  }

  function commitRename() {
    const id = renaming;
    if (!id) return;
    renaming = null;
    const folder = tree.find((r) => r.type === 'folder' && r.id === id);
    const name = renameValue.trim();
    if (!folder || folder.type !== 'folder' || name === '' || name === folder.name) return;
    run(() => api.folderRename(id, name));
  }

  function renameKey(event: KeyboardEvent) {
    if (event.key === 'Enter') {
      event.preventDefault();
      commitRename();
    } else if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      renaming = null;
    }
  }

  function focusAndSelect(input: HTMLInputElement) {
    input.focus();
    input.select();
  }

  function openPicker(row: TreeRow) {
    if (!context) return;
    picker = { x: context.x, y: context.y, row };
    context = null;
  }

  function pickColor(row: TreeRow, choice: ColorChoice) {
    picker = null;
    const color = choice === 'inherit' ? null : choice;
    run(() => (row.type === 'folder' ? api.folderSetColor(row.id, color) : api.itemSetColor(row.id, color)));
  }

  function toTopLevel(row: TreeRow) {
    context = null;
    run(() => (row.type === 'folder' ? api.folderMove(row.id, null, tree.filter((r) => r.type === 'folder' && r.parent === null).length) : api.itemMove(row.id, null)));
  }

  function pin(row: Row) {
    context = null;
    run(() => (row.pinned ? api.unpin(row.id) : api.pin(row.id)));
  }

  function installProfile(row: Row) {
    context = null;
    run(() => catalogApi.installProfile(row.id));
  }

  function remove(folder: FolderTreeRow, mode: DeleteMode) {
    deleting = null;
    run(() => api.folderDelete(folder.id, mode));
  }

  function parentColor(row: TreeRow): FolderColor | null {
    const parent = tree.find((r) => r.type === 'folder' && r.id === row.parent);
    return parent?.color ?? null;
  }
</script>

{#snippet marked(name: string)}{#each highlight(name, query) as part, i (i)}{#if part.match}<mark>{part.text}</mark>{:else}{part.text}{/if}{/each}{/snippet}

<svelte:window
  onpointermove={pointermove}
  onpointerup={pointerup}
  onkeydown={(e) => {
    if (e.key === 'Escape') {
      context = null;
      if (drag) drag = null;
    }
  }}
/>

<div
  class="tree"
  class:dragging={drag?.moved}
  class:filtering={filtered !== null}
  class:drop-root={drag?.moved && drag.drop?.indicator.rowId === null}
  bind:this={list}
  role="tree"
  tabindex="-1"
  aria-label={tr('Connections')}
  oncontextmenu={(e) => openContext(e, null)}
>
  {#each visible as entry (entry.id)}
    {@const at = indicator(entry.id)}
    {#if entry.type === 'folder'}
      {@const badge = folderBadge(entry)}
      <div
        data-tree-row
        data-id={entry.id}
        data-folder="true"
        class="trow"
        class:drop-before={at === 'before'}
        class:drop-after={at === 'after'}
        class:drop-into={at === 'into'}
        class:refused={drag?.refused === entry.id}
        class:lifted={drag?.moved && drag.dragged.id === entry.id}
        style:--level={indentLevel(entry.depth)}
        role="treeitem"
        aria-selected="false"
        aria-expanded={isOpen(entry)}
        aria-level={entry.depth + 1}
      >
        {#if renaming === entry.id}
          <div class="row folder editing">
            <span class="chev" class:open={!isCollapsed(entry)}><Icon name="chevron" /></span>
            <FolderIcon color={entry.color} />
            <input class="rename" aria-label={tr('Folder name')} bind:value={renameValue} maxlength="64" onkeydown={renameKey} onblur={commitRename} use:focusAndSelect />
          </div>
        {:else}
          <button
            class="row folder"
            onclick={() => clickFolder(entry)}
            ondblclick={() => enabled && !teamOf(teamFolders, entry.id) && startRename(entry)}
            oncontextmenu={(e) => openContext(e, entry)}
            onpointerdown={(e) => pointerdown(e, { type: 'folder', id: entry.id }, entry.name)}
          >
            <span class="chev" class:open={isOpen(entry)} class:empty={entry.itemCount + entry.folderCount === 0}><Icon name="chevron" /></span>
            <FolderIcon color={entry.color} open={isOpen(entry)} />
            <span class="label">{@render marked(entry.name)}</span>
            {#if isTeamRoot(teamFolders, entry)}<TeamBadge name={entry.name} />{/if}
            {#if badge.count !== null || badge.dot}
              <span class="badge {badge.dot ?? ''}" role="img" aria-label={tr('%lld active', badge.count ?? 0)}>
                {#if badge.dot}<span class="dot"></span>{/if}{#if badge.count !== null}{badge.count}{/if}
              </span>
            {:else if entry.itemCount > 0 && !isOpen(entry)}
              <span class="count">{entry.itemCount}</span>
            {/if}
          </button>
        {/if}
      </div>
    {:else}
      {@const row = byId.get(entry.id)}
      {#if row}
        <div
          data-tree-row
          data-id={entry.id}
          class="trow"
          class:drop-before={at === 'before'}
          class:drop-after={at === 'after'}
          class:lifted={drag?.moved && drag.dragged.id === entry.id}
          style:--level={indentLevel(entry.depth)}
          role="treeitem"
          aria-selected={row.id === selected}
          aria-level={entry.depth + 1}
        >
          <button
            class="row item"
            class:selected={row.id === selected}
            class:active={row.id === active}
            class:unavailable={!row.available}
            class:tinted={entry.color !== null}
            style:--tint={colorToken(entry.color)}
            onclick={() => clickItem(row.id)}
            oncontextmenu={(e) => openContext(e, entry)}
            onpointerdown={(e) => pointerdown(e, { type: 'item', id: row.id }, row.name)}
          >
            <TypeIcon kind={row.kind} state={row.state} size="sm" />
            <span class="text">
              <span class="name">
                <span class="label">{@render marked(row.name)}</span>
                {#if row.pinned}
                  <svg class="pin" viewBox="0 0 16 16" role="img" aria-label={tr('Pinned')}>
                    <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
                  </svg>
                {/if}
                {#if entry.ownColor}
                  <span class="own" style:--own={colorToken(entry.ownColor)} role="img" aria-label={tr('Own colour')} title={tr('Own colour')}></span>
                {/if}
                {#if row.catalog}<span class="team"><TeamBadge name={row.catalog.name} /></span>{/if}
              </span>
              <span class="type"
                >{subtitle(row)}{#if engineLink(row)}<span aria-hidden="true"> – </span><span
                    class="setup-link"
                    role="link"
                    tabindex="-1"
                    onpointerdown={(e) => e.stopPropagation()}
                    onclick={openSetup}
                    onkeydown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') openSetup(e);
                    }}>{tr('System Status')}</span
                  >{/if}</span
              >
              {#if row.certificateWarning}<span class="cert-warning"><Icon name="warning" />{row.certificateWarning}</span>{/if}
              {#if row.catalog?.pendingRemoval}<span class="removal">{tr('Removed from the team catalog — disappears after you disconnect')}</span>{/if}
              {#if row.heldBy.length > 0}<span class="held">{tr('Held by %@', row.heldBy.join(', '))}</span>{/if}
              <PublishedBadges published={row.published} />
            </span>
          </button>
        </div>
      {/if}
    {/if}
  {/each}
  {#if drag?.moved && enabled && drag.drop?.action.type !== 'pinMove'}
    <div class="root-zone" class:active={drag.drop?.indicator.rowId === null}>
      <Icon name="arrow-up" />
      {tr('Top level')}
    </div>
  {/if}
</div>

{#if drag?.moved}
  {@const draggedRow = drag.dragged.type === 'item' ? byId.get(drag.dragged.id) : undefined}
  <div
    class="ghost"
    use:popover={{ anchor: { left: drag.x + 14, right: drag.x - 14, top: drag.y - 10, bottom: drag.y + 10 } }}
    class:none={!drag.drop}
    class:with-reason={drag.reason !== null}
  >
    {#if draggedRow}
      <TypeIcon kind={draggedRow.kind} size="sm" />
    {:else}
      <Icon name="folder" />
    {/if}
    <span>{drag.label}</span>
    {#if drag.reason}<span class="reason">{drag.reason}</span>{/if}
  </div>
{/if}

{#if context}
  {@const target = context.row}
  <div class="dismiss" role="presentation" onpointerdown={() => (context = null)}></div>
  <div class="menu" role="menu" use:popover={{ anchor: pointAnchor(context.x, context.y), maxWidth: 320 }}>
    {#if target === null}
      <button role="menuitem" data-action="new-folder" onclick={() => newFolder(null)}><Icon name="folder-plus" />{tr('New Folder')}</button>
    {:else if target.type === 'folder' && teamOf(teamFolders, target.id)}
      <p class="menu-note" data-team-note>{tr('A team catalog manages this folder: it cannot be changed here.')}</p>
    {:else if target.type === 'folder'}
      <button role="menuitem" data-action="new-folder" onclick={() => newFolder(target.id)}><Icon name="folder-plus" />{tr('New Folder')}</button>
      <button role="menuitem" data-action="rename" onclick={() => startRename(target)}><Icon name="pencil" />{tr('Rename')}</button>
      <button role="menuitem" data-action="colour" onclick={() => openPicker(target)}><Icon name="palette" />{tr('Colour…')}</button>
      {#if target.parent !== null}
        <button role="menuitem" data-action="top-level" onclick={() => toTopLevel(target)}><Icon name="arrow-up" />{tr('Move to Top Level')}</button>
      {/if}
      <hr />
      <button
        role="menuitem"
        class="destructive"
        data-action="delete"
        onclick={() => {
          deleting = target;
          context = null;
        }}><Icon name="trash" />{tr('Delete…')}</button
      >
    {:else}
      {@const row = byId.get(target.id)}
      {#if row}
        <button role="menuitem" data-action="pin" onclick={() => pin(row)}>
          <svg class="icon pin-icon" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
          </svg>
          {row.pinned ? tr('Unpin') : tr('Pin to Top')}
        </button>
      {/if}
      {#if row?.catalog}
        {@const team = row}
        <button role="menuitem" data-action="colour" onclick={() => openPicker(target)}><Icon name="palette" />{tr('Colour…')}</button>
        <button
          role="menuitem"
          data-action="duplicate"
          onclick={() => {
            context = null;
            duplicating = team;
          }}><Icon name="copy" />{tr('Duplicate as personal connection…')}</button
        >
        {#if team.catalog?.profileOutdated}
          <button role="menuitem" data-action="install-profile" onclick={() => installProfile(team)}><Icon name="download" />{tr('Install profile')}</button>
        {/if}
      {:else if enabled}
        <button role="menuitem" data-action="colour" onclick={() => openPicker(target)}><Icon name="palette" />{tr('Colour…')}</button>
        {#if target.parent !== null}
          <button role="menuitem" data-action="top-level" onclick={() => toTopLevel(target)}><Icon name="arrow-up" />{tr('Move to Top Level')}</button>
        {/if}
        <hr />
        <button role="menuitem" data-action="new-folder" onclick={() => newFolder(null)}><Icon name="folder-plus" />{tr('New Folder')}</button>
      {/if}
    {/if}
  </div>
{/if}

{#if picker}
  {@const row = picker.row}
  <ColorPicker
    {palette}
    value={row.ownColor}
    target={row.type}
    inherited={parentColor(row)}
    team={row.type === 'item' && !!byId.get(row.id)?.catalog}
    x={picker.x}
    y={picker.y}
    onpick={(choice) => pickColor(row, choice)}
    onclose={() => (picker = null)}
  />
{/if}

{#if deleting}
  {@const folder = deleting}
  <DeleteFolderDialog {folder} ondelete={(mode) => remove(folder, mode)} oncancel={() => (deleting = null)} />
{/if}

{#if duplicating}
  {@const original = duplicating}
  <DuplicateDialog
    itemId={original.id}
    name={original.name}
    oncancel={() => (duplicating = null)}
    ondone={(copy) => {
      duplicating = null;
      onselect(copy);
    }}
  />
{/if}

{#if failure}
  <Modal title={tr('Could not change the folders')} message={failure} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (failure = null) }]} />
{/if}

<style>
  .cert-warning {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: var(--text-sm);
    color: var(--state-busy-text);
  }
  .cert-warning :global(.icon) {
    flex: none;
    width: 11px;
    height: 11px;
  }
  .tree {
    display: flex;
    flex-direction: column;
    min-height: 100%;
    padding-bottom: 12px;
    box-sizing: border-box;
    border-radius: 10px;
    outline: none;
    transition: background-color var(--duration) var(--ease);
  }
  .tree.dragging {
    cursor: grabbing;
  }
  .trow {
    position: relative;
    padding-left: calc(var(--level, 0) * 14px);
  }
  .trow.lifted {
    opacity: 0.4;
  }
  /* The insertion line (before / after a row), indented like the row, with a dot at its start. */
  .trow.drop-before::before,
  .trow.drop-after::after {
    content: '';
    position: absolute;
    z-index: 2;
    left: calc(var(--level, 0) * 14px + 6px);
    right: 6px;
    height: 2px;
    border-radius: 1px;
    background: var(--accent);
    pointer-events: none;
  }
  .trow.drop-before::before {
    top: -2px;
  }
  .trow.drop-after::after {
    bottom: -1px;
  }
  .trow.drop-into > .row {
    background: var(--accent-soft);
    box-shadow: inset 0 0 0 2px var(--accent);
  }
  .trow.refused > .row {
    background: var(--state-fail-soft);
    box-shadow: inset 0 0 0 1.5px color-mix(in srgb, var(--state-fail) 60%, transparent);
    cursor: not-allowed;
  }
  .row {
    --badge-ring: var(--sidebar);
    position: relative;
    display: flex;
    align-items: center;
    gap: var(--space-4);
    width: 100%;
    min-height: 0;
    margin-bottom: 2px;
    padding: 6px 8px;
    border: none;
    border-radius: 10px;
    background: transparent;
    box-shadow: none;
    color: inherit;
    font: inherit;
    font-weight: 400;
    text-align: left;
    justify-content: flex-start;
    box-sizing: border-box;
  }
  .row:hover:not(.selected):not(.editing) {
    background: var(--fill-hover);
  }
  .row:active:not(.selected):not(.editing) {
    background: var(--fill-pressed);
  }
  .row.selected,
  .row.selected:hover {
    --badge-ring: var(--surface);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .row:focus-visible {
    box-shadow: var(--focus-ring);
  }
  /* The search result Up / Down moved to (Return opens it). */
  .row.active:not(.selected) {
    background: var(--accent-soft);
    outline: 1px solid color-mix(in srgb, var(--accent) 35%, transparent);
    outline-offset: -1px;
  }
  .row.active.selected {
    outline-color: var(--focus-border);
  }
  /* The part of a name the search matched. */
  mark {
    padding: 0 1px;
    margin: 0 -1px;
    border-radius: 3px;
    background: color-mix(in srgb, var(--state-busy) 32%, transparent);
    color: inherit;
  }
  /* While searching the folders are not toggled. */
  .filtering .chev :global(.icon) {
    opacity: 0.45;
  }
  /* The effective colour: a slim bar on the row's left edge. */
  .row.tinted::before {
    content: '';
    position: absolute;
    left: 1px;
    top: 9px;
    bottom: 9px;
    width: 3px;
    border-radius: 2px;
    background: var(--tint);
  }
  .folder {
    gap: 6px;
    padding: 5px 8px 5px 2px;
    font-weight: 600;
  }
  .chev {
    flex: none;
    display: inline-flex;
    width: 14px;
    justify-content: center;
    color: var(--tertiary);
  }
  .chev :global(.icon) {
    width: 10px;
    height: 10px;
    stroke-width: 2;
    transition: transform var(--duration) var(--ease);
  }
  .chev.open :global(.icon) {
    transform: rotate(90deg);
  }
  /* An empty folder has nothing to show or hide: no chevron (its place is kept for the alignment). */
  .chev.empty :global(.icon) {
    visibility: hidden;
  }
  .rename {
    flex: 1;
    min-width: 0;
    margin: -2px 0;
    padding: 2px 6px;
    border: 1px solid var(--focus-border);
    border-radius: var(--radius-xs);
    background: var(--field);
    color: var(--text);
    font: inherit;
    font-weight: 500;
    box-shadow: var(--focus-ring);
    -webkit-user-select: text;
    user-select: text;
  }
  .text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
    font-weight: 500;
  }
  .folder .label {
    flex: 1;
    min-width: 0;
  }
  .label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .type {
    font-size: var(--text-sm);
    color: var(--secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  /* "… – System Status": the engine is missing, System Status installs it. */
  .setup-link {
    font-weight: 500;
    color: var(--accent-text);
    cursor: pointer;
  }
  .setup-link:hover {
    text-decoration: underline;
  }
  .row.unavailable :global(.bubble),
  .row.unavailable .name {
    opacity: 0.5;
  }
  .held {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--state-on-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pin {
    width: 10px;
    height: 10px;
    flex: none;
    color: var(--tertiary);
  }
  /* An own colour (an override of the folder's): a small ringed dot after the name. */
  .own {
    flex: none;
    margin-left: 2px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--own);
    box-shadow:
      0 0 0 1.5px var(--sidebar),
      0 0 0 2.5px color-mix(in srgb, var(--own) 55%, transparent);
  }
  .selected .own {
    box-shadow:
      0 0 0 1.5px var(--surface),
      0 0 0 2.5px color-mix(in srgb, var(--own) 55%, transparent);
  }
  .badge,
  .count {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 16px;
    font-variant-numeric: tabular-nums;
  }
  .count {
    color: var(--tertiary);
  }
  .badge {
    background: var(--fill-hover);
    color: var(--secondary);
  }
  .badge.on {
    background: var(--state-on-soft);
    color: var(--state-on-text);
  }
  .badge.busy {
    background: var(--state-busy-soft);
    color: var(--state-busy-text);
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }
  .on .dot {
    background: var(--state-on);
  }
  .busy .dot {
    background: var(--state-busy);
  }
  .root-zone {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 34px;
    margin-top: 6px;
    border: 1.5px dashed var(--border-strong);
    border-radius: 10px;
    color: var(--tertiary);
    font-size: var(--text-sm);
    font-weight: 500;
    transition:
      background-color var(--duration) var(--ease),
      border-color var(--duration) var(--ease);
  }
  .root-zone :global(.icon) {
    width: 12px;
    height: 12px;
  }
  .root-zone.active,
  .drop-root .root-zone {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent-text);
  }
  .ghost {
    position: fixed;
    z-index: 60;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 200px;
    padding: 4px 10px 4px 8px;
    border-radius: var(--radius-pill);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    font-size: var(--text-sm);
    font-weight: 500;
    pointer-events: none;
    white-space: nowrap;
  }
  .ghost span {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ghost :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--accent);
  }
  .ghost.none {
    opacity: 0.75;
  }
  .ghost.with-reason {
    max-width: 300px;
    flex-wrap: wrap;
    white-space: normal;
    border-radius: var(--radius-card);
  }
  .ghost .reason {
    color: var(--state-fail-text);
    font-weight: 400;
  }
  .team {
    display: inline-flex;
    margin-left: 2px;
  }
  .removal {
    font-size: var(--text-xs);
    color: var(--state-busy-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .menu-note {
    margin: 0;
    max-width: 260px;
    padding: 4px 8px;
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .ghost.none :global(.icon) {
    color: var(--tertiary);
  }
  .dismiss {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
  /* Placed by `popover` (fixed, inside the window, at most 320 pt wide): long items wrap rather than widen it. */
  .menu {
    position: fixed;
    z-index: 40;
    min-width: 190px;
    width: max-content;
    padding: 5px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    display: flex;
    flex-direction: column;
    animation: pop 0.14s var(--ease);
  }
  .menu button {
    display: flex;
    align-items: center;
    justify-content: flex-start;
    gap: 8px;
    min-height: 26px;
    text-align: left;
    padding: 3px 10px 3px 8px;
    white-space: normal;
    overflow-wrap: break-word;
    line-height: 1.3;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    box-shadow: none;
    color: inherit;
    font: inherit;
  }
  .menu button :global(.icon) {
    flex: none;
    width: 14px;
    height: 14px;
    color: var(--secondary);
  }
  .menu .pin-icon {
    width: 12px;
    height: 12px;
    margin: 0 1px;
    color: var(--secondary);
  }
  .menu button.destructive {
    color: var(--state-fail-text);
  }
  .menu button.destructive :global(.icon) {
    color: currentColor;
  }
  .menu button:hover,
  .menu button:focus-visible {
    background: var(--accent);
    color: var(--on-accent);
    box-shadow: none;
    outline: none;
  }
  .menu button:hover :global(.icon),
  .menu button:hover .pin-icon,
  .menu button:focus-visible :global(.icon) {
    color: var(--on-accent);
  }
  .menu button.destructive:hover {
    background: var(--state-fail);
  }
  .menu hr {
    border: none;
    border-top: 1px solid var(--separator);
    margin: 4px 6px;
  }
  @keyframes pop {
    from {
      opacity: 0;
      transform: translateY(-4px) scale(0.98);
    }
  }
</style>
