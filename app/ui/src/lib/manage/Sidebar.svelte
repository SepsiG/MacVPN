<script lang="ts">
  // The connections as a folder tree (spec 3; lib/folders/FolderTree.svelte): per folder its subfolders, then the
  // pinned rows (reordered by dragging), then the others by use. The "New" menu creates a connection of a kind, a
  // folder, or imports files. The search field above the tree filters it as you type (manage/search.ts): Cmd+F
  // focuses it, Up / Down move through the results, Return opens the highlighted one, Escape clears the field and
  // then leaves it. The footer's sections stay reachable while searching.
  import { api, type Choice, type FolderColor, type Kind, type Row, type TreeRow } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon, { type IconName } from '../Icon.svelte';
  import FolderTree from '../folders/FolderTree.svelte';
  import { treeOf } from '../folders/tree';
  import { backupApi } from '../vault/backupApi';
  import { popover } from '../popover';
  import { searchTree, step } from './search';

  let {
    rows,
    tree,
    foldersEnabled = false,
    foldersNote = null,
    palette = [],
    selected,
    kinds,
    onselect,
    onimport,
    paired = false,
    pairedCount = 0,
    onpaired,
    credentials = false,
    credentialCount = 0,
    oncredentials = () => {},
    backupAvailable = false,
    teamCatalogs = false,
    teamCatalogCount = 0,
    onteamcatalogs = () => {},
    teamFolders = {},
    publishing = false,
    publicationCount = 0,
    onpublishing = () => {},
    query = $bindable(''),
  }: {
    rows: Row[];
    /// The folder tree over `rows` (an older view model has none: the rows at the top level).
    tree?: TreeRow[];
    foldersEnabled?: boolean;
    /// Why folders cannot be edited now.
    foldersNote?: string | null;
    palette?: FolderColor[];
    selected: string | null;
    kinds: Choice<Kind>[];
    onselect: (id: string) => void;
    onimport: () => void;
    /// The Paired apps section is shown.
    paired?: boolean;
    pairedCount?: number;
    onpaired: () => void;
    /// The Credentials section is shown.
    credentials?: boolean;
    credentialCount?: number;
    oncredentials?: () => void;
    /// "Back up everything…" and "Restore from backup…" are offered (the vault is open).
    backupAvailable?: boolean;
    /// The Team catalogs section is shown.
    teamCatalogs?: boolean;
    teamCatalogCount?: number;
    onteamcatalogs?: () => void;
    /// The folders team catalogs own (read-only, with the "Team" badge).
    teamFolders?: Record<string, string>;
    /// The Publishing section is shown.
    publishing?: boolean;
    publicationCount?: number;
    onpublishing?: () => void;
    /// The search field's text ('': the whole tree).
    query?: string;
  } = $props();

  let menuOpen = $state(false);
  let newButton: HTMLButtonElement | undefined = $state();
  /// The menu hangs under the New button, right-aligned to it, kept inside the window (`popover`).
  const newButtonRect = () => newButton?.getBoundingClientRect() ?? { left: 0, top: 0, right: 0, bottom: 0 };
  let folderTree: ReturnType<typeof FolderTree> | undefined = $state();
  const shownTree = $derived(treeOf({ tree, rows }));

  let searchField: HTMLInputElement | undefined = $state();
  const filtered = $derived(searchTree(shownTree, rows, query));
  /// The result Up / Down moved to; the first result until then (or once it is gone).
  let picked = $state<string | null>(null);
  const active = $derived(filtered ? (picked !== null && filtered.items.includes(picked) ? picked : (filtered.items[0] ?? null)) : null);

  function clearSearch() {
    query = '';
    picked = null;
  }

  function searchKey(event: KeyboardEvent) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (filtered) picked = step(filtered.items, active, event.key === 'ArrowDown' ? 1 : -1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (active) onselect(active);
    } else if (event.key === 'Escape') {
      // Not the window's Escape (it closes menus): first the text goes, then the focus.
      event.preventDefault();
      event.stopPropagation();
      if (query !== '') clearSearch();
      else searchField?.blur();
    }
  }
  /// The footer's section links, one row style each: `.link-<id>` (not the section's own class: a section's global
  /// stylesheet, like `.publishing`, must not reach its link).
  const footerLinks: { id: string; icon: IconName; label: string; selected: boolean; count: number; onclick: () => void }[] =
    $derived([
      { id: 'credentials', icon: 'key', label: tr('Credentials'), selected: credentials, count: credentialCount, onclick: oncredentials },
      { id: 'paired', icon: 'link', label: tr('Paired apps'), selected: paired, count: pairedCount, onclick: onpaired },
      { id: 'team-catalogs', icon: 'globe', label: tr('Team catalogs'), selected: teamCatalogs, count: teamCatalogCount, onclick: onteamcatalogs },
      { id: 'publishing', icon: 'export', label: tr('Publishing'), selected: publishing, count: publicationCount, onclick: onpublishing },
    ]);

  function create(kind: Kind) {
    menuOpen = false;
    api.createConnection(kind).catch(console.error);
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape') menuOpen = false;
    // Cmd+F: the search field (this window's only find).
    if (e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      searchField?.focus();
      searchField?.select();
    }
  }}
/>

<nav class="sidebar">
  <div class="toolbar">
    <div class="search" class:filled={query !== ''}>
      <Icon name="search" />
      <input
        class="query"
        type="text"
        role="searchbox"
        spellcheck="false"
        autocomplete="off"
        placeholder={tr('Search connections')}
        aria-label={tr('Search connections')}
        aria-controls="connection-tree"
        bind:value={query}
        bind:this={searchField}
        oninput={() => (picked = null)}
        onkeydown={searchKey}
      />
      {#if query !== ''}
        <button class="clear" title={tr('Clear Search')} aria-label={tr('Clear Search')} onclick={() => { clearSearch(); searchField?.focus(); }}>
          <Icon name="cross" />
        </button>
      {/if}
    </div>
    <button class="new" bind:this={newButton} aria-haspopup="menu" aria-expanded={menuOpen} title={tr('New')} onclick={() => (menuOpen = !menuOpen)}>
      <Icon name="plus" />
      {tr('New')}
    </button>
    {#if menuOpen}
      <div class="menu" role="menu" use:popover={{ anchor: newButtonRect, align: 'end', gap: 6, maxWidth: 320 }}>
        {#each kinds as kind (kind.value)}
          <button role="menuitem" onclick={() => create(kind.value)}>{kind.title}</button>
        {/each}
        <hr />
        {#if foldersEnabled}
          <button
            role="menuitem"
            data-action="new-folder"
            onclick={() => {
              menuOpen = false;
              clearSearch();
              folderTree?.newFolder(null);
            }}>{tr('New Folder')}</button
          >
        {/if}
        <button
          role="menuitem"
          onclick={() => {
            menuOpen = false;
            onimport();
          }}>{tr('Import from File…')}</button
        >
        {#if backupAvailable}
          <hr />
          <button
            role="menuitem"
            class="backup"
            onclick={() => {
              menuOpen = false;
              backupApi.showWindow('backup').catch(console.error);
            }}>{tr('Back Up Everything…')}</button
          >
          <button
            role="menuitem"
            class="restore"
            onclick={() => {
              menuOpen = false;
              backupApi.showWindow('restore').catch(console.error);
            }}>{tr('Restore from Backup…')}</button
          >
        {/if}
      </div>
    {/if}
  </div>
  {#if foldersNote}<p class="folders-note" role="note">{foldersNote}</p>{/if}
  <div class="list" id="connection-tree">
    {#if filtered && filtered.tree.length === 0}
      <div class="no-match" role="status">
        <p>{tr('No connections match “%@”', query.trim())}</p>
        <button class="clear-search" onclick={() => { clearSearch(); searchField?.focus(); }}>{tr('Clear Search')}</button>
      </div>
    {:else}
      <FolderTree
        bind:this={folderTree}
        {rows}
        tree={shownTree}
        {selected}
        enabled={foldersEnabled}
        {palette}
        {teamFolders}
        {onselect}
        {query}
        {filtered}
        {active}
        onclearfilter={clearSearch}
      />
    {/if}
  </div>
  <div class="footer">
    {#each footerLinks as link (link.id)}
      <button class="row section-link link-{link.id}" class:selected={link.selected} onclick={link.onclick}>
        <span class="section-icon" aria-hidden="true"><Icon name={link.icon} /></span>
        <span class="text">
          <span class="name"><span class="label">{link.label}</span></span>
        </span>
        {#if link.count > 0}<span class="count">{link.count}</span>{/if}
      </button>
    {/each}
  </div>
</nav>

<style>
  .sidebar {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--sidebar);
    border-right: 1px solid var(--separator);
  }
  .toolbar {
    position: relative;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 12px 12px 6px;
  }
  /* The search field: a card-style pill like the New button, the magnifier inside it. */
  .search {
    position: relative;
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
  }
  .search > :global(.icon) {
    position: absolute;
    left: 9px;
    width: 13px;
    height: 13px;
    color: var(--tertiary);
    pointer-events: none;
  }
  .search input.query {
    flex: 1;
    min-width: 0;
    box-sizing: border-box;
    height: 26px;
    min-height: 0;
    margin: 0;
    padding: 0 10px 0 27px;
    border: none;
    border-radius: var(--radius-pill);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    color: var(--text);
    font: inherit;
    -webkit-user-select: text;
    user-select: text;
    transition: box-shadow var(--duration) var(--ease);
  }
  .search.filled input.query {
    padding-right: 26px;
  }
  .search input.query::placeholder {
    color: var(--tertiary);
  }
  .search input.query:focus {
    outline-color: var(--focus-border);
    box-shadow: var(--shadow-card), var(--focus-ring);
  }
  .clear {
    position: absolute;
    right: 4px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    min-height: 0;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: var(--fill-pressed);
    box-shadow: none;
    color: var(--secondary);
  }
  .clear :global(.icon) {
    width: 9px;
    height: 9px;
    stroke-width: 2.4;
  }
  .clear:hover {
    background: var(--border-strong);
    color: var(--text);
  }
  .no-match {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-3);
    margin-top: var(--space-6);
    padding: var(--space-6) var(--space-4);
    text-align: center;
    color: var(--secondary);
  }
  .no-match p {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .clear-search {
    padding: 4px 12px;
    border-radius: var(--radius-pill);
  }
  .new {
    flex: none;
    gap: 4px;
    padding: 4px 12px 4px 9px;
    border-radius: var(--radius-pill);
  }
  .new :global(.icon) {
    width: 14px;
    height: 14px;
    color: var(--accent);
  }
  .folders-note {
    margin: 0 14px 6px;
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .list {
    flex: 1;
    overflow: auto;
    /* The tree fills the list (its empty space takes drops for the top level) and has its own bottom padding. */
    padding: 0 10px;
  }
  .row {
    --badge-ring: var(--sidebar);
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
  }
  .row:hover:not(.selected) {
    background: var(--fill-hover);
  }
  .row:active:not(.selected) {
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
  .label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .footer {
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 2px;
    padding: 6px 10px 10px;
    border-top: 1px solid var(--separator);
  }
  .footer .row {
    margin: 0;
  }
  .section-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border-radius: var(--radius-icon);
    color: #fff;
    background: linear-gradient(180deg, var(--accent), var(--accent-pressed));
  }
  .section-icon :global(.icon) {
    width: 14px;
    height: 14px;
    stroke-width: 1.8;
  }
  .section-link .text {
    flex: 1;
  }
  .count {
    flex: none;
    min-width: 18px;
    padding: 0 6px;
    border-radius: var(--radius-pill);
    background: var(--fill-pressed);
    color: var(--secondary);
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 18px;
    text-align: center;
  }
  /* Placed by `popover` (fixed, inside the window, at most 320 pt wide): long items wrap rather than widen it. */
  .menu {
    position: fixed;
    z-index: 20;
    min-width: 200px;
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
    justify-content: flex-start;
    min-height: 26px;
    text-align: left;
    padding: 3px 10px;
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
  .menu button:hover,
  .menu button:hover:not(:disabled),
  .menu button:focus-visible {
    background: var(--accent);
    color: var(--on-accent);
    box-shadow: none;
    outline: none;
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
