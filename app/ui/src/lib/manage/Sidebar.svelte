<script lang="ts">
  // The connections as a folder tree (spec 3; lib/folders/FolderTree.svelte): per folder its subfolders, then the
  // pinned rows (reordered by dragging), then the others by use. The "New" menu creates a connection of a kind, a
  // folder, or imports files.
  import { api, type Choice, type FolderColor, type Kind, type Row, type TreeRow } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import FolderTree from '../folders/FolderTree.svelte';
  import { treeOf } from '../folders/tree';
  import { backupApi } from '../vault/backupApi';
  import { popover } from '../popover';

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
  } = $props();

  let menuOpen = $state(false);
  let newButton: HTMLButtonElement | undefined = $state();
  /// The menu hangs under the New button, right-aligned to it, kept inside the window (`popover`).
  const newButtonRect = () => newButton?.getBoundingClientRect() ?? { left: 0, top: 0, right: 0, bottom: 0 };
  let folderTree: ReturnType<typeof FolderTree> | undefined = $state();
  const shownTree = $derived(treeOf({ tree, rows }));

  function create(kind: Kind) {
    menuOpen = false;
    api.createConnection(kind).catch(console.error);
  }
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape') menuOpen = false;
  }}
/>

<nav class="sidebar">
  <div class="toolbar">
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
  <div class="list">
    <FolderTree bind:this={folderTree} {rows} tree={shownTree} {selected} enabled={foldersEnabled} {palette} {onselect} />
  </div>
  <div class="footer">
    <button class="row section-link shared-credentials" class:selected={credentials} onclick={oncredentials}>
      <span class="paired-icon" aria-hidden="true"><Icon name="key" /></span>
      <span class="text">
        <span class="name"><span class="label">{tr('Credentials')}</span></span>
      </span>
      {#if credentialCount > 0}<span class="count">{credentialCount}</span>{/if}
    </button>
    <button class="row paired" class:selected={paired} onclick={onpaired}>
      <span class="paired-icon" aria-hidden="true"><Icon name="link" /></span>
      <span class="text">
        <span class="name"><span class="label">{tr('Paired apps')}</span></span>
      </span>
      {#if pairedCount > 0}<span class="count">{pairedCount}</span>{/if}
    </button>
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
    justify-content: flex-end;
    padding: 12px 12px 4px;
  }
  .new {
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
  .paired-icon {
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
  .paired-icon :global(.icon) {
    width: 14px;
    height: 14px;
    stroke-width: 1.8;
  }
  .paired .text,
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
