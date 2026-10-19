<script lang="ts">
  // A folder in the menu, in the card style but slimmer than a connection: the collapse chevron, the folder in its
  // colour, the name, and on the right the number of active connections inside with a dot (green: one of them is
  // connected, also while the folder is collapsed; amber: only connecting).
  import type { FolderTreeRow } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import FolderIcon from './FolderIcon.svelte';
  import { folderBadge } from './tree';

  let { folder, collapsed, ontoggle }: { folder: FolderTreeRow; collapsed: boolean; ontoggle: () => void } = $props();

  const badge = $derived(folderBadge(folder));
</script>

<button class="folder" class:collapsed class:empty={folder.itemCount + folder.folderCount === 0} aria-expanded={!collapsed} onclick={ontoggle}>
  <Icon name="chevron" class="chevron" />
  <FolderIcon color={folder.color} open={!collapsed} size={17} />
  <span class="name">{folder.name}</span>
  {#if badge.count !== null || badge.dot}
    <span class="badge {badge.dot ?? ''}" role="img" aria-label={tr('%lld active', badge.count ?? 0)}>
      {#if badge.dot}<span class="dot"></span>{/if}
      {#if badge.count !== null}{badge.count}{/if}
    </span>
  {/if}
</button>

<style>
  .folder {
    display: flex;
    align-items: center;
    gap: 7px;
    width: 100%;
    min-height: 28px;
    padding: 4px 10px 4px 7px;
    border: none;
    border-radius: 10px;
    background: color-mix(in srgb, var(--surface) 72%, transparent);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    color: var(--text);
    font: inherit;
    font-size: var(--text-md);
    font-weight: 600;
    text-align: left;
    box-sizing: border-box;
    transition: background-color var(--duration) var(--ease);
  }
  .folder:hover {
    background: var(--surface-hover);
  }
  .folder:active {
    background: var(--surface-pressed);
  }
  .folder :global(.chevron) {
    width: 10px;
    height: 10px;
    color: var(--tertiary);
    stroke-width: 2;
    transform: rotate(90deg);
    transition: transform var(--duration) var(--ease);
  }
  .collapsed :global(.chevron) {
    transform: none;
  }
  /* Nothing to show or hide: no chevron (its place is kept for the alignment). */
  .empty :global(.chevron) {
    visibility: hidden;
  }
  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .badge {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    min-width: 8px;
    padding: 1px 7px;
    border-radius: var(--radius-pill);
    background: var(--fill-hover);
    color: var(--secondary);
    font-size: var(--text-xs);
    font-weight: 600;
    line-height: 15px;
    font-variant-numeric: tabular-nums;
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
</style>
