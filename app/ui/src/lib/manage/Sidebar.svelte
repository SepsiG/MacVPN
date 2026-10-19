<script lang="ts">
  // The one ranked list (spec 10e): the pinned rows first (reordered by dragging), then the others by use; a
  // row's context menu pins or unpins it. The "New" menu creates a connection of a kind or imports files.
  import { api, type Choice, type Kind, type Row } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import TypeIcon from '../TypeIcon.svelte';
  import { dropIndex, isMove } from './reorder';

  let {
    rows,
    selected,
    kinds,
    onselect,
    onimport,
    paired = false,
    pairedCount = 0,
    onpaired,
  }: {
    rows: Row[];
    selected: string | null;
    kinds: Choice<Kind>[];
    onselect: (id: string) => void;
    onimport: () => void;
    /// The Paired apps section is shown.
    paired?: boolean;
    pairedCount?: number;
    onpaired: () => void;
  } = $props();

  const pinned = $derived(rows.filter((r) => r.pinned));
  const others = $derived(rows.filter((r) => !r.pinned));
  let menuOpen = $state(false);
  let context = $state<{ row: Row; x: number; y: number } | null>(null);

  // Dragging a pinned row: the index it came from and the gap it would drop into.
  let drag = $state<{ from: number; startY: number; moved: boolean; gap: number } | null>(null);
  let pinnedList: HTMLElement | undefined = $state();

  function subtitle(row: Row): string {
    return row.managed ? row.typeLabel : tr('%@ · System VPN', row.typeLabel);
  }

  function pointerdown(event: PointerEvent, index: number) {
    if (event.button !== 0) return;
    drag = { from: index, startY: event.clientY, moved: false, gap: index };
  }

  function pointermove(event: PointerEvent) {
    if (!drag || !pinnedList) return;
    if (!drag.moved && Math.abs(event.clientY - drag.startY) < 4) return;
    drag.moved = true;
    const mids = Array.from(pinnedList.querySelectorAll<HTMLElement>('[data-row]')).map((el) => {
      const r = el.getBoundingClientRect();
      return r.top + r.height / 2;
    });
    drag.gap = dropIndex(mids, event.clientY);
  }

  function pointerup() {
    if (!drag) return;
    const { from, gap, moved } = drag;
    drag = null;
    if (moved && isMove(from, gap)) api.movePinned([from], gap).catch(console.error);
  }

  function openContext(event: MouseEvent, row: Row) {
    event.preventDefault();
    context = { row, x: event.clientX, y: event.clientY };
  }

  function pin(row: Row) {
    context = null;
    (row.pinned ? api.unpin(row.id) : api.pin(row.id)).catch(console.error);
  }

  function create(kind: Kind) {
    menuOpen = false;
    api.createConnection(kind).catch(console.error);
  }
</script>

<svelte:window
  onpointermove={pointermove}
  onpointerup={pointerup}
  onkeydown={(e) => {
    if (e.key === 'Escape') {
      menuOpen = false;
      context = null;
    }
  }}
/>

<nav class="sidebar">
  <div class="toolbar">
    <button class="new" aria-haspopup="menu" aria-expanded={menuOpen} title={tr('New')} onclick={() => (menuOpen = !menuOpen)}>
      <Icon name="plus" />
      {tr('New')}
    </button>
    {#if menuOpen}
      <div class="menu" role="menu">
        {#each kinds as kind (kind.value)}
          <button role="menuitem" onclick={() => create(kind.value)}>{kind.title}</button>
        {/each}
        <hr />
        <button
          role="menuitem"
          onclick={() => {
            menuOpen = false;
            onimport();
          }}>{tr('Import from File…')}</button
        >
      </div>
    {/if}
  </div>
  <div class="list">
    {#if pinned.length > 0}
      <h2>{tr('Pinned')}</h2>
      <div bind:this={pinnedList} class:dragging={drag?.moved}>
        {#each pinned as row, i (row.id)}
          {#if drag?.moved && drag.gap === i}<div class="gap"></div>{/if}
          <button
            data-row
            class="row"
            class:selected={row.id === selected}
            onclick={() => onselect(row.id)}
            oncontextmenu={(e) => openContext(e, row)}
            onpointerdown={(e) => pointerdown(e, i)}
          >
            <TypeIcon kind={row.kind} state={row.state} size="sm" />
            <span class="text">
              <span class="name"><span class="label">{row.name}</span>
                <svg class="pin" viewBox="0 0 16 16" role="img" aria-label={tr('Pinned')}>
                  <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
                </svg>
              </span>
              <span class="type">{subtitle(row)}</span>
              {#if row.heldBy.length > 0}<span class="held">{tr('Held by %@', row.heldBy.join(', '))}</span>{/if}
            </span>
          </button>
        {/each}
        {#if drag?.moved && drag.gap === pinned.length}<div class="gap"></div>{/if}
      </div>
    {/if}
    <h2>{tr('Connections')}</h2>
    {#each others as row (row.id)}
      <button class="row" class:selected={row.id === selected} onclick={() => onselect(row.id)} oncontextmenu={(e) => openContext(e, row)}>
        <TypeIcon kind={row.kind} state={row.state} size="sm" />
        <span class="text">
          <span class="name"><span class="label">{row.name}</span></span>
          <span class="type">{subtitle(row)}</span>
          {#if row.heldBy.length > 0}<span class="held">{tr('Held by %@', row.heldBy.join(', '))}</span>{/if}
        </span>
      </button>
    {/each}
  </div>
  <div class="footer">
    <button class="row paired" class:selected={paired} onclick={onpaired}>
      <span class="paired-icon" aria-hidden="true"><Icon name="link" /></span>
      <span class="text">
        <span class="name"><span class="label">{tr('Paired apps')}</span></span>
      </span>
      {#if pairedCount > 0}<span class="count">{pairedCount}</span>{/if}
    </button>
  </div>
</nav>

{#if context}
  <div class="dismiss" role="presentation" onpointerdown={() => (context = null)}></div>
  <div class="menu context" role="menu" style="left: {context.x}px; top: {context.y}px">
    <button role="menuitem" onclick={() => context && pin(context.row)}>
      {context.row.pinned ? tr('Unpin') : tr('Pin to Top')}
    </button>
  </div>
{/if}

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
  .list {
    flex: 1;
    overflow: auto;
    padding: 0 10px 12px;
  }
  h2 {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--tertiary);
    margin: 12px 8px 6px;
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
  .dragging .row {
    cursor: grabbing;
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
  .type {
    font-size: var(--text-sm);
    color: var(--secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .held {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--state-on-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .footer {
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
  .paired .text {
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
  .pin {
    width: 10px;
    height: 10px;
    flex: none;
    color: var(--tertiary);
  }
  .gap {
    height: 3px;
    margin: 1px 8px;
    border-radius: 2px;
    background: var(--accent);
  }
  .menu {
    position: absolute;
    top: 44px;
    right: 12px;
    z-index: 20;
    min-width: 200px;
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
  .menu.context {
    position: fixed;
    right: auto;
    z-index: 40;
  }
  .menu button {
    justify-content: flex-start;
    min-height: 26px;
    text-align: left;
    padding: 3px 10px;
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
  .dismiss {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
  @keyframes pop {
    from {
      opacity: 0;
      transform: translateY(-4px) scale(0.98);
    }
  }
</style>
