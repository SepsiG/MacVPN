<script lang="ts">
  // The one ranked list (spec 10e): the pinned rows first (reordered by dragging), then the others by use; a
  // row's context menu pins or unpins it. The "New" menu creates a connection of a kind or imports files.
  import { api, type Choice, type Kind, type Row } from '../api';
  import { tr } from '../l10n.svelte';
  import StatusDot from '../StatusDot.svelte';
  import { dropIndex, isMove } from './reorder';

  let {
    rows,
    selected,
    kinds,
    onselect,
    onimport,
  }: {
    rows: Row[];
    selected: string | null;
    kinds: Choice<Kind>[];
    onselect: (id: string) => void;
    onimport: () => void;
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
    <button class="icon" aria-haspopup="menu" aria-expanded={menuOpen} title={tr('New')} aria-label={tr('New')} onclick={() => (menuOpen = !menuOpen)}>
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M7.3 2h1.4v5.3H14v1.4H8.7V14H7.3V8.7H2V7.3h5.3z" fill="currentColor" /></svg>
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
            <StatusDot state={row.state} />
            <span class="text">
              <span class="name">{row.name}
                <svg class="pin" viewBox="0 0 16 16" role="img" aria-label={tr('Pinned')}>
                  <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
                </svg>
              </span>
              <span class="type">{subtitle(row)}</span>
            </span>
          </button>
        {/each}
        {#if drag?.moved && drag.gap === pinned.length}<div class="gap"></div>{/if}
      </div>
    {/if}
    <h2>{tr('Connections')}</h2>
    {#each others as row (row.id)}
      <button class="row" class:selected={row.id === selected} onclick={() => onselect(row.id)} oncontextmenu={(e) => openContext(e, row)}>
        <StatusDot state={row.state} />
        <span class="text">
          <span class="name">{row.name}</span>
          <span class="type">{subtitle(row)}</span>
        </span>
      </button>
    {/each}
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
    padding: 8px;
  }
  .list {
    flex: 1;
    overflow: auto;
    padding: 0 8px 8px;
  }
  h2 {
    font-size: 11px;
    font-weight: 600;
    color: var(--secondary);
    margin: 10px 8px 4px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 5px 8px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
  }
  .row.selected {
    background: var(--selection);
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
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .type {
    font-size: 11px;
    color: var(--secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .pin {
    width: 10px;
    height: 10px;
    flex: none;
    color: var(--secondary);
  }
  .gap {
    height: 2px;
    margin: 1px 8px;
    border-radius: 1px;
    background: var(--accent);
  }
  .menu {
    position: absolute;
    top: 36px;
    right: 8px;
    z-index: 20;
    min-width: 180px;
    padding: 4px;
    border-radius: 7px;
    background: var(--panel);
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.25);
    display: flex;
    flex-direction: column;
  }
  .menu.context {
    position: fixed;
    right: auto;
    z-index: 40;
  }
  .menu button {
    text-align: left;
    padding: 4px 10px;
    border: none;
    border-radius: 4px;
    background: transparent;
    color: inherit;
    font: inherit;
  }
  .menu button:hover,
  .menu button:focus-visible {
    background: var(--accent);
    color: #fff;
    outline: none;
  }
  .menu hr {
    border: none;
    border-top: 1px solid var(--separator);
    margin: 4px 0;
  }
  .dismiss {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
</style>
