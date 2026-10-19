<script lang="ts">
  // The Log tab (the Swift `LogView`): the live tail of the connection's log (or the native debug collection),
  // the last 5000 lines, filter, search, follow, copy, save.
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { api, onLogLines, type Choice, type LogFilter, type LogLineView, type Notice } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import { applyChunk, visibleLines } from '../logview';

  let { id, filters, onnotice }: { id: string; filters: Choice<LogFilter>[]; onnotice: (n: Notice) => void } = $props();

  let lines = $state<LogLineView[]>([]);
  let generation = 0;
  let filter = $state<LogFilter>('all');
  let search = $state('');
  let follow = $state(true);
  let scroller: HTMLElement | undefined = $state();
  const visible = $derived(visibleLines(lines, filter, search));

  async function scrollToEnd() {
    if (!follow) return;
    await tick();
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }

  let unlisten: Promise<() => void> | null = null;
  onMount(() => {
    unlisten = onLogLines((event) => {
      if (event.generation !== generation) return;
      lines = applyChunk(lines, event.reset, event.lines);
      scrollToEnd();
    });
    api.logSubscribe(untrack(() => id)).then((first) => {
      if (!first) return;
      generation = first.generation;
      lines = applyChunk([], true, first.lines);
      scrollToEnd();
    }, console.error);
  });
  onDestroy(() => {
    unlisten?.then((f) => f());
  });

  async function save() {
    const notice = await api.logSave();
    if (notice) onnotice(notice);
  }
</script>

<div class="log">
  <div class="toolbar">
    <div class="segmented" role="radiogroup">
      {#each filters as f (f.value)}
        <button role="radio" aria-checked={filter === f.value} class:on={filter === f.value} onclick={() => (filter = f.value)}>
          {f.title}
        </button>
      {/each}
    </div>
    <span class="search-field">
      <Icon name="search" />
      <input class="search" type="search" placeholder={tr('Search')} aria-label={tr('Search')} bind:value={search} />
    </span>
    <label class="check"><input type="checkbox" bind:checked={follow} onchange={scrollToEnd} />{tr('Follow')}</label>
    <button onclick={() => api.logCopy(filter, search).catch(console.error)}><Icon name="copy" />{tr('Copy')}</button>
    <button onclick={() => save().catch(console.error)}><Icon name="save" />{tr('Save…')}</button>
  </div>
  <div class="lines" bind:this={scroller}>
    {#each visible as line, i (i)}
      <div class="line {line.kind}">{line.text}</div>
    {/each}
  </div>
</div>

<style>
  .log {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    height: 100%;
    min-height: 0;
    box-sizing: border-box;
    padding: var(--space-4) var(--space-7) var(--space-7);
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .toolbar .segmented :global(button) {
    padding: 2px 11px;
  }
  .toolbar button :global(.icon) {
    width: 13px;
    height: 13px;
    color: var(--secondary);
  }
  .search-field {
    position: relative;
    flex: 1 1 150px;
    min-width: 150px;
    display: flex;
  }
  .search-field :global(.icon) {
    position: absolute;
    left: 9px;
    top: 50%;
    width: 13px;
    height: 13px;
    margin-top: -6.5px;
    color: var(--tertiary);
    pointer-events: none;
  }
  .search {
    flex: 1;
    min-width: 0;
  }
  .search-field .search {
    padding-left: 27px;
  }
  .toolbar .check {
    align-items: center;
    gap: 5px;
    white-space: nowrap;
  }
  .toolbar .check input {
    margin: 0;
  }
  .lines {
    flex: 1;
    overflow: auto;
    padding: 10px 12px;
    border-radius: var(--radius-card);
    background: var(--code-background);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    font: 11px / 1.55 var(--mono);
    -webkit-user-select: text;
    user-select: text;
    cursor: text;
  }
  .line {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    margin-bottom: 1px;
  }
  .header {
    font-weight: 700;
  }
  .step {
    color: var(--accent-text);
  }
  .command {
    color: var(--purple);
  }
  .error {
    color: var(--state-fail-text);
  }
  .output {
    color: var(--secondary);
  }
</style>
