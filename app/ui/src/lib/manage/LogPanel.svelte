<script lang="ts">
  // The Log tab (the Swift `LogView`): the live tail of the connection's log (or the native debug collection),
  // the last 5000 lines, filter, search, follow, copy, save.
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { api, onLogLines, type Choice, type LogFilter, type LogLineView, type Notice } from '../api';
  import { tr } from '../l10n.svelte';
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
    <input class="search" type="search" placeholder={tr('Search')} aria-label={tr('Search')} bind:value={search} />
    <label class="check"><input type="checkbox" bind:checked={follow} onchange={scrollToEnd} />{tr('Follow')}</label>
    <button onclick={() => api.logCopy(filter, search).catch(console.error)}>{tr('Copy')}</button>
    <button onclick={() => save().catch(console.error)}>{tr('Save…')}</button>
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
    height: 100%;
    min-height: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px;
    border-bottom: 1px solid var(--separator);
  }
  .search {
    flex: 1;
    min-width: 80px;
  }
  .lines {
    flex: 1;
    overflow: auto;
    padding: 8px;
    background: var(--text-background);
    font: 11px ui-monospace, SFMono-Regular, Menlo, monospace;
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
    color: var(--blue);
  }
  .command {
    color: var(--purple);
  }
  .error {
    color: var(--red);
  }
  .output {
    color: var(--secondary);
  }
</style>
