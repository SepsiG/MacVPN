<script lang="ts">
  // The Log tab (the Swift `LogView`): the live tail of the connection's log (or the native debug collection),
  // the last 5000 lines, filter, search, time range, follow, copy, save, clear.
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { api, onLogLines, type Choice, type LogFilter, type LogLineView, type Notice } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import Modal from './Modal.svelte';
  import { applyChunk, customRange, presetRange, visibleLines, type TimePreset } from '../logview';

  let { id, name, filters, onnotice }: { id: string; name: string; filters: Choice<LogFilter>[]; onnotice: (n: Notice) => void } =
    $props();

  let lines = $state<LogLineView[]>([]);
  let generation = 0;
  let filter = $state<LogFilter>('all');
  let search = $state('');
  let follow = $state(true);
  let scroller: HTMLElement | undefined = $state();
  // The time range: a quick preset (relative to `now`, which moves on while the tab is shown) or "From" / "To".
  let preset = $state<TimePreset>('any');
  let customFrom = $state('');
  let customTo = $state('');
  let now = $state(new Date());
  const range = $derived(preset === 'custom' ? customRange(customFrom, customTo) : presetRange(preset, now));
  const visible = $derived(visibleLines(lines, filter, search, range));
  const presets: { value: TimePreset; title: string }[] = [
    { value: 'any', title: tr('Any Time') },
    { value: '5m', title: tr('Last 5 Minutes') },
    { value: '15m', title: tr('Last 15 Minutes') },
    { value: '1h', title: tr('Last Hour') },
    { value: 'today', title: tr('Today') },
    { value: 'custom', title: tr('Custom Range') },
  ];
  let confirmClear = $state(false);
  let clearing = $state(false);

  async function scrollToEnd() {
    if (!follow) return;
    await tick();
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }

  /// (Re)starts the view: the first lines of a new subscription (a new generation; late events of the old one are
  /// dropped).
  async function subscribe() {
    const first = await api.logSubscribe(id);
    if (!first) return;
    generation = first.generation;
    lines = applyChunk([], true, first.lines);
    scrollToEnd();
  }

  let unlisten: Promise<() => void> | null = null;
  let ticker: ReturnType<typeof setInterval> | undefined;
  onMount(() => {
    unlisten = onLogLines((event) => {
      if (event.generation !== generation) return;
      lines = applyChunk(lines, event.reset, event.lines);
      scrollToEnd();
    });
    untrack(() => subscribe()).catch(console.error);
    ticker = setInterval(() => (now = new Date()), 15_000);
  });
  onDestroy(() => {
    unlisten?.then((f) => f());
    clearInterval(ticker);
  });

  function choosePreset(value: TimePreset) {
    now = new Date();
    preset = value;
  }

  async function save() {
    const notice = await api.logSave();
    if (notice) onnotice(notice);
  }

  /// "Clear Log…" confirmed: the log is emptied by the backend, then the view starts over with what the log now
  /// holds (the "Log cleared at" line).
  async function clear() {
    confirmClear = false;
    clearing = true;
    try {
      const notice = await api.logClear(id);
      if (notice) onnotice(notice);
      lines = [];
      await subscribe();
    } finally {
      clearing = false;
    }
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
    <select class="time" aria-label={tr('Time')} title={tr('Time')} value={preset} onchange={(e) => choosePreset((e.currentTarget as HTMLSelectElement).value as TimePreset)}>
      {#each presets as p (p.value)}
        <option value={p.value}>{p.title}</option>
      {/each}
    </select>
    <label class="check"><input type="checkbox" bind:checked={follow} onchange={scrollToEnd} />{tr('Follow')}</label>
    <button onclick={() => api.logCopy(filter, search, range.from, range.to).catch(console.error)}><Icon name="copy" />{tr('Copy')}</button>
    <button onclick={() => save().catch(console.error)}><Icon name="save" />{tr('Save…')}</button>
    <button class="clear-log" disabled={clearing} onclick={() => (confirmClear = true)}><Icon name="trash" />{tr('Clear Log…')}</button>
  </div>
  {#if preset === 'custom'}
    <div class="toolbar range">
      <label class="field">{tr('From')}<input class="from" type="datetime-local" step="1" bind:value={customFrom} /></label>
      <label class="field">{tr('To')}<input class="to" type="datetime-local" step="1" bind:value={customTo} /></label>
    </div>
  {/if}
  <div class="lines" bind:this={scroller}>
    {#each visible as line, i (i)}
      <div class="line {line.kind}">{line.text}</div>
    {/each}
  </div>
</div>

{#if confirmClear}
  <Modal
    title={tr('Clear the log of %@?', name)}
    message={tr('This cannot be undone.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirmClear = false) },
      { label: tr('Clear Log'), kind: 'destructive', action: () => clear().catch(console.error) },
    ]}
  />
{/if}

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
  .range .field {
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
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
