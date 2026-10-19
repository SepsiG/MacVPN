<script lang="ts">
  // One connection of the menu as a card: the type's icon bubble with the state badge, the name (with the pin),
  // the type and state line, and the switch.
  import type { Row } from './api';
  import { tr } from './l10n.svelte';
  import { statusLine, statusText } from './status';
  import TypeIcon from './TypeIcon.svelte';

  let { row, now, onToggle }: { row: Row; now: number; onToggle: (row: Row, debug: boolean) => void } = $props();

  const line = $derived(statusLine(row, now));

  // Option-click (or Option + Space / Return) on the switch: connect in debug mode.
  function click(event: MouseEvent) {
    onToggle(row, event.altKey);
  }
</script>

<div class="card {line.tone}" class:unavailable={!row.available}>
  <TypeIcon kind={row.kind} state={row.state} />
  <div class="text">
    <div class="name">
      <span class="label">{row.name}</span>
      {#if row.pinned}
        <svg class="pin" viewBox="0 0 16 16" role="img" aria-label={tr('Pinned')}>
          <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
        </svg>
      {/if}
    </div>
    <div class="subtitle" title={statusText(line)}>
      <span class="type">{line.type}</span>{#if line.status}<span class="dot" aria-hidden="true">·</span><span class="status">{line.status}</span>{/if}
    </div>
    {#if row.heldBy.length > 0}
      <div class="held">{tr('Held by %@', row.heldBy.join(', '))}</div>
    {/if}
  </div>
  <button
    class="switch"
    class:on={row.switchOn}
    role="switch"
    aria-checked={row.switchOn}
    aria-label={row.name}
    disabled={!row.switchEnabled}
    onclick={click}
  >
    <span class="knob"></span>
  </button>
</div>

<style>
  .card {
    --badge-ring: var(--surface);
    display: flex;
    align-items: center;
    gap: var(--space-4);
    min-height: 34px;
    padding: 9px 10px 9px 10px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    transition:
      background-color var(--duration) var(--ease),
      outline-color var(--duration) var(--ease);
  }
  .card.on {
    outline-color: color-mix(in srgb, var(--state-on) 45%, transparent);
  }
  .card.busy {
    outline-color: color-mix(in srgb, var(--state-busy) 35%, transparent);
  }
  .card.fail {
    outline-color: color-mix(in srgb, var(--state-fail) 35%, transparent);
  }
  .unavailable .text,
  .unavailable :global(.bubble) {
    opacity: 0.5;
  }
  .text {
    flex: 1;
    min-width: 0;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 5px;
    font-weight: 600;
    line-height: 17px;
  }
  .label {
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
  .subtitle {
    display: flex;
    min-width: 0;
    margin-top: 1px;
    font-size: var(--text-sm);
    line-height: 14px;
    color: var(--secondary);
    white-space: nowrap;
  }
  .type {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .held {
    margin-top: 2px;
    font-size: var(--text-xs);
    line-height: 13px;
    font-weight: 600;
    color: var(--state-on-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .dot {
    flex: none;
    padding: 0 4px;
  }
  .status {
    flex: 0 0 auto;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    font-weight: 500;
    font-variant-numeric: tabular-nums;
  }
  .on .status {
    color: var(--state-on-text);
  }
  .busy .status {
    color: var(--state-busy-text);
  }
  .fail .status {
    color: var(--state-fail-text);
  }

  .switch {
    flex: none;
    position: relative;
    width: 34px;
    height: 20px;
    padding: 0;
    border: none;
    border-radius: var(--radius-pill);
    background: var(--switch-off);
    transition:
      background-color var(--duration) var(--ease),
      box-shadow var(--duration) var(--ease);
  }
  .switch:not(:disabled):hover {
    background: color-mix(in srgb, var(--switch-off) 100%, var(--text) 8%);
  }
  .switch.on,
  .switch.on:not(:disabled):hover {
    background: var(--accent);
  }
  .on .switch.on,
  .on .switch.on:not(:disabled):hover {
    background: var(--state-on);
  }
  .busy .switch.on,
  .busy .switch.on:not(:disabled):hover {
    background: var(--state-busy);
  }
  .switch:disabled {
    opacity: 0.45;
  }
  .knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: var(--radius-pill);
    background: #fff;
    box-shadow: var(--shadow-knob);
    transition:
      transform var(--duration) var(--ease),
      width var(--duration) var(--ease);
  }
  .switch.on .knob {
    transform: translateX(14px);
  }
  .switch:not(:disabled):active .knob {
    width: 19px;
  }
  .switch.on:not(:disabled):active .knob {
    transform: translateX(11px);
  }
</style>
