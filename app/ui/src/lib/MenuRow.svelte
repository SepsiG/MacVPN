<script lang="ts">
  import type { Row } from './api';
  import { tr } from './l10n.svelte';
  import { uptime } from './format';
  import StatusDot from './StatusDot.svelte';

  let { row, now, onToggle }: { row: Row; now: number; onToggle: (row: Row, debug: boolean) => void } = $props();

  const subtitle = $derived.by(() => {
    switch (row.state) {
      case 'connected': {
        const parts = [row.typeLabel, row.ip].filter((p): p is string => !!p);
        if (row.since !== null) parts.push(uptime(row.since, now));
        return parts.join(' · ');
      }
      case 'failed':
        return `${row.typeLabel} · ${row.reason}`;
      case 'awaitingAuth':
        return tr('%@ · Waiting for authentication', row.typeLabel);
      default:
        return row.available ? row.typeLabel : tr('%@ · Missing tool', row.typeLabel);
    }
  });

  // Option-click (or Option + Space / Return) on the switch: connect in debug mode.
  function click(event: MouseEvent) {
    onToggle(row, event.altKey);
  }
</script>

<div class="row" class:unavailable={!row.available}>
  <StatusDot state={row.state} />
  <div class="text">
    <div class="name">
      <span class="label">{row.name}</span>
      {#if row.pinned}
        <svg class="pin" viewBox="0 0 16 16" role="img" aria-label={tr('Pinned')}>
          <path d="M9.8 1.5l4.7 4.7-1.4 1.4-.9-.4-2.6 2.6.3 2.7-1.4 1.4-2.8-2.8-3 3-.9-.9 3-3-2.8-2.8 1.4-1.4 2.7.3 2.6-2.6-.4-.9z" fill="currentColor" />
        </svg>
      {/if}
    </div>
    <div class="subtitle" title={subtitle}>{subtitle}</div>
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
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 8px;
  }
  .unavailable {
    opacity: 0.5;
  }
  .text {
    flex: 1;
    min-width: 0;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 4px;
    font-weight: 500;
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
    color: var(--secondary);
  }
  .subtitle {
    font-size: 11px;
    color: var(--secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .switch {
    flex: none;
    position: relative;
    width: 26px;
    height: 15px;
    padding: 0;
    border: none;
    border-radius: 8px;
    background: var(--switch-off);
    cursor: default;
    transition: background-color 0.15s;
  }
  .switch.on {
    background: var(--accent);
  }
  .switch:disabled {
    opacity: 0.5;
  }
  .switch:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .knob {
    position: absolute;
    top: 1.5px;
    left: 1.5px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 0.5px 1.5px rgba(0, 0, 0, 0.3);
    transition: transform 0.15s;
  }
  .switch.on .knob {
    transform: translateX(11px);
  }
</style>
