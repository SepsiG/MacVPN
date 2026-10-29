<script lang="ts">
  // A connected row's live traffic: the totals since it came up and, once known, the current rate
  // ("↓ 12.4 MB  ↑ 1.2 MB · ↓ 350 kB/s  ↑ 20.0 kB/s"; the texts are the backend's, in the UI language).
  import type { TrafficView } from './traffic';

  let { traffic, size = 'sm' }: { traffic: TrafficView; size?: 'sm' | 'md' } = $props();
</script>

<span class="traffic {size}" title={traffic.tooltip} aria-label={traffic.tooltip} data-traffic>
  <span class="totals">{traffic.totals}</span>{#if traffic.rates}<span class="dot" aria-hidden="true">·</span><span class="rates">{traffic.rates}</span>{/if}
</span>

<style>
  .traffic {
    display: flex;
    min-width: 0;
    color: var(--secondary);
    white-space: pre;
    overflow: hidden;
    text-overflow: ellipsis;
    font-variant-numeric: tabular-nums;
  }
  .sm {
    font-size: var(--text-xs);
    line-height: 13px;
  }
  .md {
    font-size: var(--text-sm);
    line-height: 16px;
  }
  .totals,
  .rates {
    flex: none;
  }
  .dot {
    flex: none;
    padding: 0 4px;
  }
</style>
