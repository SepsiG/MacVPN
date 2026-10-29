<script lang="ts">
  // A connected row's live traffic: the totals since it came up and, once known, the current rate
  // ("↓ 12.4 MB ↑ 1.2 MB   ↓ 350 kB/s ↑ 20.0 kB/s"; the texts are the backend's, in the UI language). When the
  // row is too narrow, the rate wraps to a second line instead of running under the switch.
  import type { TrafficView } from './traffic';

  let { traffic, size = 'sm' }: { traffic: TrafficView; size?: 'sm' | 'md' } = $props();
</script>

<span class="traffic {size}" title={traffic.tooltip} aria-label={traffic.tooltip} data-traffic>
  <span class="totals">{traffic.totals}</span>{#if traffic.rates}<span class="rates">{traffic.rates}</span>{/if}
</span>

<style>
  .traffic {
    display: flex;
    flex-wrap: wrap;
    column-gap: 10px;
    min-width: 0;
    color: var(--secondary);
    white-space: nowrap;
    overflow: hidden;
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
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
