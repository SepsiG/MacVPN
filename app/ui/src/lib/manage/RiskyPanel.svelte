<script lang="ts">
  // The yellow "Risky settings" panel: per line the directive and the short reason, then the acknowledgement.
  // The box is ticked only while every current risky directive is acknowledged (a new one un-ticks it).
  import type { RiskyView } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';

  let { findings, acknowledged, onchange }: { findings: RiskyView[]; acknowledged: boolean; onchange: (on: boolean) => void } =
    $props();
</script>

<div class="risky">
  <div class="title">
    <Icon name="warning" />
    {tr('Risky settings')}
  </div>
  {#each findings as f, i (i)}
    <div class="finding">
      <span class="line">{f.line}.</span>
      <code>{f.directive}</code>
      <span class="reason">{f.reason}</span>
    </div>
  {/each}
  <label class="check">
    <input type="checkbox" checked={acknowledged} onchange={(e) => onchange((e.currentTarget as HTMLInputElement).checked)} />
    {tr('I acknowledge these settings and the security risks')}
  </label>
</div>

<style>
  .risky {
    padding: 12px 14px;
    border-radius: var(--radius-card);
    background: var(--state-busy-soft);
    outline: 1px solid color-mix(in srgb, var(--state-busy) 40%, transparent);
    outline-offset: -1px;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .title {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-weight: 600;
    color: var(--state-busy-text);
  }
  .title :global(.icon) {
    width: 15px;
    height: 15px;
  }
  .finding {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    font-size: var(--text-md);
  }
  .line {
    min-width: 2.2em;
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
  }
  code {
    padding: 1px 6px;
    border-radius: var(--radius-xs);
    background: var(--surface);
    font: 600 11px var(--mono);
  }
  .reason {
    color: var(--secondary);
  }
  .check {
    margin-top: 4px;
  }
</style>
