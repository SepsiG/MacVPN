<script lang="ts">
  // The yellow "Risky settings" panel: per line the directive and the short reason, then the acknowledgement.
  // The box is ticked only while every current risky directive is acknowledged (a new one un-ticks it).
  import type { RiskyView } from '../api';
  import { tr } from '../l10n.svelte';

  let { findings, acknowledged, onchange }: { findings: RiskyView[]; acknowledged: boolean; onchange: (on: boolean) => void } =
    $props();
</script>

<div class="risky">
  <div class="title">
    <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l7 12.5H1z M7.3 6v4.2h1.4V6z M7.3 11.2v1.4h1.4v-1.4z" fill="currentColor" fill-rule="evenodd" /></svg>
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
    padding: 10px;
    border-radius: 8px;
    background: rgba(255, 204, 0, 0.15);
    border: 1px solid rgba(255, 204, 0, 0.6);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .title {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
    color: var(--orange);
  }
  .title svg {
    width: 14px;
    height: 14px;
  }
  .finding {
    display: flex;
    align-items: baseline;
    gap: 6px;
    font-size: 12px;
  }
  .line {
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
  }
  code {
    font-weight: 700;
  }
  .reason {
    color: var(--secondary);
  }
</style>
