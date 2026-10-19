<script lang="ts">
  // One System Status row (the Swift `CheckRow`): green / red mark, title, detail; the action only when not ok.
  import type { Snippet } from 'svelte';
  import type { CheckRow } from './api';

  let { row, title, children }: { row: CheckRow; title: string; children?: Snippet } = $props();
</script>

<div class="check-row">
  <span class="mark" class:ok={row.ok} aria-hidden="true">{row.ok ? '✓' : '✕'}</span>
  <div class="text">
    <strong>{title}</strong>
    <span class="detail">{row.detail}</span>
  </div>
  {#if !row.ok}
    <div class="action">{@render children?.()}</div>
  {/if}
</div>

<style>
  .check-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .mark {
    flex: none;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 700;
    color: #fff;
    background: var(--red);
  }
  .mark.ok {
    background: var(--green);
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1;
    min-width: 0;
  }
  .detail {
    color: var(--secondary);
    font-size: 12px;
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .action {
    flex: none;
  }
</style>
