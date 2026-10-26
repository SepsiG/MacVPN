<script lang="ts">
  // One System Status row (the Swift `CheckRow`): green / red mark, title, detail; the action only when not ok
  // (or when `showAction`: WinVPN's OpenVPN row and MacVPN's tools row offer "Update" while they are green).
  import type { Snippet } from 'svelte';
  import type { CheckRow } from './api';
  import Icon from './Icon.svelte';

  let {
    row,
    title,
    showAction = false,
    children,
  }: { row: CheckRow; title: string; showAction?: boolean; children?: Snippet } = $props();
</script>

<div class="check-row">
  <span class="mark" class:ok={row.ok} aria-hidden="true"><Icon name={row.ok ? 'check' : 'cross'} /></span>
  <div class="text">
    <strong>{title}</strong>
    <span class="detail">{row.detail}</span>
  </div>
  {#if !row.ok || showAction}
    <div class="action">{@render children?.()}</div>
  {/if}
</div>

<style>
  .check-row {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    min-height: 36px;
  }
  .mark {
    flex: none;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    background: var(--state-fail);
    box-shadow: inset 0 0.5px 0 rgba(255, 255, 255, 0.25);
  }
  .mark :global(.icon) {
    width: 13px;
    height: 13px;
    stroke-width: 2.2;
  }
  .mark.ok {
    background: var(--state-on);
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
    min-width: 0;
  }
  strong {
    font-weight: 600;
  }
  .detail {
    color: var(--secondary);
    font-size: var(--text-md);
    overflow-wrap: anywhere;
    -webkit-user-select: text;
    user-select: text;
  }
  .action {
    flex: none;
  }
</style>
