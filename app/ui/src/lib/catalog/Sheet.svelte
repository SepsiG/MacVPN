<script lang="ts">
  // A dialog of the "Team catalogs" section in the card style (the same backdrop and panel as `manage/Modal.svelte`),
  // with its own content and buttons, so a button can be disabled until the input is complete. Escape cancels.
  import type { Snippet } from 'svelte';

  let {
    title,
    wide = false,
    oncancel,
    children,
    buttons,
  }: { title: string; wide?: boolean; oncancel: () => void; children: Snippet; buttons: Snippet } = $props();
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      oncancel();
    }
  }}
/>

<div class="backdrop">
  <div class="sheet" class:wide role="dialog" aria-modal="true" aria-label={title}>
    <h1>{title}</h1>
    <div class="content">{@render children()}</div>
    <div class="buttons">{@render buttons()}</div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: 48px;
    background: var(--backdrop);
    animation: fade 0.16s var(--ease);
  }
  .sheet {
    width: min(440px, calc(100vw - 40px));
    max-height: calc(100vh - 80px);
    overflow: auto;
    box-sizing: border-box;
    padding: 20px;
    border-radius: var(--radius-panel);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    animation: rise 0.18s var(--ease);
  }
  .sheet.wide {
    width: min(520px, calc(100vw - 40px));
  }
  h1 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0 0 12px;
  }
  .content {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    margin-bottom: 18px;
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: var(--space-3);
  }
  .buttons :global(button) {
    min-width: 76px;
  }
  /* The dialogs' common parts: label + field rows, hints, the error line, monospaced keys. */
  .content :global(p) {
    margin: 0;
  }
  .content :global(.form-row) {
    display: grid;
    grid-template-columns: minmax(110px, 32%) 1fr;
    align-items: center;
    gap: var(--space-4);
  }
  .content :global(.form-row > span:first-child) {
    color: var(--secondary);
  }
  .content :global(.form-row input),
  .content :global(.form-row textarea) {
    min-width: 0;
    width: 100%;
    box-sizing: border-box;
  }
  .content :global(.mono) {
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 0.02em;
  }
  .content :global(.hint) {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .content :global(.form-error) {
    font-size: var(--text-md);
    color: var(--state-fail-text);
    overflow-wrap: anywhere;
  }
  .content :global(.secondary) {
    color: var(--secondary);
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  @keyframes rise {
    from {
      opacity: 0;
      transform: translateY(6px) scale(0.98);
    }
  }
</style>
