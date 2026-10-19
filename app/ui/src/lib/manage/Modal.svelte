<script lang="ts" module>
  export interface ModalButton {
    label: string;
    kind?: 'primary' | 'destructive' | 'cancel';
    action: () => void;
  }
</script>

<script lang="ts">
  // An alert in the window (the Swift `NSAlert` / `confirmationDialog`): title, message, an optional accessory
  // (the uninstaller's checkbox), buttons. No default button: Return does nothing, Escape is the cancel button if
  // there is one.
  import type { Snippet } from 'svelte';

  let {
    title,
    message = '',
    buttons,
    children,
  }: { title: string; message?: string; buttons: ModalButton[]; children?: Snippet } = $props();

  function keydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      const cancel = buttons.find((b) => b.kind === 'cancel');
      if (cancel) {
        event.preventDefault();
        cancel.action();
      }
    }
  }
</script>

<svelte:window onkeydown={keydown} />

<div class="backdrop">
  <div class="alert" role="alertdialog" aria-modal="true" aria-labelledby="modal-title">
    <h1 id="modal-title">{title}</h1>
    {#if message}
      <p>{message}</p>
    {/if}
    {@render children?.()}
    <div class="buttons">
      {#each buttons as button (button.label)}
        <button class={button.kind ?? ''} onclick={button.action}>{button.label}</button>
      {/each}
    </div>
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
    padding-top: 60px;
    background: var(--backdrop);
    animation: fade 0.16s var(--ease);
  }
  .alert {
    width: min(420px, calc(100vw - 40px));
    max-height: calc(100vh - 100px);
    overflow: auto;
    box-sizing: border-box;
    padding: 20px;
    border-radius: var(--radius-panel);
    background: var(--surface);
    box-shadow: var(--shadow-popover);
    outline: 1px solid var(--border);
    outline-offset: -1px;
    -webkit-user-select: text;
    user-select: text;
    animation: rise 0.18s var(--ease);
  }
  h1 {
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0 0 6px;
  }
  p {
    margin: 0 0 16px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    color: var(--secondary);
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: var(--space-3);
    margin-top: 4px;
  }
  .buttons button {
    min-width: 76px;
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
