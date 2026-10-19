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
    background: rgba(0, 0, 0, 0.18);
  }
  .alert {
    width: min(440px, calc(100vw - 40px));
    max-height: calc(100vh - 100px);
    overflow: auto;
    padding: 18px;
    border-radius: 10px;
    background: var(--panel);
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
    -webkit-user-select: text;
    user-select: text;
  }
  h1 {
    font-size: 13px;
    margin: 0 0 8px;
  }
  p {
    margin: 0 0 14px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    color: var(--secondary);
  }
  .buttons {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
  }
  .destructive {
    color: var(--red);
  }
</style>
