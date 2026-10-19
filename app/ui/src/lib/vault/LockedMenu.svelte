<script lang="ts">
  // The menu while the vault is locked (or not set up yet): no connection name, no switch, no setting that reads
  // the vault – one "Unlock…" row (or "Set Up the Vault…"), the number of connections still up, and Quit.
  import type { VaultView } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';

  let {
    vault,
    version,
    onunlock,
    onquit,
  }: { vault: VaultView; version: string; onunlock: () => void; onquit: () => void } = $props();

  const creating = $derived(vault.state === 'notCreated');
</script>

<div class="locked">
  <button class="unlock-row" onclick={onunlock}>
    <span class="bubble" aria-hidden="true"><Icon name="lock" /></span>
    <span class="text">
      <span class="title">{creating ? tr('Set Up the Vault…') : tr('Unlock…')}</span>
      <span class="caption">{creating ? tr('MacVPN keeps your connections in an encrypted vault.') : tr('MacVPN is locked')}</span>
    </span>
    <Icon name="chevron" class="chevron" />
  </button>
  {#if vault.activeCount > 0}
    <p class="active" role="status">
      <span class="dot" aria-hidden="true"></span>
      {vault.activeCount === 1 ? tr('1 connection active') : tr('%lld connections active', vault.activeCount)}
    </p>
  {/if}
  <div class="footer">
    <span class="spacer"></span>
    <button class="pill quit" onclick={onquit}>
      <Icon name="power" />
      {tr('Quit MacVPN')}
    </button>
  </div>
  <p class="version">{version}</p>
</div>

<style>
  .locked {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }
  .unlock-row {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: 10px 12px;
    border: none;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: default;
  }
  .unlock-row:hover {
    background: var(--surface-hover, var(--surface));
  }
  .unlock-row:focus-visible {
    outline: none;
    box-shadow: var(--focus-ring);
  }
  .bubble {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: var(--radius-icon);
    color: #fff;
    background: linear-gradient(180deg, var(--accent), color-mix(in srgb, var(--accent) 80%, #000));
  }
  .text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    flex: 1;
    min-width: 0;
  }
  .title {
    font-weight: 600;
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .unlock-row :global(.chevron) {
    color: var(--tertiary);
  }
  .active {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin: 0;
    padding: 0 4px;
    font-size: var(--text-sm);
    color: var(--state-on-text);
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--state-on);
  }
  .footer {
    display: flex;
    align-items: center;
  }
  .spacer {
    flex: 1;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: none;
    border-radius: var(--radius-pill);
    padding: 4px 10px;
    background: transparent;
    color: var(--secondary);
    font: inherit;
    font-size: var(--text-sm);
  }
  .pill:hover {
    background: var(--surface-sunken);
    color: var(--text);
  }
  .version {
    margin: 0;
    text-align: center;
    font-size: var(--text-xs, 11px);
    color: var(--tertiary);
    padding-bottom: 2px;
  }
</style>
