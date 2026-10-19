<script lang="ts">
  // The pairing request as the pairing window shows it (the window's logic is in Pairing.svelte): the name the app
  // gave (labelled as self-reported), the full executable path (the identity the pairing pins), and the connections
  // it may use, none ticked. "Allow" works only once the input lock passed and a connection is ticked; there is no
  // default button.
  import type { PairingView } from './api';
  import Icon from './Icon.svelte';
  import { tr } from './l10n.svelte';
  import { canAllow } from './pairing';
  import { countdown } from './prompt';

  let {
    pairing,
    ticked = $bindable([]),
    armed,
    expired = false,
    left,
    onallow,
    ondeny,
  }: {
    pairing: PairingView;
    ticked?: string[];
    armed: boolean;
    /// The two minutes are over: nothing can be answered here any more.
    expired?: boolean;
    left: number;
    onallow: () => void;
    ondeny: () => void;
  } = $props();

  const allowed = $derived(!expired && canAllow(pairing.items, ticked, armed));
</script>

<div class="manage pairing">
  <h1>
    <span class="bubble" aria-hidden="true"><Icon name="link" /></span>
    {tr('Allow an App to Control VPNs?')}
  </h1>
  <p class="intro">{tr('An app on this Mac asks to bring the connections you choose up and down. Allow it only if you started this app and you trust it.')}</p>
  <div class="identity">
    <p class="caption">{tr('Name (self-reported)')}</p>
    <p class="name">{pairing.name}</p>
    <p class="caption">{tr('Executable')}</p>
    <p class="path">{pairing.executable}</p>
  </div>
  <p class="caption heading">{tr('Connections it may use')}</p>
  <div class="items">
    {#each pairing.items as item (item.id)}
      <label class="item">
        <input type="checkbox" value={item.id} bind:group={ticked} disabled={!armed || expired} />
        <span>{item.name}</span>
      </label>
    {:else}
      <p class="caption none">{tr('There are no connections to allow.')}</p>
    {/each}
  </div>
  <div class="buttons">
    <p class="caption expires">{tr('Expires in %@', countdown(left))}</p>
    <button class="deny" disabled={expired} onclick={() => !expired && ondeny()}>{tr('Deny')}</button>
    <button class="allow" disabled={!allowed} onclick={() => allowed && onallow()}>{tr('Allow')}</button>
  </div>
</div>

<style>
  .pairing {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: 18px var(--space-7) var(--space-7);
    height: 100vh;
    box-sizing: border-box;
    overflow: hidden;
  }
  h1 {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    font-size: var(--text-lg);
    font-weight: 600;
    margin: 0;
  }
  .bubble {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-icon);
    color: #fff;
    background: linear-gradient(180deg, var(--accent), var(--accent-pressed));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .bubble :global(.icon) {
    width: 16px;
    height: 16px;
    stroke-width: 1.7;
  }
  p {
    margin: 0;
  }
  .intro {
    color: var(--secondary);
  }
  .caption {
    font-size: var(--text-sm);
    color: var(--secondary);
    font-variant-numeric: tabular-nums;
  }
  .identity {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 12px;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
  }
  .identity .caption + * {
    margin-bottom: 4px;
  }
  .name {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .path {
    font: 11.5px / 1.45 var(--mono);
    overflow-wrap: anywhere;
    word-break: break-all;
    -webkit-user-select: text;
    user-select: text;
  }
  .heading {
    margin-top: 2px;
    font-weight: 600;
  }
  .items {
    flex: 1;
    min-height: 0;
    overflow: auto;
    display: flex;
    flex-direction: column;
    padding: 4px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 5px 8px;
    border-radius: var(--radius-sm);
  }
  .item:hover {
    background: var(--fill-hover);
  }
  .item span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .none {
    padding: 6px 8px;
  }
  .buttons {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--space-3);
  }
  .expires {
    margin-right: auto;
    padding: 3px 9px;
    border-radius: var(--radius-pill);
    background: var(--surface-sunken);
  }
</style>
