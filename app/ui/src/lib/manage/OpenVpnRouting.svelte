<script lang="ts">
  // LinVPN's OpenVPN "Send all traffic over VPN" (decisions 7 and 8): Server decides / Always / Never as a segmented
  // control (the native editors' setting, three-way). The choice lives in the config text: the backend reads it
  // from `config` and rewrites the text on a click, and `onchange` hands the new text to the editor, so Save,
  // Cancel and the validator treat it as any other text edit. The editor shows it only where `visible()` says.
  import { api } from '../api';
  import { tr } from '../l10n.svelte';
  import { helpText, routingOptions, type RoutingId } from './openvpnRouting';

  let {
    config,
    pushVisible = true,
    disabled = false,
    onchange,
  }: { config: string; pushVisible?: boolean; disabled?: boolean; onchange: (text: string) => void } = $props();

  const options = routingOptions(tr);
  let routing = $state<RoutingId>('server');
  // Only the newest read's answer counts (the text changes while a read is under way).
  let generation = 0;

  $effect(() => {
    const text = config;
    const mine = ++generation;
    api
      .openvpnRoutingRead(text)
      .then((r) => {
        if (mine === generation) routing = r;
      })
      .catch(console.error);
  });

  async function choose(id: RoutingId) {
    if (disabled || id === routing) return;
    try {
      onchange(await api.openvpnRoutingWrite(config, id));
    } catch (e) {
      console.error(e);
    }
  }
</script>

<div class="routing">
  <div class="field">
    <span>{tr('Send all traffic over VPN')}</span>
    <div class="segmented" role="radiogroup" aria-label={tr('Send all traffic over VPN')}>
      {#each options as o (o.id)}
        <button type="button" role="radio" aria-checked={routing === o.id} class:on={routing === o.id} {disabled} onclick={() => choose(o.id)}
          >{o.label}</button
        >
      {/each}
    </div>
  </div>
  <p class="note">{helpText(routing, { pushVisible }, tr)}</p>
</div>

<style>
  .routing {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .routing .segmented {
    justify-self: start;
  }
</style>
