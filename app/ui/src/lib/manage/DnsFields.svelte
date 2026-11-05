<script lang="ts">
  // The connection's DNS settings (macOS root layer 15): the mode and the own DNS servers and domains. Shown by the
  // editors only where `visible` says so (see dnsFields.ts).
  import { tr } from '../l10n.svelte';
  import { type Dns, joinList, modes, overrideProblem, splitList, targetedNote } from './dnsFields';

  let { dns = $bindable(), fullTunnel }: { dns: Dns; fullTunnel?: boolean } = $props();

  const choices = $derived(modes(tr, fullTunnel));
  const note = $derived(targetedNote(tr, dns, fullTunnel));
  const problem = $derived(overrideProblem(tr, dns));
  let serversText = $state(joinList(dns.servers));
  let domainsText = $state(joinList(dns.domains));
</script>

<div class="dns-modes" role="radiogroup" aria-label={tr('DNS')}>
  {#each choices as m (m.id)}
    <label class="check">
      <input type="radio" name="dns-mode" value={m.id} bind:group={dns.mode} />
      <span>{m.label}<span class="note">{m.help}</span></span>
    </label>
  {/each}
</div>
{#if note}
  <p class="note">{note}</p>
{/if}
<label class="field">
  <span>{tr('Own DNS servers')}</span>
  <textarea
    rows="2"
    spellcheck="false"
    bind:value={serversText}
    oninput={() => (dns.servers = splitList(serversText))}
  ></textarea>
</label>
<label class="field">
  <span>{tr('Own domains')}</span>
  <textarea
    rows="2"
    spellcheck="false"
    bind:value={domainsText}
    oninput={() => (dns.domains = splitList(domainsText))}
  ></textarea>
</label>
<label class="check">
  <input type="checkbox" bind:checked={dns.overrideVpn} />
  {tr("Use these instead of the VPN's DNS")}
</label>
{#if problem}
  <p class="error">{problem}</p>
{/if}
