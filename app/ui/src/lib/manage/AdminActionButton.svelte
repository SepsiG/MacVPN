<script lang="ts">
  // The failure banner's button for the administrator step the error names (WinVPN 2c): **Allow L2TP Behind NAT…**
  // (then "Restart Windows…") or **Trust This CA in Windows…** (an SSTP connection's custom CA). Each runs after a
  // UAC confirmation; the outcome is shown in an alert.
  import { api, type AdminAction, type Notice } from '../api';
  import { tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';
  import { adminActionLabel } from './ras';
  import TrustCa from './TrustCa.svelte';

  let { id, action }: { id: string; action: AdminAction } = $props();

  let outcome = $state<Notice | null>(null);
  let running = $state(false);

  async function allowNat() {
    const title = adminActionLabel('allow-l2tp-behind-nat', tr);
    running = true;
    try {
      outcome = { title, message: await api.rasAllowL2tpNat() };
    } catch (e) {
      outcome = { title, message: String(e) };
    } finally {
      running = false;
    }
  }
</script>

{#if action === 'trust-ca-in-windows'}
  <TrustCa {id} pick={false} />
{:else}
  <button disabled={running} onclick={() => allowNat().catch(console.error)}>{adminActionLabel(action, tr)}</button>
{/if}

{#if outcome}
  <Modal title={outcome.title} message={outcome.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (outcome = null) }]} />
{/if}
