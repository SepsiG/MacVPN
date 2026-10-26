<script lang="ts">
  // **Trust This CA in Windows…** (WinVPN 2c): the CA's summary (an SSTP connection's custom CA, or a PEM file the
  // user picks for IKEv2), the confirmation with the warning, then the administrator step (a UAC prompt; it runs
  // off the UI thread in the backend) and its outcome. `trusted`: Windows trusts the SSTP CA already ("Trusted by
  // Windows" instead of the button). `compact`: a link-sized button (the failure banner).
  import { api, type CaConfirmView, type Notice } from '../api';
  import { i18n, tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';
  import { caConfirmMessage } from './ras';

  let {
    id,
    pick,
    trusted = null,
    disabled = false,
    onchanged = () => {},
  }: { id: string; pick: boolean; trusted?: boolean | null; disabled?: boolean; onchanged?: () => void } = $props();

  let confirm = $state<CaConfirmView | null>(null);
  let outcome = $state<Notice | null>(null);
  let running = $state(false);

  const title = $derived(tr('Trust This CA in Windows…'));

  async function start() {
    try {
      confirm = await api.rasCaSummary(id, pick);
    } catch (e) {
      outcome = { title, message: String(e) };
    }
  }

  async function trust() {
    confirm = null;
    running = true;
    try {
      outcome = { title, message: await api.rasTrustCa(id) };
    } catch (e) {
      outcome = { title, message: String(e) };
    } finally {
      running = false;
      onchanged();
    }
  }
</script>

{#if trusted === true}
  <span class="ok">{tr('Trusted by Windows')}</span>
{:else}
  <button disabled={disabled || running} onclick={() => start().catch(console.error)}>{title}</button>
{/if}

{#if confirm}
  <Modal
    {title}
    message={caConfirmMessage(confirm, i18n.language, tr)}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirm = null) },
      { label: tr('Trust'), kind: 'primary', action: () => trust().catch(console.error) },
    ]}
  />
{/if}

{#if outcome}
  <Modal title={outcome.title} message={outcome.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (outcome = null) }]} />
{/if}
