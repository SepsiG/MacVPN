<script lang="ts">
  // A system VPN not created by MacVPN: connect / disconnect, and for L2TP / Cisco IPsec the PSK / password kept
  // in MacVPN's keychain with the one-time code setting (the Swift `SystemServiceDetail`). A VPN removed from
  // macOS while shown (the selection's `selectedRemoved`, or the editor's own `removed`) stays, read-only, under a
  // banner, until another row is selected or it returns. Its saved secrets can still be forgotten.
  import { onDestroy, onMount, untrack } from 'svelte';
  import { api, type Row, type SystemFields } from '../api';
  import { tr } from '../l10n.svelte';
  import Icon from '../Icon.svelte';
  import TypeIcon from '../TypeIcon.svelte';
  import AdminActionButton from './AdminActionButton.svelte';
  import CredentialSelector from './CredentialSelector.svelte';
  import { EditorSession } from './session.svelte';
  import { forgetDisabled } from './live';
  import OtpFields from './OtpFields.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { row, epoch, selectedRemoved = false }: { row: Row; epoch: number; selectedRemoved?: boolean } = $props();

  const session = untrack(() => (row.storedSecrets ? new EditorSession(row.id) : null));

  // The backend dropped the editors (changes discarded): load again.
  let loadedEpoch = untrack(() => epoch);
  $effect(() => {
    if (epoch !== loadedEpoch) {
      loadedEpoch = epoch;
      untrack(() => session?.open());
    }
  });
  const fields = $derived(session?.fields as SystemFields | null);
  const view = $derived(session?.view ?? null);
  const removed = $derived(selectedRemoved || (view?.removed ?? false));

  $effect(() => {
    if (session?.fields) {
      JSON.stringify(session.fields);
      untrack(() => session.changed());
    }
  });

  onMount(() => {
    session?.open();
  });
  onDestroy(() => session?.dispose());

  function toggle() {
    (row.switchOn ? api.disconnect(row.id) : api.connect(row.id, false)).catch(console.error);
  }
</script>

<div class="system">
  <div class="intro">
    <div class="head">
      <TypeIcon kind={null} state={row.state} size="lg" />
      <div class="title">
        <h1>{row.name}</h1>
        <p class="secondary">{tr('%@ · system VPN (not created by MacVPN)', row.typeLabel)}</p>
      </div>
      <button class:primary={!row.switchOn} onclick={toggle} disabled={removed || row.state === 'disconnecting'}>{row.switchOn ? tr('Disconnect') : tr('Connect')}</button>
    </div>
    {#if removed}
      <div class="removed" role="status">
        <Icon name="warning" />
        <span>{tr('This VPN was removed from macOS')}</span>
      </div>
    {/if}
    <p class="about">{tr('This connection can only be connected and disconnected here. Its settings are in System Settings or in its own app.')}</p>
    {#if row.state === 'failed'}
      <p class="error">{row.reason}</p>
      <!-- WinVPN 2c: Allow L2TP Behind NAT… after a system L2TP VPN's error 809 (absent on macOS). -->
      {#if row.adminAction === 'allow-l2tp-behind-nat'}<div><AdminActionButton id={row.id} action={row.adminAction} /></div>{/if}
    {/if}
  </div>
  {#if session && fields}
    <div class="form">
      <section>
        <label class="field">
          <span>{tr('Shared secret (PSK)')}</span>
          <SecretField
            label={tr('Shared secret (PSK)')}
            stored={view?.hasStoredSecret.psk ?? false}
            bind:value={fields.psk}
            disabled={removed}
          />
        </label>
        {#if view?.platform?.pskNote && view.hasStoredSecret.psk}
          <p class="note">{view.platform.pskNote}</p>
        {/if}
        <CredentialSelector
          item={row.id}
          credential={view?.credential ?? null}
          passwordOnly
          disabled={removed}
          onchanged={() => session.open()}
        />
        {#if !view?.credential}
          <label class="field">
            <span>{tr('Password (optional, if not saved in macOS)')}</span>
            <SecretField
              label={tr('Password (optional, if not saved in macOS)')}
              stored={view?.hasStoredSecret.password ?? false}
              bind:value={fields.password}
              disabled={removed}
            />
          </label>
        {/if}
        <p class="note">
          {tr('Stored in the MacVPN vault and passed to macOS when connecting. Needed when macOS cannot read the shared secret on its own ("incorrect user shared secret").')}
        </p>
      </section>
      <section>
        <h2>{tr('One-time code (MFA)')}</h2>
        <OtpFields bind:otp={fields.otp} disabled={removed} />
      </section>
      <section>
        {#if view?.error}
          <p class="error">{view.error}</p>
        {/if}
        <Status dirty={view?.dirty ?? false} savedText={view?.saved ? tr('Saved') : null} />
        <div class="footer">
          <button class="destructive" disabled={forgetDisabled(removed, view)} onclick={() => session.forget().catch(console.error)}>
            {tr('Forget saved secrets')}
          </button>
          <span class="spacer"></span>
          <button class="primary" disabled={removed || !view?.dirty} onclick={() => session.save().catch(console.error)}>{tr('Save')}</button>
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .system {
    overflow: auto;
    height: 100%;
  }
  .intro {
    --badge-ring: var(--background);
    padding: 18px var(--space-7) 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--space-5);
  }
  .title {
    flex: 1;
    min-width: 0;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .intro p {
    margin: 0;
  }
  .title p {
    font-size: var(--text-md);
  }
  .removed {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 10px 12px;
    border-radius: var(--radius-card);
    background: var(--state-busy-soft);
    font-size: var(--text-md);
    font-weight: 500;
  }
  .removed :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    color: var(--state-busy);
  }
  .about {
    padding: 10px 12px;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
    color: var(--secondary);
    font-size: var(--text-md);
  }
</style>
