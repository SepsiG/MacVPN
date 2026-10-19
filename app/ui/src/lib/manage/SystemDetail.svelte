<script lang="ts">
  // A system VPN not created by MacVPN: connect / disconnect, and for L2TP / Cisco IPsec the PSK / password kept
  // in MacVPN's keychain with the one-time code setting (the Swift `SystemServiceDetail`).
  import { onDestroy, onMount, untrack } from 'svelte';
  import { api, type Row, type SystemFields } from '../api';
  import { tr } from '../l10n.svelte';
  import { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { row, epoch }: { row: Row; epoch: number } = $props();

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
    <h1>{row.name}</h1>
    <p class="secondary">{tr('%@ · system VPN (not created by MacVPN)', row.typeLabel)}</p>
    <p>{tr('This connection can only be connected and disconnected here. Its settings are in System Settings or in its own app.')}</p>
    <div>
      <button onclick={toggle} disabled={row.state === 'disconnecting'}>{row.switchOn ? tr('Disconnect') : tr('Connect')}</button>
    </div>
    {#if row.state === 'failed'}
      <p class="error">{row.reason}</p>
    {/if}
  </div>
  {#if session && fields}
    <div class="form">
      <section>
        <label class="field">
          <span>{tr('Shared secret (PSK)')}</span>
          <SecretField label={tr('Shared secret (PSK)')} stored={view?.hasStoredSecret.psk ?? false} bind:value={fields.psk} />
        </label>
        <label class="field">
          <span>{tr('Password (optional, if not saved in macOS)')}</span>
          <SecretField
            label={tr('Password (optional, if not saved in macOS)')}
            stored={view?.hasStoredSecret.password ?? false}
            bind:value={fields.password}
          />
        </label>
        <p class="note">
          {tr('Stored in the MacVPN keychain and passed to macOS when connecting. Needed when macOS cannot read the shared secret on its own ("incorrect user shared secret").')}
        </p>
      </section>
      <section>
        <h2>{tr('One-time code (MFA)')}</h2>
        <OtpFields bind:otp={fields.otp} />
      </section>
      <section>
        {#if view?.error}
          <p class="error">{view.error}</p>
        {/if}
        <Status dirty={view?.dirty ?? false} savedText={view?.saved ? tr('Saved') : null} />
        <div class="footer">
          <button class="destructive" disabled={!view?.hasStored && !view?.dirty} onclick={() => session.forget().catch(console.error)}>
            {tr('Forget saved secrets')}
          </button>
          <span class="spacer"></span>
          <button class="primary" disabled={!view?.dirty} onclick={() => session.save().catch(console.error)}>{tr('Save')}</button>
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
    padding: 16px 16px 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  h1 {
    font-size: 15px;
    margin: 0;
  }
  .intro p {
    margin: 0;
  }
</style>
