<script lang="ts">
  // An IKEv2 connection's client certificate (client credential audit G4), under its config text, with "Import Client
  // Certificate…" (a PKCS#12 file, or a PEM certificate and its key; the backend shows the open panel, checks the
  // files and keeps them in the vault), the imported one's form and SHA-256 fingerprint, and "Remove" (asks
  // first). At connect MacVPN copies it into the root-only run folder, LinVPN writes it (PEM only) as private runtime
  // files for NetworkManager; the auth = pubkey rounds without certs of their own use it. The key never reaches the
  // web view.
  import type { ClientCertView } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';
  import { formLabel, notes } from './clientcert';

  let {
    cert,
    readOnly = false,
    onimport,
    onremove,
    onconvert,
  }: {
    cert: ClientCertView;
    /// A team catalog's connection: nothing can be imported or removed.
    readOnly?: boolean;
    onimport: () => Promise<void>;
    onremove: () => Promise<void>;
    /// LinVPN: the password of the chosen PKCS#12 file (`null`: Cancel).
    onconvert: (password: string | null) => Promise<void>;
  } = $props();

  let password = $state('');
  let convertError = $state<string | null>(null);

  async function convert(value: string | null) {
    convertError = null;
    busy = true;
    try {
      await onconvert(value);
      password = '';
    } catch (e) {
      convertError = String(e);
    } finally {
      busy = false;
    }
  }

  let busy = $state(false);
  let asking = $state(false);
  let error = $state<string | null>(null);
  const lines = $derived(notes(cert));

  async function run(action: () => Promise<void>) {
    asking = false;
    error = null;
    busy = true;
    try {
      await action();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<fieldset class="client-cert">
  <legend>{tr('Client certificate')}</legend>
  {#if cert.imported}
    <div class="cert-row">
      <span class="cert-form">{formLabel(cert.imported)}</span>
      <code class="fingerprint" title={tr('SHA-256 fingerprint')}>{cert.imported.sha256}</code>
    </div>
  {:else}
    <p class="note no-cert">{tr('No client certificate imported. MacVPN uses the certificates in Homebrew’s etc/swanctl folder.')}</p>
  {/if}
  {#each lines as line (line)}
    <p class="note">{line}</p>
  {/each}
  <div class="cert-actions">
    <button class="import-cert" type="button" disabled={readOnly || busy} onclick={() => run(onimport).catch(console.error)}
      ><Icon name="key" />{tr('Import Client Certificate…')}</button
    >
    {#if cert.imported}
      <button class="remove-cert" type="button" disabled={readOnly || busy} onclick={() => (asking = true)}>{tr('Remove')}</button>
    {/if}
    <span class="note">{tr('Used by the auth = pubkey rounds that name no certs of their own. Kept in the vault.')}</span>
  </div>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
</fieldset>

{#if cert.pkcs12Password}
  <Modal
    title={tr('Password of the PKCS#12 file')}
    message={tr('LinVPN converts the file into a certificate and a key. The key keeps this password: it is filled in as the Private key password, and saved when you save the connection.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => convert(null).catch(console.error) },
      { label: tr('Import'), kind: 'primary', action: () => convert(password).catch(console.error) },
    ]}
  >
    <div class="form">
      <label class="form-row"><span>{tr('Password')}</span><input data-field="pkcs12-password" type="password" autocomplete="off" spellcheck="false" disabled={busy} bind:value={password} /></label>
      {#if convertError}<p class="form-error" role="alert">{convertError}</p>{/if}
    </div>
  </Modal>
{/if}

{#if asking}
  <Modal
    title={tr('Remove the client certificate?')}
    message={tr('Its key is deleted from the vault. Import it again to use it.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (asking = false) },
      { label: tr('Remove'), kind: 'destructive', action: () => run(onremove).catch(console.error) },
    ]}
  />
{/if}

<style>
  .client-cert {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .cert-row {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .cert-form {
    flex: none;
    color: var(--secondary);
  }
  .fingerprint {
    flex: 1;
    min-width: 0;
    font-family: var(--mono);
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
    user-select: all;
  }
  .cert-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }
  .cert-actions .note {
    flex: 1;
    min-width: 12em;
  }
  .note {
    margin: 0;
    color: var(--secondary);
  }
</style>
