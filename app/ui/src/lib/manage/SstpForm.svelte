<script lang="ts">
  // SSTP: the config as a form, the password in the Keychain, the server certificate mode with the CA file
  // (the Swift `SSTPConfigForm`).
  import type { SstpFields } from '../api';
  import { tr } from '../l10n.svelte';
  import type { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { session }: { session: EditorSession } = $props();

  const fields = $derived(session.fields as SstpFields);
  const view = $derived(session.view);

  // As the Swift number field: an input that is not a whole number keeps the previous port.
  function setPort(event: Event) {
    const raw = (event.currentTarget as HTMLInputElement).value.trim();
    if (/^-?\d{1,18}$/.test(raw)) fields.port = Number.parseInt(raw, 10);
  }
</script>

<div class="form">
  <section>
    <label class="field"><span>{tr('Name')}</span><input type="text" bind:value={fields.name} /></label>
    <label class="field">
      <span>{tr('Server')}</span><input type="text" placeholder="vpn.example.com" autocomplete="off" bind:value={fields.server} />
    </label>
    <label class="field">
      <span>{tr('Port')}</span><input type="text" inputmode="numeric" value={String(fields.port)} onchange={setPort} />
    </label>
    <label class="field"><span>{tr('Username')}</span><input type="text" autocomplete="off" bind:value={fields.user} /></label>
    <label class="field">
      <span>{tr('Password')}</span>
      <SecretField label={tr('Password')} stored={view?.hasStoredSecret.password ?? false} bind:value={fields.password} />
    </label>
    {#if view?.passwordRule}
      <p class="error">{view.passwordRule}</p>
    {/if}
    <p class="note">{tr('The password is stored in the Keychain. Use user@domain instead of DOMAIN\\user.')}</p>
  </section>
  <section>
    <label class="field">
      <span>{tr('Server certificate')}</span>
      <select bind:value={fields.cert}>
        <option value="system">{tr('System CA')}</option>
        <option value="ca">{tr('Custom CA file')}</option>
        <option value="insecure">{tr('No verification')}</option>
      </select>
    </label>
    {#if fields.cert === 'system'}
      <p class="note">
        {tr("Uses the CA certificates of Homebrew's OpenSSL, not the macOS Keychain. For a company CA, choose a custom CA file.")}
      </p>
    {:else if fields.cert === 'ca'}
      <div class="row">
        {#if (view?.certCount ?? 0) > 0}
          <span class="ok">{tr('Certificates loaded: %lld', view?.certCount ?? 0)}</span>
        {:else}
          <span class="warn">{tr('No CA certificate loaded')}</span>
        {/if}
        <span class="spacer"></span>
        <button onclick={() => session.chooseCa().catch(console.error)}>{tr('Choose PEM File…')}</button>
      </div>
      {#if view?.importError}
        <p class="error">{view.importError}</p>
      {/if}
    {:else}
      <p class="error">
        {tr("The server's certificate is not verified. Anyone between you and the server can impersonate it and capture your login. Use this only for testing.")}
      </p>
    {/if}
  </section>
  <section>
    <h2>{tr('One-time code (MFA)')}</h2>
    <OtpFields bind:otp={fields.otp} />
  </section>
  <section>
    <label class="check"><input type="checkbox" bind:checked={fields.routeAll} />{tr('Send all traffic over VPN')}</label>
    <label class="check"><input type="checkbox" bind:checked={fields.peerDns} />{tr("Use the server's DNS")}</label>
  </section>
  <section>
    {#if view && view.issues.length > 0}
      <ul class="issues">
        {#each view.issues as issue, i (i)}
          <li>{issue}</li>
        {/each}
      </ul>
    {/if}
    <div class="footer">
      <Status dirty={view?.dirty ?? false} savedAt={view?.savedAt ?? null} />
      <span class="spacer"></span>
      <button class="primary" onclick={() => session.save().catch(console.error)}>{tr('Save')}</button>
    </div>
  </section>
</div>
