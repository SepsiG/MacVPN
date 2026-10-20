<script lang="ts">
  // L2TP / Cisco IPsec: the form whose save generates and opens the configuration profile (the Swift
  // `NativeConfigForm`).
  import type { NativeFields } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import CredentialSelector from './CredentialSelector.svelte';
  import type { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { session, kind }: { session: EditorSession; kind: string } = $props();

  const fields = $derived(session.fields as NativeFields);
  const view = $derived(session.view);
  /// A team catalog's connection: read-only (its profile is installed from the detail's "Install profile").
  const readOnly = $derived(view?.readOnly ?? null);
</script>

<div class="form">
  {#if readOnly}
    <p class="readonly-note" role="note"><Icon name="lock" /><span>{readOnly}</span></p>
  {/if}
  <fieldset class="lock" disabled={readOnly !== null}>
    <section>
      <label class="field"><span>{tr('Name')}</span><input type="text" bind:value={fields.name} /></label>
      <label class="field"><span>{tr('Server')}</span><input type="text" autocomplete="off" bind:value={fields.server} /></label>
      <CredentialSelector item={session.id} credential={view?.credential ?? null} onchanged={() => session.open()} />
      <label class="field"><span>{tr('Account name')}</span><input type="text" autocomplete="off" bind:value={fields.account} /></label>
      {#if view?.credential}
        <p class="note">{tr('The account name is only written into the profile. MacVPN signs in with the shared credential.')}</p>
      {:else}
        <label class="field">
          <span>{tr('Password')}</span>
          <SecretField label={tr('Password')} stored={view?.hasStoredSecret.password ?? false} bind:value={fields.password} />
        </label>
      {/if}
      <label class="field">
        <span>{tr('Pre-shared key (PSK)')}</span>
        <SecretField label={tr('Pre-shared key (PSK)')} stored={view?.hasStoredSecret.psk ?? false} bind:value={fields.psk} />
      </label>
      {#if kind === 'cisco'}
        <label class="field"><span>{tr('Group name')}</span><input type="text" autocomplete="off" bind:value={fields.groupName} /></label>
      {/if}
      <label class="check"><input type="checkbox" bind:checked={fields.sendAllTraffic} />{tr('Send all traffic over VPN')}</label>
    </section>
    <section>
      <h2>{tr('One-time code (MFA)')}</h2>
      <OtpFields bind:otp={fields.otp} />
    </section>
  </fieldset>
  <section>
    <p class="note">
      {tr('Saving creates and opens a configuration profile. Approve it in System Settings → General → Device Management (Profiles). After each change it has to be approved again. The password is not in the profile: MacVPN passes it when connecting (from System Settings, macOS asks for it).')}
    </p>
    {#if view?.error}
      <p class="error">{view.error}</p>
    {/if}
    <div class="footer">
      <Status
        dirty={view?.dirty ?? false}
        savedText={view?.saved ? tr('Profile opened, approve it in System Settings.') : null}
      />
      <span class="spacer"></span>
      <button class="primary" disabled={readOnly !== null} onclick={() => session.save().catch(console.error)}>{tr('Save and Install Profile')}</button>
    </div>
  </section>
</div>
