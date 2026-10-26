<script lang="ts">
  // L2TP / Cisco IPsec: the form whose save generates and opens the configuration profile (the Swift
  // `NativeConfigForm`). WinVPN (the backend's `platform` notes): saving writes the Windows VPN entry at once
  // ("Save", nothing to approve), and a Cisco IPsec connection, which Windows cannot run, shows why and offers
  // **Make an L2TP/IPsec Copy**.
  import { api, type NativeFields, type Notice } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import CredentialSelector from './CredentialSelector.svelte';
  import Modal from './Modal.svelte';
  import PlatformNotes from './PlatformNotes.svelte';
  import { nativeSaveLabel, nativeSaveNote, nativeSavedText } from './ras';
  import type { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { session, kind }: { session: EditorSession; kind: string } = $props();

  const fields = $derived(session.fields as NativeFields);
  const view = $derived(session.view);
  /// A team catalog's connection: read-only (its profile is installed from the detail's "Install profile").
  const readOnly = $derived(view?.readOnly ?? null);
  const platform = $derived(view?.platform);

  /// "Make an L2TP/IPsec Copy": the copy is selected (its editor opens); a failed entry write is reported.
  let copyFailure = $state<Notice | null>(null);
  async function makeCopy() {
    await session.flush();
    try {
      const failure = await api.makeL2tpCopy(session.id);
      if (failure) copyFailure = { title: tr('Make an L2TP/IPsec Copy'), message: failure };
    } catch (e) {
      copyFailure = { title: tr('Make an L2TP/IPsec Copy'), message: String(e) };
    }
  }
</script>

<div class="form">
  {#if readOnly}
    <p class="readonly-note" role="note"><Icon name="lock" /><span>{readOnly}</span></p>
  {/if}
  <PlatformNotes {platform} part="reasons" />
  {#if platform?.l2tpCopy}
    <div class="row">
      <span class="spacer"></span>
      <button onclick={() => makeCopy().catch(console.error)}>{tr('Make an L2TP/IPsec Copy')}</button>
    </div>
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
    <p class="note">{nativeSaveNote(platform, tr)}</p>
    {#if view?.error}
      <p class="error">{view.error}</p>
    {/if}
    <div class="footer">
      <Status
        dirty={view?.dirty ?? false}
        savedText={view?.saved ? nativeSavedText(platform, tr) : null}
      />
      <span class="spacer"></span>
      <button class="primary" disabled={readOnly !== null} onclick={() => session.save().catch(console.error)}>{nativeSaveLabel(platform, tr)}</button>
    </div>
  </section>
</div>

{#if copyFailure}
  <Modal title={copyFailure.title} message={copyFailure.message} buttons={[{ label: tr('OK'), kind: 'primary', action: () => (copyFailure = null) }]} />
{/if}
