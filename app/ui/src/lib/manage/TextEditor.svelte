<script lang="ts">
  // OpenVPN, WireGuard, strongSwan: the config text with the error list and the risky panel, the vault
  // secrets, the one-time code setting (the Swift `TextConfigEditor`). WinVPN, IKEv2 (the backend's `platform`
  // notes): the settings Windows cannot run as yellow notes above the config (not save errors: the config stays
  // valid for macOS), Windows' summary of the entry and the settings it ignores in grey under it, and **Trust This
  // CA in Windows…** with a PEM file the user picks.
  import type { TextFields } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import CredentialSelector from './CredentialSelector.svelte';
  import type { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import PlatformNotes from './PlatformNotes.svelte';
  import RiskyPanel from './RiskyPanel.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';
  import TrustCa from './TrustCa.svelte';

  let { session, kind }: { session: EditorSession; kind: string } = $props();

  const fields = $derived(session.fields as TextFields);
  const view = $derived(session.view);
  const showsUser = $derived(kind === 'openvpn' || kind === 'strongswan');
  const showsPsk = $derived(kind === 'strongswan');
  const showsKeyPassword = $derived(kind === 'openvpn');
  /// A team catalog's connection: everything is read-only but the risky settings' checkbox (saved with "Save").
  const readOnly = $derived(view?.readOnly ?? null);
  const platform = $derived(view?.platform);

  /// A refused save of a read-only editor (the catalog changed the config since it was loaded): the draft loads
  /// again from the new version, and the reason stays shown above it.
  let refused = $state<string | null>(null);

  async function save() {
    refused = null;
    await session.save();
    if (readOnly !== null && (session.view?.issues.length ?? 0) > 0) {
      const reason = session.view?.issues.join(' ') ?? null;
      await session.open();
      refused = reason;
    }
  }

  function acknowledge(on: boolean) {
    fields.acknowledged = on && view ? [...new Set(view.risky.map((r) => r.directive))].sort() : [];
  }
</script>

<div class="editor">
  {#if readOnly}
    <p class="readonly-note" role="note"><Icon name="lock" /><span>{readOnly}</span></p>
    {#if refused}<p class="warn" role="alert">{refused}</p>{/if}
  {/if}
  <PlatformNotes {platform} part="reasons" />
  <input class="wide" type="text" placeholder={tr('Name')} aria-label={tr('Name')} disabled={readOnly !== null} bind:value={fields.name} />
  <textarea
    class="config"
    class:invalid={(view?.issues.length ?? 0) > 0}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
    disabled={readOnly !== null}
    bind:value={fields.text}
  ></textarea>
  {#if view && view.issues.length > 0}
    <ul class="issues">
      {#each view.issues as issue, i (i)}
        <li>{issue}</li>
      {/each}
    </ul>
  {/if}
  {#if platform && (platform.summary || platform.warnings.length > 0 || platform.trustCa)}
    <div class="platform">
      <div class="platform-notes"><PlatformNotes {platform} part="summary" /></div>
      {#if platform.trustCa}
        <TrustCa id={session.id} pick={true} />
      {/if}
    </div>
  {/if}
  {#if view && view.risky.length > 0}
    <RiskyPanel findings={view.risky} acknowledged={view.acknowledgesRisk} onchange={acknowledge} />
  {/if}
  {#if showsUser || showsPsk}
    <fieldset class="lock" disabled={readOnly !== null}>
      <fieldset>
        <legend>{tr('Authentication (stored in the vault)')}</legend>
        {#if showsUser}
          <CredentialSelector item={session.id} credential={view?.credential ?? null} onchanged={() => session.open()} />
          {#if !view?.credential}
            <input type="text" placeholder={tr('Username')} aria-label={tr('Username')} autocomplete="off" bind:value={fields.username} />
            <SecretField label={tr('Password')} placeholder={tr('Password')} stored={view?.hasStoredSecret.password ?? false} bind:value={fields.password} />
          {/if}
        {/if}
        {#if showsKeyPassword}
          <SecretField
            label={tr('Private key password')}
            placeholder={tr('Private key password')}
            stored={view?.hasStoredSecret.keyPassword ?? false}
            bind:value={fields.keyPassword}
          />
        {/if}
        {#if showsPsk}
          <SecretField
            label={tr('Pre-shared key (PSK)')}
            placeholder={tr('Pre-shared key (PSK)')}
            stored={view?.hasStoredSecret.psk ?? false}
            bind:value={fields.psk}
          />
        {/if}
      </fieldset>
      <fieldset>
        <legend>{tr('One-time code (MFA)')}</legend>
        {#if kind === 'openvpn' && view?.staticChallenge}
          <p class="info">
            {tr('This config uses static-challenge: MacVPN asks for the code when connecting and sends it with the password (SCRV1).')}
          </p>
        {:else}
          <OtpFields bind:otp={fields.otp} />
        {/if}
        {#if kind === 'openvpn'}
          <p class="note">
            {tr('Codes and web sign-in requested by the server during the connection (challenge/response, SAML, push) are asked for automatically.')}
          </p>
        {/if}
      </fieldset>
    </fieldset>
  {/if}
  <div class="footer">
    <Status dirty={view?.dirty ?? false} savedAt={view?.savedAt ?? null} />
    <span class="spacer"></span>
    <!-- Read-only: "Save" stores only the risky settings' acknowledgement (there is nothing else to save). -->
    <button class="primary" disabled={readOnly !== null && (view?.risky.length ?? 0) === 0} onclick={() => save().catch(console.error)}
      >{tr('Save')}</button
    >
  </div>
</div>

<style>
  .platform {
    display: flex;
    align-items: flex-start;
    gap: var(--space-4);
  }
  .platform-notes {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    min-width: 0;
  }
</style>
