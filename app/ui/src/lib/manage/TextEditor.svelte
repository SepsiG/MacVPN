<script lang="ts">
  // OpenVPN, WireGuard, strongSwan: the config text with the error list and the risky panel, the Keychain
  // secrets, the one-time code setting (the Swift `TextConfigEditor`).
  import type { TextFields } from '../api';
  import { tr } from '../l10n.svelte';
  import type { EditorSession } from './session.svelte';
  import OtpFields from './OtpFields.svelte';
  import RiskyPanel from './RiskyPanel.svelte';
  import SecretField from './SecretField.svelte';
  import Status from './Status.svelte';

  let { session, kind }: { session: EditorSession; kind: string } = $props();

  const fields = $derived(session.fields as TextFields);
  const view = $derived(session.view);
  const showsUser = $derived(kind === 'openvpn' || kind === 'strongswan');
  const showsPsk = $derived(kind === 'strongswan');
  const showsKeyPassword = $derived(kind === 'openvpn');

  function acknowledge(on: boolean) {
    fields.acknowledged = on && view ? [...new Set(view.risky.map((r) => r.directive))].sort() : [];
  }
</script>

<div class="editor">
  <input class="wide" type="text" placeholder={tr('Name')} aria-label={tr('Name')} bind:value={fields.name} />
  <textarea
    class="config"
    class:invalid={(view?.issues.length ?? 0) > 0}
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
    bind:value={fields.text}
  ></textarea>
  {#if view && view.issues.length > 0}
    <ul class="issues">
      {#each view.issues as issue, i (i)}
        <li>{issue}</li>
      {/each}
    </ul>
  {/if}
  {#if view && view.risky.length > 0}
    <RiskyPanel findings={view.risky} acknowledged={view.acknowledgesRisk} onchange={acknowledge} />
  {/if}
  {#if showsUser || showsPsk}
    <fieldset>
      <legend>{tr('Authentication (stored in the Keychain)')}</legend>
      {#if showsUser}
        <input type="text" placeholder={tr('Username')} aria-label={tr('Username')} autocomplete="off" bind:value={fields.username} />
        <SecretField label={tr('Password')} placeholder={tr('Password')} stored={view?.hasStoredSecret.password ?? false} bind:value={fields.password} />
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
  {/if}
  <div class="footer">
    <Status dirty={view?.dirty ?? false} savedAt={view?.savedAt ?? null} />
    <span class="spacer"></span>
    <button class="primary" onclick={() => session.save().catch(console.error)}>{tr('Save')}</button>
  </div>
</div>
