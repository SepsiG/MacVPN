<script lang="ts">
  // The editors' choice between the connection's own user name and password and a shared credential (spec 3a):
  // "Own username and password" or "Use credential: <name>". Choosing a credential asks first, because the
  // connection's own stored user name and password are deleted; then the editor hides its own fields and never
  // writes them. Going back to its own fields needs no question (they are empty). `passwordOnly`: the editor's
  // user name is in its config (SSTP) or not stored by MacVPN (a system VPN), so only the password is shared.
  import { api, type CredentialItem } from '../api';
  import { tr } from '../l10n.svelte';
  import Modal from './Modal.svelte';
  import { OWN, selectorValue } from './shared';
  import { sharedCredentials } from './sharedStore.svelte';

  let {
    item,
    credential,
    disabled = false,
    passwordOnly = false,
    items = undefined,
    onchanged,
  }: {
    /// The connection's key.
    item: string;
    /// The linked credential's name (`null`: its own fields).
    credential: string | null;
    disabled?: boolean;
    passwordOnly?: boolean;
    /// The credentials to offer (default: the Credentials section's list from the view model).
    items?: CredentialItem[];
    /// After a link change: the editor loads its fields again.
    onchanged: () => Promise<void>;
  } = $props();

  const list = $derived(items ?? sharedCredentials.view.items);
  const value = $derived(selectorValue(credential, list));
  let confirming = $state<CredentialItem | null>(null);
  let error = $state<string | null>(null);
  let busy = $state(false);

  function choose(event: Event) {
    const select = event.currentTarget as HTMLSelectElement;
    const next = select.value;
    // The shown choice follows the backend, not the click (a question comes first).
    select.value = value;
    if (next === value) return;
    if (next === OWN) {
      link(null).catch(console.error);
    } else {
      confirming = list.find((c) => c.id === next) ?? null;
    }
  }

  async function link(id: string | null) {
    confirming = null;
    busy = true;
    error = null;
    try {
      await api.credentialLink(item, id);
      await onchanged();
    } catch (e) {
      error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="credential-selector">
  <label class="field">
    <span>{passwordOnly ? tr('Password from') : tr('User name and password')}</span>
    <select class="credential-choice" {value} onchange={choose} disabled={disabled || busy}>
      <option value={OWN}>{tr('Own username and password')}</option>
      {#each list as c (c.id)}
        <option value={c.id}>{tr('Use credential: %@', c.name)}</option>
      {/each}
      {#if credential !== null && value !== OWN && !list.some((c) => c.id === value)}
        <option {value}>{tr('Use credential: %@', credential)}</option>
      {/if}
    </select>
  </label>
  {#if credential !== null}
    <p class="note linked">
      {passwordOnly
        ? tr('The password comes from the shared credential %@. Change it in the Credentials section.', credential)
        : tr('The user name and password come from the shared credential %@. Change them in the Credentials section.', credential)}
    </p>
  {/if}
  {#if error}
    <p class="error">{error}</p>
  {/if}
</div>

{#if confirming}
  {@const c = confirming}
  <Modal
    title={tr('Use the shared credential %@?', c.name)}
    message={tr("The user name and password stored for this connection are deleted. It then signs in with the shared credential's.")}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (confirming = null) },
      { label: tr('Use Credential'), kind: 'primary', action: () => link(c.id).catch(console.error) },
    ]}
  />
{/if}

<style>
  .credential-selector {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .credential-selector select {
    min-width: 0;
  }
</style>
