<script lang="ts">
  // The Connections window's "Credentials" section (spec 3a): named user name + password pairs that many
  // connections can share. Add, Edit, Rename and Delete (a credential in use: "Copy into each connection" or
  // Cancel, naming the connections), and "Create from connection…" (a connection's values become a credential;
  // the other connections with the same user name and password are offered for linking, by name only). The
  // password field never shows a stored password ("Saved — type to replace"); the backend never sends one.
  import { api, type CredentialItem, type CredentialMatch, type CredentialsView, type Row, type SecretInput } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import CredentialDeleteQuestion from './CredentialDeleteQuestion.svelte';
  import CredentialList from './CredentialList.svelte';
  import Modal from './Modal.svelte';
  import SecretField from './SecretField.svelte';
  import { canSaveForm, sourceRows, tickedItems } from './shared';

  let { view, rows }: { view: CredentialsView; rows: Row[] } = $props();

  interface Form {
    mode: 'add' | 'edit' | 'rename';
    id: string | null;
    original: string | null;
    name: string;
    username: string;
    password: SecretInput;
    stored: boolean;
    error: string | null;
  }

  let form = $state<Form | null>(null);
  let deleting = $state<{ credential: CredentialItem; connections: string[] } | null>(null);
  let pending = $state<string | null>(null);
  let failure = $state<string | null>(null);
  /// "Create from connection…": pick the connection and the name, then tick the matches.
  let from = $state<{
    step: 'pick' | 'link';
    item: string;
    name: string;
    matches: CredentialMatch[];
    unticked: Set<string>;
    error: string | null;
  } | null>(null);
  let busy = $state(false);

  const sources = $derived(sourceRows(rows));

  function add() {
    form = { mode: 'add', id: null, original: null, name: '', username: '', password: null, stored: false, error: null };
  }

  function edit(c: CredentialItem, mode: 'edit' | 'rename') {
    form = { mode, id: c.id, original: c.name, name: c.name, username: c.username, password: null, stored: c.hasPassword, error: null };
  }

  async function saveForm() {
    const f = form;
    if (!f || busy) return;
    if (f.mode === 'rename' && f.name.trim() === f.original) {
      form = null;
      return;
    }
    if (!canSaveForm(f.mode, f.name, f.original)) {
      f.error = tr('A credential name must have 1 to 64 characters and no control characters.');
      return;
    }
    busy = true;
    try {
      if (f.mode === 'add') await api.credentialCreate(f.name, f.username, f.password === '' ? null : f.password);
      else if (f.mode === 'rename') await api.credentialUpdate(f.id!, f.name, null, null);
      else await api.credentialUpdate(f.id!, f.name, f.username, f.password);
      form = null;
    } catch (e) {
      f.error = String(e);
    } finally {
      busy = false;
    }
  }

  async function remove(c: CredentialItem, copyInto: boolean) {
    pending = c.id;
    failure = null;
    try {
      const inUse = await api.credentialDelete(c.id, copyInto);
      deleting = inUse ? { credential: c, connections: inUse } : null;
    } catch (e) {
      deleting = null;
      failure = String(e);
    } finally {
      pending = null;
    }
  }

  function startFrom() {
    from = { step: 'pick', item: sources[0]?.id ?? '', name: '', matches: [], unticked: new Set(), error: null };
  }

  async function findMatches() {
    const f = from;
    if (!f || busy || f.item === '') return;
    busy = true;
    try {
      f.matches = await api.credentialMatches(f.item);
      f.unticked = new Set();
      f.error = null;
      f.step = 'link';
    } catch (e) {
      f.error = String(e);
    } finally {
      busy = false;
    }
  }

  function tick(item: string, on: boolean) {
    if (!from) return;
    const next = new Set(from.unticked);
    if (on) next.delete(item);
    else next.add(item);
    from.unticked = next;
  }

  async function createFrom() {
    const f = from;
    if (!f || busy) return;
    busy = true;
    try {
      await api.credentialFromConnection(f.item, f.name, tickedItems(f.matches, f.unticked));
      from = null;
    } catch (e) {
      f.error = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="credentials-section">
  <header class="hero">
    <span class="hero-icon" aria-hidden="true"><Icon name="key" /></span>
    <div class="hero-text">
      <h1>{tr('Credentials')}</h1>
      <p class="secondary">
        {tr('A user name and password that several connections share. Change it here once, and every connection that uses it signs in with the new one. Passwords are stored in the vault and never shown.')}
      </p>
    </div>
  </header>

  {#if failure}
    <p class="failure"><Icon name="warning" /><span>{failure}</span></p>
  {/if}

  <CredentialList
    {view}
    {pending}
    onadd={add}
    onfrom={startFrom}
    onedit={(c) => edit(c, 'edit')}
    onrename={(c) => edit(c, 'rename')}
    ondelete={(c) => remove(c, false).catch(console.error)}
  />
</div>

{#if deleting}
  {@const d = deleting}
  <CredentialDeleteQuestion
    name={d.credential.name}
    connections={d.connections}
    oncancel={() => (deleting = null)}
    oncopy={() => remove(d.credential, true).catch(console.error)}
  />
{:else if form}
  {@const f = form}
  <Modal
    title={f.mode === 'add' ? tr('New Shared Credential') : f.mode === 'rename' ? tr('Rename %@', f.original ?? '') : tr('Edit %@', f.original ?? '')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (form = null) },
      { label: tr('Save'), kind: 'primary', action: () => saveForm().catch(console.error) },
    ]}
  >
    <div class="credential-form">
      <label class="form-row"><span>{tr('Name')}</span><input class="cred-name" type="text" autocomplete="off" bind:value={f.name} /></label>
      {#if f.mode !== 'rename'}
        <label class="form-row"><span>{tr('Username')}</span><input class="cred-user" type="text" autocomplete="off" bind:value={f.username} /></label>
        <div class="form-row">
          <span>{tr('Password')}</span>
          <SecretField label={tr('Password')} stored={f.stored} bind:value={f.password} />
        </div>
        <p class="hint">{tr('Without a password, MacVPN asks for it when connecting and can save it here.')}</p>
      {/if}
      {#if f.error}
        <p class="form-error">{f.error}</p>
      {/if}
    </div>
  </Modal>
{:else if from}
  {@const f = from}
  {#if f.step === 'pick'}
    <Modal
      title={tr('Create from Connection')}
      message={tr("The connection's stored user name and password become a shared credential that it then uses. The values are not shown.")}
      buttons={[
        { label: tr('Cancel'), kind: 'cancel', action: () => (from = null) },
        { label: tr('Next'), kind: 'primary', action: () => findMatches().catch(console.error) },
      ]}
    >
      <div class="credential-form">
        <label class="form-row">
          <span>{tr('Connection')}</span>
          <select class="from-source" bind:value={f.item}>
            {#each sources as row (row.id)}
              <option value={row.id}>{row.name}</option>
            {/each}
          </select>
        </label>
        <label class="form-row"><span>{tr('Name')}</span><input class="from-name" type="text" autocomplete="off" bind:value={f.name} /></label>
        {#if f.error}
          <p class="form-error">{f.error}</p>
        {/if}
      </div>
    </Modal>
  {:else}
    <Modal
      title={tr('Link the Same Sign-in?')}
      message={f.matches.length > 0
        ? tr('These connections have the same user name and password. The ticked ones will use the new shared credential too.')
        : tr('No other connection has the same user name and password.')}
      buttons={[
        { label: tr('Cancel'), kind: 'cancel', action: () => (from = null) },
        { label: tr('Create and Link'), kind: 'primary', action: () => createFrom().catch(console.error) },
      ]}
    >
      {#if f.matches.length > 0}
        <div class="matches">
          {#each f.matches as m (m.item)}
            <label class="match">
              <input type="checkbox" value={m.item} checked={!f.unticked.has(m.item)} onchange={(e) => tick(m.item, e.currentTarget.checked)} />
              <span>{m.name}</span>
            </label>
          {/each}
        </div>
      {/if}
      {#if f.error}
        <p class="form-error">{f.error}</p>
      {/if}
    </Modal>
  {/if}
{/if}

<style>
  .credentials-section {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
    padding: var(--space-7) var(--space-7) var(--space-8);
    height: 100%;
    box-sizing: border-box;
    overflow: auto;
  }
  .hero {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 2px;
  }
  .hero-icon {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: 10px;
    color: #fff;
    background: linear-gradient(180deg, var(--accent), var(--accent-pressed));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .hero-icon :global(.icon) {
    width: 22px;
    height: 22px;
    stroke-width: 1.7;
  }
  .hero-text {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  h1 {
    font-size: var(--text-xl);
    font-weight: 650;
    letter-spacing: -0.01em;
    margin: 0;
  }
  p {
    margin: 0;
  }
  .secondary {
    color: var(--secondary);
    font-size: var(--text-md);
  }
  .failure {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: 8px 10px;
    border-radius: var(--radius-control);
    font-size: var(--text-md);
    background: var(--state-fail-soft);
    overflow-wrap: anywhere;
  }
  .failure :global(.icon) {
    flex: none;
    width: 15px;
    height: 15px;
    margin-top: 1px;
    color: var(--state-fail);
  }
  .credential-form {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin-bottom: 16px;
  }
  .form-row {
    display: grid;
    grid-template-columns: minmax(90px, 30%) 1fr;
    align-items: center;
    gap: var(--space-4);
  }
  .form-row > span:first-child {
    color: var(--secondary);
  }
  .form-row :global(select) {
    min-width: 0;
  }
  .hint {
    font-size: var(--text-sm);
    color: var(--secondary);
  }
  .form-error {
    font-size: var(--text-md);
    color: var(--state-fail-text);
    overflow-wrap: anywhere;
  }
  .matches {
    display: flex;
    flex-direction: column;
    margin-bottom: 16px;
    padding: 3px;
    max-height: 200px;
    overflow: auto;
    border-radius: var(--radius-control);
    background: var(--surface-sunken);
  }
  .match {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 4px 8px;
    border-radius: var(--radius-sm);
  }
</style>
