<script lang="ts">
  // The Connections window's "Publishing" section (spec 7, plan Task 17): the admin key page, "Publish Catalog…"
  // and the publications list; the publish wizard takes the section's place while it runs. Everything is empty
  // while the vault is locked.
  import type { Row, TreeRow } from '../api';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import AdminKeys from './AdminKeys.svelte';
  import CopySubscription from './CopySubscription.svelte';
  import Publications from './Publications.svelte';
  import PublishWizard from './PublishWizard.svelte';
  import { EMPTY_PUBLISHING, type PublicationView, type PublishingView } from './publishApi';
  import type { Mode } from './wizard';
  import './publishing.css';

  let {
    view = EMPTY_PUBLISHING,
    rows,
    tree,
    teamFolders = {},
  }: {
    view?: PublishingView;
    rows: Row[];
    tree: TreeRow[];
    teamFolders?: Record<string, string>;
  } = $props();

  let wizard = $state<{ mode: Mode; publication: PublicationView | null } | null>(null);
  let copying = $state<PublicationView | null>(null);

  const hasKey = $derived(view.adminKeys.some((k) => k.role === 'primary'));
</script>

<div class="publishing">
  {#if wizard}
    {#key wizard}
      {@const publication = wizard.publication}
      <PublishWizard
        mode={wizard.mode}
        {publication}
        {rows}
        {tree}
        {teamFolders}
        onclose={() => (wizard = null)}
        onagain={() => (wizard = { mode: 'again', publication })}
      />
    {/key}
  {:else}
    <header class="hero">
      <span class="hero-icon" aria-hidden="true"><Icon name="export" /></span>
      <div class="hero-text">
        <h1>{tr('Publishing')}</h1>
        <p class="secondary">{tr('Share connections with your team as a signed and encrypted team catalog file. Each member keeps their own user names and passwords.')}</p>
      </div>
    </header>

    <AdminKeys keys={view.adminKeys} />

    <div class="card actions-card">
      <div class="toolbar">
        <h2>{tr('Team Catalogs You Publish')}</h2>
        <span class="spacer"></span>
        <button class="primary publish-new" disabled={!hasKey} onclick={() => (wizard = { mode: 'new', publication: null })}><Icon name="plus" />{tr('Publish Catalog…')}</button>
      </div>
      {#if !hasKey}
        <p class="caption">{tr('Generate an admin key first.')}</p>
      {/if}
    </div>

    <Publications
      publications={view.publications}
      canPublish={hasKey}
      onagain={(p) => (wizard = { mode: 'again', publication: p })}
      onrotate={(p) => (wizard = { mode: 'rotate', publication: p })}
      oncopy={(p) => (copying = p)}
    />
  {/if}

  {#if copying}
    <CopySubscription catalogId={copying.id} name={copying.name} onclose={() => (copying = null)} />
  {/if}
</div>
