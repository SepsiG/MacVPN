<script lang="ts">
  // A team catalog connection's lines in its detail (spec 6): the "Team" badge with the catalog's name, the pending
  // removal ("Removed from the team catalog — disappears after you disconnect"), the native profile the catalog
  // changed ("Install profile"), and "Duplicate as personal connection…".
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import type { CatalogBadge } from './catalogApi';
  import { catalogApi } from './catalogApi';
  import DuplicateDialog from './DuplicateDialog.svelte';
  import Sheet from './Sheet.svelte';
  import TeamBadge from './TeamBadge.svelte';

  let {
    id,
    name,
    badge,
    native = false,
    onselect = () => {},
  }: { id: string; name: string; badge: CatalogBadge; native?: boolean; onselect?: (id: string) => void } = $props();

  let duplicating = $state(false);
  let installing = $state(false);
  let failure = $state<string | null>(null);
  let confirming = $state(false);

  async function confirmInstalled() {
    confirming = false;
    failure = null;
    try {
      await catalogApi.profileInstalled(id);
    } catch (e) {
      failure = typeof e === 'string' ? e : String(e);
    }
  }

  async function install() {
    if (installing) return;
    installing = true;
    failure = null;
    try {
      await catalogApi.installProfile(id);
    } catch (e) {
      failure = typeof e === 'string' ? e : String(e);
    } finally {
      installing = false;
    }
  }
</script>

<div class="team-bar">
  <div class="line">
    <TeamBadge name={badge.name} />
    <span class="managed">{badge.name}</span>
    <span class="spacer"></span>
    {#if native}
      <button class="install-profile" disabled={installing} onclick={() => install().catch(console.error)}>{tr('Install profile')}</button>
    {/if}
    <button class="duplicate-personal" onclick={() => (duplicating = true)}><Icon name="copy" />{tr('Duplicate as personal connection…')}</button>
  </div>
  {#if badge.pendingRemoval}
    <p class="note removal" role="note"><Icon name="warning" /><span>{tr('Removed from the team catalog — disappears after you disconnect')}</span></p>
  {/if}
  {#if badge.profileOutdated}
    <div class="note outdated" role="note">
      <Icon name="warning" /><span>{tr('The team catalog changed this connection: reinstall its profile')}</span>
      <button class="profile-installed" onclick={() => (confirming = true)}>{tr('I installed it')}</button>
    </div>
  {/if}
  {#if failure}
    <p class="note failure" role="alert"><Icon name="warning" /><span>{failure}</span></p>
  {/if}
</div>

{#if confirming}
  <Sheet title={tr('Is the New Profile Installed?')} oncancel={() => (confirming = false)}>
    {#snippet children()}
      <p class="secondary">
        {tr('Confirm only after you clicked “Install profile” and approved the new profile in System Settings → General → Device Management. MacVPN cannot always see the change. If the old profile is still installed, the connection uses settings the team catalog has replaced.')}
      </p>
    {/snippet}
    {#snippet buttons()}
      <button class="cancel" onclick={() => (confirming = false)}>{tr('Cancel')}</button>
      <button class="primary confirm-installed" onclick={() => confirmInstalled().catch(console.error)}>{tr('I installed it')}</button>
    {/snippet}
  </Sheet>
{/if}

{#if duplicating}
  <DuplicateDialog
    itemId={id}
    {name}
    oncancel={() => (duplicating = false)}
    ondone={(copy) => {
      duplicating = false;
      onselect(copy);
    }}
  />
{/if}

<style>
  .team-bar {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin: 0 var(--space-7) var(--space-5);
    padding: 8px 10px 8px 12px;
    border-radius: var(--radius-card);
    background: var(--surface);
    box-shadow: var(--shadow-card);
    outline: 1px solid var(--border);
    outline-offset: -1px;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    min-width: 0;
  }
  .managed {
    min-width: 0;
    font-size: var(--text-md);
    color: var(--secondary);
    overflow-wrap: anywhere;
  }
  .spacer {
    flex: 1;
  }
  .line button {
    gap: 5px;
  }
  .line button :global(.icon) {
    width: 13px;
    height: 13px;
  }
  .note {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    margin: 0;
    padding: 6px 10px;
    border-radius: var(--radius-control);
    font-size: var(--text-md);
    background: var(--state-busy-soft);
    overflow-wrap: anywhere;
  }
  .note span {
    flex: 1;
  }
  .note button {
    flex: none;
    margin: -2px 0;
  }
  .note.failure {
    background: var(--state-fail-soft);
  }
  .note :global(.icon) {
    flex: none;
    width: 14px;
    height: 14px;
    margin-top: 1px;
    color: var(--state-busy);
  }
</style>
