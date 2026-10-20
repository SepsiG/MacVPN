<script lang="ts">
  // The publications list (spec 7, user guide 16.8–16.9): per catalog its version, last publish time, file and the
  // number of connections changed since the last publish, with Publish New Version (the wizard over the saved
  // selection), Rotate Team Key (the revoke explanation first, then the review), Copy Subscription String and
  // Forget (confirmed; the published file stays where it is).
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import Modal from '../manage/Modal.svelte';
  import { dateText } from './labels';
  import { publishApi, type PublicationView } from './publishApi';
  import { rotateNeedsReview } from './wizard';

  let {
    publications,
    canPublish,
    rotating = $bindable(null),
    onagain,
    onrotate,
    oncopy,
  }: {
    publications: PublicationView[];
    /// An admin key exists.
    canPublish: boolean;
    /// The publication whose rotation is being confirmed.
    rotating?: PublicationView | null;
    onagain: (p: PublicationView) => void;
    /// Confirmed: the wizard's review of the rotation.
    onrotate: (p: PublicationView) => void;
    oncopy: (p: PublicationView) => void;
  } = $props();

  let forgetting = $state<PublicationView | null>(null);
  let failure = $state<string | null>(null);

  async function forget(p: PublicationView) {
    forgetting = null;
    failure = null;
    try {
      await publishApi.forget(p.id);
    } catch (e) {
      failure = String(e);
    }
  }
</script>

{#each publications as p (p.id)}
  <div class="card publication" data-publication={p.id}>
    <div class="head">
      <span class="badge-icon" aria-hidden="true"><Icon name="export" /></span>
      <div class="text">
        <span class="name">{p.name}</span>
        <span class="caption">{tr('Version %lld', p.version)} · {tr('Last published %@', dateText(p.lastPublished))}</span>
        {#if p.fileName}<span class="caption file">{tr('File: %@', p.fileName)}</span>{/if}
      </div>
      {#if p.changed > 0}
        <span class="pill busy changed">{p.changed === 1 ? tr('1 changed since the last publish') : tr('%lld changed since the last publish', p.changed)}</span>
      {:else}
        <span class="pill on">{tr('Up to date')}</span>
      {/if}
    </div>
    {#if p.successorDropped}
      <p class="banner warn successor-dropped"><Icon name="warning" /><span>{tr('The last version announced a backup admin key as the successor; the next version would not, so members could not follow a switch to it.')}</span></p>
    {/if}
    <div class="buttons">
      <button class="again" disabled={!canPublish} onclick={() => onagain(p)}>{tr('Publish New Version…')}</button>
      <button class="rotate" disabled={!canPublish} onclick={() => (rotating = p)}>{tr('Rotate Team Key…')}</button>
      <button class="copy-subscription" onclick={() => oncopy(p)}>{tr('Copy Subscription String…')}</button>
      <span class="spacer"></span>
      <button class="forget destructive" onclick={() => (forgetting = p)}>{tr('Forget…')}</button>
    </div>
  </div>
{:else}
  <div class="card">
    <p class="caption none">{tr('Nothing published yet. Publish Catalog… writes the first version of a catalog.')}</p>
  </div>
{/each}

{#if failure}
  <p class="banner error" role="alert"><Icon name="warning" /><span>{failure}</span></p>
{/if}

{#if rotating && rotateNeedsReview(rotating)}
  {@const p = rotating}
  <Modal
    title={tr('Rotate the Team Key of “%@”?', p.name)}
    message={tr('The published connections changed since the last publish. Publish the catalog and review the changes first, then rotate the team key.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (rotating = null) },
      {
        label: tr('Publish New Version…'),
        kind: 'primary',
        action: () => {
          // `p` follows `rotating`: read it before the dialog closes.
          const chosen = p;
          rotating = null;
          onagain(chosen);
        },
      },
    ]}
  />
{:else if rotating}
  {@const p = rotating}
  <Modal
    title={tr('Rotate the Team Key of “%@”?', p.name)}
    message={tr('Rotating the team key is the only way to revoke access to a catalog someone already has. A new team key is made and published at once as the next version; members who stay need the new key or a new subscription string. Whoever left keeps what they already downloaded, including its team secrets: change those secrets and their server account too.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (rotating = null) },
      {
        label: tr('Review…'),
        kind: 'primary',
        action: () => {
          // `p` follows `rotating`: read it before the dialog closes.
          const chosen = p;
          rotating = null;
          onrotate(chosen);
        },
      },
    ]}
  />
{:else if forgetting}
  {@const p = forgetting}
  <Modal
    title={tr('Forget “%@”?', p.name)}
    message={tr('MacVPN forgets this publication and its team key. The published file stays where it is, and members keep their subscription, but you cannot publish new versions of this catalog any more.')}
    buttons={[
      { label: tr('Cancel'), kind: 'cancel', action: () => (forgetting = null) },
      { label: tr('Forget'), kind: 'destructive', action: () => forget(p).catch(console.error) },
    ]}
  />
{/if}
