<script lang="ts">
  // The publish wizard (spec 7, user guide 16.8): 1. the folders and connections in a tree with checkboxes (a ticked
  // folder brings its subtree; system VPNs and team catalog items are not offered); 2. the review – the counts, the
  // refused connections with their reasons (fix them first), the warning when the announced successor key would be
  // dropped, a tick for each key inside a config (the WireGuard private key's tick is "Everyone with this catalog
  // uses the same WireGuard key"), the personal fields explained, the stored team secrets as opt-in ticks and the
  // credential slots (ticked by default, without user names or passwords); 3. the name (a new catalog only);
  // 4. the save panel (in the backend); 5. the result – the version and the fingerprint, and the team key shown
  // once (`TeamKeyReveal`). A new version starts on the review of the saved selection; a team key rotation
  // reviews the saved selection first, then saves and reveals the new key.
  import { onDestroy, onMount } from 'svelte';
  import type { Row, TreeRow } from '../api';
  import { connectionsText, credentialSlotsText, foldersText, teamSecretsText } from '../counts';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import TypeIcon from '../TypeIcon.svelte';
  import CopySubscription from './CopySubscription.svelte';
  import Fingerprint from './Fingerprint.svelte';
  import { inlineText, itemName, personalText, refusalText, secretText } from './labels';
  import { publishApi, type PublicationView, type PublishedView, type PublishPreview } from './publishApi';
  import TeamKeyReveal from './TeamKeyReveal.svelte';
  import {
    defaultSlots,
    droppedSuccessorIn,
    fieldKey,
    firstStep,
    fromSelection,
    isPicked,
    covered,
    nextStep,
    offered,
    pickedConnections,
    previousStep,
    reviewBlockers,
    selectionOf,
    stepsOf,
    toggle,
    withTick,
    NO_TICKS,
    NOTHING,
    type Mode,
    type Picked,
    type Step,
    type Ticks,
  } from './wizard';

  let {
    mode,
    publication = null,
    rows,
    tree,
    teamFolders = {},
    onclose,
    onagain = () => {},
    initialStep = undefined,
    initialPreview = null,
    initialPicked = undefined,
    initialTicks = undefined,
    initialName = '',
    initialResult = null,
  }: {
    mode: Mode;
    /// The publication of a new version or a rotation.
    publication?: PublicationView | null;
    rows: Row[];
    tree: TreeRow[];
    /// Folders a team catalog owns (not offered).
    teamFolders?: Record<string, string>;
    onclose: () => void;
    /// A refused rotation: "Publish New Version…" of the same publication in its place.
    onagain?: () => void;
    // A state to start from (the view tests; otherwise the flow's start).
    initialStep?: Step;
    initialPreview?: PublishPreview | null;
    initialPicked?: Picked;
    initialTicks?: Ticks;
    initialName?: string;
    initialResult?: PublishedView | null;
  } = $props();

  // svelte-ignore state_referenced_locally
  const saved = fromSelection(publication?.selection);
  // svelte-ignore state_referenced_locally
  let step = $state<Step>(initialStep ?? firstStep(mode));
  // svelte-ignore state_referenced_locally
  let picked = $state<Picked>(initialPicked ?? (mode === 'new' ? NOTHING : saved.picked));
  // svelte-ignore state_referenced_locally
  let ticks = $state<Ticks>(initialTicks ?? (mode === 'new' ? NO_TICKS : saved.ticks));
  // svelte-ignore state_referenced_locally
  let preview = $state<PublishPreview | null>(initialPreview);
  // svelte-ignore state_referenced_locally
  let name = $state(initialName);
  // svelte-ignore state_referenced_locally
  let result = $state<PublishedView | null>(initialResult);
  /// The new team key, until the reveal took it ("I Saved It") or closed.
  // svelte-ignore state_referenced_locally
  let teamKey = $state<string | null>(initialResult?.teamKey ?? null);
  // svelte-ignore state_referenced_locally
  let revealOpen = $state(teamKey !== null);
  let copying = $state(false);
  let busy = $state(false);
  let failure = $state<string | null>(null);
  /// The rotation was refused (a published connection changed since the last publish): publish first.
  let refused = $state(false);
  /// The credential slots the review has shown (new ones are ticked by default).
  const seenSlots = new Set<string>();
  // svelte-ignore state_referenced_locally
  let tickNewSlots = mode === 'new';

  const shown = $derived(offered(tree, rows, teamFolders));
  const connectionCount = $derived(pickedConnections(tree, shown, picked));
  const anything = $derived(picked.folders.size + picked.connections.size > 0);
  const blockers = $derived(reviewBlockers(preview, ticks));
  const names = $derived(new Map<string, string>([...rows.map((r): [string, string] => [r.id, r.name])]));
  const flow = $derived(stepsOf(mode));
  const index = $derived(flow.indexOf(step) + 1);
  const rowsById = $derived(new Map(rows.map((r) => [r.id, r])));
  const tickedSecrets = $derived(preview ? preview.availableSecrets.filter((f) => ticks.secrets.has(fieldKey(f))).length : 0);
  const tickedSlots = $derived(preview ? preview.availableSlots.filter((s) => ticks.slots.has(s.id)).length : 0);

  const title = $derived(
    mode === 'new'
      ? tr('Publish Catalog')
      : mode === 'again'
        ? tr('Publish a New Version of “%@”', publication?.name ?? '')
        : tr('Rotate the Team Key of “%@”', publication?.name ?? ''),
  );

  function stepTitle(s: Step): string {
    return s === 'select' ? tr('Connections') : s === 'review' ? tr('Review') : s === 'name' ? tr('Name and File') : tr('Done');
  }

  onMount(() => {
    if (step === 'review' && preview === null) loadPreview().catch(console.error);
  });

  async function loadPreview() {
    busy = true;
    failure = null;
    try {
      const next = await publishApi.preview(selectionOf(tree, picked, ticks, preview));
      ticks = defaultSlots(ticks, next, seenSlots, tickNewSlots);
      tickNewSlots = true;
      preview = next;
    } catch (e) {
      failure = String(e);
    } finally {
      busy = false;
    }
  }

  function go(next: Step | null) {
    if (next === null) return;
    failure = null;
    step = next;
    if (next === 'review') {
      preview = null;
      loadPreview().catch(console.error);
    }
  }

  async function write() {
    if (busy || blockers.length > 0) return;
    busy = true;
    failure = null;
    try {
      const selection = selectionOf(tree, picked, ticks, preview);
      const written =
        mode === 'rotate'
          ? await publishApi.rotate(publication!.id)
          : await publishApi.publish(publication?.id ?? null, mode === 'new' ? name.trim() : (publication?.name ?? name), selection);
      if (written === null) return;
      teamKey = written.teamKey;
      revealOpen = teamKey !== null;
      result = { ...written, teamKey: null };
      step = 'done';
    } catch (e) {
      failure = String(e);
      refused = mode === 'rotate';
    } finally {
      busy = false;
    }
  }

  function primaryAction() {
    if (step === 'select') go(nextStep(mode, step));
    else if (step === 'review' && mode === 'new') go(nextStep(mode, step));
    else write().catch(console.error);
  }

  const primaryLabel = $derived(
    step === 'select' || (step === 'review' && mode === 'new')
      ? tr('Next')
      : mode === 'rotate'
        ? tr('Rotate and Save…')
        : tr('Publish…'),
  );

  const primaryDisabled = $derived(
    busy || (step === 'select' ? !anything : step === 'review' ? blockers.length > 0 : step === 'name' ? name.trim() === '' : false),
  );

  /// A slot decides whether an SSTP user name needs its own tick: the review is checked again.
  function tickSlot(id: string, on: boolean) {
    ticks = { ...ticks, slots: withTick(ticks.slots, id, on) };
    loadPreview().catch(console.error);
  }

  function forgetKey() {
    teamKey = null;
  }

  // Leaving the wizard (another section, a closed window) keeps no key.
  onDestroy(() => {
    teamKey = null;
    result = null;
  });
</script>

<div class="wizard" data-step={step} data-mode={mode}>
  <header class="hero">
    <span class="hero-icon" aria-hidden="true"><Icon name="export" /></span>
    <div class="hero-text">
      <h1>{title}</h1>
      <p class="secondary step-title">{tr('Step %lld of %lld: %@', index, flow.length, stepTitle(step))}</p>
    </div>
  </header>

  {#if step === 'select'}
    <div class="card select-step">
      <p class="secondary">{tr('Tick folders and connections. A ticked folder brings everything inside it; a connection whose folder is not ticked goes to the catalog’s top level. System VPNs and connections from team catalogs cannot be published.')}</p>
      <ul class="list tree" role="tree">
        {#each shown as r (r.id)}
          {@const on = isPicked(tree, picked, r)}
          {@const locked = covered(tree, picked, r.id)}
          <li class="tree-row" class:folder={r.type === 'folder'} role="treeitem" aria-selected={on} style:--depth={Math.min(r.depth, 6)}>
            <label class="check">
              <input type="checkbox" data-pick={r.id} checked={on} disabled={locked || busy} onchange={(e) => (picked = toggle(tree, picked, r, e.currentTarget.checked))} />
              {#if r.type === 'folder'}
                <Icon name="folder" />
                <span class="row-name">{r.name}</span>
              {:else}
                {@const row = rowsById.get(r.id)}
                <TypeIcon kind={row?.kind ?? null} state={row?.state ?? 'disconnected'} size="sm" />
                <span class="row-name">{row?.name ?? r.id}</span>
              {/if}
            </label>
          </li>
        {:else}
          <li class="caption">{tr('There are no connections to publish.')}</li>
        {/each}
      </ul>
      <p class="caption count">{connectionCount === 1 ? tr('1 connection selected') : tr('%lld connections selected', connectionCount)}</p>
    </div>
  {:else if step === 'review'}
    {#if mode === 'rotate'}
      <p class="banner warn revoke"><Icon name="warning" /><span>{tr('Rotating the team key is the only way to revoke access to a catalog someone already has. Check what this version publishes; the new key is shown once after the file is saved.')}</span></p>
    {/if}
    {#if !preview}
      <div class="card"><p class="caption">{busy ? tr('Checking the selection…') : ''}</p></div>
    {:else}
      {@const p = preview}
      <div class="card counts">
        <h2>{tr('What the catalog contains')}</h2>
        <p class="secondary count-line">
          {connectionsText(p.counts.connections)}, {foldersText(p.counts.folders)} · {credentialSlotsText(tickedSlots)}, {teamSecretsText(tickedSecrets)}
        </p>
      </div>
      {#if droppedSuccessorIn(p).length > 0}
        <p class="banner warn successor-dropped" role="alert"><Icon name="warning" /><span>{tr('The last version of %@ announced a backup admin key as the successor; the next version would not. Members then cannot follow a switch to that key. Import or generate the backup key first if you still plan to switch to it.', droppedSuccessorIn(p).join(', '))}</span></p>
      {/if}
      {#if p.refused.length > 0}
        <div class="card refused">
          <p class="banner error"><Icon name="warning" /><span>{tr('These connections cannot be published. Fix them first, or untick them.')}</span></p>
          <ul class="list">
            {#each p.refused as f (fieldKey(f))}
              <li data-refused={f.item}><strong>{itemName(names, f.item)}</strong>: {refusalText(f.field)}</li>
            {/each}
          </ul>
        </div>
      {/if}
      {#if p.inlineSecrets.length > 0}
        <div class="card inline-secrets">
          <h2>{tr('Keys inside the configs')}</h2>
          <p class="caption">{tr('Every member gets these keys as they are. Tick each one to publish it.')}</p>
          <div class="list">
            {#each p.inlineSecrets as f (fieldKey(f))}
              <label class="check">
                <input type="checkbox" data-inline={fieldKey(f)} checked={ticks.inline.has(fieldKey(f))} disabled={busy} onchange={(e) => (ticks = { ...ticks, inline: withTick(ticks.inline, fieldKey(f), e.currentTarget.checked) })} />
                <span>{inlineText(f.field)}<span class="detail">{itemName(names, f.item)}</span></span>
              </label>
            {/each}
          </div>
        </div>
      {/if}
      {#if p.personal.length > 0}
        <div class="card personal">
          <h2>{tr('Personal fields')}</h2>
          <ul class="list">
            {#each p.personal as f (fieldKey(f))}
              <li data-personal={fieldKey(f)}><strong>{itemName(names, f.item)}</strong>: {personalText(f.field)}</li>
            {/each}
          </ul>
        </div>
      {/if}
      {#if p.availableSecrets.length > 0}
        <div class="card secrets">
          <h2>{tr('Team secrets')}</h2>
          <p class="caption">{tr('None is published unless you tick it. Tick only the secrets everyone in the team may know, such as a shared PSK.')}</p>
          <div class="list">
            {#each p.availableSecrets as f (fieldKey(f))}
              {@const on = ticks.secrets.has(fieldKey(f))}
              <label class="check">
                <input type="checkbox" data-secret={fieldKey(f)} checked={on} disabled={busy} onchange={(e) => (ticks = { ...ticks, secrets: withTick(ticks.secrets, fieldKey(f), e.currentTarget.checked) })} />
                <span>{secretText(f.field)} · {itemName(names, f.item)}{#if on}<span class="detail warn-text">{tr('Everyone with the team key can read this secret')}</span>{/if}</span>
              </label>
            {/each}
          </div>
        </div>
      {/if}
      {#if p.availableSlots.length > 0}
        <div class="card slots">
          <h2>{tr('Credential slots')}</h2>
          <p class="caption">{tr('The shared credentials the selected connections use, without user names or passwords: only the name and an id go into the catalog. Without a slot, each member is asked for that connection’s sign-in separately.')}</p>
          <div class="list">
            {#each p.availableSlots as s (s.id)}
              <label class="check">
                <input type="checkbox" data-slot={s.id} checked={ticks.slots.has(s.id)} disabled={busy} onchange={(e) => tickSlot(s.id, e.currentTarget.checked)} />
                <span>{s.name}<span class="detail">{s.connections === 1 ? tr('Used by 1 connection') : tr('Used by %lld connections', s.connections)}</span></span>
              </label>
            {/each}
          </div>
        </div>
      {/if}
      {#if blockers.includes('inline')}
        <p class="note blocker">{tr('Tick every key inside the configs to go on, or leave those connections out.')}</p>
      {/if}
    {/if}
  {:else if step === 'name'}
    <div class="card name-step">
      <label class="form-row"><span>{tr('Catalog name')}</span><input class="catalog-name" type="text" autocomplete="off" spellcheck="false" disabled={busy} bind:value={name} /></label>
      <p class="caption">{tr('Members see it as the name of the catalog’s folder. The file is saved as <name>.macvpncatalog.')}</p>
      <p class="banner info"><Icon name="export" /><span>{tr('MacVPN does not upload anything: put the file on your web server or share.')}</span></p>
    </div>
  {:else if step === 'done' && result}
    {@const r = result}
    <div class="card result">
      <p class="banner ok" role="status"><Icon name="check" /><span>{tr('Version %lld was written to %@.', r.version, r.fileName)}</span></p>
      <p class="secondary">{tr('Signed by the admin key with this fingerprint:')}</p>
      <Fingerprint value={r.fingerprint} />
      <p class="caption">{tr('MacVPN does not upload anything: put the file on your web server or share.')}</p>
    </div>
    {#if revealOpen}
      <!-- Mounted once: it keeps the key itself until "I Saved It" (this wizard drops its copy then). -->
      <TeamKeyReveal teamKey={teamKey ?? ''} onforget={forgetKey} onclose={() => { teamKey = null; revealOpen = false; }} />
    {/if}
  {/if}

  {#if failure}
    <p class="banner error" role="alert"><Icon name="warning" /><span>{failure}</span></p>
    {#if refused && publication}
      <div class="buttons"><button class="publish-instead" onclick={onagain}>{tr('Publish New Version…')}</button></div>
    {/if}
  {/if}

  <div class="buttons wizard-buttons">
    {#if step === 'done'}
      {#if !revealOpen && result}
        <button class="copy-subscription" onclick={() => (copying = true)}>{tr('Copy Subscription String…')}</button>
      {/if}
      <span class="spacer"></span>
      <button class="primary finish" disabled={revealOpen} onclick={onclose}>{tr('Done')}</button>
    {:else}
      {#if previousStep(mode, step)}
        <button class="back" disabled={busy} onclick={() => go(previousStep(mode, step))}>{tr('Back')}</button>
      {/if}
      <span class="spacer"></span>
      <button class="cancel-wizard" disabled={busy} onclick={onclose}>{tr('Cancel')}</button>
      <button class="primary next" disabled={primaryDisabled} onclick={primaryAction}>{primaryLabel}</button>
    {/if}
  </div>
</div>

{#if copying && result}
  <CopySubscription catalogId={result.catalogId} name={publication?.name ?? name} onclose={() => (copying = false)} />
{/if}

<style>
  .wizard {
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }
  .tree {
    max-height: 340px;
    overflow: auto;
  }
  .tree-row {
    padding-left: calc(8px + var(--depth, 0) * 18px) !important;
  }
  .tree-row.folder .row-name {
    font-weight: 600;
  }
  .tree-row :global(.icon) {
    width: 15px;
    height: 15px;
    color: var(--secondary);
  }
  .tree-row .check {
    align-items: center;
  }
  .tree-row .check input {
    margin: 0;
  }
  .row-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .warn-text {
    color: var(--state-busy-text) !important;
  }
</style>
