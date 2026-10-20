<script lang="ts">
  // The team key of a new catalog or a rotation, shown once (spec 7, like the recovery key): Copy, "I Saved It",
  // then one group of it retyped. After "I Saved It" the key is gone from the page and from this component (only
  // the asked group's text is kept for the check), and the parent is told to drop its copy (`onforget`). Closing
  // keeps nothing. "Copy" hands the key to the backend, which puts it on the pasteboard concealed and empties it
  // a minute later, at a lock or at quit if it is still there (never the web view's clipboard).
  import { onDestroy } from 'svelte';
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { publishApi } from './publishApi';
  import { closeReveal, groupMatches, reveal, savedIt, type Reveal } from './wizard';

  let {
    teamKey,
    initial = undefined,
    typed = $bindable(''),
    onforget = () => {},
    onclose,
  }: {
    /// The key as the backend returned it (`TEAM-` and 14 groups).
    teamKey: string;
    /// A state to start from (the view tests).
    initial?: Reveal;
    typed?: string;
    /// The key left this component: the parent drops its copy too.
    onforget?: () => void;
    onclose: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  let phase = $state<Reveal>(initial ?? reveal(teamKey));
  let copied = $state(false);
  const matches = $derived(groupMatches(phase.expected, typed));

  async function copy() {
    const key = phase.key;
    if (!key) return;
    try {
      await publishApi.copyTeamKey(key);
      copied = true;
    } catch (e) {
      console.error(e);
    }
  }

  function saved() {
    phase = savedIt(phase);
    onforget();
  }

  function done() {
    if (!matches) return;
    typed = '';
    phase = closeReveal();
    onclose();
  }

  onDestroy(() => {
    phase = closeReveal();
    typed = '';
  });
</script>

<div class="card team-key-reveal" role="group" aria-labelledby="team-key-title">
  <h2 id="team-key-title">{tr('Team Key')}</h2>
  {#if phase.step === 'key' && phase.key}
    <p class="banner warn"><Icon name="warning" /><span>{tr('The team key is shown only now. MacVPN keeps it in your vault to publish later versions, but never shows it again. Copy it and keep it safe.')}</span></p>
    <code class="team-key" data-team-key>{phase.key}</code>
    <p class="caption">{tr('Members need it to subscribe: send it, or the subscription string, only through a secure channel, never by plain e-mail.')}</p>
    <div class="buttons">
      <button class="copy-key" onclick={() => copy().catch(console.error)}><Icon name="copy" />{copied ? tr('Copied') : tr('Copy')}</button>
      <span class="spacer"></span>
      <button class="primary saved-it" onclick={saved}>{tr('I Saved It')}</button>
    </div>
  {:else if phase.step === 'confirm'}
    <label class="form-row">
      <span>{tr('Type group %d of the team key', (phase.group ?? 0) + 1)}</span>
      <input class="group-input" data-field="group" type="text" autocomplete="off" spellcheck="false" maxlength="4" bind:value={typed} />
    </label>
    {#if typed.length >= 4 && !matches}
      <p class="form-error" role="alert">{tr('This is not group %d of the team key.', (phase.group ?? 0) + 1)}</p>
    {/if}
    <div class="buttons">
      <span class="spacer"></span>
      <button class="primary confirm-group" disabled={!matches} onclick={done}>{tr('Done')}</button>
    </div>
  {/if}
</div>
