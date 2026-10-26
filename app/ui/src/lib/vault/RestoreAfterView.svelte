<script lang="ts">
  // After a restore: each backed-up preference with its own checkbox (nothing is applied until "Apply Selected
  // Preferences"; the control API is never ticked at first), then the native L2TP / Cisco profiles, reinstalled one
  // after another through the existing installer (macOS asks to approve each; WinVPN installed them already and
  // shows why one could not be, e.g. Cisco IPsec).
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import type { Preference, PreferenceFailure, RestoreOutcome } from './backupApi';

  let {
    outcome,
    ticks = $bindable({}),
    applied = null,
    applying = false,
    installing = false,
    error = null,
    onapply,
    onreinstall,
    ondone,
  }: {
    outcome: RestoreOutcome;
    ticks?: Record<string, boolean>;
    /// The failures of the applied preferences (empty: all applied), or null before.
    applied?: PreferenceFailure[] | null;
    applying?: boolean;
    installing?: boolean;
    error?: string | null;
    onapply: () => void;
    onreinstall: () => void;
    ondone: () => void;
  } = $props();

  function label(key: Preference): string {
    switch (key) {
      case 'autoCheck':
        return tr('Check for Updates Automatically');
      case 'delay24h':
        return tr('Only Offer Updates Published at Least 24 Hours Ago');
      case 'launchAtLogin':
        return tr('Launch at Login');
      case 'controlApi':
        return tr('Allow other apps to control VPNs');
      case 'autoUnlock':
        return tr('Unlock automatically');
    }
  }

  function onOff(on: boolean): string {
    return on ? tr('On') : tr('Off');
  }

  // A profile the platform refused (its note says why) is not offered again.
  const remaining = $derived(outcome.nativeProfiles.filter((p) => !p.installed && !p.note).length);
  const busy = $derived(applying || installing);
</script>

<div class="restore-after">
  <p class="banner ok" role="status"><Icon name="check" /><span>{tr('The backup was restored.')}</span></p>
  {#if outcome.skippedCatalogItems.length > 0}
    <p class="caption skipped-catalog">
      {tr('A team catalog provides these, so the backup’s copies were not restored: %@', outcome.skippedCatalogItems.join(', '))}
    </p>
  {/if}
  <section class="card preferences">
    <h2>{tr('Preferences')}</h2>
    <p class="caption">{tr('The backup’s preferences are not applied by themselves. Tick the ones to use on this Mac.')}</p>
    <div class="rows">
      {#each outcome.preferences as p (p.key)}
        <label class="check" data-preference={p.key}>
          <input type="checkbox" disabled={busy || applied !== null || p.backedUp === p.current} bind:checked={ticks[p.key]} />
          <span>
            {label(p.key)}
            <span class="caption">
              {p.backedUp === p.current
                ? tr('Already the same: %@', onOff(p.current))
                : tr('Backup: %@ · This Mac: %@', onOff(p.backedUp), onOff(p.current))}
            </span>
            {#if p.key === 'controlApi' && p.backedUp && !p.current}
              <span class="caption">{tr('Tick it only if you use paired apps on this Mac. They pair again after a restore.')}</span>
            {/if}
          </span>
        </label>
      {/each}
    </div>
    {#if applied !== null}
      {#if applied.length === 0}
        <p class="caption applied">{tr('The selected preferences were applied.')}</p>
      {:else}
        {#each applied as failure (failure.key)}
          <p class="banner error" role="alert"><Icon name="warning" /><span>{label(failure.key)}: {failure.message}</span></p>
        {/each}
      {/if}
    {:else}
      <button type="button" class="apply" disabled={busy} onclick={onapply}>{tr('Apply Selected Preferences')}</button>
    {/if}
  </section>
  {#if outcome.nativeProfiles.length > 0}
    <section class="card profiles">
      <h2>{tr('Native profiles')}</h2>
      <p class="caption">{tr('L2TP and Cisco IPsec connections need their profile on this Mac. macOS asks you to approve each one.')}</p>
      <div class="rows">
        {#each outcome.nativeProfiles as profile (profile.id)}
          <p class="profile">
            <span>{profile.name}</span>
            {#if profile.installed}<span class="caption done">{tr('Opened for approval')}</span>{/if}
            {#if profile.note}<span class="caption note">{profile.note}</span>{/if}
          </p>
        {/each}
      </div>
      {#if remaining > 0}
        <button type="button" class="reinstall" disabled={busy} onclick={onreinstall}>
          {#if installing}<span class="spinner" aria-hidden="true"></span>{/if}
          {remaining === 1 ? tr('Reinstall 1 Native Profile') : tr('Reinstall %lld Native Profiles', remaining)}
        </button>
      {/if}
    </section>
  {/if}
  {#if error}
    <p class="banner error" role="alert"><Icon name="warning" /><span>{error}</span></p>
  {/if}
  <p class="caption">{tr('A missing tool or root helper shows in System Status, as usual.')}</p>
  <div class="buttons">
    <button type="button" class="primary done" disabled={busy} onclick={ondone}>{tr('Done')}</button>
  </div>
</div>

<style>
  .restore-after {
    display: contents;
  }
  .preferences .apply,
  .profiles .reinstall {
    align-self: flex-start;
  }
</style>
