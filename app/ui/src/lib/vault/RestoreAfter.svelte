<script lang="ts">
  // The steps after a restore (the restore window, and the create-vault window after a fresh restore): the ticked
  // preferences are applied by name (the backend takes the values from the backup), and the native profiles are
  // reinstalled one after another.
  import { untrack } from 'svelte';
  import { initialTicks, tickedKeys } from './backup';
  import { backupApi, type PreferenceFailure, type RestoreOutcome } from './backupApi';
  import RestoreAfterView from './RestoreAfterView.svelte';

  let { outcome: initial, ondone }: { outcome: RestoreOutcome; ondone: () => void } = $props();

  // A copy of the restore's result (taken once): the profile list is updated as profiles are installed.
  let outcome = $state<RestoreOutcome>(untrack(() => structuredClone($state.snapshot(initial))));
  let ticks = $state<Record<string, boolean>>(untrack(() => initialTicks(initial.preferences)));
  let applied = $state<PreferenceFailure[] | null>(null);
  let applying = $state(false);
  let installing = $state(false);
  let error = $state<string | null>(null);

  async function apply() {
    applying = true;
    error = null;
    try {
      applied = await backupApi.applyPreferences(tickedKeys(outcome.preferences, ticks));
    } catch (e) {
      error = String(e);
    } finally {
      applying = false;
    }
  }

  /// One profile after the other, each opened for approval.
  async function reinstall() {
    installing = true;
    error = null;
    try {
      for (const profile of outcome.nativeProfiles.filter((p) => !p.installed)) {
        outcome.nativeProfiles = await backupApi.reinstallProfile(profile.id);
      }
    } catch (e) {
      error = String(e);
    } finally {
      installing = false;
    }
  }
</script>

<RestoreAfterView
  {outcome}
  bind:ticks
  {applied}
  {applying}
  {installing}
  {error}
  onapply={() => apply().catch(console.error)}
  onreinstall={() => reinstall().catch(console.error)}
  {ondone}
/>
