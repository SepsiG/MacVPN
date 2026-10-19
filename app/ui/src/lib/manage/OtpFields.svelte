<script lang="ts">
  // "Code after the password" (the Swift `OTPSettingFields`), the same in every editor.
  import type { Otp } from '../api';
  import { tr } from '../l10n.svelte';

  let { otp = $bindable(), disabled = false }: { otp: Otp; disabled?: boolean } = $props();
</script>

<label class="check">
  <input type="checkbox" bind:checked={otp.enabled} {disabled} />
  {tr('Ask for a one-time code at connect and append it to the password')}
</label>
{#if otp.enabled}
  <label class="field">
    <span>{tr('Separator')}</span>
    <select bind:value={otp.separator} {disabled}>
      <option value="none">{tr('None')}</option>
      <option value="comma">,</option>
      <option value="colon">:</option>
    </select>
  </label>
  <p class="note">{tr('The code is never stored. If no password is saved here, the code alone is sent as the password.')}</p>
{/if}
