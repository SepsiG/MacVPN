<script lang="ts">
  import type { RowState } from './api';
  import { tr } from './l10n.svelte';

  let { state }: { state: RowState['state'] } = $props();
</script>

{#if state === 'connecting' || state === 'disconnecting'}
  <span class="dot spinner" aria-hidden="true"></span>
{:else if state === 'connected'}
  <span class="dot on" aria-hidden="true"></span>
{:else if state === 'failed'}
  <span class="dot fail" aria-hidden="true"></span>
{:else if state === 'awaitingAuth'}
  <svg class="dot key" viewBox="0 0 16 16" role="img" aria-label={tr('Waiting for authentication')}>
    <circle cx="5" cy="8" r="3.5" fill="currentColor" />
    <rect x="7.5" y="7" width="7.5" height="2.2" rx="0.6" fill="currentColor" />
    <rect x="12" y="8.5" width="2" height="3" rx="0.5" fill="currentColor" />
  </svg>
{:else}
  <span class="dot off" aria-hidden="true"></span>
{/if}

<style>
  .dot {
    display: inline-block;
    flex: none;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    box-sizing: border-box;
  }
  .on {
    background: var(--green);
  }
  .fail {
    background: var(--red);
  }
  .off {
    border: 1.5px solid var(--secondary);
  }
  .key {
    border-radius: 0;
    color: var(--orange);
  }
  .spinner {
    border: 1.5px solid var(--separator);
    border-top-color: var(--secondary);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
