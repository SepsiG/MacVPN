<script lang="ts">
  // A connection's coloured icon bubble (one colour and glyph per VPN type; `null`: a system VPN), with the
  // connection state as a badge: green connected, amber connecting / awaiting authentication (pulsing unless
  // reduced motion is asked for), red failed, grey disconnected.
  import type { Kind, RowState } from './api';
  import { tr } from './l10n.svelte';

  let {
    kind,
    state = null,
    size = 'md',
  }: { kind: Kind | null; state?: RowState['state'] | null; size?: 'sm' | 'md' | 'lg' } = $props();

  const type = $derived(kind ?? 'system');
  const tone = $derived(
    state === 'connected'
      ? 'on'
      : state === 'connecting' || state === 'disconnecting' || state === 'awaitingAuth'
        ? 'busy'
        : state === 'failed'
          ? 'fail'
          : 'off',
  );
</script>

<span class="bubble {type} {size}">
  <svg class="glyph" viewBox="0 0 16 16" aria-hidden="true">
    {#if type === 'openvpn'}
      <path d="M8 2.6a3.5 3.5 0 0 0-1.7 6.55L5.5 13.4h5l-.8-4.25A3.5 3.5 0 0 0 8 2.6z" fill="currentColor" />
    {:else if type === 'wireguard'}
      <path d="M2.4 6.2c1.9-2.1 3.7-2.1 5.6 0s3.7 2.1 5.6 0M2.4 10.4c1.9-2.1 3.7-2.1 5.6 0s3.7 2.1 5.6 0" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
    {:else if type === 'strongswan'}
      <path d="M8 1.9l5 1.9v3.7c0 3.1-2 5.5-5 6.6-3-1.1-5-3.5-5-6.6V3.8z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
      <path d="M5.7 7.9l1.6 1.6 3-3.1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
    {:else if type === 'l2tp'}
      <path d="M2.6 13.4V8.2a5.4 5.4 0 0 1 10.8 0v5.2M5.6 13.4V8.6a2.4 2.4 0 0 1 4.8 0v4.8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
    {:else if type === 'cisco'}
      <path d="M2.8 7v2M5.4 5.2v5.6M8 3.2v9.6M10.6 5.2v5.6M13.2 7v2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
    {:else if type === 'sstp'}
      <path d="M5.4 7.2V5.4a2.6 2.6 0 0 1 5.2 0v1.8" fill="none" stroke="currentColor" stroke-width="1.5" />
      <rect x="3.6" y="7" width="8.8" height="6.6" rx="1.6" fill="currentColor" />
    {:else}
      <circle cx="8" cy="8" r="5.6" fill="none" stroke="currentColor" stroke-width="1.4" />
      <path d="M2.6 8h10.8M8 2.4c1.6 1.6 2.3 3.5 2.3 5.6S9.6 12 8 13.6C6.4 12 5.7 10.1 5.7 8S6.4 4 8 2.4z" fill="none" stroke="currentColor" stroke-width="1.3" />
    {/if}
  </svg>
  {#if state !== null}
    {#if state === 'awaitingAuth'}
      <span class="badge {tone}" role="img" aria-label={tr('Waiting for authentication')}></span>
    {:else}
      <span class="badge {tone}" aria-hidden="true"></span>
    {/if}
  {/if}
</span>

<style>
  .bubble {
    --c1: var(--vpn-system);
    --c2: var(--vpn-system-2);
    position: relative;
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: var(--radius-icon);
    color: #fff;
    background: linear-gradient(180deg, var(--c1), var(--c2));
    box-shadow:
      inset 0 0.5px 0 rgba(255, 255, 255, 0.25),
      0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .sm {
    width: 26px;
    height: 26px;
    border-radius: 7px;
  }
  .lg {
    width: 40px;
    height: 40px;
    border-radius: 10px;
  }
  .glyph {
    width: 16px;
    height: 16px;
  }
  .sm .glyph {
    width: 14px;
    height: 14px;
  }
  .lg .glyph {
    width: 22px;
    height: 22px;
  }
  .openvpn {
    --c1: var(--vpn-openvpn);
    --c2: var(--vpn-openvpn-2);
  }
  .wireguard {
    --c1: var(--vpn-wireguard);
    --c2: var(--vpn-wireguard-2);
  }
  .strongswan {
    --c1: var(--vpn-ikev2);
    --c2: var(--vpn-ikev2-2);
  }
  .l2tp {
    --c1: var(--vpn-l2tp);
    --c2: var(--vpn-l2tp-2);
  }
  .cisco {
    --c1: var(--vpn-cisco);
    --c2: var(--vpn-cisco-2);
  }
  .sstp {
    --c1: var(--vpn-sstp);
    --c2: var(--vpn-sstp-2);
  }
  .badge {
    position: absolute;
    right: -3px;
    bottom: -3px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    box-sizing: border-box;
    border: 2px solid var(--badge-ring, var(--surface));
    background: var(--state-off);
  }
  .lg .badge {
    width: 13px;
    height: 13px;
    border-width: 2.5px;
  }
  .badge.on {
    background: var(--state-on);
  }
  .badge.fail {
    background: var(--state-fail);
  }
  .badge.busy {
    background: var(--state-busy);
  }
  .badge.busy::after {
    content: '';
    position: absolute;
    inset: -2px;
    border-radius: 50%;
    box-shadow: 0 0 0 0 var(--state-busy-glow);
    animation: pulse 1.6s var(--ease) infinite;
  }
  @keyframes pulse {
    0% {
      box-shadow: 0 0 0 0 var(--state-busy-glow);
    }
    70% {
      box-shadow: 0 0 0 5px transparent;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
    }
  }
</style>
