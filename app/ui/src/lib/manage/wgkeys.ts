// The WireGuard key panel's rules (pure, tested by node --test). The backend derives everything from the draft's
// config text (`EditorView.wireguard`); the web view never makes or derives key material.
import type { WireGuardKeyLine, WireGuardKeysView } from '../api';
import { tr } from '../l10n.svelte';

/// The public key row: the key to show and copy, or why there is none.
export type PublicKeyLine = { state: 'key'; key: string } | { state: 'invalid' } | { state: 'none' };

export function publicKeyLine(keys: WireGuardKeysView): PublicKeyLine {
  if (keys.publicKey) return { state: 'key', key: keys.publicKey };
  return keys.privateKey ? { state: 'invalid' } : { state: 'none' };
}

/// The confirmation shown before a generated key replaces one in the config; null: nothing to replace, generate
/// at once.
export function replaceQuestion(keys: WireGuardKeysView, which: WireGuardKeyLine): { title: string; message: string } | null {
  if (which === 'privateKey') {
    if (!keys.privateKey) return null;
    return {
      title: tr('Replace the private key?'),
      message: tr('The other side must be updated with the new public key.'),
    };
  }
  if (!keys.presharedKey) return null;
  return {
    title: tr('Replace the preshared key?'),
    message: tr('The other side must be updated with the new preshared key.'),
  };
}

/// "Generate Preshared Key" is offered for a config with exactly one peer (the key is that peer's).
export function offersPresharedKey(keys: WireGuardKeysView): boolean {
  return keys.peers === 1;
}
