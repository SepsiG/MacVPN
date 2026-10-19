// The pairing window's rules (the backend checks the answer again: `PairingBroker::answer`).
import type { PairingItem } from './api';

/// The pairing ID of a pairing window's label (`pair-<id>`).
export function pairingIdOfLabel(label: string): number | null {
  const m = /^pair-(\d{1,15})$/.exec(label);
  return m ? Number(m[1]) : null;
}

/// The ticked keys that the window offers, in the offered order, each once.
export function allowedKeys(items: readonly PairingItem[], ticked: readonly string[]): string[] {
  return items.filter((i) => ticked.includes(i.id)).map((i) => i.id);
}

/// "Allow" works once the input lock passed and at least one offered connection is ticked.
export function canAllow(items: readonly PairingItem[], ticked: readonly string[], armed: boolean): boolean {
  return armed && allowedKeys(items, ticked).length > 0;
}
