// Keyboard shortcuts with the platform's primary modifier: Cmd on macOS, Ctrl on Windows and Linux. Pure, so
// `node --test` can check it; the components pass the OS from `i18n.platform`.
import type { Os } from './l10n-core.ts';

/// The parts of a `KeyboardEvent` the rule reads.
export type ShortcutEvent = Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey' | 'shiftKey'>;

/// `key` (lower case) with the primary modifier alone: macOS `metaKey` and no `ctrlKey`, Windows and Linux
/// `ctrlKey` and no `metaKey`; never with Alt or Shift.
export function isPrimaryShortcut(event: ShortcutEvent, key: string, os: Os): boolean {
  if (event.altKey || event.shiftKey || event.key.toLowerCase() !== key) return false;
  return os === 'macos' ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey;
}
