// LinVPN's card panel (spike L0-2, CP-L0): on Linux the menu window is a transparent overlay over the work area
// (GNOME on Wayland places no window where its client asks). The page draws the card at the overlay's top-right,
// below the top bar, and reports the card's rectangle, the only part of the window that takes clicks; a click
// anywhere else passes through to the window below. Pure, so `node --test` can check it.
import type { Os } from './l10n-core.ts';

/// The class on `<html>` that turns the menu into the overlay's card (Menu.svelte, app.css).
export const OVERLAY_CLASS = 'overlay';

/// Whether this window is the card panel's overlay: the menu window on Linux.
export function usesOverlay(os: Os, label: string): boolean {
  return os === 'linux' && label === 'menu';
}

/// The card's rectangle as the backend takes it (`set_menu_card`: CSS pixels, left, top, width, height).
export function cardRect(rect: { left: number; top: number; width: number; height: number }) {
  return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
}
