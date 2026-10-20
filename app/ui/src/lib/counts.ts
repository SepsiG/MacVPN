// Counted nouns in the window's language: "1 connection", "2 connections" (English needs the singular; Hungarian
// keeps the noun singular after a number, so both of its forms read the same). Each form is its own literal key,
// like every other counted text of the app (a singular key with "1", a plural key with "%lld").
import { tr } from './l10n.svelte';

export function connectionsText(n: number): string {
  return n === 1 ? tr('1 connection') : tr('%lld connections', n);
}

export function foldersText(n: number): string {
  return n === 1 ? tr('1 folder') : tr('%lld folders', n);
}

export function credentialSlotsText(n: number): string {
  return n === 1 ? tr('1 credential slot') : tr('%lld credential slots', n);
}

export function teamSecretsText(n: number): string {
  return n === 1 ? tr('1 team secret') : tr('%lld team secrets', n);
}

export function savedSecretsText(n: number): string {
  return n === 1 ? tr('1 saved secret') : tr('%lld saved secrets', n);
}
