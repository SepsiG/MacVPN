// The UI's text lookup over the single EN/HU table (crates/core/l10n/strings.json, scope `app`). The language comes
// from the backend (the core's rule over the macOS preferred languages); before the first view model, the same
// rule over the web view's languages.
import table from '../../../../crates/core/l10n/strings.json';
import { MACOS, resolveLanguage, translate, type Language, type Platform, type Table } from './l10n-core.ts';

const strings: Table = (table as { strings: Table }).strings;

// The OS and product (the wording of the per-OS variants); macOS until the backend says otherwise (`get_platform`).
export const i18n = $state<{ language: Language; platform: Platform }>({
  language: resolveLanguage(navigator.languages ?? []),
  platform: { ...MACOS },
});

export function setLanguage(language: string): void {
  i18n.language = language === 'hu' ? 'hu' : 'en';
}

export function setPlatform(platform: Platform): void {
  i18n.platform = { os: platform.os, product: platform.product };
}

export function tr(key: string, ...args: (string | number)[]): string {
  return translate(strings, i18n.language, i18n.platform, key, args);
}
