// The UI's text lookup over the single EN/HU table (crates/core/l10n/strings.json, scope `app`). The language comes
// from the backend (the core's rule over the macOS preferred languages); before the first view model, the same
// rule over the web view's languages.
import table from '../../../../crates/core/l10n/strings.json';
import { resolveLanguage, translate, type Language, type Table } from './l10n-core.ts';

const strings: Table = (table as { strings: Table }).strings;

export const i18n = $state<{ language: Language }>({ language: resolveLanguage(navigator.languages ?? []) });

export function setLanguage(language: string): void {
  i18n.language = language === 'hu' ? 'hu' : 'en';
}

export function tr(key: string, ...args: (string | number)[]): string {
  return translate(strings, i18n.language, key, args);
}
