// The Language setting (the menu's Settings): System (the OS's language, exactly the rule before the setting) or a
// fixed language for the whole app. The backend applies it (`set_language`) and every window follows its next view
// model. The language names are in their own language, the same in every UI language; System is translated.
import type { Language } from './l10n-core.ts';

export type LanguageSetting = 'system' | Language;

/// The choices, in the menu's order.
export const LANGUAGE_SETTINGS: readonly LanguageSetting[] = ['system', 'en', 'hu'];

/// Each language's own name.
const NAMES: Record<Language, string> = { en: 'English', hu: 'Magyar' };

/// The choice's label: the language's own name, or `system` (the translated "Match System") for System.
export function languageLabel(setting: LanguageSetting, system: string): string {
  return setting === 'system' ? system : NAMES[setting];
}

export function isLanguageSetting(value: unknown): value is LanguageSetting {
  return typeof value === 'string' && (LANGUAGE_SETTINGS as readonly string[]).includes(value);
}

/// The language of a `get_platform` reply (the UI language now, for a new window's first render); `null`: absent or
/// unknown (the web view's own languages stay until the first view model).
export function languageOf(reply: unknown): Language | null {
  if (typeof reply !== 'object' || reply === null) return null;
  const { language } = reply as { language?: unknown };
  return language === 'en' || language === 'hu' ? language : null;
}
