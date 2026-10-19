// The language rule and the String(format:) subset of the core (crates/core/src/l10n.rs), for the UI.
// Pure functions, so `node --test` can check them without a bundler.

export type Language = 'en' | 'hu';

export interface Entry {
  hu: string;
  scope: string;
}

export type Table = Record<string, Entry>;

/// The first preferred language that is Hungarian or English; anything else (or nothing) means English
/// (core `AppLanguage::resolve`).
export function resolveLanguage(preferred: readonly string[]): Language {
  for (const language of preferred) {
    const code = language.toLowerCase();
    if (code === 'hu' || code.startsWith('hu-') || code.startsWith('hu_')) return 'hu';
    if (code === 'en' || code.startsWith('en-') || code.startsWith('en_')) return 'en';
  }
  return 'en';
}

/// `%@`, `%d`, `%ld`, `%lld`, `%u` (also positional, `%1$@`) and `%%` (core `format_string`).
export function format(fmt: string, args: readonly (string | number)[]): string {
  let out = '';
  let next = 0;
  let i = 0;
  while (i < fmt.length) {
    const c = fmt[i];
    if (c !== '%') {
      out += c;
      i += 1;
      continue;
    }
    let j = i + 1;
    if (fmt[j] === '%') {
      out += '%';
      i = j + 1;
      continue;
    }
    let k = j;
    while (k < fmt.length && fmt[k] >= '0' && fmt[k] <= '9') k += 1;
    let position: number | undefined;
    if (k > j && fmt[k] === '$') {
      position = Math.max(0, Number.parseInt(fmt.slice(j, k), 10) - 1);
      j = k + 1;
    }
    while (fmt[j] === 'l') j += 1;
    const spec = fmt[j];
    if (spec === '@' || spec === 'd' || spec === 'u') {
      const index = position ?? next++;
      const arg = args[index];
      if (arg !== undefined) out += String(arg);
      i = j + 1;
    } else {
      out += '%';
      i += 1;
    }
  }
  return out;
}

/// The UI texts: only the `app` scope of the table is used (core messages arrive translated from the backend).
export function translate(table: Table, language: Language, key: string, args: readonly (string | number)[]): string {
  const entry = table[key];
  const fmt = language === 'hu' && entry !== undefined && entry.scope === 'app' ? entry.hu : key;
  return args.length > 0 ? format(fmt, args) : fmt;
}
