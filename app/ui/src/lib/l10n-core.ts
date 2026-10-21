// The language rule and the String(format:) subset of the core (crates/core/src/l10n.rs), for the UI.
// Pure functions, so `node --test` can check them without a bundler.

export type Language = 'en' | 'hu';

export type Os = 'macos' | 'windows' | 'linux';

/// The OS and product the texts are worded for (core `TextPlatform`).
export interface Platform {
  os: Os;
  product: string;
}

export const MACOS: Platform = { os: 'macos', product: 'MacVPN' };

/// The backend's `get_platform` reply (`{ os, productName }`).
export interface PlatformReply {
  os: string;
  productName: string;
}

const OSES: readonly string[] = ['macos', 'windows', 'linux'] satisfies Os[];

/// The platform of a `get_platform` reply; anything else (an unknown OS, no product name) keeps the macOS default.
export function platformOf(reply: unknown): Platform {
  if (typeof reply !== 'object' || reply === null) return { ...MACOS };
  const { os, productName } = reply as Partial<Record<keyof PlatformReply, unknown>>;
  if (typeof os !== 'string' || !OSES.includes(os) || typeof productName !== 'string' || productName === '') {
    return { ...MACOS };
  }
  return { os: os as Os, product: productName };
}

/// The product name of the keys, replaced by `Platform.product` on other products.
const BASE_PRODUCT = 'MacVPN';

export interface Entry {
  hu: string;
  scope: string;
  /// The OSes whose code paths show the text (absent: every OS).
  only?: Os[];
  /// The text on an OS whose wording differs from the key's.
  variants?: Partial<Record<Os, { en: string; hu: string }>>;
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
/// The OS's variant if the entry has one, else the base text; on another product `MacVPN` becomes the product
/// name, except in texts only another OS shows (core `l10n::tr_for`).
export function translate(
  table: Table,
  language: Language,
  platform: Platform,
  key: string,
  args: readonly (string | number)[],
): string {
  const found = table[key];
  const entry = found !== undefined && found.scope === 'app' ? found : undefined;
  const variant = entry?.variants?.[platform.os];
  let fmt = variant !== undefined ? variant[language] : language === 'hu' && entry !== undefined ? entry.hu : key;
  const foreign = entry?.only !== undefined && entry.only.length > 0 && !entry.only.includes(platform.os);
  if (platform.product !== BASE_PRODUCT && !foreign) fmt = fmt.replaceAll(BASE_PRODUCT, platform.product);
  return args.length > 0 ? format(fmt, args) : fmt;
}
