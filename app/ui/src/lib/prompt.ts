// The MFA prompt's checks, as the core's `mfa::is_valid_code` (the backend checks the answer again).

/// Not empty, at most 256 bytes (UTF-8), no line break and no control character (C0, DEL, C1, U+2028/U+2029).
export function isValidCode(code: string): boolean {
  if (code === '' || new TextEncoder().encode(code).length > 256) return false;
  for (const c of code) {
    const v = c.codePointAt(0) ?? 0;
    if (v < 0x20 || (v >= 0x7f && v <= 0x9f) || v === 0x2028 || v === 0x2029) return false;
  }
  return true;
}

/// The countdown: `m:ss`.
export function countdown(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/// The prompt ID of a prompt window's label (`prompt-<id>`).
export function promptIdOfLabel(label: string): number | null {
  const m = /^prompt-(\d{1,15})$/.exec(label);
  return m ? Number(m[1]) : null;
}
