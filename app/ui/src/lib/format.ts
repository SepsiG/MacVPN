// Display helpers for the menu rows.

/// The uptime of a connection (`since`, Unix seconds) as `m:ss` or `h:mm:ss`.
export function uptime(since: number, nowMs: number): string {
  const total = Math.max(0, Math.floor(nowMs / 1000 - since));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const two = (n: number) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${two(m)}:${two(s)}` : `${m}:${two(s)}`;
}

/// The menu's footer line: the running product's name and the backend's version ("MacVPN <version>" on macOS,
/// "WinVPN <version>" on Windows; the same in every language).
export function versionLabel(version: string, product = 'MacVPN'): string {
  return `${product} ${version}`;
}

/// An idle row's type and status: the type, with the backend's reason as the status when the row cannot start
/// ("Not installed: OpenVPN", "Not ready: …", the engine's or the platform's reason). Before the first setup check
/// there is no reason yet: only the type, never a guessed one.
export function idleLine(row: { available: boolean; typeLabel: string; unavailableReason?: string }): {
  type: string;
  status: string | null;
} {
  if (row.available || !row.unavailableReason) return { type: row.typeLabel, status: null };
  return { type: row.typeLabel, status: row.unavailableReason };
}

/// The row is unavailable and System Status can install or repair its engine ("… – System Status").
export function engineLink(row: { available: boolean; setupLink?: boolean }): boolean {
  return !row.available && row.setupLink === true;
}
