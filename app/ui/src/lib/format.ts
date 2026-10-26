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

/// An idle row's type and status: the type; "<type> · Missing tool" (`missingTool`) when its tool is missing; or,
/// while the platform has no VPN engine (WinVPN 2a), the type with that reason as the status, never "Missing tool".
export function idleLine(
  row: { available: boolean; typeLabel: string; unavailableReason?: string },
  missingTool: (type: string) => string,
): { type: string; status: string | null } {
  if (row.available) return { type: row.typeLabel, status: null };
  if (row.unavailableReason) return { type: row.typeLabel, status: row.unavailableReason };
  return { type: missingTool(row.typeLabel), status: null };
}

/// The row is unavailable and System Status can install or repair its engine ("… – System Status").
export function engineLink(row: { available: boolean; setupLink?: boolean }): boolean {
  return !row.available && row.setupLink === true;
}
