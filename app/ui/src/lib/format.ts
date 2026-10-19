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

/// The menu's footer line: the product name and the backend's version ("MacVPN <version>", the same in every language).
export function versionLabel(version: string): string {
  return `MacVPN ${version}`;
}
