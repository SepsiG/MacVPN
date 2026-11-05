// The connection's DNS settings in the editor (macOS root layer 15): the mode (Automatic, Full, Targeted, Strict),
// the connection's own DNS servers and domains, and "Use these instead of the VPN's DNS". Only on macOS and only for
// the kinds the root layer's DNS manager handles (OpenVPN, WireGuard, SSTP); elsewhere the stored values travel back
// unchanged. The backend validates again on save (`DnsFields::setting`).
import type { Os } from "../l10n-core";
import type { Tr } from "./ras";

export type DnsModeId = "automatic" | "full" | "targeted" | "strict";

export interface Dns {
  mode: DnsModeId;
  servers: string[];
  domains: string[];
  overrideVpn: boolean;
}

/// The section is shown on macOS for OpenVPN, WireGuard and SSTP.
export function visible(os: Os, kind: string, dns: Dns | undefined): boolean {
  return (
    os === "macos" &&
    dns !== undefined &&
    ["openvpn", "wireguard", "sstp"].includes(kind)
  );
}

/// The modes in the control's order, each with its one-line explanation. Targeted is left out when the config
/// sends all traffic through the VPN (`fullTunnel` true): there it would act as Automatic.
export function modes(
  tr: Tr,
  fullTunnel: boolean | undefined,
): { id: DnsModeId; label: string; help: string }[] {
  const all: { id: DnsModeId; label: string; help: string }[] = [
    {
      id: "automatic",
      label: tr("Automatic (recommended)"),
      help: tr(
        "Every name through the VPN's DNS; if it cannot resolve internet names, only the VPN's domains use it.",
      ),
    },
    {
      id: "full",
      label: tr("Full"),
      help: tr(
        "Every name through the VPN's DNS, also when it does not work. The local network's own names stay local.",
      ),
    },
    {
      id: "targeted",
      label: tr("Targeted"),
      help: tr("Only the VPN's domains use the VPN's DNS."),
    },
    {
      id: "strict",
      label: tr("Strict"),
      help: tr(
        "DNS never leaves the tunnel, even if the VPN's DNS does not work.",
      ),
    },
  ];
  return fullTunnel === true ? all.filter((m) => m.id !== "targeted") : all;
}

/// The grey note under Targeted when the server decides the routing.
export function targetedNote(
  tr: Tr,
  dns: Dns,
  fullTunnel: boolean | undefined,
): string | null {
  return dns.mode === "targeted" && fullTunnel === undefined
    ? tr(
        "If the server sends all traffic through the VPN, Targeted works like Automatic.",
      )
    : null;
}

/// A text area's entries: split at commas, blanks and line breaks; empty ones dropped.
export function splitList(text: string): string[] {
  return text.split(/[\s,]+/).filter((s) => s !== "");
}

/// The text area's text of a list (one per line).
export function joinList(list: string[]): string {
  return list.join("\n");
}

/// "Use these instead of the VPN's DNS" needs at least one own server: the message, or null when fine.
export function overrideProblem(tr: Tr, dns: Dns): string | null {
  return dns.overrideVpn && dns.servers.length === 0
    ? tr(
        "Using your own DNS instead of the VPN's needs at least one DNS server.",
      )
    : null;
}
