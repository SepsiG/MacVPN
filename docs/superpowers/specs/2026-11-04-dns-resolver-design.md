# VPN DNS through a dynamic-store resolver, DNS modes per connection (macOS) – design draft

Date: 2026-11-04. Status: **draft, for the maintainer's review** (nothing built yet).

## Why

Today (root layers ≤ 14) the helper writes the VPN's DNS servers and search domains into **every** network
service's persistent preferences, keeps the originals in a ledger and restores them at disconnect. Consequences:

- Every DNS question goes to the VPN's DNS while connected, also on a split tunnel (only some networks routed), so
  plain internet lookups travel to the office and depend on the tunnel.
- A VPN DNS that resolves only internal names (no recursion) breaks internet browsing while connected.
- A persistent change needs the ledger and a careful restore; a crash leaves it to the reconcile.
- A VPN that pushes no DNS leaves internal names unresolvable, with no hint in the app.

## Design

### 1. The resolver entry

Instead of editing the services' preferences, the helper publishes the VPN's DNS in the dynamic store (not
persistent; gone at reboot), as Tunnelblick and Viscosity do: `State:/Network/Service/<macvpn-uuid>/DNS` with
`ServerAddresses`, `SearchDomains` and, for the targeted mode, `SupplementalMatchDomains`. For the full mode the
entry must win over the primary service's DNS (to be settled in the implementation plan: the standard technique is
an override entry ordered first / the primary service's `State:` DNS replaced in the dynamic store, restored at
disconnect). The ledger keeps only what the dynamic store needs to restore; a crash or reboot leaves nothing behind.

### 2. DNS mode per connection

- **Automatic (default):** full DNS (as today). **Principle (maintainer, 2026-11-04): a bad VPN setting must never
  break the internet.** At connect, and again whenever lookups through the VPN's DNS start failing during the
  session, the helper asks the VPN's DNS for a known public name through the tunnel (short timeout). If it does not
  resolve it (no recursion, no answer, unreachable), the session falls back: the VPN's domains (as in the targeted
  mode) keep using the VPN's DNS, every other name goes to the original DNS of the network — on a split tunnel and
  on a full tunnel alike. Logged and notified ("The VPN's DNS does not resolve internet names; only the VPN's
  domains use it now."). On a full tunnel the notice also says that internet names are resolved outside the tunnel
  meanwhile. When the VPN's DNS answers again, full DNS comes back.
- **The local network's own names stay local (Automatic and Full, maintainer 2026-11-04):** the primary network's own
  domain (its DHCP-given domain / search domain, e.g. `lan`, `home`, `fritz.box`) and the reverse zone of its subnet
  get supplemental resolver entries to the network's original DNS, and its search domain is appended after the
  VPN's, so `nas`, `nas.lan` and the home router keep resolving while the VPN is up. On an overlap (the same domain
  at home and in the VPN) the VPN wins. `.local` (mDNS/Bonjour) is not DNS and keeps working anyway. Not in the
  Strict mode (nothing leaves the tunnel there).
- **Strict (off by default):** never falls back (DNS stays inside the tunnel even if it does not work); a warning
  only. For connections where DNS privacy matters more than a working internet.
- **Full:** every name through the VPN's DNS.
- **Targeted:** only the VPN's domains: the pushed search domains (`dhcp-option DOMAIN`), OpenVPN 2.6+
  `dns … resolve-domains`, and the connection's own domain list (for split-horizon names such as an internal
  `portal.company.com`), plus the reverse zones of the routed private networks. Everything else stays on the local
  DNS. Not offered for a full tunnel.

### 3. Own DNS per connection

Servers and domains in the connection's settings, used when the VPN sends no DNS (or always, with "override"). When
the VPN sends none and nothing is set, the log and the connection's details say so ("The VPN sent no DNS; internal
names will not resolve.").

### 4. Leak protection (non-negotiable)

- The only path by which DNS leaves a full tunnel is the Automatic mode's fallback, when the VPN's DNS does not
  work, and it is always notified; the Strict mode never does it.
- IPv6: the entry covers both families; tests with an IPv6-only and a dual-stack primary network.
- Network switch while connected (Wi-Fi → Ethernet): the entry stays in effect; tested.
- Disconnect, crash, reboot: nothing left behind (dynamic store), verified.

## Open questions for the maintainer

1. Default mode **Automatic** with the fallback on split and full tunnels (maintainer: "nem akarok olyat, hogy eldobja
   a netet, mert rossz a vpn beállítás"): decided.
2. The public probe name: `apple.com`, fixed, not configurable: decided.
3. WireGuard and SSTP the same way (they use the same DNS manager): yes by default.

## Tests

Unit tests for the mode decision and the entry contents; root tests with a fake dynamic store; live tests on the
maintainer's Mac: split tunnel (OpenVPN), the targeted mode with a split-horizon name, a VPN without DNS, a VPN DNS
without recursion (a test resolver), network switch, crash/reboot cleanup.
