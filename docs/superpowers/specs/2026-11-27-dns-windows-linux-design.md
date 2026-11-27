# Per-connection DNS on Windows and Linux – design draft

Date: 2026-11-27. Status: **approved 2026-11-27** (D1 = A; Windows and Linux verified by unit tests and CI only, no live VM run).

## Goal

The macOS DNS settings of 2.1.8+ ([the macOS design](2026-11-04-dns-resolver-design.md)) work the same way in
WinVPN and LinVPN, in one release (maintainer, 2026-11-27: "Egyben, teljes egyezés"; Windows verified by CI and
unit tests only). That covers:

- the four modes: Automatic (default), Strict, Full, Targeted;
- the connection's own DNS servers and domains, and "use these instead of the VPN's DNS";
- the probe (`apple.com` through the VPN's DNS) and Automatic's fallback, both at connect and every 5 minutes;
- the local network's own names staying local (Automatic, Full);
- the notices: no DNS, fallback, failing, Targeted on a full tunnel, Targeted without domains;
- cleanup after a disconnect, a crash or a reboot.

Kinds: the same as on macOS (OpenVPN, WireGuard, SSTP). The other kinds keep today's behavior.

Today both apps store the setting and ignore it (`dns_settings.rs`); the editor shows the DNS section on macOS only
(`dnsFields.ts`).

## Shared part (all three OSes)

The pure logic moves out of the macOS root helper into `macvpn-core` (new module `dns_policy`), unchanged:

- `decide` (mode × tunnel × probe → layout and warning);
- `Pushed`, `Effective` and `effective` (the VPN's DNS merged with the connection's own);
- the reverse zones;
- the probe (`probe_server`: std UDP, bounded, two sends, 1.5 s each).

The macOS helper uses it from there. Moving it changes the root helper binary, so the root layer becomes **20**
(behavior unchanged; existing root tests cover it).

Two more shared pieces:

- **The 5-minute check:** the app's existing `dns-check` loop (`app-core`) drives all three OSes through
  `HelperClient`.
- **Status and notices:** `DnsState` and the notices are reused as they are.

The UI shows the DNS section on all three OSes for OpenVPN, WireGuard and SSTP. The help texts and the user guides
change per OS.

## Windows

The WinVPN Service (LocalSystem) owns the DNS of OpenVPN and WireGuard. SSTP is dialed by RAS in the app's process,
so the app asks the service to apply its DNS (a new `dns-apply` request carrying the RAS adapter's LUID and the
request).

**Mechanism: the Name Resolution Policy Table (NRPT).** The rules are local, not Group Policy. They go under
`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\WinVPN-<id>-<n>`: the same place and
technique OpenVPN's interactive service uses for `--dns`, and the one Windows' own VPN client uses. Each rule names
its domains and its servers. After a change, the resolver cache is flushed and the DNS client is told to re-read the
policy, as openvpnserv does.

**What the VPN sent.** After connect, the service reads the VPN adapter's DNS servers and connection suffix
(`GetAdaptersAddresses`):

- OpenVPN (DCO or TAP) and RAS put the pushed DNS there;
- WireGuard's DNS comes from the plan as today;
- OpenVPN's full pushed list (`dhcp-option DOMAIN`, `domain-search`, `dns … resolve-domains`) is also read from
  `PUSH: Received control message: 'PUSH_REPLY,…'` line of OpenVPN's own output (verb 3), which the service
  already reads from the process's stdout (`sys/openvpn.rs`).

| Layout (from `decide`) | NRPT rules | VPN adapter's own DNS |
|---|---|---|
| Vpn (Automatic, Full) | `.` → VPN servers; local domain and its reverse zone → the physical adapter's DNS (exemption) | kept |
| Vpn without local (Strict) | `.` → VPN servers only | kept |
| Split (Targeted) / Fallback (Automatic) | VPN domains + reverse zones → VPN servers | cleared while connected, so Windows' parallel lookup ("smart multi-homed") does not send everything to it; OpenVPN and RAS restore it on stop |

**Probe.** The service sends the query (to the VPN's servers, through the routing table, as on macOS). The fallback
and its return rewrite the rules at runtime. Windows allows that without a reconnect.

**Cleanup.** Every rule's name starts with `WinVPN-<id>`. At disconnect the connection's rules go. At service start
(after a crash or a reboot) every `WinVPN-*` rule whose connection is not running goes.

**Status.** The `status` reply's `dns` field is filled, as on macOS.

## Linux

The app (not root) writes the mode into the NetworkManager profile before activating it. NM and systemd-resolved do
the rest. The keys go through the existing `nm_plan/dns.rs`, which every kind already calls.

| Mode | Profile keys |
|---|---|
| Full | `dns-search` = VPN domains + `~.`, `dns-priority` 50: the VPN is the default; the physical link keeps its own domains (local names stay local) |
| Strict | `~.`, `dns-priority` −50: exclusive, the local network's domains too |
| Targeted (split tunnel only) | `~domain` for every VPN domain and reverse zone, `dns-priority` 50, no `~.` |
| Own servers | `dns` (servers), plus `ignore-auto-dns` with "use instead" |
| Own domains | added to `dns-search` (`~domain`: match only) |

**The one platform limit (spike 2026-11-27, NM 1.54.3 source):**

- NM gives a plugin VPN (OpenVPN, L2TP, IKEv2, SSTP) the settings copied at connect. It has no "reapply" for VPNs.
- Changing them later means a reconnect, with a new sign-in.
- resolved's own D-Bus calls need an admin password.

So Automatic's **fallback at runtime** needs a different lever on Linux (decision below, D1). Everything else
(Full, Strict, Targeted, own servers and domains, the probe and its notices) is exact.

The app runs the probe itself (plain UDP, no privilege).

**Cleanup:** the keys live in the connection's own profile, so nothing is left behind. D1's option A leaves at most
a runtime-only priority on the physical link, which NM drops at the link's next reconnect. The app restores it at
disconnect and at start.

### D1 – Automatic's fallback on Linux (decided: A)

**A. Lower the physical link's DNS priority while falling back (chosen).**
- How: `nmcli device modify <wifi/eth> ipv4.dns-priority 40` (runtime only, allowed for the desktop user).
  - The physical link takes the default DNS role back.
  - The VPN keeps its domains.
  - On recovery the original priority comes back.
- Behavior: exactly the macOS behavior, for every kind.
- Costs:
  - It touches the user's physical connection at runtime.
  - Every default-route link has to be handled.
  - It needs live verification on the test VM (a Wi-Fi reapply also re-reads that link's secrets).

**B. Let resolved ask both in parallel.**
- How: Automatic gives the VPN link the default DNS role *next to* the physical link, not instead of it. resolved
  takes the first good answer, so a broken VPN DNS never breaks the internet, with no runtime change at all.
- Cost: in Automatic, internet names are asked from the local network's DNS too while the VPN is up (Strict and Full
  do not). On a full tunnel that is a DNS leak, which the macOS design does not allow in Automatic unless the VPN's
  DNS fails.
- Needs live verification too (that NM keeps both links in the default role at equal priority).

**C. Automatic = Full on Linux, with the probe's warning only** (no fallback). Simplest, but a bad VPN DNS breaks
browsing until the user picks Targeted: against the maintainer's rule.

## Tests

- **Unit:** the shared `decide`/`effective` tests move with the code.
  - New: NRPT rule sets per layout (pure builder), NM key sets per mode and kind, the Windows reconcile (which rules
    are stale), and the app's `dns-check` routing per OS.
- **Windows:** CI (unit and `windows-admin` jobs). The registry writes go through a trait with a fake in tests; the
  real NRPT is not exercised live (maintainer: CI is enough).
- **Linux:**
  - unit tests on macOS and in CI;
  - `lab_e2e` on the VM for Full, Strict, Targeted and Automatic's fallback against the lab DNS, which forwards
    nothing (so the probe fails).
  - Not run for this release (maintainer: unit tests are enough). The physical-link priority change (D1 A) is
    therefore unverified live; it is built so that a leftover is harmless (runtime only, dropped by NM at the
    link's next reconnect).
- **macOS:** root tests (root 20 is a move only) and `cargo test`.

## Release

One release (2.1.15) for all three. MacVPN root 19 → 20 (the user presses Authorize once). User guides EN/HU for all
three; release notes.
