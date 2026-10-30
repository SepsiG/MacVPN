# MacVPN / WinVPN test lab

A throwaway set of VPN servers in Docker for the manual tests of MacVPN (macOS), WinVPN (Windows) and LinVPN
(Linux): every
connection kind the apps have, with generated credentials, a lab PKI and ready-to-import client profiles. Built for
plan 2c, Task 4 (`docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md`; its checkpoints CP1/CP2 used it); the
2.0.0 manual checks (`docs/manual-test-checklist.md`, "A VPN-labor előkészítése" and the sections after it) use it.

Nothing here is meant for real use: the credentials are random and short-lived, the CA is limited to the lab's own
names and expires after 90 days, and `down.sh` deletes everything.

## What it serves

| Kind | Server | Authentication | Published on `LAB_BIND` |
|---|---|---|---|
| OpenVPN, routed (`tun`) | OpenVPN 2.7 | user name + password; static challenge (SCRV1), dynamic challenge (CRV1) and "code appended to the password" for the one-time-code user; user `labfull` gets a pushed `redirect-gateway def1` (`server/ccd/labfull`) | UDP 1194 |
| OpenVPN, layer 2 (`tap`) | OpenVPN 2.7 | user name + password | UDP 1195 |
| WireGuard | kernel WireGuard (Docker Desktop's VM kernel has it) | key pairs + preshared key | UDP 51820 |
| IKEv2 | strongSwan 6.0 | EAP-MSCHAPv2 (server certificate), PSK, client certificate | UDP 500, 4500; alternative 4510 |
| Cisco IPsec | strongSwan 6.0, IKEv1 Aggressive Mode | PSK + group name (KeyID) + XAUTH | same as IKEv2 |
| L2TP/IPsec | strongSwan 6.0 (IKEv1 PSK, ESP transport) + xl2tpd 1.3 + pppd 2.5 | PSK, then MS-CHAPv2 | same as IKEv2 |
| SSTP | accel-ppp 1.14 | MS-CHAPv2 over TLS (lab CA) | TCP 443; alternative 8443 |
| the lab CA's CRL | busybox httpd | – | TCP 8081 |

Behind the tunnels (all IPv4; the lab has no IPv6):

| What | Address |
|---|---|
| Test page (says which server the request came through) | `http://10.99.0.10/` |
| Lab DNS (answers only `*.lab.test`, forwards nothing) | `10.99.0.53`; test name `whoami.lab.test` → `10.99.0.10` |
| Services network (internal: no route out) | `10.99.0.0/24` |
| Client addresses | OpenVPN tun `10.99.11.0/24`, tap `10.99.12.0/24`; WireGuard `10.99.13.0/24`; IKEv2 `10.99.14.0/24`; Cisco `10.99.15.0/24`; L2TP `10.99.16.0/24`; SSTP `10.99.17.0/24` |
| PPP gateways (also answer HTTP and DNS, forwarded to the two above) | L2TP `10.99.16.1`, SSTP `10.99.17.1` |
| Docker networks (inside Docker only) | edge `172.31.99.0/24`, services `10.99.0.0/24` |

Every profile routes **only `10.99.0.0/24`** (and the server's tunnel address): nothing overlaps a home or office
LAN unless that LAN is in `10.99.0.0/16`. The one exception is the OpenVPN user `labfull`: the server itself pushes
`redirect-gateway def1` to it (no internet while connected), to test a server-pushed full tunnel. The servers forward a client's traffic only into `10.99.0.0/24`
(`server/common.sh`: `FORWARD` policy `DROP`); a client that sends everything through the tunnel ("Send all traffic
over VPN", `route_all=yes`, `remote_ts = 0.0.0.0/0`) has **no internet** while connected. The services network has no
way out at all.

### Components and why

- **One server image** (`images/server.Dockerfile`): official Alpine 3.24 packages only — strongSwan, xl2tpd,
  ppp, OpenVPN, wireguard-tools, accel-ppp, dnsmasq, iptables, busybox httpd. The base is pinned by digest, the
  packages by minor series (`strongswan~6.0` …); the exact versions are in `/lab-packages.txt` and printed by
  `check.sh`. No third-party image.
  - **strongSwan** carries IKEv2, Cisco-style IKEv1 XAUTH and L2TP's IPsec in one daemon (one IKE port pair).
  - **accel-ppp** for SSTP: packaged by Alpine, small, MS-CHAPv2 with SSTP crypto binding (what Windows requires).
    SoftEther was not chosen: not packaged by Alpine or Debian, much larger, its own management protocol.
  - **Kernel WireGuard**: Docker Desktop's LinuxKit kernel has it (also `xfrm`, `l2tp`, `ppp`, `tun`), so no
    user-space implementation (wireguard-go / boringtun) is needed.
- **The selftest image** (`images/client.Dockerfile`): Debian 13's clients (an independent build of each protocol,
  and `sstp-client`, which Alpine does not package). L2TP's selftest client runs on the Alpine image instead: Debian
  13's xl2tpd 1.3.18 did not bring PPP up with ppp 2.5 here, Alpine's 1.3.20 does.

Versions as built (2026-10-25): Alpine 3.24.2 — strongSwan 6.0.7, xl2tpd 1.3.20, ppp 2.5.3, OpenVPN 2.7.7,
wireguard-tools 1.0.20260223, accel-ppp 1.14.0, dnsmasq 2.92, OpenSSL 3.5.8; Debian 13 (selftest) — strongSwan
6.0.1, OpenVPN 2.6.14, sstp-client 1.0.20, ppp 2.5.2.

## Usage

Needs Docker (Docker Desktop on the Mac, running) and OpenSSL 3 (`brew install openssl@3`). No `sudo`.

```bash
ipconfig getifaddr en0                     # the Mac's LAN address (read only); use it as LAB_BIND
scripts/vpn-lab/up.sh --bind <LAN-IPv4>    # generate the state, build, start (ports on that address only)
scripts/vpn-lab/check.sh                   # server-side health + port probes from this host
scripts/vpn-lab/selftest.sh                # end-to-end: every kind from a client container (inside Docker)
scripts/vpn-lab/down.sh                    # remove containers, networks, images and the generated state
```

- `up.sh --host <name>` puts a DNS name into the certificates and profiles instead of the address (the clients
  must resolve it; Windows resolves `<mac>.local` through mDNS). `--renew` makes new credentials and a new PKI.
  `--no-ike-standard-ports` leaves UDP 500/4500 unpublished (see "MacVPN on the Mac that runs the lab").
- `profiles.sh` regenerates the server configs and the client profiles (credentials and PKI are kept unless
  `--renew` or the name/address changed). It needs no Docker. After it, `up.sh` again (it recreates the containers).
- `down.sh --keep-state` keeps the credentials and the PKI (so a CA trusted on a test machine stays valid).
- Every script has `--dry-run` (prints the docker commands, runs nothing); `scripts/test-vpn-lab.sh` tests the lab
  without Docker (shellcheck, the generated PKI and profiles, MacVPN's own validators for macOS, Windows and Linux, the
  compose files).
- The addresses never enter the repository: they are arguments or environment variables (`LAB_BIND`, `LAB_HOST`)
  and are written only into the git-ignored `.state/`.

### The generated state (`scripts/vpn-lab/.state/`, git-ignored, mode 700)

- `client/CREDENTIALS.txt` — user names (also `labfull`), password, PSK, Cisco group name, the one-time code, the
  `.p12` password.
- `client/macos/` — MacVPN imports: `openvpn-*.ovpn`, `wireguard-macos.conf`, `ikev2-{eap,psk,cert}.swanctl.conf`
  (with `remote_port = 4510`), `sstp-*.sstp`, `l2tp.txt` and `cisco-ipsec.txt` (the values to type into the form),
  `lab-ca.pem`, and `swanctl/{x509ca,x509,private}` (the CA, the client certificate and its key for strongSwan).
- `client/windows/` — WinVPN imports: the same set without `remote_port`, plus `openvpn-tap-l2.ovpn`,
  `wireguard-windows.conf`, `lab-ca.cer` (DER) and `lab-client.p12` (the IKEv2 computer certificate).
- `client/linux/` — LinVPN imports: the `client/macos` set (OpenVPN, IKEv2 with `remote_port = 4510` — NetworkManager's
  charon-nm sends to the profile's port —, SSTP, `l2tp.txt`, `cisco-ipsec.txt`, `lab-ca.pem`) with its own WireGuard
  peer, `wireguard-linux.conf` (`10.99.13.5`, so the Mac, the Windows VM and the Linux VM can be connected at once;
  `wireguard-linux.pub` is its public key), and `swanctl/{x509ca,x509,private}`, whose contents go into LinVPN's
  credential folder `$XDG_DATA_HOME/LinVPN/swanctl/` (`~/.local/share/LinVPN/swanctl/`).
- `server/`, `pki/`, `crl/`, `secrets.env` — the servers' side.

Which profile tests what:

| File | Tests |
|---|---|
| `openvpn-tun-dco.ovpn` | OpenVPN; on Windows the DCO driver. With user `labotp`: the dynamic challenge (CRV1: the code window appears during the connection) or, with "append a one-time code", the appended code |
| `openvpn-tun-cbc.ovpn` | AES-256-CBC: on Windows the TAP-Windows6 driver in `tun` mode |
| `openvpn-tap-l2.ovpn` | `dev tap` (Windows only: macOS has no tap driver) |
| `openvpn-static-challenge.ovpn` | the static challenge (user `labotp`; the code is asked before connecting) |
| any `openvpn-tun-*.ovpn` with user `labfull` | a server-pushed `redirect-gateway def1` (LinVPN: "Send all traffic over VPN" = **Server decides** sends everything through the tunnel — no internet while connected —, **Never** keeps the default route; macOS and Windows honour the push too) |
| `wireguard-*.conf` | WireGuard (separate keys for the Mac, the Windows VM and the Linux VM, so all can be connected at once) |
| `ikev2-eap.swanctl.conf` | IKEv2 EAP-MSCHAPv2 with the server certificate (the lab CA must be trusted) |
| `ikev2-psk.swanctl.conf` | IKEv2 PSK on both sides (macOS; on Windows it imports greyed with the reason: Windows' IKEv2 client has no PSK sign-in) |
| `ikev2-cert.swanctl.conf` | IKEv2 with a client certificate |
| `sstp-ca.sstp` / `sstp-ca-alt-port.sstp` | SSTP with the lab CA in the profile; port 443 / 8443 |
| `sstp-system-ca.sstp` | SSTP with the system's CAs: fails on macOS (Homebrew OpenSSL does not know the lab CA); on Windows works once the lab CA is in the computer's Trusted Root store |
| `sstp-no-verification.sstp` | macOS: connects (red warning); Windows: refused with the "Windows always checks…" reason |
| `l2tp.txt`, `cisco-ipsec.txt` | L2TP/IPsec and Cisco IPsec through the forms (same PSK and password as the other kinds) |

## What works through Docker Desktop (verified 2026-10-25: Docker Desktop with Engine 29.8.2, LinuxKit kernel 7.0, macOS on arm64)

- **Every published port delivers**: `check.sh` sends one datagram from the Mac to each UDP port and reads the
  server's firewall counter, and makes a TLS handshake (lab CA, name check) on both SSTP ports — all pass. One
  oddity: **UDP 500 sent from the Mac to its own address** was not delivered in the first runs of the session
  (also with a plain Python socket) and was delivered in every later run, also after a `docker restart`; the cause
  was not found (possibly Docker Desktop's forwarding of privileged ports settling). `check.sh` reports a miss on
  macOS as `info`, not as a failure; LAN clients do not go through this path, and CP1 checks UDP 500 from the VM.
- **Every kind connects end to end** from the selftest containers (39 checks: WireGuard; OpenVPN tun/DCO ciphers,
  AES-256-CBC, tap, static and dynamic challenge, appended code, wrong password refused, no route outside the lab;
  IKEv2 EAP-MSCHAPv2 / PSK / certificate on both the standard and the alternative port; Cisco IKEv1 Aggressive
  Mode PSK + XAUTH; L2TP/IPsec with MS-CHAPv2; SSTP on 443 and 8443; the test page and the lab DNS through each).
  Docker Desktop does not forward a container's packets to the host's published ports (no hairpin), so the
  selftest reaches the servers on Docker's edge network instead (same ports, the profiles unchanged; the servers
  still see a NAT). The published path itself is covered by the probes above and by the real clients at CP1.
- **IPsec through Docker's NAT**: the server is always behind NAT (it sees every client from Docker's edge
  gateway), so IKE moves to UDP 4500 and ESP is UDP-encapsulated (NAT-T); raw ESP (IP protocol 50) is never needed
  and never published. Consequences:
  - **Windows L2TP/IPsec** refuses a server behind NAT (error 809) until
    `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent\AssumeUDPEncapsulationContextOnSendRule` = 2 and a restart
    — exactly WinVPN's **Allow L2TP Behind NAT…** step (plan 2c, Task 12), which CP1 tests with this lab.
  - strongSwan's `bypass-lan` plugin is disabled in the lab (it would exempt Docker's edge network, where every
    client appears to come from, from IPsec, and L2TP's replies would leave unencrypted).
- **UDP idle timeouts** of Docker Desktop's port forwarding: IKE NAT-T keepalives (20 s), WireGuard's
  `PersistentKeepalive = 25` and OpenVPN's `keepalive 10 60` keep the mappings alive.

### MacVPN on the Mac that runs the lab

The Mac's own IKE clients need UDP 500/4500 themselves, and Docker holds them on the LAN address:

- **IKEv2** (MacVPN runs Homebrew's charon): start the lab with `up.sh --bind <LAN-IPv4> --no-ike-standard-ports`
  and use `client/macos/ikev2-*.swanctl.conf` (`remote_port = 4510`, published as the alternative port and
  redirected to the server's 4500 inside the container). The selftest verifies this path (`macOS form, alt port`).
  The Windows tests need the standard ports: run `up.sh` again without the flag.
- **L2TP/IPsec and Cisco IPsec** (macOS' own IKE daemon, fixed ports 500/4500, no port setting): cannot reach a lab
  on the same Mac. Run the lab on **another machine** for these two: any Linux box or VM with Docker (the same
  scripts; on Linux the ports are published by iptables DNAT, so the server sees the real client address), or a
  second Mac with Docker Desktop. This is also the fallback if the Windows VM's L2TP/IKE traffic does not get
  through Docker Desktop (not expected: UDP 500/4500/4510 reach the servers).
- OpenVPN, WireGuard and SSTP from the same Mac work (the clients use ephemeral ports).

### Findings for the apps (from building the lab)

- **F1 — MacVPN IKEv2 certificates on macOS.** Before 2.0.0, MacVPN's helper loaded a connection with
  `swanctl --load-all --file <run>/config`. With `--file`, swanctl reads `x509ca/`, `x509/` and `private/` **next to
  that file** (the private run folder), not from `/opt/homebrew/etc/swanctl/`, and it unloads private keys it does
  not find there (seen with strongSwan 6.0.1: "opening directory '<run>/x509ca' failed"). So the user guide's
  advice (put the CA into `/opt/homebrew/etc/swanctl/x509ca/`) only works if something loaded that CA into the
  running charon before (`sudo swanctl --load-creds`; certificates stay loaded), and **client-certificate
  authentication (`local { auth = pubkey; certs = … }`) cannot work** (the key is unloaded at every connect).
  **Fixed in MacVPN 2.0.0** (root layer 9): before `--load-all` the helper copies the regular files of
  `$(brew --prefix)/etc/swanctl/{x509,x509ca,x509ocsp,x509aa,x509ac,x509crl,pubkey,private,rsa,ecdsa,pkcs8,pkcs12}/`
  into the root-only run folder (folders 0700, files 0600; no symlinks, no hidden files) and calls
  `swanctl --load-all --noprompt --file <run>/config`; the run folder (with the key copy) is removed at disconnect.
  The CP steps copy `client/macos/swanctl/*` into `$(brew --prefix)/etc/swanctl/` once; no `swanctl --load-creds`.

## Firewall

- **The Mac**: macOS' application firewall (if on) asks once whether Docker (`com.docker.backend`) may accept
  incoming connections: allow it, or the VM cannot connect. Nothing else changes on the Mac; the lab never touches
  its network settings.
- **The LAN**: the VMs must reach the Mac's address on UDP 500, 4500, 1194, 1195, 51820 and TCP 443, 8443, 8081
  (8081: the CRL, which Windows' SSTP client downloads to check revocation).
- **Windows**: no inbound rule is needed (all connections are outgoing).

## Security notes

- Ports are published on `LAB_BIND` only (`up.sh` refuses `0.0.0.0`); stop the lab when not testing.
- The lab CA has **name constraints** (only the lab's address/name and `*.lab.test`), **extended key usages**
  limited to TLS server, TLS client and the IKE intermediate (`1.3.6.1.5.5.8.2.2`; Windows applies a CA's EKUs to
  the whole chain, so it can never vouch for code signing) and a 90-day lifetime. Its **private key is deleted**
  as soon as the server and client certificates and the CRL are made: nothing can be signed with it afterwards.
  The CRL is valid as long as the certificates (89 days); there is no re-signing – a new CRL or certificate means
  a whole new lab (`up.sh --renew`, then trust the new CA and import the new client certificate). Still, remove
  the CA from every machine after testing (Windows: `certlm.msc` → Trusted Root Certification Authorities →
  "MacVPN Lab CA (throwaway)" → Delete; and the client certificate from Personal).
- IKEv1 Aggressive Mode with a PSK (Cisco IPsec) lets an observer brute-force the PSK offline; acceptable only
  because the PSK is a throwaway (strongSwan needs `i_dont_care_about_security_and_use_aggressive_mode_psk`).
- The credentials are in `.state/` only (mode 700/600, git-ignored); `down.sh` deletes them. It deletes only the
  lab's own state: `LAB_STATE` must resolve to a folder inside `scripts/vpn-lab/` holding the `.vpn-lab-state`
  marker `profiles.sh` writes; anything else (a stray `LAB_STATE=$HOME/…`, a symbolic link) is refused and left
  alone (delete it yourself, or use `--keep-state`).

## Maintainer steps

The full Hungarian lists are in `docs/manual-test-checklist.md` ("A VPN-labor előkészítése", "MacVPN a laborral
(macOS)" and the WinVPN sections); in short:

1. On the Mac: `scripts/vpn-lab/up.sh --bind <LAN-IPv4>` → `scripts/vpn-lab/check.sh --selftest` → all `ok`
   (on macOS the UDP 500 line may be `info`).
2. Copy `scripts/vpn-lab/.state/client/windows/` to the VM (for example
   `scp -r scripts/vpn-lab/.state/client/windows "$WINVPN_SSH":lab-client`), and keep `CREDENTIALS.txt` at hand.
3. WinVPN on the VM (desktop, standard user): OpenVPN (`openvpn-tun-dco`, `-tun-cbc`, `-tap-l2`, static and dynamic
   challenge), WireGuard, L2TP (first the 809 text, then **Allow L2TP Behind NAT…**), IKEv2 ×3 (the PSK profile
   greyed with the Windows reason), SSTP ×4 files, Cisco (greyed, **Make an L2TP/IPsec Copy** → the copy connects).
   Each connected: `http://10.99.0.10/` shows "MacVPN lab: OK" and the server; `nslookup whoami.lab.test` →
   `10.99.0.10`.
4. MacVPN on the Mac: OpenVPN, WireGuard, SSTP (same Mac is fine); IKEv2 with `--no-ike-standard-ports` and the
   `client/macos` profiles (EAP, PSK and certificate, after copying `client/macos/swanctl/*` into
   `$(brew --prefix)/etc/swanctl/`); L2TP and Cisco only against a lab on another machine.
5. Afterwards: remove the lab CA and the client certificate from the VM, `scripts/vpn-lab/down.sh`.
