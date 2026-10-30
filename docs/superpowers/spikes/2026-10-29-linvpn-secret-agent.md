# Spike L0-4: OpenVPN challenges through a NetworkManager secret agent

Spike L0-4 decides how LinVPN gets OpenVPN's secrets and one-time codes to NetworkManager (L-b plan, resolved
point 8): `BRANCH` (A: LinVPN's own agent answers every secret; B: static secrets inline, CRV1 through the agent),
`CRV1_DEADLINE` (how long a dynamic challenge may wait for the user's code), the hint strings, and whether the static
challenge's SCRV1 password connects.

## Part 1 (stock `nm-openvpn`, L-b Task 2)

Not run as a separate spike. Task 14 shipped with the fallbacks (`DEFAULT_SECRET_MODE = SecretMode::Agent`,
`CRV1_DEADLINE_SECS = 110`, both marked `// L0-4:` in `crates/platform-linux/src/pure/nm/agent.rs`). Part 2 measures
them with LinVPN's own engine and agent instead of the throwaway spike agent, against LinVPN's NM OpenVPN service.

## Part 2 (LinVPN's NM OpenVPN service, L-b Task 26 Step 2)

Run with the real `Engine` (`crates/platform-linux/tests/lab_e2e.rs`: `lab_openvpn_static_challenge`,
`lab_openvpn_crv1`, `lab_openvpn_append_code`) in the desktop session of the test VM (Ubuntu 26.04,
NetworkManager 1.54.3, network-manager-openvpn 1.12.5 + LinVPN's patch, OpenVPN 2.7), the lab's OpenVPN server and
its one-time-code user. Results: see "Results" below (filled in from the lab run).

### Results (run 2)

- **The agent is asked for the new service type:** yes. NM asked LinVPN's agent (registered by the engine's own bus
  connection) for `org.freedesktop.NetworkManager.linvpn-openvpn`'s `vpn` secrets, both the password and the dynamic
  challenge. With the plain user the static secrets answered by the agent connected (branch A works).
- **The CRV1 hints:** the challenge reached `AuthStateReader` 2.3 s after the start with method `crv1`, the server's
  text ("Enter the lab one-time code") and echo on, so NM passed `x-dynamic-challenge-echo:challenge-response` and an
  `x-vpn-message:` hint, as `pure::nm::agent` parses them.
- **The connect after the code:** CRV1 connected 0.3 s after `respond`; the static challenge's `SCRV1:` password
  (answered by the agent as `password`) and the appended code connected at once. (A first run failed only because the
  test read the wrong code from the lab sheet.)
- **A wrong code:** CRV1: one new challenge, ended by Cancel, `AuthFailed`. Static / appended: NM's 60 s timeout (see
  the E2E record's wrong-password row).
- **CRV1_DEADLINE:** the code answered 105 s after NM's request (`L04_CRV1_DELAY=105`) still connected (0.3 s after
  the answer); NM did not cancel. 110 s (inside NM's 120 s agent timeout) stays.
- **GNOME Shell's agent:** not seen in the agent path; whether a GNOME dialog appeared is a CP-screen check.

`BRANCH = A`, `CRV1_DEADLINE = 110` (105 s measured), hints `x-dynamic-challenge-echo:challenge-response` and
`x-vpn-message:<server text>`, secret keys read: `password` (also the packed `SCRV1:` form) and
`challenge-response`; the static challenge's SCRV1 password connected.
