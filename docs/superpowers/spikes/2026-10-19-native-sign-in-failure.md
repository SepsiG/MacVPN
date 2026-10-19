# Spike: native L2TP / Cisco IPsec sign-in failures (plan task 1, part b)

**Date:** 2026-10-19
**Question:** can MacVPN tell a native (L2TP, Cisco IPsec) sign-in failure – a wrong password or a wrong PSK –
apart from other failures such as an unreachable server, so that the credential prompt can re-prompt once?
**Decision: no.** Native connections get **no** re-prompt after a sign-in failure in 1.1. The pre-connect
credential prompt still applies to managed native connections; system VPNs get neither.

## Method

This part of the spike was done by reading the public SDK headers and the MacVPN code only. No VPN was
connected and no profile was changed: the go/no-go test of the plan (a wrong password and a wrong PSK each give a
`LastCause` value that an unreachable server never gives, on macOS 14 and 15) needs deliberate failing connects
against a test server, which were out of bounds for this run.

## Findings

- `SCNetworkConnectionCopyExtendedStatus` (`SCNetworkConnection.h`) documents a `PPP` dictionary with `Status`
  and `LastCause` ("Available when the status is Disconnected and contains the last error associated with
  connecting or disconnecting"), and an `IPSec` dictionary with `Status` and `ConnectTime` only. There is **no
  documented `LastCause` for IPSec**, so a Cisco IPsec failure has no cause value at all in the public API.
- `SCSchemaDefinitions.h` declares `kSCPropNetPPPLastCause` and `kSCPropNetPPPDeviceLastCause` as `CFNumber`,
  but the public SDK does not define the values. They are the private exit codes of Apple's `pppd` and of its
  L2TP plug-in (open source, not an API), which can change between macOS releases.
- For L2TP the PSK is checked in the IPsec phase, before PPP authenticates: a wrong PSK and an unreachable server
  both end before PPP, so they are expected to land on the same (device) cause. Whether they differ can only be
  observed on a real failing connect.
- MacVPN today only sees the scutil status (`Disconnected` after `Connecting`, see `Op::AwaitingNative` in
  `manager.rs`); no extended status is read anywhere.

## Consequence for the plan

- Task 4: the native re-prompt step (`NativeController::last_sign_in_failure`, `ConnectionEvent::SignInFailed`,
  `reconnect_after_sign_in_failure`) is **not** implemented. The re-prompt applies to the root-layer kinds only
  (OpenVPN `AUTH_FAILED`, the MFA bridge's final "Authentication failed", SSTP's wrong user name or password).
- System VPNs get no credential prompt at all in 1.1 (no pre-connect prompt, see the plan's "Resolved" points,
  and no re-prompt).
- Task 11: the user guide does not promise a re-prompt for L2TP / Cisco IPsec, and the manual checklist's
  optional "L2TP with a wrong password → re-prompt" item is dropped.
- To revisit (1.2 or later): run the plan's task 1 measurement on macOS 14 and 15 against a test L2TP and Cisco
  IPsec server; only a stable, distinct `PPP` → `LastCause` for a wrong password and a wrong PSK would justify
  the re-prompt.

## Note for root layer 8 (review M2)

The 1.1 re-prompt for the root kinds matches `mvpn`'s last stderr line against three messages. One of them, the
MFA bridge's final "Authentication failed", is also the result of a wrong or expired one-time code, not only of
a wrong user name or password. Root VERSION 8 (plan `2026-10-19-vault-folders.md`) should emit distinct bridge
messages, for example one for a rejected user name / password and another for a rejected code or challenge (and
the strongSwan EAP failure), so the user name / password re-prompt fires only on a real credential failure.

**TODO for 1.2 (with root VERSION 8):** once root 8 emits `Authentication failed (EAP)` (and its key is in
`crates/core/l10n/strings.json`), add it to `SIGN_IN_FAILURES` in `crates/core/src/credentials.rs` so that an IKEv2
EAP sign-in failure re-prompts once too. Not done in 1.1: the key does not exist on the 1.1 branch.
