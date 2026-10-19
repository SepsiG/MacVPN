# Spike: system VPN change notifications (plan 2026-10-19-credential-prompt-live-system, Task 1 part a)

Question: which notification source reports a system VPN being added, renamed or deleted, so the menu and the
Connections window can update the list at once (spec section 5)?

The native sign-in failure part of Task 1 (part b) is a separate spike and is not covered here.

## Constraints of this run

- The spike ran without admin rights. It did **not** create, rename or delete any system VPN profile, and it did
  not install a profile: that needs admin rights and changes the maintainer's system.
- Only one Mac was available: macOS 27.0.1 (build 26A434). The plan's macOS 14 and 15 runs were not possible.
- So the plan's go criterion ("fires for every add, rename and delete within 2 s, 10 out of 10 times, on both
  macOS versions") could not be measured. The decision below follows the safe default the plan allows.

## Candidates

A throwaway C probe (not kept in the repository) ran the plan's three sources at once, each printing a timestamped
line per callback and nothing else (no names, no secrets):

- **A:** `SCPreferencesCreate` (default preferences, i.e. `/Library/Preferences/SystemConfiguration/preferences.plist`)
  + `SCPreferencesSetCallback` + `SCPreferencesScheduleWithRunLoop`; flags `kSCPreferencesNotificationCommit` (1)
  and `kSCPreferencesNotificationApply` (2).
- **B:** `SCDynamicStoreCreate` + `SCDynamicStoreSetNotificationKeys(NULL, ["Setup:/Network/Service/[^/]+",
  "Setup:/Network/Service/[^/]+/(PPP|IPSec|VPN|Interface)"])` + a run loop source.
- **C:** `scutil --nc list` every second, printing when the output changes.

## Observations

1. **All three start without admin rights.** `SCPreferencesCreate`, `SCPreferencesSetCallback`,
   `SCPreferencesScheduleWithRunLoop`, `SCDynamicStoreSetNotificationKeys` all succeed for a normal user.
2. **Idle: no callbacks.** 10 minutes idle (normal desktop use, Wi-Fi on): A fired 0 times, B 0 times, and C saw no
   change. The idle criterion ("not more than once per second") is met with a wide margin.
3. **The listed services live in the SystemConfiguration preferences.** On this Mac `scutil --nc list` lists one
   L2TP VPN and two PPP modems. Every listed service ID is a key of `NetworkServices` in `preferences.plist` and is
   in a network set. The L2TP VPN is also in `/Library/Preferences/com.apple.networkextension.plist`: System
   Settings keeps VPNs in the Network Extension store and mirrors them into the SystemConfiguration preferences,
   which is where `scutil --nc list` (`SCNetworkConnectionCopyAvailableServices`) reads them.
4. **What follows from 3.** An add, rename or delete that changes the `scutil --nc list` output must write
   `preferences.plist`, and writing it through the SystemConfiguration API is a commit, which source A reports
   (`kSCPreferencesNotificationCommit`; the header documents it as "new preferences have been saved"). B only sees
   the change once the preferences are applied to the dynamic store (`Setup:` keys), so A covers everything B does.
5. **Not observed:** a real add, rename or delete (see the constraints), a `.mobileconfig` install, and whether the
   mirror into the SystemConfiguration preferences happens within 2 s on every macOS version.

## Decision

- **Source A** (`SCPreferences` commit / apply callback), as the plan prefers A over B. Implemented in
  `crates/platform-mac/src/sc_watch.rs` (`SystemVpnWatcher`).
- **The poll fallback stays on as well.** Until the manual checks below pass on real Macs, the watcher is not
  trusted to report every change (`macvpn_app_core::live::WATCHER_TRUSTED = false`). The status poller therefore
  uses the fallback pace even when the watcher runs: 3 s with an active connection, 5 s while a MacVPN window (the
  menu popover, Connections, System Status, Update) is open, 30 s otherwise. The watcher only makes a change show up
  sooner (about 0.5 s after the last notification of a burst).
- If the watcher fails to start, the app logs it once and relies on the poll fallback alone.
- Once the manual checks pass 10 out of 10 on macOS 14 and 15, `WATCHER_TRUSTED` can be set to `true` (the idle
  pace with a window open then goes back to 30 s).

## Follow-up for 1.2

- A removed system VPN keeps its secrets saved in MacVPN (the PSK and password), so they apply again if the
  same service returns; "Forget saved secrets" still works on the removed detail. Nothing prunes them yet: with
  the vault (1.2), delete the secrets of a service that has not been listed for more than 30 days, together with
  its folder placement (spec section 5).

## Manual checks (maintainer, with admin rights)

Run each 10 times on macOS 14 and 15, with MacVPN running, and write the results under this section.

1. Watcher alone: `cargo test -p macvpn-platform-mac --test sc_watch -- --ignored --nocapture` (an `#[ignore]`d
   test that prints a line per callback for two minutes). Then, in System Settings → VPN:
   - add an L2TP VPN, then an IKEv2 VPN;
   - rename each;
   - delete each.
   Each step must print a line within about 1 s (note the delay).
2. In the app: open the menu popover, then add, rename and delete a VPN in System Settings. The row must appear,
   change and disappear within about 1 s.
3. Open the Connections window and select a system VPN, then delete it in System Settings. The detail must stay,
   with the "This VPN was removed from macOS" banner, and every field and button disabled. Add a VPN: its row must
   appear without reopening the window.
4. Install and remove a MacVPN-generated `.mobileconfig` (a managed L2TP connection's "Save"): the list must follow.
5. Leave the app idle with the menu closed for 10 minutes: no more than one refresh every 30 s (no busy loop).
