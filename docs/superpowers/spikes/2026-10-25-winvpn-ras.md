# Spike: the Windows RAS API for WinVPN's native VPNs (2c plan, Task 2)

Question: does every RAS behaviour that `docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md` relies on hold
on Windows 11 for a standard user, and what exactly does Microsoft's own tool write into a phonebook for each kind?

## Constraints of this run

- Machine: the Windows test VM, Windows 11 Pro 26H2 x64, build **26300.9711** (the registry's `ProductName` still says
  "Windows 10 Pro", as on every Windows 11), Windows display language **hu-HU**, Windows PowerShell 5.1.26100.
- Account: the standard user `winvpn-dev` (not an administrator), in two contexts:
  - **SSH**: a network logon (token group `NETWORK`, S-1-5-2), no desktop, no Credential Manager (2a: error 1312).
  - **Desktop**: the same user's interactive RDP session (group `INTERACTIVE`, S-1-5-4), reached with a one-shot
    `schtasks /Create /SC ONCE /IT /RU winvpn-dev` task (deleted after each run), the way `scripts/win-smoke.sh` works.
- Nothing was installed, no administrator right was used, and no real VPN server was dialled. Every dial goes to
  `192.0.2.1` (TEST-NET-1, RFC 5737: never answers). Only dummy secrets were used (PSK `spike-psk-not-secret`, user
  `spike-user`, password `spike-password-not-secret`). The user's own VPN entries were not touched: the default
  phonebook (`%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk`) did not exist before, received only entries
  named `WinVPN-spike-<n>` / `WinVPN-spike-x-<random>`, and was gone again after each run (see 12).
- The probe is `scripts/ras-spike.ps1` (kept for re-runs on a new Windows build): C# P/Invoke into `rasapi32.dll`
  through `Add-Type`, nothing merged into the crates. `capture` writes Microsoft's reference entries with
  `Add-VpnConnection`; `probe` runs the checks in a private phonebook under `%LOCALAPPDATA%\WinVPN-spike\ras\spike.pbk`
  (folder ACL protected: the user and SYSTEM, full control, inherited, set with `icacls`) and deletes everything it
  created. Runs: desktop `all` twice (the second one is the source of the fixtures and of the tables below), SSH
  `probe` three times, and after a reboot of the VM one more desktop `probe` (run 3: the three open checks at the
  end).
- No VPN server was available (open question 2 / Task 4), so nothing here proves that a connection *succeeds*:
  authentication, the PSK actually being used, routes, DNS and the IPsec policy on the wire are checkpoint (CP1) items.

## Summary of decisions

| Plan assumption (Task 2 Step 2) | Result |
|---|---|
| Private phonebook works (write, read, dial) | **Confirmed** for L2TP, SSTP and IKEv2 (EAP, machine certificate). No fallback to the default phonebook is needed. |
| 1. Entries equal Microsoft's reference apart from GUID and name | **Confirmed with corrections**: equal once the flags below are used; the plan's guessed flags were wrong for IKEv2 (`ERROR_INVALID_PARAMETER`), SSTP/IKEv2 encryption and IKEv2's EAP data. |
| 2. Dials to 192.0.2.1 fail with an 800/809/868/13801-class code; hang-up works | **Partly contradicted**: the codes are 789 (L2TP), `0x8007274C` (SSTP), 628 (IKEv2). Hang-up during a dial and the handle release are confirmed at the desktop, but **not over SSH** (section 2; SSH run 3 with the corrected struct sizes: the same). |
| 3. `RasEnumConnectionsW` shows the private phonebook path | **Confirmed** (desktop): the full path **exactly as passed to `RasDialW`** (letter case included: an upper-case path comes back upper case), no `\\?\` prefix. Over SSH a network logon's own connections are not listed at all. |
| 4. PSK store over SSH, and `RasDeleteEntryW` clearing it | **Confirmed, better than assumed**: `RasSetCredentialsW(RASCM_PreSharedKey)` works over SSH too (no 1312). After delete and re-create of the same name, no PSK is found. |
| 5. Policy keys survive `RasSetEntryPropertiesW` | **Confirmed**, with a catch: a rewrite never *resets* them either. |
| 6. Policy blob = six DWORDs in `ROUTER_CUSTOM_IKEv2_POLICY0` order | **Contradicted (order)**: six little-endian DWORDs, but in the order integrity, encryption, **DH group, cipher transform, auth transform, PFS group**, with the VpnClient enum values. |
| 7. `RasConnectionNotificationW(INVALID_HANDLE_VALUE)` fires for failing dials | **Contradicted**: it fired only for the L2TP failure (twice), never for SSTP / IKEv2 failures or hang-ups, and never over SSH. |
| 8. `RasEnumEntriesW(NULL, NULL)` lists the default phonebooks only | **Confirmed** for the per-user phonebook (path in `szPhonebookPath`); the all-users phonebook does not exist on the VM (not exercised). |
| 9. SSTP `host:port` in `szLocalPhoneNumber` | **Confirmed**: accepted, and the SYN goes to the given port. |
| 10. IKEv2 EAP-MSCHAPv2 takes `szUserName`/`szPassword` non-interactively | **Not contradicted**: the dial reaches `RASCS_Authenticate` and fails like the certificate entry (no `RASCS_InvokeEapUI`, no 703). Final proof needs a server (CP1). |
| 11. Device name | **Confirmed: empty `szDeviceName` + `szDeviceType = "vpn"`** works; Windows picks the WAN Miniport itself. No `RasEnumDevicesW`. |
| (Per-kind table) IKEv2 PSK through `RASEO2_UsePreSharedKeyForIkev2Initiator` | **Contradicted**: `Add-VpnConnection` has no PSK method on this build; RAS refuses the flag alone (87) and an entry with it plus EAP or certificate fails at once with `E_FAIL` (0x80004005) even with a PSK stored. |
| (Task 5) `windows-sys` struct sizes | `RASDIALPARAMSW` must be **2120** bytes and `RASCONNW` **1388** (ras.h is `pack(4)`); `windows-sys 0.61.2` declares both `packed(4)` on 64-bit, so `size_of` is right. A naturally aligned copy (2128 / 1392) is refused with 632. |

## 1. Reference entries (`capture`, desktop only)

`Add-VpnConnection`, `Get-VpnConnection`, `Set-VpnConnectionIPsecConfiguration` fail over SSH ("Cannot connect to
CIM server. Access denied", the VpnClient CIM provider refuses a network logon), so `capture` runs only in the
desktop session. On this build `-AuthenticationMethod` accepts `Pap;Chap;MSChapv2;Eap;MachineCertificate` only:
**`PSK` is refused**, so there is no `ikev2_psk.pbk`. The dummy PSK of the L2TP entries is not in the phonebook file
(checked as ASCII and UTF-16 after every entry); the file has a `PreSharedKey=` key, always empty.

Fixtures (`crates/winsys/tests/fixtures/ras/`, each the entry's section of `rasphone.pbk`, CRLF, ANSI as Windows
writes it; server `vpn.example.com`):

| Fixture | `Add-VpnConnection` arguments |
|---|---|
| `l2tp_psk.pbk` / `l2tp_psk_split.pbk` | `-TunnelType L2tp -L2tpPsk <dummy> -AuthenticationMethod MSChapv2 -EncryptionLevel Required -Force` (/ `-SplitTunneling`) |
| `sstp.pbk` / `sstp_split.pbk` | `-TunnelType Sstp -AuthenticationMethod MSChapv2` (/ `-SplitTunneling`) |
| `sstp_port.pbk` | the same with `-ServerAddress vpn.example.com:8443` |
| `ikev2_eap.pbk` / `ikev2_eap_split.pbk` | `-TunnelType Ikev2 -AuthenticationMethod Eap` (/ `-SplitTunneling`) |
| `ikev2_machinecert.pbk` | `-TunnelType Ikev2 -AuthenticationMethod MachineCertificate` |
| `ikev2_policy.pbk` | IKEv2 EAP + `Set-VpnConnectionIPsecConfiguration -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -DHGroup Group14 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -PfsGroup None` |
| `ikev2_policy_gcm.pbk` | the same with `GCMAES256 / GCMAES256 / ECP384 / GCMAES256 / SHA384 / ECP384` |
| `ikev2_policy_3des.pbk` | the same with `SHA196 / DES3 / Group2 / DES3 / SHA1 / PFS2048` (a third point to pin the field order) |
| `ras_entry_fields.txt` | every reference entry's non-zero `RASENTRYW` fields, read back with `RasGetEntryPropertiesW` |

`RASENTRYW` of the references (`dwSize` 6724, `dwType` 2 = `RASET_Vpn`, `dwFramingProtocol` 1, `dwfNetProtocols`
0xC = IP + IPv6, `szDeviceType` "vpn", `dwSubEntries` 1, `dwDialMode` 0, `dwRedialCount` 3, `dwRedialPause` 60 in all):

| Reference | `dwVpnStrategy` | `dwfOptions` | `dwfOptions2` | `dwEncryptionType` | other |
|---|---|---|---|---|---|
| L2TP PSK | 3 `VS_L2tpOnly` | `0x27001D10` | `0x00002114` | 1 `ET_Require` | – |
| L2TP split | 3 | `0x27001D00` | `0x00000114` | 1 | – |
| SSTP | 5 `VS_SstpOnly` | `0x27000D10` | `0x00002104` | **3 `ET_Optional`** | – |
| SSTP split | 5 | `0x27000D00` | `0x00000104` | 3 | – |
| IKEv2 EAP | 7 `VS_Ikev2Only` | `0x07020110` | `0x00002104` | 3 | `dwCustomAuthKey` 26, `dwNetworkOutageTime` 1800, file key `CustomAuthData` |
| IKEv2 EAP split | 7 | `0x07020100` | `0x00000104` | 3 | as above |
| IKEv2 machine cert | 7 | `0x07000110` | `0x00402104` | 3 | `dwNetworkOutageTime` 1800 |

Decoded: `0x07000000` / `0x27000000` = `RASEO_PreviewUserPw | RASEO_PreviewDomain | RASEO_ShowDialingProgress`
(+ `RASEO_RequireMsCHAP2` 0x20000000); `0x100` = `RASEO_ModemLights`; `0x1C00` = `RequireDataEncryption |
RequireMsEncryptedPw | RequireEncryptedPw` (`0xC00` without data encryption); `0x10` = `RASEO_RemoteDefaultGateway`;
`0x20000` = `RASEO_RequireEAP`. `dwfOptions2`: `0x4` `DontNegotiateMultilink`, `0x100` `ReconnectIfDropped`,
`0x10` `UsePreSharedKey`, `0x2000` `IPv6RemoteDefaultGateway`, `0x400000` `RequireMachineCertificates`.
`-SplitTunneling` clears exactly `RASEO_RemoteDefaultGateway` and `RASEO2_IPv6RemoteDefaultGateway`; it does **not**
set `RASEO2_PlumbIKEv2TSAsRoutes`. The preview/progress/modem-lights bits only drive Windows' own dialler UI
(rasphone); WinVPN leaves them off (they appear as `PreviewUserPw=0` etc. in the file, nothing else changes).

## 2. The private phonebook (`probe`) – checks of Task 2 Step 2

**1. Write / read.** With the flags of section 1 minus the UI bits, `RasSetEntryPropertiesW` into the private
phonebook gives sections that equal the references except: the entry name, `Guid`, `DialParamsUID`,
`LowDateTime`/`HighDateTime`, `PhoneNumber`, the five UI keys (`PreviewUserPw`, `PreviewDomain`,
`ShowDialingProgress`, `ShowMonitorIconInTaskBar` 1 → 0) and `PowershellCreatedProfile` (1 → 0). The plan's first
guesses differed in three ways (run 1):
- **IKEv2 entries were refused** with `ERROR_INVALID_PARAMETER` (87). A field matrix (check 1a) shows: an IKEv2
  entry must have `RASEO_RequireEAP` or `RASEO2_RequireMachineCertificates` (anything else alone: 87), and it must
  not have `RASEO_RequireMsEncryptedPw` or `RASEO_RequireMsCHAP2` (87). Accepted on top of EAP: every
  `ET_*`, `RASEO_RequireDataEncryption`, `RemoteDefaultGateway`, `IPv6RemoteDefaultGateway`,
  `PlumbIKEv2TSAsRoutes`, `IPv4ExplicitMetric` (+ metric 9000), `fDisableIKEv2Fragmentation`, the redial and
  multilink bits.
- **SSTP and IKEv2 use `ET_Optional`** (`DataEncryption=8`) without `RASEO_RequireDataEncryption` in Microsoft's
  entries; the plan said `ET_Require` (`DataEncryption=256`). Both are accepted and both dial (run 2's `sstpreq`).
- **IKEv2 EAP needs `CustomAuthData`** (the EAP method's configuration): the reference has
  `CustomAuthData=314442431A00000008000000010000000000000000000000`. `RASENTRYW` has no field for it;
  `RasSetCustomAuthDataW` writes it, but wraps what it is given in its own header (`"1DBC"`, EAP type 0x1A,
  length) and a 4-byte zero terminator: passing the whole reference blob produced
  `314442431A00000018000000` + the 24 bytes + `00000000`. So the payload to pass is the reference's inner 8 bytes
  `01 00 00 00 00 00 00 00`: desktop run 3 confirmed that this writes exactly the reference's
  `CustomAuthData=314442431A00000008000000010000000000000000000000` (see "After the reboot").
- `dwDialMode` is 0 in the references (the plan had 1); `dwNetworkOutageTime` is 1800 for IKEv2.

`RasGetEntryPropertiesW` reads back what was written. Over SSH it returned `szDeviceType` empty (the desktop: "vpn")
although the file holds `DEVICE=vpn`: read-back checks must not compare `szDeviceType`. A rewrite with
`RasSetEntryPropertiesW` keeps the entry's `Guid` (`guidId`) and its stored PSK.

**2. Dialling 192.0.2.1** (`RasDialW`, notifier type 1 = `RasDialFunc1`, desktop run 2):

| Entry | `RasDialW` | States (callback) | Result |
|---|---|---|---|
| L2TP PSK | 0 | 0, 1, 2 (`RASCS_ConnectDevice`) | **789** after 65 s ("security layer … initial negotiations") |
| SSTP (`192.0.2.1`, and `ET_Require` variant) | 0 | 0, 1, 2 | **`0x8007274C`** (HRESULT of `WSAETIMEDOUT`) after 21 s; `RasGetErrorStringW` gives Winsock's text in the display language |
| SSTP `192.0.2.1:8443` | 0 | 0, 1, 2 | the same, the SYN went to port 8443 |
| IKEv2 EAP (user + password, no EAP extension) | 0 | 0 … 5 (`RASCS_Authenticate`) | **628** after 5 s, state `RASCS_Disconnected` |
| IKEv2 machine certificate | 0 | 0 … 5 | **628** after 5 s |
| IKEv2 PSK (EAP + PSK flag, PSK stored) | 0 | 0 … 5 | **`0x80004005`** (E_FAIL) after 0.2 s |
| IKEv2 PSK (certificate + PSK flag, PSK stored) | 0 | 0 … 5 | **`0x80004005`** after 0.1 s |
| L2TP, `RasHangUpW` after 3 s | 0 | 0, 1, 2 | callback error **618**; `RasGetConnectStatusW` → `ERROR_INVALID_HANDLE` (6) after ≤ 77 ms |
| IKEv2, `RasHangUpW` after 3 s | 0 | 0 … 5 | callback error **31**, state 8193; handle invalid after ≤ 1 ms |

After a failed dial `RasHangUpW` returns 0 or 668 (`ERROR_NO_CONNECTION`); both release the handle
(`RasGetConnectStatusW` → 6 within 25 ms) and no connection of the entry is left. The handle given by `RasDialW` equals
the `hrasconn` of every callback. Two caveats seen in run 2, when dials followed each other within a second: a
callback of the *previous* handle (error 618 / 633) arrived after the next dial had started, and one dial failed late
with **633** (device in use) — callbacks must be matched by `hrasconn`, and a dial right after a hang-up can find the
WAN Miniport port still busy.

**Over SSH** (run 1, and run 3 with the corrected struct sizes, see the end): the dial starts and fails with the
same codes (789 after 65 s, `0x8007274C` with the SYN to 443 / 8443, 628 after 5 s), but `RasGetConnectStatusW` on the handle answered **668 already during the
dial**, `RasHangUpW` answered 668, `rasdial.exe` listed no connection, and the next `RasDialW` of the same L2TP entry
returned **756** ("This connection is already being dialed"): in a network logon the dialling process cannot see or
release its own RAS connection.

**3. `RasEnumConnectionsW` during a dial** (desktop, `RASCONNW` 1388 bytes; 1360 = the pre-Windows 7 size is also
accepted): `szEntryName` = the entry name, `szPhonebook` = `C:\Users\winvpn-dev\AppData\Local\WinVPN-spike\ras\spike.pbk`
(exactly the path passed, letter case included — run 3 dialled with the path in upper case and got it back in upper
case —; drive letter, no `\\?\`), `szDeviceName` "WAN Miniport (IKEv2)", `hrasconn` = the dial's
handle, `guidEntry` = the entry's `guidId`, `dwFlags` 0. L2TP and SSTP connections did not appear in the one sample
taken at 1 s (still in `RASCS_ConnectDevice`), IKEv2 ones did; WinVPN keeps its own handles for its dials and uses
the enumeration for connections it did not start (another process, the previous app run).

**4. The PSK store.** `RasSetCredentialsW(private pbk, entry, RASCM_PreSharedKey)` returns 0 **over SSH and at the
desktop**; `RasGetCredentialsW` then reports `dwMask = RASCM_PreSharedKey` and a 16-character placeholder in
`szPassword` (not the 20-character PSK: Windows never returns it). The PSK bytes are not in the phonebook file. It
survives a rewrite of the entry. After `RasDeleteEntryW` and re-creating the same name, `RasGetCredentialsW` finds no
PSK (rc 2 or `0x80004005`, `dwMask` 0: the code differs between runs; "no PSK" is `dwMask` without the bit).
`RasSetCredentialsW(…, fClearCredentials = TRUE)` returns 0 and clears it. Whether the secret is also erased from
LSA's store on delete cannot be observed from user mode: WinVPN keeps clearing it explicitly before every delete.
`RASCM_UserName | RASCM_Password` of the entry stay empty (nothing is cached when `RasDialW` gets the password).

**5. Policy keys.** `WritePrivateProfileStringW` of `NumCustomPolicy=1` and `CustomIPSecPolicies=<hex>` into the
private entry, re-read equal. `RasSetEntryPropertiesW` on the same entry — with the read-back `RASENTRYW` and with a
fresh one — keeps both keys. `RasSetEntryPropertiesW` writes `NumCustomPolicy=0` only when it *creates* a section. So
a rewrite does not drop a policy, but it does not remove an old one either: WinVPN must write `NumCustomPolicy`
(and remove or rewrite `CustomIPSecPolicies`) after every `RasSetEntryPropertiesW`. The file stays ANSI (no BOM) after
`WritePrivateProfileStringW`; the keys sit after `CacheCredentials=` in Windows' own entries, but the position does not
matter to `GetPrivateProfileStringW`.

**6. The policy blob** (`CustomIPSecPolicies`, 24 bytes = six little-endian DWORDs):

| Policy (`Set-VpnConnectionIPsecConfiguration`) | DWORDs |
|---|---|
| SHA256128 / AES256 / Group14 / AES256 / SHA256 / None | 2, 4, 3, 5, 2, 0 |
| GCMAES256 / GCMAES256 / ECP384 / GCMAES256 / SHA384 / ECP384 | 3, 6, 5, 8, 5, 5 |
| SHA196 / DES3 / Group2 / DES3 / SHA1 / PFS2048 | 1, 1, 2, 2, 1, 3 |

With the VpnClient enums (read from the cmdlet's parameter types on the VM), the order is: **1 IntegrityCheckMethod,
2 EncryptionMethod, 3 DHGroup, 4 CipherTransformConstants, 5 AuthenticationTransformConstants, 6 PfsGroup** — not the
plan's (`ROUTER_CUSTOM_IKEv2_POLICY0`: …, cipher, auth, PFS, DH). Values:

| Field | Values |
|---|---|
| IntegrityCheckMethod | MD5 0, SHA1 1, SHA256 2, SHA384 3 |
| EncryptionMethod | DES 0, DES3 1, AES128 2, AES192 3, AES256 4, GCMAES128 5, GCMAES256 6 |
| DHGroup | None 0, Group1 1, Group2 2, Group14 3, ECP256 4, ECP384 5, Group24 6 |
| CipherTransformConstants | DES 1, DES3 2, AES128 3, AES192 4, AES256 5, GCMAES128 6, GCMAES192 7, GCMAES256 8 |
| AuthenticationTransformConstants | MD596 0, SHA196 1, SHA256128 2, GCMAES128 3, GCMAES192 4, GCMAES256 5 |
| PfsGroup | None 0, PFS1 1, PFS2 2, PFS2048 3, ECP256 4, ECP384 5, PFSMM 6, PFS24 7 |

(There is no GCMAES192 `EncryptionMethod`.) The three rows above are the fixtures; the plan's default (AES-256-CBC /
SHA-256 / group 14, ESP AES-256 / SHA-256-128 / no PFS) is exactly `ikev2_policy.pbk`:
`020000000400000003000000050000000200000000000000`.

**7. `RasConnectionNotificationW(INVALID_HANDLE_VALUE, event, RASCN_Connection | RASCN_Disconnection)`** returns 0
in both contexts. At the desktop the event fired twice right after the L2TP failure and **never** for the SSTP or IKEv2
failures nor for any hang-up; over SSH it never fired. Whether it fires for a *successful* connection and its
disconnection is a CP1 item. WinVPN's own dials are followed through their dial callback; the watcher's RASCN event is a
hint for connections of other processes, and the manager's poll stays the fallback (as the plan already says).

**8. `RasEnumEntriesW(NULL, NULL)`** (both contexts) listed the default-phonebook throwaway entry with
`szPhonebookPath = C:\Users\winvpn-dev\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk`, `dwFlags` 0
(= the user's phonebook; `REN_AllUsers` = 1), and none of the private entries. `RasEnumEntriesW(NULL, <private path>)`
lists the private entries with that path. The all-users phonebook (`%ProgramData%`) does not exist on the VM, so its
entries were not seen (creating one needs an administrator).

**9. SSTP port form**: `szLocalPhoneNumber = "192.0.2.1:8443"` is stored as `PhoneNumber=192.0.2.1:8443`, and
`netstat` showed the SYN to `192.0.2.1:8443` (the plain entry: `:443`). Microsoft's own `vpn.example.com:8443`
entry is stored the same way.

**10. IKEv2 EAP credentials**: `RasDialW` with `szUserName` / `szPassword` set and no `RASDIALEXTENSIONS` went through
`RASCS_Authenticate` without a `RASCS_InvokeEapUI` (4100) or `RASCS_Interactive` state and without 703; it failed
with 628 like the certificate entry (the server never answers). Run 1 (without `CustomAuthData`) and run 2 (with it)
behaved the same. Whether the EAP-MSCHAPv2 exchange then uses the given credentials can only be seen with a server.

**11. The device.** `RasEnumDevicesW` lists `WAN Miniport (PPPOE)`, `(PPTP)`, `(L2TP)`, `(IKEv2)`, `(SSTP)` (two ports
each; English names although the display language is Hungarian). An entry written with an **empty**
`szDeviceName` and `szDeviceType = "vpn"` gets `Device=WAN Miniport (L2TP)` (SSTP, IKEv2 likewise) and dials; a bogus
`szDeviceName` ("No Such Device") is ignored and replaced the same way.

**12. Other facts found on the way.**
- `RasValidateEntryNameW(private pbk, "WinVPN-<UUID>")` = 0 (43 characters; also before the file exists), 183
  (`ERROR_ALREADY_EXISTS`) for an existing name, 123 (`ERROR_INVALID_NAME`) for `bad\name`.
- The private phonebook file is created by the first `RasSetEntryPropertiesW` (the folder must exist), inherits the
  folder's ACL, and RasMan (SYSTEM) reads and dials it with the protected user + SYSTEM ACL. **Deleting the last
  entry deletes the phonebook file** (private and default phonebook alike): the watcher must expect the file to come
  and go, and "no file" means "no entries".
- Phonebooks are ANSI (no BOM), CRLF.
- `IPv4ExplicitMetric`/`IPv6ExplicitMetric` with metric 9000 are stored as `IpInterfaceMetric=9000` /
  `Ipv6InterfaceMetric=9000` (SSTP `peer_dns = no`).
- `PlumbIKEv2TSAsRoutes` is stored as `PlumbIKEv2TSAsRoutes=1`; a split entry (no default gateway) also stores
  `IpPrioritizeRemote=0`.
- Struct sizes (x64): `RASENTRYW` 6724, `RASDIALPARAMSW` 2120, `RASCONNW` 1388, `RASCONNSTATUSW` 608,
  `RASENTRYNAMEW` 1048, `RASCREDENTIALSW` 1068. `RASDIALPARAMSW` and `RASCONNW` contain pointer-sized fields at
  4-byte offsets (`packed(4)` in `windows-sys`): Rust code must copy their fields out (no references to packed fields).

## What this means for the plan

Proposed edits (the coordinator applies them before Wave 1; **applied to the plan on `c-t2`, 2026-10-25**, with the core change of item 3 and the `dpd_action` / `start_action` warnings; item 6 became the plan's G-12, Task 7 being merged):

1. **Per-kind mapping, L2TP row**: confirmed; write `dwfOptions = RequireMsCHAP2 | RequireDataEncryption |
   RequireMsEncryptedPw | RequireEncryptedPw (| RemoteDefaultGateway)`, `dwfOptions2 = DontNegotiateMultilink |
   ReconnectIfDropped | UsePreSharedKey (| IPv6RemoteDefaultGateway)`, `ET_Require`, `dwDialMode` 0, redial 3 / 60.
2. **SSTP row**: `ET_Require` → Microsoft's default `ET_Optional` without `RASEO_RequireDataEncryption` (SSTP is
   protected by TLS; both values are accepted, the choice only matters against a server, CP1). Options as L2TP without
   the PSK bit. `host:port` confirmed.
3. **IKEv2 rows**: EAP = `RASEO_RequireEAP`, `dwCustomAuthKey` 26, `CustomAuthData` written with
   `RasSetCustomAuthDataW` (payload `01 00 00 00 00 00 00 00`), `dwNetworkOutageTime` 1800, `ET_Optional`; never
   `RASEO_RequireMsCHAP2` / `RequireMsEncryptedPw` (87). Certificate = `RASEO2_RequireMachineCertificates` (no
   `RASEO_RequireEAP`), the rest the same. **PSK: change to "not supported on Windows"** (`local auth = psk` gets a
   reason, like `eap-tls`) unless the lab proves an entry form that works; see "IKEv2 PSK" below.
4. **The IPsec policy paragraph**: the six DWORDs are integrity, encryption, DH group, cipher transform, auth
   transform, PFS group, numbered as the VpnClient enums (table in 6); Task 3's policy table uses these values and
   pins them with the three fixtures. WinVPN writes `NumCustomPolicy` after **every** `RasSetEntryPropertiesW`
   (1 + the blob, or 0 and no `CustomIPSecPolicies` key), because a rewrite keeps whatever was there.
5. **Task 5 (`winsys::ras`)**: no `RasEnumDevicesW` (empty device name); `RasSetCustomAuthDataW` added to the
   surface; `dwSize = size_of::<…>()` of the `windows-sys` types (2120 / 1388 are right; never a hand-made struct);
   callbacks matched by `hrasconn` (late callbacks of an old handle happen); the phonebook file disappears with its
   last entry; `szDeviceType` is not compared on read-back; `RASCONNW.szPhonebook` is the path exactly as the
   dialler passed it, so "ours" compares it with the private phonebook's path without regard to letter case (and
   WinVPN always passes the one canonical path it builds). The dial-and-hang-up tests over SSH cannot pass
   (section 2, "Over SSH"): those tests are `#[ignore = "desktop: …"]` and listed in `scripts/ignored-everywhere.txt`,
   run at the desktop (CP1 or a `win-smoke.sh`-style scheduled task); entry, enumeration, PSK-store and policy-key
   tests run over SSH.
6. **Task 7 (error texts)**: add 789 as the L2TP "no answer / IPsec failed" case (the dial to a silent host gives
   789, not 809), `0x8007274C` (SSTP: server did not answer), 628 for IKEv2 (no answer or closed), 618 and 31 after
   WinVPN's own hang-up (cancelled, not an error; run 3 also gave **87** for an L2TP hang-up during the dial: any
   code after WinVPN's own hang-up is "cancelled"), 633 (the VPN device is still busy: retry), 756 (already
   dialling), **766** for an L2TP PSK entry dialled without a stored PSK (run 3; Windows' text speaks of a missing
   machine certificate: WinVPN says the PSK could not be stored), `0x80004005` (unspecified). Codes arrive as
   `i32` HRESULTs for SSTP: compare as `u32`.
7. **Task 9 (watcher)**: RASCN is not a reliable "connection ended" signal for failed dials; keep the poll as the
   source of truth for system VPNs (already the plan's fallback), and treat a RASCN event as "reload now".
8. **Task 2's file list**: `ikev2_psk.pbk` cannot be produced (no PSK method in `Add-VpnConnection`); added
   `l2tp_psk_split`, `sstp_split`, `ikev2_eap_split`, `ikev2_policy_gcm`, `ikev2_policy_3des`, `ras_entry_fields.txt`.
9. **Testing on the VM** (Resolved points): the VpnClient cmdlets do not work over SSH (CIM access denied); the
   PSK store does (no 1312), so no PSK test needs `#[ignore]`.

### IKEv2 PSK

Windows' documented flag `RASEO2_UsePreSharedKeyForIkev2Initiator` is accepted by `RasSetEntryPropertiesW` only next
to `RASEO_RequireEAP` or `RASEO2_RequireMachineCertificates`, and both such entries fail in `RASCS_Authenticate`
within 0.2 s with `E_FAIL`, before any packet could have been answered, while the EAP / certificate entries without
the flag run into the 5-second IKE timeout. `Add-VpnConnection` on this build offers no PSK method at all, and the
Settings app offers PSK only for L2TP. The safe plan change is to treat `local auth = psk` / `remote auth = psk` in a
`swanctl.conf` as "not supported on Windows" (reason text, the connection kept, usable on macOS); if the Task 4 lab
exists, a CP1 item can try the flag against a real strongSwan PSK responder and, if it connects, restore the row.

## After the reboot of the VM (the three open checks)

Run after a reboot of the VM (same build 26300.9711): the SSH run 3 log (`probe` over SSH with the corrected struct
sizes, made before the reboot) read back, and one desktop `probe` (run 3, a one-shot `/IT` scheduled task, deleted
afterwards; everything it created was deleted, the private phonebook file was gone at the end).

- **SSH run 3** (`RASDIALPARAMSW` 2120, `RASCONNW` 1388 — both accepted, `RasDialW` 0 and `RasEnumConnectionsW` 0):
  the same as run 1. `RasEnumConnectionsW` returns 0 with **no connection** during every dial (IKEv2 included, which
  the desktop lists at 1 s); `RasGetConnectStatusW` answers **668** at 1 s; the dials still fail with 789 /
  `0x8007274C` / 628 / `0x80004005` through the callback (handle = the `RasDialW` handle); `RasHangUpW` answers 668
  and the handle never becomes invalid (668 still after 15 s); the RASCN event never fires. The unreleased
  connections then hold the WAN Miniport ports: the next IKEv2 / L2TP dials fail within 60 ms with **633**, and a
  second dial of the first L2TP entry gets **756**. They are released when the SSH process ends (later runs were
  clean). So the struct sizes were not the cause: in a network logon the process cannot see or end its own RAS
  connections. Dial / hang-up / enumeration tests are desktop-only; entry, PSK-store and INI tests run over SSH.
- **`RasSetCustomAuthDataW` with the 8-byte payload `01 00 00 00 00 00 00 00`** (desktop run 3, three IKEv2 EAP
  entries): rc 0, and the entry's `CustomAuthData` is exactly the reference's
  `314442431A00000008000000010000000000000000000000`; the section's diff to `ikev2_eap.pbk` lists only the
  instance keys of section 2 (no `CustomAuthData` line). **Confirmed.** (The script's own "equals the reference"
  printed `False` because `Section … | Where-Object` received the section as one array item and compared the joined
  text; fixed in `scripts/ras-spike.ps1` after the run.)
- **`szPhonebook` letter case** (desktop run 3, the IKEv2 certificate entry dialled with
  `C:\USERS\WINVPN-DEV\APPDATA\LOCAL\WINVPN-SPIKE\RAS\SPIKE.PBK`): the dial works and `RasEnumConnectionsW` reports
  `szPhonebook` = `C:\USERS\WINVPN-DEV\APPDATA\LOCAL\WINVPN-SPIKE\RAS\SPIKE.PBK`, **exactly as passed** (Windows does
  not normalise it); the same entry dialled with the normal path reports the normal path. "Is this connection
  ours" must compare the path case-insensitively.

Also seen in desktop run 3 (recorded for Task 7): an L2TP hang-up during the dial ended with callback error **87**
(run 2: 618) and the handle was invalid within 1 ms; the L2TP entry dialled without a stored PSK failed at once with
**766** ("A certificate could not be found…"); both IKEv2 PSK-flag entries failed with `0x80004005` again; all other
codes as in run 2 (789 / `0x8007274C` / 628, IKEv2 hang-up 31); hang-ups after a failed dial returned 0 or 668 and
released the handle within 1 ms.
