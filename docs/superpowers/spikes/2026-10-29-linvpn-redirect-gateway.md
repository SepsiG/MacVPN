# Spike L0-1b: honoring a server-pushed `redirect-gateway` on Linux

**Date:** 2026-10-29
**Spec:** [LinVPN design](../specs/2026-10-29-linvpn-design.md), section 2 (decisions 3 and 7) and section 4
("OpenVPN full or split tunnel").
**Follows:** [Spike L0-1](2026-10-29-linvpn-nm-openvpn.md), which found that NM ignores a pushed `redirect-gateway`.
**Requirement (maintainer):** when an OpenVPN server pushes `redirect-gateway` (any variant), LinVPN makes the VPN
the default route automatically, as on macOS. It must not depend only on the client profile or on a manual switch.
**Method:** source reading only; no VM, no live tunnel. Versions match the test VM and Ubuntu 26.04 (`resolute`,
checked on Launchpad): NetworkManager **1.54.3**, `network-manager-openvpn` **1.12.5**, OpenVPN **2.7.0**.

| Source | Tag / commit read |
|---|---|
| GNOME `NetworkManager-openvpn` | `1.12.5`, and `main` at `d10793b` (1.12.5-21, translations only since) |
| OpenVPN | `v2.7.0`, and `master` at `54a66f35` |
| NetworkManager | `1.54.3`, and `main` at `1c71c568e` |

## Verdict

1. **Stock NM does not honor a pushed `redirect-gateway`. Confirmed.** The NM-openvpn `--up` helper never reads
   any redirect information and never sends `NEVER_DEFAULT`. NM then adds a default route unless the connection's
   `ipv4.never-default` is `yes`. So the connection setting alone decides. No setting makes NM follow the push:
   `never-default` is a plain boolean with no "auto".
2. **The information now exists.** OpenVPN **2.7** added `route_redirect_gateway_ipv4` / `route_redirect_gateway_ipv6`
   to the `--up` environment, explicitly "to communicate desired gateway redirection to NM". Ubuntu 26.04 ships
   OpenVPN 2.7.0, so the value reaches NM-openvpn's helper on our target, but the helper (1.12.5 and `main`)
   ignores it.
3. **LinVPN cannot learn the push from outside without root.** NM runs OpenVPN at `--verb 1`, and the
   `PUSH: Received control message` line is logged only from verb 3. `verb` is not a `vpn.data` key. NM has no
   `Reapply` for VPN connections, so even a detected push would need a reconnect, with a leak window on the
   first connect.
4. **Recommended:** LinVPN ships its **own NM VPN service for OpenVPN**, a build of upstream NM-openvpn 1.12.5 with a
   small patch: the helper turns `route_redirect_gateway_ipv4/ipv6` into `NEVER_DEFAULT`. NM still does routes,
   DNS and secrets; OpenVPN itself decides "full or split" from the profile plus the push, exactly as on macOS.
   There is no leak window, no reconnect and no polkit prompt. The cost is a second root component (spawned by NM,
   not by LinVPN) and a fork to track. In parallel, offer the patch upstream. Details and ranking below.
5. **Already works today:** pushed `route`s (split tunnel), and pushed `redirect-gateway ipv6` when the server
   also gives an IPv6 address (OpenVPN exports four specific IPv6 routes that NM installs).

## 1. Source evidence

### 1.1 NM-openvpn helper (`src/nm-openvpn-service-openvpn-helper.c`, 1.12.5)

**Environment variables it reads** (every `getenv` in the file):

| Function | Variables |
|---|---|
| `get_ip4_routes()` | `route_network_<n>`, `route_netmask_<n>`, `route_gateway_<n>`, `route_metric_<n>` |
| `get_ip6_routes()` | `route_ipv6_network_<n>`, `route_ipv6_gateway_<n>`, fallback `ifconfig_ipv6_remote` |
| `trusted_remote_to_gvariant()` | `trusted_ip6`, `trusted_ip`, `remote_1` |
| `main()` | `route_vpn_gateway`, `dev`, `ifconfig_local`, `ifconfig_remote`, `ifconfig_netmask`, `ifconfig_ipv6_local`, `ifconfig_ipv6_netbits`, `foreign_option_<n>` (only `dhcp-option DNS/WINS/DOMAIN/DOMAIN-SEARCH`), `tun_mtu` |

Nothing named `redirect_gateway`, `route_redirect_gateway_*` or `route_net_gateway`. `route_vpn_gateway` is used
only as the internal gateway:

```c
	/* Internal VPN subnet gateway */
	tmp = getenv ("route_vpn_gateway");
	val = addr4_to_gvariant (tmp);
	if (val)
		g_variant_builder_add (&ip4builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, val);
```

`NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT` / `NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT` appear **nowhere** in
`src/` (grep, 1.12.5 and `main`). The `_PREFIX` keys the helper sends are the address prefix only
(`NM_VPN_PLUGIN_IP4_CONFIG_PREFIX` from `ifconfig_netmask`), not a route.

**How NM-openvpn starts OpenVPN** (`src/nm-openvpn-service.c`, `nm_openvpn_start_openvpn_binary()`):

```c
	/* do not let openvpn setup routes or addresses, NM will handle it */
	args_add_strv (args, "--route-noexec");
	args_add_strv (args, "--ifconfig-noexec");
```

and `--up "<libexecdir>/nm-openvpn-service-openvpn-helper --debug … --bus-name … --tun --"` plus `--up-restart`.
The helper path is a compile-time constant:

```c
#define NM_OPENVPN_HELPER_PATH LIBEXECDIR"/nm-openvpn-service-openvpn-helper"
```

**Verbosity** (`main()` of the service): `--verb` follows `NM_VPN_LOG_LEVEL`, which NM derives from its own
`VPN_PLUGIN` log domain:

```c
	if (gl.log_level >= 0) {
		if (gl.log_level >= LOG_DEBUG)
			gl.log_level_ovpn = 10;
		else if (gl.log_level >= LOG_INFO)
			gl.log_level_ovpn = 5;
		else if (gl.log_level > 0)
			gl.log_level_ovpn = 2;
		else
			gl.log_level_ovpn = 1;
	...
		/* the default level is already "--verb 1", which is fine for us. */
```

`shared/nm-service-defines.h` has no `verb` key (all 66 `NM_OPENVPN_KEY_*` keys checked); there is no pass-through
for arbitrary options.

### 1.2 OpenVPN: which variables carry the redirect state

**`route_redirect_gateway_ipv4` / `_ipv6`: OpenVPN 2.7 and later.** Added by commit `1cc3525b`
(Gert Doering, 2025-08-26), "Introduce env variables to communicate desired gateway redirection to NM":

> When run under Network Manager control, OpenVPN is not allowed to control routing. Instead, NM uses the
> OpenVPN-set environment variables ("route_network_1" etc) to set up routes as requested. This method never
> worked properly for "redirect-gateway", as the information was not made available in environment variables.
> … `<not set>` = no gateway redirection desired, `1` = "redirect-gateway for that protocol in question",
> `2` = "include block-local to redirect the local LAN as well"

First tag containing it: `v2.7_beta1`; it is in `v2.7.0`. Not in 2.6 (`v2.6.14` has no match), so Debian 13
(OpenVPN 2.6.x) does not get it.

`src/openvpn/options.c`, `add_option()`, branch `redirect-gateway` / `redirect-private` (v2.7.0):

```c
        if (options->routes->flags & RG_REROUTE_GW)
        {
            setenv_int(es, "route_redirect_gateway_ipv4",
                       (options->routes->flags & RG_BLOCK_LOCAL) ? 2 : 1);
        }
        if (options->routes_ipv6 && (options->routes_ipv6->flags & RG_REROUTE_GW))
        {
            setenv_int(es, "route_redirect_gateway_ipv6",
                       (options->routes->flags & RG_BLOCK_LOCAL) ? 2 : 1);
        }
```

- This runs for both the local config and pushed options. Pushed options are applied with `c->c2.es`
  (`push.c`: `apply_push_options(c, &c->options, buf, permission_mask, option_types_found, c->c2.es, …)`), and the
  `--up` script runs with the same `c->c2.es` (`init.c`, `do_open_tun()`: `run_up_down(c->options.up_script, …,
  "init", NULL, "up", c->c2.es)`). The man page (`doc/man-sections/script-options.rst`) says "Set prior to
  ``--up`` script execution."
- Flags: `!ipv4` clears `RG_REROUTE_GW`, so `redirect-gateway ipv6 !ipv4` exports only `_ipv6`. `redirect-private`
  never sets `RG_REROUTE_GW`, so it exports nothing (correct: it does not move the default route). `def1`, `local`,
  `autolocal`, `bypass-*` are deliberately not exported.
- `push-remove redirect-gateway` (`remove_option()`) and `push-update` (`update_option()`) delete both variables.
- `pull-filter ignore "redirect-gateway"` drops the option before `add_option()`, so nothing is exported.

**`redirect_gateway` (old variable): useless under NM.** `init.c`, `do_route()`:

```c
    if (!route_noexec_enabled(options, tt) && (route_list || route_ipv6_list))
    {
        ret = add_routes(route_list, route_ipv6_list, tt, ROUTE_OPTION_FLAGS(options), es, ctx);
        setenv_int(es, "redirect_gateway", route_did_redirect_default_gateway(route_list));
    }
```

It is set only when OpenVPN adds routes itself (NM passes `--route-noexec`), and only after `--up`.

**The IPv4 redirect routes never reach the environment.** `route.c`, `redirect_default_route_to_vpn()` adds
`0.0.0.0/1` and `128.0.0.0/1` with `add_route3()` directly; they are not in `route_list`, so `setenv_routes()` does
not export them as `route_network_<n>`. It is called only from `add_routes()`, which `--route-noexec` skips.

**The IPv6 redirect routes do reach the environment.** `init.c`, `do_init_route_ipv6_list()`:

```c
    if (options->routes_ipv6->flags & RG_REROUTE_GW && options->ifconfig_ipv6_local)
    {
        char *opt_list[] = { "::/3", "2000::/4", "3000::/4", "fc00::/7", NULL };
        ...
            add_route_ipv6_to_option_list(options->routes_ipv6, ...);
    }
    if (init_route_ipv6_list(...))
    {
        /* copy routes to environment */
        setenv_routes_ipv6(es, route_ipv6_list);
    }
```

These four become `route_ipv6_network_<n>`, which the NM helper sends as `NM_VPN_PLUGIN_IP6_CONFIG_ROUTES`. They are
not default routes, so `ipv6.never-default` does not filter them. Result: **`redirect-gateway ipv6` already works
under stock NM when the VPN has an IPv6 address** (since commit `d227929b`, 2015). Without an IPv6 address OpenVPN
itself adds nothing (same as plain OpenVPN).

**`PUSH: Received control message`** is logged with `D_PUSH`, which is `LOGLEV(3, 34, 0)` in `errlevel.h`. At NM's
default `--verb 1` it is not logged.

### 1.3 NetworkManager: plugin `NEVER_DEFAULT` versus `ipv4.never-default`

`src/core/vpn/nm-vpn-connection.c` (1.54.3; same in `main`), `_dbus_signal_ip_config_cb()` (handles the plugin's
`Ip4Config`/`Ip6Config` signals):

```c
    if (g_variant_lookup(dict,
                         IS_IPv4 ? NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT
                                 : NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT,
                         "b",
                         &v_b))
        never_default = v_b;
    else
        never_default = FALSE;

    if (!never_default) {
        ...  /* default route via gw_internal, table_any, metric_any */
        nm_l3_config_data_add_route(l3cd, addr_family, NULL, &route.rx);
    }
```

and `_l3cfg_get_merge_flags()`:

```c
        if (s_ip4 && nm_setting_ip_config_get_never_default(s_ip4))
            merge_flags |= NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES;
```

`src/core/nm-l3-config-data.c`, `nm_l3_config_data_merge()` then drops every default route (`plen 0`) of that
config when the flag is set:

```c
                    if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT(r_src)) {
                        if (NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES)
                            && !NM_FLAGS_HAS(src->flags,
                                             NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES))
                            continue;
```

**So the two are ANDed; either side can suppress the default route, neither can force it:**

| Plugin `NEVER_DEFAULT` | Connection `never-default` | VPN default route |
|---|---|---|
| absent / `false` | `no` | **yes** |
| absent / `false` | `yes` | no (filtered at merge) |
| `true` | `no` | no (never created) |
| `true` | `yes` | no |

Side effects of the same code:
- A pushed `route 0.0.0.0 0.0.0.0` reaches NM as a `plen 0` route and is filtered only by the connection's
  `never-default`, not by the plugin flag.
- Pushed `route 0.0.0.0 128.0.0.0` + `route 128.0.0.0 128.0.0.0` (some servers do "def1 by hand") are not default
  routes and are always installed, whatever `never-default` says.
- NM always adds the host route to the VPN server via the parent device (`_l3cfg_l3cd_gw_extern_update()`, unless
  `ipv4.auto-route-ext-gw=false`), so the tunnel survives a full-tunnel default route.

`ipv4.never-default` is a plain boolean, default `FALSE` (`nm-setting-ip-config.c`:
`g_param_spec_boolean(NM_SETTING_IP_CONFIG_NEVER_DEFAULT, …, FALSE, …)`). There is no ternary/"auto" value.

**No live re-apply for VPNs.** `org.freedesktop.NetworkManager.Connection.Active` and `…VPN.Connection` define no
methods (`introspection/*.xml`). `Device.Reapply` works on a device's own activation; the OpenVPN tun device has
none, and `nm-device.c`, `check_and_reapply_connection()`, fails with `"Device is not activated"` outside
PREPARE..ACTIVATED. `Settings.Connection.Update2` changes the stored (here volatile) profile only; the VPN's
*applied* connection (`_get_applied_connection()`) is a snapshot taken at activation. A changed `never-default`
therefore needs a reconnect.

### 1.4 History and issues

- NM-openvpn `git log` (all branches): no commit ever read a redirect variable or set `NEVER_DEFAULT`.
  The importer (`properties/import-export.c`) only maps `route 0.0.0.0 0.0.0.0` to `never-default=FALSE`
  ("which is already the default"), commit `935df24` (2016).
- MR !26 "WIP: Support redirect-gateway & don't redirect gateway by default" (2020): import-time only, closed
  unmerged 2020-09-17.
- Issues #48 (2020) and #149 (2024) "always adds default route": closed without a change. #85 (IPv6 not rerouted)
  is open.
- OpenVPN 2.7's variables (2025-08) were added for NM; NM-openvpn `main` (1.12.5-21) has not adopted them, and no
  open MR mentions them.

## 2. Can a setting make stock NM honor the push?

**No.** The helper never sends `NEVER_DEFAULT`, so the default route depends only on `ipv4.never-default`, which is
a boolean fixed at activation. `never-default=no` gives a full tunnel always; `yes` gives a split tunnel always.
Neither follows the server.

The only push-aware piece that works unmodified is IPv6 (section 1.2): with `ipv6.never-default=yes` and a pushed
`redirect-gateway ipv6` plus an IPv6 address, the four specific routes still go into the tunnel.

## 3. Alternatives, ranked

| Rank | Option | Honors push | Leak window | Root code | Polkit | Complexity |
|---|---|---|---|---|---|---|
| **1** | **(d) LinVPN's own NM OpenVPN service (patched NM-openvpn build)** | yes, exactly | none | yes, spawned by NM | none | medium (C fork + packaging) |
| 2 | (c) Own OpenVPN runner (spec option B) | yes | none | yes, our helper | none (if helper is a system service) | high |
| 3 | (e) Divert the system helper with a wrapper | partly (def1 routes) | none | yes | none | low code, high blast radius |
| 4 | (a)+(b) Detect from the log, then reconnect with `never-default=no` | after a reconnect | **yes, first connect** | config only | none | medium, fragile |
| — | (b) alone: `Update2`/`Reapply` the running VPN | impossible | — | — | — | — |

Upstreaming the patch to NM-openvpn is not an alternative for 2.1.0 (Ubuntu 26.04 is frozen at 1.12.5), but it is
the long-term exit from rank 1.

### (d) Recommended: `linvpn-openvpn` NM VPN service

**What ships in the `.deb`:**

| File | Content |
|---|---|
| `/usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name` | `[VPN Connection]` `name=linvpn-openvpn`, `service=org.freedesktop.NetworkManager.linvpn-openvpn`, `program=/usr/lib/linvpn/nm-linvpn-openvpn-service`, `supports-multiple-connections=true`, `supports-safe-private-file-access=true`. No `[GNOME]` section (no editor, no auth dialog). |
| `/usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf` | the upstream policy with the new prefix (root may own `org.freedesktop.NetworkManager.linvpn-openvpn*`) |
| `/usr/lib/linvpn/nm-linvpn-openvpn-service`, `/usr/lib/linvpn/nm-linvpn-openvpn-service-openvpn-helper` | upstream 1.12.5 built with `--libexecdir=/usr/lib/linvpn` plus our patch |

NM watches `/usr/lib/NetworkManager/VPN` (`nm-vpn-manager.c`, `vpn_dir_changed()`), so no NM restart; the postinst
reloads D-Bus. NM spawns the program with `--bus-name <service>.Connection_<n>` (`nm-vpn-connection.c`), which the
upstream service already accepts. It keeps the upstream hardening: `--user nm-openvpn` / chroot (the `.deb` depends
on `network-manager-openvpn` for the user, the `openvpn` binary and the system plugin for system VPNs).

**The patch (helper, about 30 lines):**
- Read `route_redirect_gateway_ipv4` and `route_redirect_gateway_ipv6`.
- Send `NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT = !(ipv4 var set)` and `NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT =
  !(ipv6 var set)`.
- Only when the service says OpenVPN is ≥ 2.7 (the service already runs `openvpn --version`,
  `openvpn_binary_detect_version()`), passed as a new helper argument. With 2.6 it sends nothing and behaves as stock.
- Value `2` (`block-local`): treat as `1` and log a warning; see Risks.

**The patch (service, optional but small):** accept LinVPN `vpn.data` keys that are passed straight to OpenVPN, so
OpenVPN itself merges profile and push the way it does on macOS:
- `redirect-gateway` (the profile's flags, for example `def1 ipv6`) → `--redirect-gateway …`. With
  `--route-noexec` this only sets the variables, which is exactly what the helper needs.
- `pull-filter` lines and `route-nopull` → passed through (closes the "only some `pull-filter` prefixes" gap from
  L0-1, and removes the need to emulate them with `ignore-auto-*`).
- `verb` → `--verb 3`, so the Log tab shows the `PUSH:` line as on macOS (journal, via `linvpn-logd`).

**What `nm_plan` sets:**
- `vpn.service-type = org.freedesktop.NetworkManager.linvpn-openvpn` for LinVPN's own OpenVPN connections (system
  VPNs keep the stock plugin).
- `ipv4.never-default = no`, `ipv6.never-default = no` (the plugin now decides).
- "Send all traffic over VPN" becomes a three-way choice, default **Server decides** (macOS behaviour):
  - Server decides → no extra key;
  - Always → `redirect-gateway def1 ipv6`;
  - Never → `pull-filter ignore "redirect-gateway"` and `ipv4/ipv6.never-default = yes`.
- On OpenVPN < 2.7 (not our target, but possible on Debian 13), LinVPN cannot honor the push: it falls back to
  decision 7's rule (profile or switch, default split) and System Status says why.

**Reliability:** OpenVPN computes the state with its own option parser (profile, push, `push-remove`, `pull-filter`,
`!ipv4`), the variable OpenVPN added for this purpose. On `--up-restart` (reconnect with `persist-tun`) the helper
runs again with the new push, and NM applies the new config.
**Timing:** the default route is part of the first IP config NM applies; there is no window. Before the VPN is up
traffic uses the LAN, as on macOS.
**Polkit:** none. Activation of a `permissions=user:<name>` connection is the same for any VPN service.
**IPv6:** `redirect-gateway ipv6` gives `::/0` plus OpenVPN's four specifics; without `ipv6` the plugin suppresses
NM's IPv6 default route (today stock NM adds it whenever the server gives an IPv6 address). `block-ipv6` is enforced
inside OpenVPN's packet path and needs IPv6 routed into the tunnel, as with plain OpenVPN.
**Complexity / maintenance:** GPL-2.0+ C code from upstream plus one patch, built in our CI for amd64 and arm64.
We must track upstream releases and security fixes, and ship the source (the patch and upstream tarball) next to
the `.deb` (LinVPN itself stays MIT; this is aggregation).

### (c) Own OpenVPN runner (spec option B)

Works fully (OpenVPN adds its own routes, `redirect-gateway` and `block-local` included) with no leak window.
But it needs a LinVPN root helper with route and DNS handling (systemd-resolved over D-Bus), its own reconnect and
liveness logic, and a security review of all of it. That is the WinVPN Service again, and it contradicts decision 3.
More root code than (d) for the same result.

### (e) Divert the system helper

`dpkg-divert` `/usr/libexec/nm-openvpn-service-openvpn-helper` and install a wrapper that, when
`route_redirect_gateway_ipv4` is set, appends `route_network_<n>` = `0.0.0.0/128.0.0.0` and `128.0.0.0/128.0.0.0`
via `route_vpn_gateway`, then execs the real helper. The stock helper cannot be made to send `NEVER_DEFAULT`, so
"no push → split" still needs `never-default=yes`, and the def1 routes bypass `never-default`. It changes every
NM OpenVPN connection on the machine, other users' included (the wrapper would need a marker such as a `dev`
name prefix to touch only LinVPN's), and diverting another package's file is fragile. Not recommended.

### (a) + (b) Detect, then reconnect

- **Detect:** impossible at the default `--verb 1`. The `PUSH:` line needs verb 3. The only knob is NM's
  `VPN_PLUGIN` log level, set as root (`SetLogging` is in the "Root-only functions" of NM's D-Bus policy,
  `src/core/org.freedesktop.NetworkManager.conf`), or a `.deb`-shipped `[logging] domains=…,VPN_PLUGIN:DEBUG` in `/etc/NetworkManager/conf.d/`. `DEBUG` maps to
  `--verb 5` (per-packet noise) and makes the helper dump its whole environment, for every VPN on the machine.
  `VPN_PLUGIN:INFO` only reaches `--verb 2`.
- **Apply:** no `Reapply` for VPNs (section 1.3), so LinVPN must disconnect and reconnect with `never-default=no`
  and remember "this server pushes a full tunnel" per connection.
- **Leak:** on the first connect (and whenever the server changes its mind) the tunnel runs split while the server
  expects full; traffic leaks until the reconnect. A server that stops pushing keeps getting a full tunnel until
  LinVPN notices.
- Usable only as a stop-gap for OpenVPN < 2.7; not for 2.1.0.

## 4. The reverse case: no push, only `route`s

Confirmed from source. OpenVPN computes pushed routes even under `--route-noexec`: `do_open_tun()` calls
`do_init_route_list()` before the `--up` script, and that function exports them:

```c
    if (init_route_list(route_list, options->routes, gw, metric,
                        link_socket_current_remote(link_socket_info), es, ctx))
    {
        /* copy routes to environment */
        setenv_routes(es, route_list);
```

The helper's `get_ip4_routes()` loops over `route_network_<n>` / `route_netmask_<n>` / `route_gateway_<n>` /
`route_metric_<n>` and sends them as `NM_VPN_PLUGIN_IP4_CONFIG_ROUTES` (IPv6 likewise via `get_ip6_routes()`).
NM installs them unless `ipv4.ignore-auto-routes` is set. With the recommended plugin (no push → `NEVER_DEFAULT`)
or with stock NM and `never-default=yes`, the result is a split tunnel through exactly those routes.

## 5. Risks and open points

- **Second root component.** Spec section 8 says "no root component except `linvpn-logd`". The plugin runs as root
  under NM (then drops to `nm-openvpn`), like the stock plugin. Needs the maintainer's decision and a place in the
  security review (scope: the patch).
- **Fork maintenance.** Upstream NM-openvpn changes rarely (1.12.5 → `main` is translations only), but security
  fixes must be picked up. Offer the helper patch upstream (it is what OpenVPN 2.7 intended); when a distro ships
  it, LinVPN can drop the fork.
- **OpenVPN < 2.7** has no variables; the push stays invisible. Ubuntu 26.04 is fine (2.7.0); Debian 13 is not.
- **`block-local`** (value 2): NM has no "route the LAN into the tunnel except the gateway" primitive, and the
  helper does not know the LAN prefix. Degrade to a normal full tunnel and show a warning (same as L0-1's RISKY).
- **To verify on the VM before building on it:** NM accepts a `.name` file without a `[libnm]`/`[GNOME]`
  section; the secret agent gets requests for the new service type (GNOME Shell's agent has no auth dialog for it
  and must not grab them, ties in with L0-4); `route_redirect_gateway_*` present in the helper's environment
  with a pushed and a local `redirect-gateway` (lab server, helper at `--debug` once).
- **Spec changes if accepted:** decision 7 becomes "server decides" by default with an Always/Never override;
  section 4's "NM ignores a pushed `redirect-gateway`" paragraph, the Linux tier's `redirect-gateway`/`pull-filter`/
  `route-nopull` rows, and section 7's dependencies (build of the plugin, source shipping) change.
