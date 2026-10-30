#!/usr/bin/python3 -I
"""Offline NM-openvpn import: loads the plugin's editor library and calls its import function.
Talks to no NetworkManager daemon (no D-Bus, no polkit). Inline blobs go to $XDG_DATA_HOME."""
import sys, glob, os
import gi
gi.require_version("NM", "1.0")
from gi.repository import NM, GLib

info = next(i for i in NM.VpnPluginInfo.list_load() if i.get_name() == "openvpn")
plugin = info.load_editor_plugin()
print("plugin:", info.get_filename(), info.get_plugin())
for path in sys.argv[1:]:
    print("===", path)
    try:
        con = plugin.import_(path)
    except GLib.Error as e:
        print("refused:", e.message)
        continue
    s_vpn = con.get_setting_vpn()
    for k in sorted(s_vpn.get_data_keys() or []):
        print("data:", k, "=", s_vpn.get_data_item(k))
    for k in sorted(s_vpn.get_secret_keys() or []):
        print("secret:", k, "= <%d chars>" % len(s_vpn.get_secret(k) or ""))
    for fam, s in (("ipv4", con.get_setting_ip4_config()), ("ipv6", con.get_setting_ip6_config())):
        if s is None:
            continue
        routes = [f"{r.get_dest()}/{r.get_prefix()} via {r.get_next_hop()} metric {r.get_metric()}" for r in (s.props.routes or [])]
        print(f"{fam}: method={s.get_method()} never-default={s.get_never_default()} routes={routes} dns={list(s.props.dns or [])}")
    c = con.get_setting_connection()
    print("conn: id=%s permissions=%s" % (c.get_id(), [c.get_permission(i) for i in range(c.get_num_permissions())]))
print("DONE")
