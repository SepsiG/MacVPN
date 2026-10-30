#!/usr/bin/python3 -I
"""Spike L0-3: can an unprivileged user read a WireGuard peer's last handshake and rx/tx?

Runs as the desktop user inside the user's systemd manager (`systemd-run --user`), where polkit treats the caller
like the active local session. Safety:
- polkit is asked first, non-interactively (flags 0: never shows a dialog), for every action used; the spike stops
  unless all are authorized;
- every NM D-Bus call is made without the ALLOW_INTERACTIVE_AUTHORIZATION flag;
- one connection: permissions user:<me>, in memory, volatile, bound to this D-Bus client, never-default, a dead
  peer at a TEST-NET-1 endpoint, AllowedIPs 10.99.250.0/24 only, no DNS;
- deactivated and deleted at the end (and NM removes it anyway when this process exits: bind-activation).
"""
import base64, errno, os, pwd, socket, struct, subprocess, sys, time
import gi
gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM

ME = pwd.getpwuid(os.getuid()).pw_name
NM_BUS, NM_PATH = "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)


def call(path, iface, method, args, reply=None):
    return bus.call_sync(NM_BUS, path, iface, method, args, GLib.VariantType(reply) if reply else None,
                         Gio.DBusCallFlags.NONE, 30000, None).unpack()


def props(path, iface):
    return call(path, "org.freedesktop.DBus.Properties", "GetAll", GLib.Variant("(s)", (iface,)), "(a{sv})")[0]


def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    print(f"$ {' '.join(cmd)}\n  rc={p.returncode}\n  stdout={p.stdout.strip()!r}\n  stderr={p.stderr.strip()!r}")


# --- 1. polkit, non-interactive -------------------------------------------------------------------------------------
stat = open("/proc/self/stat").read().rsplit(")", 1)[1].split()
start_time = int(stat[19])
subject = ("unix-process", {"pid": GLib.Variant("u", os.getpid()), "start-time": GLib.Variant("t", start_time),
                            "uid": GLib.Variant("i", os.getuid())})
need = ["org.freedesktop.NetworkManager.settings.modify.own", "org.freedesktop.NetworkManager.network-control",
        "org.freedesktop.NetworkManager.enable-disable-statistics"]
auth = {}
for action in need:
    r = bus.call_sync("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                      "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
                      GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 0, "")),
                      GLib.VariantType("((bba{ss}))"), Gio.DBusCallFlags.NONE, 10000, None).unpack()[0]
    auth[action] = r[0]
    print(f"polkit {action}: authorized={r[0]} challenge={r[1]}")
if not (auth[need[0]] and auth[need[1]]):
    print("ABORT: not authorized without interaction; nothing added")
    sys.exit(2)

# --- 2. one volatile, user-owned WireGuard connection -----------------------------------------------------------------
priv = base64.b64encode(os.urandom(32)).decode()
peer_pub = base64.b64encode(os.urandom(32)).decode()
con = NM.SimpleConnection.new()
s_con = NM.SettingConnection.new()
s_con.set_property("id", "linvpn-l0a-wg-spike")
s_con.set_property("uuid", NM.utils_uuid_generate())
s_con.set_property("type", "wireguard")
s_con.set_property("interface-name", "l0awg0")
s_con.set_property("autoconnect", False)
s_con.add_permission("user", ME, None)
con.add_setting(s_con)
s_wg = NM.SettingWireGuard.new()
s_wg.set_property("private-key", priv)
s_wg.set_property("private-key-flags", NM.SettingSecretFlags.NONE)
s_wg.set_property("peer-routes", True)
peer = NM.WireGuardPeer.new()
peer.set_public_key(peer_pub, True)
peer.set_endpoint("192.0.2.1:51820", True)
peer.append_allowed_ip("10.99.250.0/24", True)
peer.set_persistent_keepalive(5)
peer.seal()
s_wg.append_peer(peer)
con.add_setting(s_wg)
s_ip4 = NM.SettingIP4Config.new()
s_ip4.set_property("method", "manual")
s_ip4.add_address(NM.IPAddress.new(socket.AF_INET, "10.99.250.2", 32))
s_ip4.set_property("never-default", True)
s_ip4.set_property("ignore-auto-dns", True)
con.add_setting(s_ip4)
s_ip6 = NM.SettingIP6Config.new()
s_ip6.set_property("method", "disabled")
con.add_setting(s_ip6)
con.verify()

settings = con.to_dbus(NM.ConnectionSerializationFlags.ALL)
opts = {"persist": GLib.Variant("s", "volatile"), "bind-activation": GLib.Variant("s", "dbus-client")}
conn_path, ac_path, result = call(NM_PATH, "org.freedesktop.NetworkManager", "AddAndActivateConnection2",
                                  GLib.Variant.new_tuple(settings, GLib.Variant("o", "/"), GLib.Variant("o", "/"),
                                                         GLib.Variant("a{sv}", opts)),
                                  "(ooa{sv})")
print("added+activating:", conn_path, ac_path, result)
s = props(conn_path, "org.freedesktop.NetworkManager.Settings.Connection")
print("settings flags (1=unsaved 2=nm-generated 4=volatile 8=external):", s.get("Flags"), "unsaved:", s.get("Unsaved"))

try:
    dev = None
    for _ in range(30):
        a = props(ac_path, "org.freedesktop.NetworkManager.Connection.Active")
        if a.get("Devices"):
            dev = a["Devices"][0]
        if a.get("State") == 2:
            break
        time.sleep(0.5)
    print("active state:", a.get("State"), "(2=activated) device:", dev)
    d = props(dev, "org.freedesktop.NetworkManager.Device")
    ifname = d["Interface"]
    print("interface:", ifname, "ip4config:", d.get("Ip4Config"))

    # Traffic into the tunnel: the peer is dead, so the kernel keeps sending handshake initiations.
    sh(["ping", "-c", "5", "-i", "1", "-W", "1", "10.99.250.1"])
    time.sleep(6)

    # --- 3. what an unprivileged user can read --------------------------------------------------------------------
    print("\n[A] NM D-Bus org.freedesktop.NetworkManager.Device.WireGuard:")
    xml = call(dev, "org.freedesktop.DBus.Introspectable", "Introspect", None, "(s)")[0]
    wg_props = props(dev, "org.freedesktop.NetworkManager.Device.WireGuard")
    print("  properties:", {k: (v if k != "PublicKey" else f"<{len(v)} bytes>") for k, v in wg_props.items()})
    iface_xml = xml[xml.find('org.freedesktop.NetworkManager.Device.WireGuard'):]
    iface_xml = iface_xml[:iface_xml.find("</interface>")]
    print("  introspection:", " ".join(l.strip() for l in iface_xml.splitlines()))

    print("\n[B] NM D-Bus org.freedesktop.NetworkManager.Device.Statistics:")
    st = props(dev, "org.freedesktop.NetworkManager.Device.Statistics")
    print("  before:", st)
    if auth[need[2]]:
        try:
            call(dev, "org.freedesktop.DBus.Properties", "Set",
                 GLib.Variant("(ssv)", ("org.freedesktop.NetworkManager.Device.Statistics", "RefreshRateMs",
                                        GLib.Variant("u", 1000))))
            time.sleep(2.5)
            print("  RefreshRateMs=1000 set; after:", props(dev, "org.freedesktop.NetworkManager.Device.Statistics"))
        except GLib.Error as e:
            print("  set RefreshRateMs failed:", e.message)
    else:
        print("  enable-disable-statistics not authorized without interaction: RefreshRateMs not set")

    print("\n[C] sysfs /sys/class/net/%s/statistics:" % ifname)
    for f in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "tx_errors", "tx_dropped"):
        print(f"  {f} =", open(f"/sys/class/net/{ifname}/statistics/{f}").read().strip())
    sh(["ip", "-s", "-j", "link", "show", ifname])

    print("\n[D] wg (wireguard-tools) as the user:")
    sh(["wg", "show", ifname])
    sh(["wg", "show", ifname, "latest-handshakes"])
    sh(["wg", "show", ifname, "transfer"])

    print("\n[E] generic netlink WG_CMD_GET_DEVICE as the user:")
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)  # NETLINK_GENERIC

    def nla(t, data):
        ln = 4 + len(data)
        return struct.pack("HH", ln, t) + data + b"\0" * ((4 - ln % 4) % 4)

    def genl(fam, cmd, flags, attrs, seq):
        body = struct.pack("BBH", cmd, 1, 0) + attrs
        return struct.pack("IHHII", 16 + len(body), fam, flags, seq, 0) + body

    nl.send(genl(0x10, 3, 0x1 | 0x4, nla(2, b"wireguard\0"), 1))  # GENL_ID_CTRL, CTRL_CMD_GETFAMILY
    msg = nl.recv(65536)
    ln, typ = struct.unpack("IH", msg[:6])
    off, fam_id = 20, None
    while off < ln:
        alen, atyp = struct.unpack("HH", msg[off:off + 4])
        if atyp == 1:  # CTRL_ATTR_FAMILY_ID
            fam_id = struct.unpack("H", msg[off + 4:off + 6])[0]
        off += (alen + 3) & ~3
    print("  wireguard genl family id:", fam_id)
    nl.send(genl(fam_id, 0, 0x1 | 0x4 | 0x300, nla(2, ifname.encode() + b"\0"), 2))  # WG_CMD_GET_DEVICE, dump
    msg = nl.recv(65536)
    ln, typ = struct.unpack("IH", msg[:6])
    if typ == 2:  # NLMSG_ERROR
        err = struct.unpack("i", msg[16:20])[0]
        print(f"  reply: NLMSG_ERROR {err} ({errno.errorcode.get(-err, '?')}: {os.strerror(-err) if err else 'ok'})")
    else:
        print(f"  reply: type {typ}, {ln} bytes (device data returned)")
finally:
    print("\n[cleanup]")
    try:
        call(NM_PATH, "org.freedesktop.NetworkManager", "DeactivateConnection", GLib.Variant("(o)", (ac_path,)))
        print("  deactivated")
    except GLib.Error as e:
        print("  deactivate:", e.message)
    time.sleep(2)
    try:
        call(conn_path, "org.freedesktop.NetworkManager.Settings.Connection", "Delete", None)
        print("  deleted explicitly")
    except GLib.Error as e:
        print("  delete:", e.message, "(volatile: NM already removed it)")
    left = call(NM_PATH + "/Settings", "org.freedesktop.NetworkManager.Settings", "ListConnections", None, "(ao)")[0]
    print("  connection still listed:", conn_path in left)
    print("  interface still present:", os.path.exists("/sys/class/net/l0awg0"))
print("DONE")
