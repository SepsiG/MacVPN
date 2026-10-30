#!/usr/bin/env python3
"""Drive the GNOME Wayland session for the tray spike: pointer input and screenshots.

Uses Mutter's own org.gnome.Mutter.RemoteDesktop + ScreenCast D-Bus APIs (reachable from the
session bus of the logged-in user, no portal dialog), and GStreamer's pipewiresrc for frames.

Usage: drive.py ACTION...   with ACTION one of
  shot:FILE.png        grab one frame of the monitor
  move:X,Y             absolute pointer move (logical px)
  click:BTN            press+release; BTN = left|right|middle
  dbl:BTN              two clicks 80 ms apart
  key:KEYSYM           press+release a keysym (hex or int), e.g. key:0xff1b for Escape
  sleep:SECONDS
"""
import subprocess, sys, time
import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

BTN = {"left": 0x110, "right": 0x111, "middle": 0x112}
DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
loop = GLib.MainLoop()
RD, SC = "org.gnome.Mutter.RemoteDesktop", "org.gnome.Mutter.ScreenCast"

rd = bus.get_object(RD, "/org/gnome/Mutter/RemoteDesktop")
rd_path = rd.CreateSession(dbus_interface=RD)
rd_sess = bus.get_object(RD, rd_path)
sid = rd_sess.Get(RD + ".Session", "SessionId", dbus_interface="org.freedesktop.DBus.Properties")
sc = bus.get_object(SC, "/org/gnome/Mutter/ScreenCast")
sc_path = sc.CreateSession({"remote-desktop-session-id": sid}, dbus_interface=SC)
sc_sess = bus.get_object(SC, sc_path)
monitor = sys.argv[1] if sys.argv[1].startswith("Virtual") else "Virtual-1"
stream_path = sc_sess.RecordMonitor(monitor, {"cursor-mode": dbus.UInt32(1)}, dbus_interface=SC + ".Session")
node = {}

def added(node_id):
    node["id"] = int(node_id)
    loop.quit()

bus.add_signal_receiver(added, "PipeWireStreamAdded", SC + ".Stream", path=stream_path)
rd_sess.Start(dbus_interface=RD + ".Session")
GLib.timeout_add_seconds(10, loop.quit)
loop.run()
s = dbus.Interface(rd_sess, RD + ".Session")

def pump(t=0.05):
    end = time.time() + t
    ctx = loop.get_context()
    while time.time() < end:
        ctx.iteration(False)
        time.sleep(0.005)

def button(b):
    s.NotifyPointerButton(dbus.Int32(BTN[b]), True); pump(0.03)
    s.NotifyPointerButton(dbus.Int32(BTN[b]), False); pump(0.03)

try:
    for act in [a for a in sys.argv[1:] if not a.startswith("Virtual")]:
        verb, _, arg = act.partition(":")
        if verb == "shot":
            subprocess.run(["gst-launch-1.0", "-q", "pipewiresrc", f"path={node['id']}", "num-buffers=1",
                            "!", "videoconvert", "!", "pngenc", "!", "filesink", f"location={arg}"],
                           check=True, timeout=20)
            print("shot", arg)
        elif verb == "move":
            x, y = (float(v) for v in arg.split(","))
            s.NotifyPointerMotionAbsolute(stream_path, x, y); pump(0.1)
        elif verb == "click":
            button(arg)
        elif verb == "dbl":
            button(arg); pump(0.08); button(arg)
        elif verb == "key":
            k = dbus.UInt32(int(arg, 0))
            s.NotifyKeyboardKeysym(k, True); pump(0.03); s.NotifyKeyboardKeysym(k, False)
        elif verb == "sleep":
            pump(float(arg))
        print(act, flush=True)
        pump(0.1)
finally:
    s.Stop()
