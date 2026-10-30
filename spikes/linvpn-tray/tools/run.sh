#!/bin/sh
# Start the spike in linvpn-dev's desktop session (from SSH). Usage: run.sh NAME [VAR=value...]
# Log: ~/spike/logs/NAME.log. Stop with: pkill -x linvpn-tray-spi
name=$1; shift
mkdir -p ~/spike/logs
export XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
       WAYLAND_DISPLAY=wayland-0 DISPLAY=:0
# Xwayland's cookie (the session's own apps inherit XAUTHORITY; an SSH shell does not).
export XAUTHORITY="$(ls /run/user/1001/.mutter-Xwaylandauth.* 2>/dev/null | head -1)"
pkill -x linvpn-tray-spi; sleep 0.5
env "$@" nohup ~/spike/linvpn-tray/tauri-panel/target/debug/linvpn-tray-spike > ~/spike/logs/$name.log 2>&1 &
sleep 3
cat ~/spike/logs/$name.log
