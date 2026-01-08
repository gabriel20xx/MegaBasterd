#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

# Make sure the default download directory (".") is persisted.
# MegaBasterd uses "." as default when no default_down_dir is set.
cd /downloads

# Virtual display
Xvfb :0 -screen 0 1280x720x24 -nolisten tcp &

# Lightweight window manager (helps Swing behave normally)
fluxbox >/tmp/fluxbox.log 2>&1 &

# VNC server
x11vnc -display :0 -forever -shared -rfbport 5900 -nopw -quiet &

# noVNC (WebSockets -> VNC)
# Browse: http://localhost:6080/vnc.html
websockify --web=/usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# Launch MegaBasterd
exec java \
  -Duser.home=/config \
  -Djava.awt.headless=false \
  -jar /app/megabasterd.jar
