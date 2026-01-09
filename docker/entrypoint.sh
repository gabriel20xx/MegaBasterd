#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

: "${DISPLAY:=:0}"
export DISPLAY

# Ensure X11 socket dir exists with correct perms
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp /tmp/.X11-unix || true

# Make sure the default download directory (".") is persisted.
# MegaBasterd uses "." as default when no default_down_dir is set.
cd /downloads

# Virtual display
Xvfb "${DISPLAY}" -screen 0 1280x720x24 -nolisten tcp -ac -noreset >/tmp/xvfb.log 2>&1 &

# Wait for X to be ready (avoid x11vnc/Java racing Xvfb startup)
for _ in $(seq 1 50); do
  if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
  echo "ERROR: X display ${DISPLAY} did not become ready" >&2
  tail -n 200 /tmp/xvfb.log >&2 || true
  exit 1
fi

# Lightweight window manager (helps Swing behave normally)
fluxbox >/tmp/fluxbox.log 2>&1 &

# VNC server
x11vnc -display "${DISPLAY}" -forever -shared -rfbport 5900 -nopw -quiet &

# noVNC (WebSockets -> VNC)
# Browse: http://localhost:6080/vnc.html
websockify --web=/usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# Launch MegaBasterd
exec java \
  -Duser.home=/config \
  -Djava.awt.headless=false \
  -jar /app/megabasterd.jar
