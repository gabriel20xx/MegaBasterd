#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

: "${DISPLAY:=:0}"
export DISPLAY

DISPLAY_NUM="${DISPLAY#:}"
X_LOCK_FILE="/tmp/.X${DISPLAY_NUM}-lock"
X_SOCKET_FILE="/tmp/.X11-unix/X${DISPLAY_NUM}"

# Ensure X11 socket dir exists with correct perms
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp /tmp/.X11-unix || true

# Make sure the default download directory (".") is persisted.
# MegaBasterd uses "." as default when no default_down_dir is set.
cd /downloads

# If the display is already up, reuse it. This prevents flapping on container restarts
# and avoids failing on a stale /tmp/.X*-lock.
if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
  echo "INFO: X display ${DISPLAY} already ready; reusing" >&2
else
  # Clean up stale lock/socket files if no X server is actually running.
  if [ -f "${X_LOCK_FILE}" ]; then
    X_LOCK_PID="$(cat "${X_LOCK_FILE}" 2>/dev/null || true)"
    if [ -n "${X_LOCK_PID}" ] && echo "${X_LOCK_PID}" | grep -Eq '^[0-9]+$' && ps -p "${X_LOCK_PID}" >/dev/null 2>&1; then
      echo "INFO: Found existing X lock ${X_LOCK_FILE} (PID ${X_LOCK_PID}); waiting for ${DISPLAY}" >&2
    else
      echo "WARN: Removing stale X lock/socket for ${DISPLAY}" >&2
      rm -f "${X_LOCK_FILE}" || true
      rm -f "${X_SOCKET_FILE}" || true
    fi
  fi

  # Virtual display
  Xvfb "${DISPLAY}" -screen 0 1280x720x24 -nolisten tcp -ac -noreset >/tmp/xvfb.log 2>&1 &
fi

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
x11vnc -display "${DISPLAY}" -forever -shared -rfbport 5900 -nopw -quiet -nodpms &

# noVNC (WebSockets -> VNC)
# Browse: http://localhost:6080/vnc.html
websockify --web=/usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# Launch MegaBasterd
exec java \
  -Duser.home=/config \
  -Djava.awt.headless=false \
  -jar /app/megabasterd.jar
