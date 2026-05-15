#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

# Ensure X11 socket dir exists with correct perms
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp /tmp/.X11-unix || true

# Remove any stale X lock/socket from a previous (crashed) container run.
# supervisord will start a fresh Xvfb, so these must not be present.
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null || true


# Hand off to supervisord which manages Xvfb, fluxbox, x11vnc, websockify,
# and MegaBasterd — restarting any of them automatically if they crash.
# Browse noVNC at: http://localhost:6080/vnc.html
exec supervisord -c /etc/supervisord.conf
