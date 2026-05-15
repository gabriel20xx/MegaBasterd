#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

# Ensure X11 socket dir exists with correct perms
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp /tmp/.X11-unix || true

# Remove any stale X lock/socket from a previous (crashed) container run.
# supervisord will start a fresh Xvfb, so these must not be present.
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null || true

# Pre-seed fluxbox config so "Failed to read: session.screen0.*" messages
# never appear, even on a completely fresh volume mount.
if [ ! -f /config/.fluxbox/init ]; then
    mkdir -p /config/.fluxbox
    cat > /config/.fluxbox/init << 'FLUXBOX_INIT'
session.screen0.slit.acceptKdeDockapps:	true
session.screen0.slit.autoHide:	false
session.screen0.slit.maxOver:	false
session.screen0.slit.placement:	RightBottom
session.screen0.slit.alpha:	255
session.screen0.slit.onhead:	0
session.screen0.slit.layer:	4
session.screen0.toolbar.autoHide:	false
session.screen0.toolbar.maxOver:	false
session.screen0.toolbar.visible:	true
session.screen0.toolbar.alpha:	255
session.screen0.toolbar.layer:	4
session.screen0.toolbar.onhead:	0
session.screen0.toolbar.placement:	BottomCenter
session.screen0.toolbar.height:	0
session.screen0.iconbar.mode:	{static groups} (workspace)
session.screen0.iconbar.alignment:	Relative
session.screen0.iconbar.iconWidth:	128
session.screen0.iconbar.iconTextPadding:	10
session.screen0.iconbar.usePixmap:	true
session.screen0.titlebar.left:	Stick
session.screen0.titlebar.right:	Minimize Maximize Close
FLUXBOX_INIT
fi

# Hand off to supervisord which manages Xvfb, fluxbox, x11vnc, websockify,
# and MegaBasterd — restarting any of them automatically if they crash.
# Browse noVNC at: http://localhost:6080/vnc.html
exec supervisord -c /etc/supervisord.conf
