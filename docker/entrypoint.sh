#!/usr/bin/env bash
set -euo pipefail

mkdir -p /config /downloads /wireguard

# Ensure X11 socket dir exists with correct perms
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp /tmp/.X11-unix || true

# Remove any stale X lock/socket from a previous (crashed) container run.
# supervisord will start a fresh Xvfb, so these must not be present.
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null || true

# Write a complete fluxbox init on every start so no "Failed to read"
# messages appear regardless of what the volume already contains.
# (Fluxbox is infrastructure here; its runtime state is not precious.)
mkdir -p /config/.fluxbox
cat > /config/.fluxbox/init << 'FLUXBOX_INIT'
session.screen0.focusModel:	ClickToFocus
session.screen0.tabFocusModel:	ClickToFocus
session.screen0.focusNewWindows:	true
session.screen0.focusSameHead:	false
session.screen0.windowPlacement:	RowSmartPlacement
session.screen0.rowPlacementDirection:	LeftToRight
session.screen0.colPlacementDirection:	TopToBottom
session.screen0.allowRemoteActions:	false
session.screen0.menu.alpha:	255
session.screen0.menuDelay:	200
session.screen0.tooltipDelay:	500
session.screen0.clientMenu.usePixmap:	true
session.screen0.tabs.usePixmap:	true
session.screen0.tabs.maxOver:	false
session.screen0.tabs.intitlebar:	true
session.screen0.tab.width:	64
session.screen0.titlebar.left:	Stick
session.screen0.titlebar.right:	Minimize Maximize Close
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
session.numWorkspaces:	4
session.doubleClickInterval:	250
session.tabPadding:	0
session.tabWidth:	64
session.tabs.usePixmap:	true
session.imageDither:	true
session.colorLimit:	4
session.forcePseudoTransparency:	false
session.ignoreBorder:	false
session.modKey:	Mod1
session.opaqueMove:	false
session.workspacewarping:	true
FLUXBOX_INIT

# Hand off to supervisord which manages Xvfb, fluxbox, x11vnc, websockify,
# and MegaBasterd — restarting any of them automatically if they crash.
# Browse noVNC at: http://localhost:6080/vnc.html
exec supervisord -c /etc/supervisord.conf
