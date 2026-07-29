/*
 __  __                  _               _               _ 
|  \/  | ___  __ _  __ _| |__   __ _ ___| |_ ___ _ __ __| |
| |\/| |/ _ \/ _` |/ _` | '_ \ / _` / __| __/ _ \ '__/ _` |
| |  | |  __/ (_| | (_| | |_) | (_| \__ \ ||  __/ | | (_| |
|_|  |_|\___|\__, |\__,_|_.__/ \__,_|___/\__\___|_|  \__,_|
             |___/                                         
© Perpetrated by tonikelope since 2016
 */
package com.tonikelope.megabasterd;

import static com.tonikelope.megabasterd.MainPanel.THREAD_POOL;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 *
 * @author tonikelope
 */
public final class SmartMegaProxyManager {

    public static final int PROXY_BLOCK_TIME = 300;
    public static final int PROXY_AUTO_REFRESH_TIME = 60;
    public static final int PROXY_AUTO_REFRESH_SLEEP_TIME = 30;
    public static final boolean RESET_SLOT_PROXY = true;
    public static final boolean RANDOM_SELECT = true;
    /**
     * Default for the post-509 window during which SmartProxy stays active for
     * the affected download even after a successful chunk. Was the hard-coded
     * {@code ChunkDownloader.SMART_PROXY_RECHECK_509_TIME = 3600}; now
     * overridable via DB setting "smart_proxy_509_recheck_window" so a user
     * whose VPN clears quota in seconds isn't forced into a 1-hour proxy-mode
     * window. (#751 / C4)
     */
    public static final int RECHECK_509_WINDOW_DEFAULT = 3600;

    private static final Logger LOG = Logger.getLogger(SmartMegaProxyManager.class.getName());
    private final ConcurrentHashMap<String, Long[]> _proxy_list;
    // ConcurrentHashMap (not HashMap): the Authenticator.getPasswordAuthentication
    // callback at SmartProxyAuthenticator.getPasswordAuthentication() runs on
    // arbitrary JDK HTTP/SOCKS connection threads, with no shared monitor with
    // refreshProxyList() which clears+repopulates this map. Plain HashMap under
    // concurrent structural mutation (clear+put) can NPE on resize and stall
    // the connection thread.
    private static final ConcurrentHashMap<String, String> PROXY_LIST_AUTH = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Ikev2Credentials> IKEV2_AUTH = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, WireguardConfig> WIREGUARD_CONFIGS = new ConcurrentHashMap<>();
    private final MainPanel _main_panel;
    private volatile int _ban_time;
    private volatile int _proxy_timeout;
    private volatile boolean _force_smart_proxy;
    private volatile int _autorefresh_time;
    private volatile long _last_refresh_timestamp;
    private volatile boolean _random_select;
    private volatile boolean _reset_slot_proxy;
    private volatile int _recheck_509_window;

    private final Object _ikev2_lock = new Object();
    private volatile String _active_ikev2_key;
    private volatile String _active_ikev2_conn;

    private volatile String _active_wireguard_key;
    private volatile String _active_wireguard_conf;

    public boolean isRandom_select() {
        return _random_select;
    }

    public boolean isReset_slot_proxy() {
        return _reset_slot_proxy;
    }

    /**
     * Window (seconds) after a 509 during which SmartProxy stays "armed" for
     * affected downloads, even after individual chunks succeed. Configurable
     * via DB setting "smart_proxy_509_recheck_window". Defaults to
     * {@link #RECHECK_509_WINDOW_DEFAULT} (3600 s). (#751 / C4)
     */
    public int getRecheck_509_window() {
        return _recheck_509_window;
    }

    public int getProxy_timeout() {
        return _proxy_timeout;
    }

    public boolean isForce_smart_proxy() {
        return _force_smart_proxy;
    }

    public SmartMegaProxyManager(MainPanel main_panel) {
        // Proxy list URLs are now discovered by scanning the "custom_proxy_list"
        // textarea for '#URL' lines on every refresh, so the manager no longer
        // needs an explicit URL parameter and can aggregate from multiple
        // sources simultaneously. (#753)
        _proxy_list = new ConcurrentHashMap<>();
        _main_panel = main_panel;

        // Install the JDK-wide proxy Authenticator HERE (was only done once at
        // startup in MainPanel.run(), inside the `if (_use_smart_proxy)` block).
        // When the user started with SmartProxy DISABLED and enabled it at
        // runtime, MainPanelView.settings_menuActionPerformed built this
        // manager but NEVER installed the Authenticator, so any proxy that
        // requires credentials (the IP:PORT@b64user:b64pass form parsed into
        // PROXY_LIST_AUTH and consumed by SmartProxyAuthenticator) silently
        // got a 407 Proxy Authentication Required on every chunk / /cs request
        // -- the whole pool looked dead and downloads never resumed, while a
        // restart with SmartProxy pre-enabled worked. Doing it in the
        // constructor makes both paths (startup and runtime-enable) identical.
        // setDefault is a global, idempotent, thread-agnostic operation. (#778)
        Authenticator.setDefault(new SmartProxyAuthenticator());

        // ChunkDownloader.java:200 silently disables SmartProxy when a static
        // HTTP proxy is also configured (`&& !MainPanel.isUse_proxy()`). The
        // user often doesn't realise this and assumes SmartProxy is still
        // protecting them from 509. Surface it loudly at startup. (#751)
        if (MainPanel.isUse_proxy()) {
            LOG.log(Level.WARNING, "[SmartProxy] Static HTTP proxy is ALSO enabled in settings; "
                    + "SmartProxy will be IGNORED by ChunkDownloader (static proxy takes priority). "
                    + "Disable the static HTTP proxy if you want SmartProxy to handle 509.");
        }

        refreshSmartProxySettings();

        THREAD_POOL.execute(() -> {
            refreshProxyList();

            // Honour MainPanel.isExit() so the auto-refresh thread terminates
            // cleanly on shutdown instead of spinning until JVM kills the
            // daemon. Also restore the interrupt flag on InterruptedException.
            while (!_main_panel.isExit()) {

                while (!_main_panel.isExit() && System.currentTimeMillis() < _last_refresh_timestamp + _autorefresh_time * 60L * 1000L) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }

                if (!_main_panel.isExit() && MainPanel.isUse_smart_proxy()) {

                    refreshProxyList();
                }
            }
        });
    }

    private static int clampWithWarn(String key, int value, int min, int max) {
        if (value < min) {
            LOG.log(Level.WARNING, "[SmartProxy] setting {0}={1} is below the supported minimum {2}; clamping. Values that low make the recovery path effectively unusable.",
                    new Object[]{key, value, min});
            return min;
        }
        if (value > max) {
            LOG.log(Level.WARNING, "[SmartProxy] setting {0}={1} is above the supported maximum {2}; clamping.",
                    new Object[]{key, value, max});
            return max;
        }
        return value;
    }

    private synchronized int countBlockedProxies() {

        int i = 0;

        Long current_time = System.currentTimeMillis();

        for (String k : _proxy_list.keySet()) {

            if (_proxy_list.get(k)[0] != -1 && _proxy_list.get(k)[0] > current_time - _ban_time * 1000L) {

                i++;
            }
        }

        return i;

    }

    // NOT synchronized (was, until #778): this only reads DB settings and
    // writes the manager's own `volatile` config fields (_ban_time,
    // _proxy_timeout, _force_smart_proxy, ...). It never touches _proxy_list,
    // so it has no reason to contend on the pool monitor. It is called on the
    // Swing EDT from MainPanelView.settings_menuActionPerformed; sharing the
    // monitor with getProxy()/refreshProxyList() meant a worker mid-refresh
    // (blocking HTTP fetch) or mid-getProxy could freeze the UI. The fields
    // are independent settings with no cross-field invariant, so volatile
    // visibility is sufficient. (#778)
    public void refreshSmartProxySettings() {
        String smartproxy_ban_time = DBTools.selectSettingValue("smartproxy_ban_time");

        // ban_time semantics:
        //   0       = permanent ban (blockProxy removes the entry from the pool)
        //   1..9    = allowed but risky: the banned proxy can be re-selected
        //             before the worker that banned it finishes retrying
        //             somewhere else, so a bad-pool can churn. We honour the
        //             user's value but log a WARNING.
        //   10..3600 = normal range
        //   >3600   = clamp to 3600 (anything longer is effectively permanent
        //             without using the 0 sentinel; clamping protects against
        //             accidental enormous values).
        // The previous code (audit #752) clamped <10 to 10, which silently
        // ignored both "0 = permanent" (documented in the SettingsDialog UI)
        // and short ban times intentionally chosen by users running curated
        // private proxy pools. (#757)
        int requested_ban = MiscTools.parseIntOr(smartproxy_ban_time, PROXY_BLOCK_TIME);
        if (requested_ban < 0) {
            LOG.log(Level.WARNING, "[SmartProxy] setting smartproxy_ban_time={0} is negative; treating as 0 (permanent ban).", requested_ban);
            requested_ban = 0;
        } else if (requested_ban > 0 && requested_ban < 10) {
            LOG.log(Level.WARNING, "[SmartProxy] setting smartproxy_ban_time={0}s is below the recommended minimum of 10s. A banned proxy may be re-selected before the worker that banned it has retried elsewhere, causing pool churn. Honouring your value, but expect noisier logs.", requested_ban);
        } else if (requested_ban > 3600) {
            LOG.log(Level.WARNING, "[SmartProxy] setting smartproxy_ban_time={0} exceeds the maximum 3600s; clamping. If you want a permanent ban, set the value to 0.", requested_ban);
            requested_ban = 3600;
        }
        _ban_time = requested_ban;

        String smartproxy_timeout = DBTools.selectSettingValue("smartproxy_timeout");

        // Clamp proxy_timeout to [3, 120] s. Below 3 s most real-world
        // public proxies cannot complete a TCP+TLS handshake, so every
        // attempt times out and the worker burns through the list without
        // ever connecting. Stored and reported in seconds; converted to
        // ms below for the JDK URLConnection setters. (#752)
        int requested_timeout = MiscTools.parseIntOr(smartproxy_timeout, Transference.HTTP_PROXY_TIMEOUT / 1000);
        _proxy_timeout = clampWithWarn("smartproxy_timeout", requested_timeout, 3, 120) * 1000;

        String force_smart_proxy_string = DBTools.selectSettingValue("force_smart_proxy");

        if (force_smart_proxy_string != null) {

            _force_smart_proxy = force_smart_proxy_string.equals("yes");
        } else {
            _force_smart_proxy = MainPanel.FORCE_SMART_PROXY;
        }

        String autorefresh_smart_proxy_string = DBTools.selectSettingValue("smartproxy_autorefresh_time");

        _autorefresh_time = MiscTools.parseIntOr(autorefresh_smart_proxy_string, PROXY_AUTO_REFRESH_TIME);

        String reset_slot_proxy = DBTools.selectSettingValue("reset_slot_proxy");

        if (reset_slot_proxy != null) {

            _reset_slot_proxy = reset_slot_proxy.equals("yes");
        } else {
            _reset_slot_proxy = RESET_SLOT_PROXY;
        }

        String random_select = DBTools.selectSettingValue("random_proxy");

        if (random_select != null) {

            _random_select = random_select.equals("yes");
        } else {
            _random_select = RANDOM_SELECT;
        }

        String recheck_setting = DBTools.selectSettingValue("smart_proxy_509_recheck_window");

        int recheck = MiscTools.parseIntOr(recheck_setting, RECHECK_509_WINDOW_DEFAULT);
        // Clamp to a sane range: anything below 60 s is pointless (a refresh
        // would arrive sooner than that), anything above 24 h is just
        // "permanent" which is what FORCE proxy mode already expresses.
        if (recheck < 60) {
            recheck = 60;
        } else if (recheck > 86_400) {
            recheck = 86_400;
        }
        _recheck_509_window = recheck;

        LOG.log(Level.INFO, "SmartProxy BAN_TIME: " + String.valueOf(_ban_time) + "   TIMEOUT: " + String.valueOf(_proxy_timeout / 1000) + "   REFRESH: " + String.valueOf(_autorefresh_time) + "   FORCE: " + String.valueOf(_force_smart_proxy) + "   RANDOM: " + String.valueOf(_random_select) + "   RESET-SLOT-PROXY: " + String.valueOf(_reset_slot_proxy) + "   RECHECK-509: " + String.valueOf(_recheck_509_window));

        // Surface activation mode so users who set up "live" proxies and then
        // see direct downloads understand why: without FORCE, SmartProxy only
        // engages after MEGA returns HTTP 509 (or while inside the post-509
        // recheck window). Reported by #757 bug 3.
        if (_force_smart_proxy) {
            LOG.log(Level.INFO, "[SmartProxy] mode: FORCE -- every chunk will be routed through a proxy regardless of MEGA quota state.");
        } else {
            LOG.log(Level.INFO, "[SmartProxy] mode: PASSIVE -- proxies are only used after MEGA returns HTTP 509 (or while inside the {0}s post-509 recheck window). Enable FORCE SMART PROXY in settings if you want every chunk routed through proxies.", _recheck_509_window);
        }
    }

    public synchronized int getProxyCount() {

        return _proxy_list.size();
    }

    /**
     * Returns a snapshot of every proxy in the pool, regardless of ban
     * state, as {@code {address, "http"|"socks"}} pairs in pool order.
     * Used by the test dialog to enumerate the pool exhaustively --
     * {@link #getProxy(ArrayList)} cannot be used for that because it
     * filters banned entries and ban-recovers via timeout, so a test
     * could never observe a currently-banned proxy. (#753 audit)
     */
    public synchronized java.util.List<String[]> getProxySnapshot() {
        java.util.List<String[]> snapshot = new ArrayList<>(_proxy_list.size());
        for (Map.Entry<String, Long[]> e : _proxy_list.entrySet()) {
            Long[] meta = e.getValue();
            boolean socks = meta != null && meta[1] != null && meta[1].longValue() != -1L;
            snapshot.add(new String[]{e.getKey(), socks ? "socks" : "http"});
        }
        return snapshot;
    }

    /**
     * Selects one usable (non-banned, non-excluded) proxy from the current
     * pool, or returns {@code null} if none is available right now. Does NOT
     * sleep or refresh -- it is a pure, fast snapshot pick. Synchronized only
     * to stay mutually exclusive with {@link #blockProxy}/{@link
     * #refreshProxyList} during the iteration; it never holds the monitor for
     * more than the (sub-millisecond) selection. (#778)
     */
    private synchronized String[] pickProxy(ArrayList<String> excluded) {

        if (_proxy_list.size() > 0) {

            Set<String> keys = _proxy_list.keySet();

            List<String> keysList = new ArrayList<>(keys);

            // IKEv2 / WireGuard are container-wide tunnels. If we already have one active and it is still usable,
            // prefer sticking to it to avoid connect/disconnect thrashing across workers.
            Long current_time_pre = System.currentTimeMillis();
            if (_active_wireguard_key != null) {
                Long[] activeData = _proxy_list.get(_active_wireguard_key);
                if (activeData != null
                        && activeData.length >= 2
                        && activeData[1] != null
                        && activeData[1] == 3L
                        && (activeData[0] == -1L || activeData[0] < current_time_pre - _ban_time * 1000)
                        && (excluded == null || !excluded.contains(_active_wireguard_key))) {
                    return new String[]{_active_wireguard_key, protoFromFlag(activeData[1])};
                }
            }
            if (_active_ikev2_key != null) {
                Long[] activeData = _proxy_list.get(_active_ikev2_key);
                if (activeData != null
                        && activeData.length >= 2
                        && activeData[1] != null
                        && activeData[1] == 2L
                        && (activeData[0] == -1L || activeData[0] < current_time_pre - _ban_time * 1000)
                        && (excluded == null || !excluded.contains(_active_ikev2_key))) {
                    return new String[]{_active_ikev2_key, protoFromFlag(activeData[1])};
                }
            }

            if (isRandom_select()) {
                Collections.shuffle(keysList);
            }

            Long current_time = System.currentTimeMillis();

            for (String k : keysList) {

                Long[] entry = _proxy_list.get(k);

                if (entry == null) {
                    continue;
                }

                if ((entry[0] == -1 || entry[0] < current_time - _ban_time * 1000L) && (excluded == null || !excluded.contains(k))) {

                    return new String[]{k, protoFromFlag(entry[1])};
                }
            }
        }

        return null;
    }

    public String[] getProxy(ArrayList<String> excluded) {

        // Iterative refresh loop with a cap. Was recursive: every call that
        // found all proxies excluded slept 30s then recursed -- with an
        // ever-growing excluded list (workers keep adding failed proxies),
        // a permanently-bad list could deepen the stack indefinitely and
        // eventually StackOverflowError. 5 attempts == ~2.5 min, plenty for
        // a refresh to pull a usable proxy.
        //
        // NOT synchronized (was, until #778): the selection is delegated to
        // the synchronized pickProxy() helper, but the Thread.sleep() and
        // refreshProxyList() below run WITHOUT holding the manager monitor.
        // The old code held `this` across the whole 30s*5 sleep + blocking
        // HTTP refresh, so with FORCE mode + N slots hitting an exhausted pool
        // every worker serialized behind the lock for minutes, and the on-EDT
        // refreshSmartProxySettings() call froze the UI. (#778)
        final int MAX_REFRESH_ATTEMPTS = 5;

        for (int attempt = 0; attempt < MAX_REFRESH_ATTEMPTS; attempt++) {

            String[] picked = pickProxy(excluded);

            if (picked != null) {
                return picked;
            }

            LOG.log(Level.WARNING, "{0} Smart Proxy Manager: NO PROXYS AVAILABLE!! (Refreshing in {1} secs, attempt {2}/{3})",
                    new Object[]{Thread.currentThread().getName(), PROXY_AUTO_REFRESH_SLEEP_TIME, attempt + 1, MAX_REFRESH_ATTEMPTS});

            try {
                Thread.sleep(PROXY_AUTO_REFRESH_SLEEP_TIME * 1000L);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return null;
            }

            refreshProxyList();
        }

        return null;
    }

    /**
     * Rewrites the {@code custom_proxy_list} DB setting so that the only
     * inline proxy entries are those whose addresses appear in
     * {@code working_addrs}. Lines starting with {@code #} (remote URL
     * sources) and blank separator lines are preserved verbatim, so a
     * user who relies on auto-refreshed lists can prune dead entries
     * without losing the URL sources that feed them. The SOCKS marker
     * and any auth trailer are looked up from live state so each saved
     * line round-trips through {@link #parseProxyEntry} unchanged. After
     * writing, kicks an async refresh so the live pool matches the new
     * textarea immediately. (#753)
     *
     * @param working_addrs addresses (IP:PORT) to keep, in the desired
     *                      output order
     * @return number of inline entries written
     * @throws SQLException if the DB write fails
     */
    public synchronized int saveWorkingProxiesToCustomList(java.util.Collection<String> working_addrs) throws SQLException {

        String current = DBTools.selectSettingValue("custom_proxy_list");
        StringBuilder sb = new StringBuilder();
        if (current != null) {
            for (String line : current.split("\\r?\\n")) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    sb.append(line).append('\n');
                }
            }
        }

        int written = 0;
        for (String addr : working_addrs) {
            Long[] entry = _proxy_list.get(addr);
            // Entry shape: {ban_ts, type} where type == -1L for HTTP and
            // 1L for SOCKS. An entry missing from the live map is still
            // saved (as HTTP, no auth) -- it was working a moment ago,
            // and over-writing is safer than dropping it silently.
            boolean socks = entry != null && entry[1] != null && entry[1] != -1L;
            String auth = PROXY_LIST_AUTH.get(addr);
            if (socks) {
                sb.append('*');
            }
            sb.append(addr);
            if (auth != null) {
                sb.append('@').append(auth);
            }
            sb.append('\n');
            written++;
        }

        DBTools.insertSettingValue("custom_proxy_list", sb.toString());

        // Refresh asynchronously so the caller (Swing EDT in practice)
        // returns immediately.
        MainPanel.THREAD_POOL.execute(this::refreshProxyList);

        return written;
    }

    private static String protoFromFlag(Long protoFlag) {
        if (protoFlag == null) {
            return "http";
        }
        if (protoFlag == 1L) {
            return "socks";
        }
        if (protoFlag == 2L) {
            return "ikev2";
        }
        if (protoFlag == 3L) {
            return "wireguard";
        }
        return "http";
    }

    private static boolean isLinux() {
        String os = System.getProperty("os.name");
        return os != null && os.toLowerCase().contains("nux");
    }

    private static String safeConnNameFromKey(String key) {
        CRC32 crc = new CRC32();
        crc.update(key.getBytes(StandardCharsets.UTF_8));
        return "megabasterd_ikev2_" + Long.toHexString(crc.getValue());
    }

    // WireGuard interface names are limited to 15 chars.
    // Generate a stable, compliant interface name from the SmartProxy key.
    private static String safeWireguardInterfaceFromKey(String key) {
        CRC32 crc = new CRC32();
        crc.update(key.getBytes(StandardCharsets.UTF_8));
        return "wg" + Long.toHexString(crc.getValue());
    }

    private static String escapeStrongSwanString(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static final class CommandResult {
        public final int exitCode;
        public final String output;

        private CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    private static CommandResult runCommand(List<String> cmd, int timeoutMs) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream is = p.getInputStream()) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } catch (IOException ignored) {
            }
        }, "SmartProxy-ipsec-reader");
        reader.setDaemon(true);
        reader.start();

        boolean done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
        if (!done) {
            p.destroyForcibly();
        }

        try {
            reader.join(1000);
        } catch (InterruptedException ignored) {
        }

        String output = out.toString(StandardCharsets.UTF_8);

        if (!done) {
            return new CommandResult(124, output);
        }
        return new CommandResult(p.exitValue(), output);
    }

    private static String limitLog(String s, int maxChars) {
        if (s == null) {
            return "";
        }
        if (s.length() <= maxChars) {
            return s;
        }
        return s.substring(0, maxChars) + "\n...[truncated]";
    }

    private static String tailFile(Path file, int maxBytes) {
        try {
            if (file == null || !Files.exists(file)) {
                return "";
            }
            long size = Files.size(file);
            if (size <= 0) {
                return "";
            }
            int toRead = (int) Math.min((long) maxBytes, size);
            byte[] all = Files.readAllBytes(file);
            int start = Math.max(0, all.length - toRead);
            return new String(Arrays.copyOfRange(all, start, all.length), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return "";
        }
    }

    public boolean ensureIkev2Connected(String ikev2Key) {
        if (ikev2Key == null) {
            return false;
        }
        Ikev2Credentials creds = IKEV2_AUTH.get(ikev2Key);
        if (creds == null) {
            LOG.log(Level.WARNING, "[Smart Proxy] IKEv2 credentials not found for key: {0}", ikev2Key);
            return false;
        }

        if (!isLinux()) {
            LOG.log(Level.WARNING, "[Smart Proxy] IKEv2 is only supported on Linux containers.");
            return false;
        }

        synchronized (_ikev2_lock) {
            if (ikev2Key.equals(_active_ikev2_key)) {
                return true;
            }

            // Ensure only one tunnel type is active at a time.
            disconnectActiveWireguard();
            disconnectActiveIkev2();

            String connName = safeConnNameFromKey(ikev2Key);

            try {
                Path ipsecConf = Paths.get("/etc/ipsec.conf");
                Path ipsecSecrets = Paths.get("/etc/ipsec.secrets");
                // In containers there is usually no syslog/journald, so charon logs would otherwise disappear.
                // Force file logging so we can surface meaningful diagnostics back to the UI.
                // We write to a dedicated include file to avoid clobbering the distro-provided template.
                Path charonLogging = Paths.get("/etc/strongswan.d/99-megabasterd-logging.conf");
                Path charonLogFile = Paths.get("/var/log/charon.log");

                try {
                    Files.createDirectories(charonLogFile.getParent());
                } catch (Exception ignored) {
                }

                try {
                    if (!Files.exists(charonLogFile)) {
                        Files.write(charonLogFile, "".getBytes(StandardCharsets.UTF_8));
                    }
                    try {
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-");
                        Files.setPosixFilePermissions(charonLogFile, java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw-rw-"));
                    } catch (Exception ignored) {
                        // Best-effort; on some filesystems Posix permissions may not be supported.
                    }
                } catch (Exception ex) {
                    LOG.log(Level.WARNING, "[Smart Proxy] IKEv2: unable to prepare charon log file {0}: {1}", new Object[]{charonLogFile.toString(), ex.getMessage()});
                }

                StringBuilder loggingConf = new StringBuilder();
                loggingConf.append("charon {\n");
                loggingConf.append("  filelog {\n");
                loggingConf.append("    /var/log/charon.log {\n");
                loggingConf.append("      time_format = %b %e %T\n");
                loggingConf.append("      append = no\n");
                loggingConf.append("      flush_line = yes\n");
                loggingConf.append("      default = 2\n");
                loggingConf.append("      ike = 2\n");
                loggingConf.append("      knl = 2\n");
                loggingConf.append("      cfg = 2\n");
                loggingConf.append("    }\n");
                loggingConf.append("  }\n");
                loggingConf.append("}\n");

                StringBuilder conf = new StringBuilder();
                conf.append("config setup\n");
                conf.append("  uniqueids=no\n\n");
                conf.append("conn ").append(connName).append("\n");
                conf.append("  keyexchange=ikev2\n");
                conf.append("  auto=add\n");
                conf.append("  left=%defaultroute\n");
                conf.append("  leftsourceip=%config\n");
                conf.append("  leftauth=eap-mschapv2\n");
                conf.append("  eap_identity=%identity\n");
                conf.append("  right=").append(creds.hostname).append("\n");
                conf.append("  rightid=%any\n");
                conf.append("  rightauth=pubkey\n");
                conf.append("  rightsubnet=0.0.0.0/0\n");
                conf.append("  dpdaction=restart\n");
                conf.append("  dpddelay=30s\n");
                conf.append("  dpdtimeout=120s\n");
                conf.append("  ike=aes256-sha2_256-modp2048,aes128-sha2_256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048\n");
                conf.append("  esp=aes256-sha2_256,aes128-sha2_256,aes256-sha1,aes128-sha1\n");

                String secrets = "\"" + escapeStrongSwanString(creds.username) + "\" : EAP \"" + escapeStrongSwanString(creds.password) + "\"\n";

                try {
                    Files.write(charonLogging, loggingConf.toString().getBytes(StandardCharsets.UTF_8));
                } catch (Exception ex) {
                    LOG.log(Level.WARNING, "[Smart Proxy] IKEv2: unable to write strongSwan logging config {0}: {1}", new Object[]{charonLogging.toString(), ex.getMessage()});
                }

                Files.write(ipsecConf, conf.toString().getBytes(StandardCharsets.UTF_8));
                Files.write(ipsecSecrets, secrets.getBytes(StandardCharsets.UTF_8));

                // Restart strongSwan with the new config
                try {
                    runCommand(Arrays.asList("ipsec", "stop"), 15_000);
                } catch (Exception ignored) {
                }

                CommandResult startRes = runCommand(Arrays.asList("ipsec", "start"), 20_000);
                if (startRes.exitCode != 0) {
                    LOG.log(Level.WARNING, "[Smart Proxy] IKEv2: failed to start strongSwan (exit={0})\n{1}", new Object[]{startRes.exitCode, limitLog(startRes.output, 8000)});
                    return false;
                }

                CommandResult upRes = runCommand(Arrays.asList("ipsec", "up", connName), Math.max(30_000, _proxy_timeout));
                if (upRes.exitCode != 0) {
                    String extra = "";
                    try {
                        CommandResult statusRes = runCommand(Arrays.asList("ipsec", "statusall"), 10_000);
                        extra = "\n[ipsec statusall exit=" + String.valueOf(statusRes.exitCode) + "]\n" + limitLog(statusRes.output, 8000);
                    } catch (Exception ignored) {
                    }

                    String charonTail = tailFile(charonLogFile, 32 * 1024);
                    if (charonTail != null && !charonTail.trim().isEmpty()) {
                        charonTail = "\n[/var/log/charon.log tail]\n" + limitLog(charonTail, 8000);
                    } else {
                        charonTail = "\n[/var/log/charon.log tail]\n" + "(empty or missing)";
                    }

                    LOG.log(Level.WARNING, "[Smart Proxy] IKEv2: failed to bring up tunnel (exit={0})\n{1}{2}{3}", new Object[]{upRes.exitCode, limitLog(upRes.output, 8000), extra, charonTail});
                    return false;
                }

                _active_ikev2_key = ikev2Key;
                _active_ikev2_conn = connName;
                LOG.log(Level.INFO, "[Smart Proxy] IKEv2 tunnel up: {0} -> {1}", new Object[]{ikev2Key, creds.hostname});
                return true;

            } catch (Exception ex) {
                LOG.log(Level.SEVERE, "[Smart Proxy] IKEv2 error: {0}", ex.getMessage());
                return false;
            }
        }
    }

    private void disconnectActiveIkev2() {
        synchronized (_ikev2_lock) {
            if (_active_ikev2_conn == null || _active_ikev2_conn.isEmpty()) {
                _active_ikev2_key = null;
                _active_ikev2_conn = null;
                return;
            }
            try {
                runCommand(Arrays.asList("ipsec", "down", _active_ikev2_conn), 20_000);
            } catch (Exception ignored) {
            }
            try {
                runCommand(Arrays.asList("ipsec", "stop"), 20_000);
            } catch (Exception ignored) {
            }
            LOG.log(Level.INFO, "[Smart Proxy] IKEv2 tunnel down: {0}", _active_ikev2_conn);
            _active_ikev2_key = null;
            _active_ikev2_conn = null;
        }
    }

    public boolean ensureWireguardConnected(String wgKey) {
        if (wgKey == null) {
            return false;
        }

        WireguardConfig cfg = WIREGUARD_CONFIGS.get(wgKey);
        if (cfg == null) {
            LOG.log(Level.WARNING, "[Smart Proxy] WireGuard config not found for key: {0}", wgKey);
            return false;
        }

        if (!isLinux()) {
            LOG.log(Level.WARNING, "[Smart Proxy] WireGuard is only supported on Linux containers.");
            return false;
        }

        synchronized (_ikev2_lock) {
            if (wgKey.equals(_active_wireguard_key)) {
                return true;
            }

            // If the calling thread is already interrupted (e.g. download pool shutting down), bail out
            // immediately instead of attempting tunnel operations that will fail with InterruptedException.
            if (Thread.currentThread().isInterrupted()) {
                LOG.log(Level.INFO, "[Smart Proxy] WireGuard: skipping connect for {0} (thread interrupted)", wgKey);
                return false;
            }

            // Ensure only one tunnel type is active at a time.
            disconnectActiveIkev2();
            disconnectActiveWireguard();

            try {
                if (!installWireguardConfig(cfg)) {
                    return false;
                }

                // Bring up by interface name (expects /etc/wireguard/<iface>.conf).
                CommandResult upRes = runCommand(Arrays.asList("wg-quick", "up", cfg.iface), Math.max(30_000, _proxy_timeout));

                // If the interface already exists (stale leftover), tear it down and retry once.
                if (upRes.exitCode != 0 && upRes.output != null && upRes.output.contains("already exists")) {
                    LOG.log(Level.INFO, "[Smart Proxy] WireGuard: interface {0} already exists, tearing down and retrying", cfg.iface);
                    try {
                        runCommand(Arrays.asList("wg-quick", "down", cfg.iface), 15_000);
                    } catch (Exception ignored) {
                    }
                    upRes = runCommand(Arrays.asList("wg-quick", "up", cfg.iface), Math.max(30_000, _proxy_timeout));
                }

                if (upRes.exitCode != 0) {
                    String extra = "";
                    try {
                        CommandResult wgShow = runCommand(Arrays.asList("wg", "show"), 10_000);
                        extra = "\n[wg show exit=" + String.valueOf(wgShow.exitCode) + "]\n" + limitLog(wgShow.output, 8000);
                    } catch (Exception ignored) {
                    }
                    LOG.log(Level.WARNING, "[Smart Proxy] WireGuard: failed to bring up tunnel (exit={0})\n{1}{2}", new Object[]{upRes.exitCode, limitLog(upRes.output, 8000), extra});
                    return false;
                }

                _active_wireguard_key = wgKey;
                _active_wireguard_conf = cfg.iface;
                LOG.log(Level.INFO, "[Smart Proxy] WireGuard tunnel up: {0} -> {1}", new Object[]{wgKey, cfg.installedPath});
                return true;

            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                LOG.log(Level.INFO, "[Smart Proxy] WireGuard: connect interrupted for {0} (thread shutting down)", wgKey);
                return false;
            } catch (Exception ex) {
                LOG.log(Level.SEVERE, "[Smart Proxy] WireGuard error ({0}): {1}", new Object[]{ex.getClass().getSimpleName(), ex.getMessage()});
                return false;
            }
        }
    }

    private void disconnectActiveWireguard() {
        synchronized (_ikev2_lock) {
            // Tear down the tracked interface first.
            if (_active_wireguard_conf != null && !_active_wireguard_conf.isEmpty()) {
                try {
                    runCommand(Arrays.asList("wg-quick", "down", _active_wireguard_conf), 20_000);
                } catch (Exception ignored) {
                }
                LOG.log(Level.INFO, "[Smart Proxy] WireGuard tunnel down: {0}", _active_wireguard_conf);
            }
            _active_wireguard_key = null;
            _active_wireguard_conf = null;

            // Clean up ALL stale wg* interfaces to prevent accumulation.
            tearDownAllWireguardInterfaces();
        }
    }

    private void tearDownAllWireguardInterfaces() {
        try {
            CommandResult wgShow = runCommand(Arrays.asList("wg", "show", "interfaces"), 10_000);
            if (wgShow.exitCode == 0 && wgShow.output != null && !wgShow.output.trim().isEmpty()) {
                for (String iface : wgShow.output.trim().split("\\s+")) {
                    iface = iface.trim();
                    if (!iface.isEmpty()) {
                        try {
                            runCommand(Arrays.asList("wg-quick", "down", iface), 15_000);
                            LOG.log(Level.INFO, "[Smart Proxy] WireGuard: cleaned up stale interface {0}", iface);
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    public synchronized void blockProxy(String proxy, String cause) {

        // All mutators (blockProxy, refreshProxyList, getProxy) are synchronized
        // on `this`, so the get-mutate sequence below is atomic w.r.t. other
        // map operations -- the ConcurrentHashMap is belt-and-braces. The
        // previous code also did a redundant put() back of the same array
        // reference; that's a no-op since proxy_data was already in the map.
        // Use computeIfPresent to express the atomic mutate-in-place clearly,
        // and to safely no-op if the entry was concurrently removed (e.g.,
        // by a refreshProxyList() that's running on the same monitor in some
        // future refactor where this method is no longer synchronized). (#751)
        if (_proxy_list.containsKey(proxy)) {

            if (this._ban_time == 0) {

                _proxy_list.remove(proxy);

                LOG.log(Level.WARNING, "[Smart Proxy] REMOVING PROXY {0} ({1})", new Object[]{proxy, cause});

            } else {

                _proxy_list.computeIfPresent(proxy, (k, proxy_data) -> {
                    proxy_data[0] = System.currentTimeMillis();
                    return proxy_data;
                });

                LOG.log(Level.WARNING, "[Smart Proxy] BLOCKING PROXY {0} ({1} secs) ({2})", new Object[]{proxy, _ban_time, cause});

            }

            // If the blocked entry is the currently active IKEv2 tunnel, tear it down.
            if (proxy != null && proxy.equals(_active_ikev2_key)) {
                disconnectActiveIkev2();
            }

            // If the blocked entry is the currently active WireGuard tunnel, tear it down.
            if (proxy != null && proxy.equals(_active_wireguard_key)) {
                disconnectActiveWireguard();
            }

            _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (" + String.valueOf(getProxyCount() - countBlockedProxies()) + ")" + (this.isForce_smart_proxy() ? " F!" : ""));

        }
    }

    /**
     * Parses a single proxy line into {@code into_list}/{@code into_auth}.
     * Accepts the historical syntax ({@code [*]IP:PORT[@user_b64:password_b64]})
     * AND scheme-prefixed forms ({@code http://}, {@code https://},
     * {@code socks://}, {@code socks4://}, {@code socks4a://}, {@code socks5://}),
     * which were previously rejected as malformed. (#753)
     * <p>
     * Note: authentication is only supported in the legacy
     * {@code IP:PORT@b64user:b64pass} trailer form. A standard
     * {@code http://user:pass@host:port} URL is NOT decoded — write
     * {@code http://host:port@b64user:b64pass} (or the bare equivalent) to
     * supply credentials.
     *
     * @param raw       raw line (will be trimmed; blank lines silently ignored)
     * @param source    "custom" or "URL" — only used in the warning log
     * @param into_list destination for {@code IP:PORT -> {ban_ts, type}} entries
     * @param into_auth destination for {@code IP:PORT -> b64user:b64pass} pairs
     */
    private static void parseProxyEntry(String raw, String source,
            java.util.Map<String, Long[]> into_list,
            java.util.Map<String, String> into_auth) {

        if (raw == null) {
            return;
        }
        String line = raw.trim();
        if (line.isEmpty()) {
            return;
        }

        // Preserve the local Linux tunnel entry formats while using the
        // upstream parser for ordinary HTTP/SOCKS entries. These entries are
        // represented in the same pool with protocol flags so the download
        // workers can establish the tunnel before opening the MEGA request.
        String initial_lower = line.toLowerCase();
        if (initial_lower.startsWith("ikev2://") || initial_lower.startsWith("ikev2 ") || initial_lower.startsWith("ikev2:")) {
            Ikev2Credentials creds = parseIkev2Credentials(line);
            if (creds != null) {
                String key = "ikev2://" + creds.username + "@" + creds.hostname;
                into_list.put(key, new Long[]{-1L, 2L});
                IKEV2_AUTH.put(key, creds);
            } else {
                LOG.log(Level.WARNING, "[Smart Proxy] skipping malformed {0} IKEv2 entry: {1}", new Object[]{source, raw});
            }
            return;
        }

        if (initial_lower.startsWith("wireguard://")) {
            String key = line.trim();
            if (WIREGUARD_CONFIGS.containsKey(key)) {
                into_list.put(key, new Long[]{-1L, 3L});
            } else {
                LOG.log(Level.WARNING, "[Smart Proxy] skipping WireGuard entry without a matching config: {0}", raw);
            }
            return;
        }

        // Lines that start with '#' identify a remote proxy-list URL embedded
        // in custom_proxy_list. They are extracted elsewhere; silently skip
        // them here instead of logging them as malformed entries.
        if (line.startsWith("#")) {
            return;
        }

        boolean socks = false;
        boolean had_scheme = false;

        // Strip the historical "*" SOCKS marker first; it can also precede a
        // scheme prefix in case a user mixed conventions.
        if (line.startsWith("*")) {
            socks = true;
            line = line.substring(1).trim();
        }

        // Recognise scheme prefixes case-insensitively. All SOCKS variants
        // collapse to JDK Proxy.Type.SOCKS. HTTPS proxies also use the
        // HTTP CONNECT method on the JDK side, so they map to
        // Proxy.Type.HTTP.
        String lower = line.toLowerCase();
        if (lower.startsWith("http://")) {
            line = line.substring(7);
            had_scheme = true;
        } else if (lower.startsWith("https://")) {
            line = line.substring(8);
            had_scheme = true;
        } else if (lower.startsWith("socks5://")) {
            socks = true;
            line = line.substring(9);
            had_scheme = true;
        } else if (lower.startsWith("socks4a://")) {
            socks = true;
            line = line.substring(10);
            had_scheme = true;
        } else if (lower.startsWith("socks4://")) {
            socks = true;
            line = line.substring(9);
            had_scheme = true;
        } else if (lower.startsWith("socks://")) {
            socks = true;
            line = line.substring(8);
            had_scheme = true;
        }

        if (line.contains("@")) {
            String[] proxy_parts = line.split("@");
            if (proxy_parts.length != 2) {
                // Stray '@' (e.g. user@pass@host:port): can't disambiguate
                // which half is the host:port, so reject. (#751)
                LOG.log(Level.WARNING, "[Smart Proxy] skipping malformed {0} entry: {1}", new Object[]{source, raw});
                return;
            }
            // The host:port half may carry a trailing path the scheme brought
            // along (e.g. http://host:port/foo@auth). Strip from that half
            // only -- the auth half is base64(user):base64(pass), and the
            // base64 alphabet includes '/', so a global path-strip would
            // silently corrupt legitimate auth values (#753 audit).
            String hostport = proxy_parts[0];
            int slash = hostport.indexOf('/');
            if (slash >= 0) {
                hostport = hostport.substring(0, slash);
            }
            hostport = hostport.trim();

            if (!hostport.matches(".+?:[0-9]{1,5}")) {
                LOG.log(Level.WARNING, "[Smart Proxy] skipping malformed {0} entry: {1}", new Object[]{source, raw});
                return;
            }

            // Disambiguation guard: a URL-style "user:pass@host:port"
            // credential where pass is numeric (e.g. "user:1234") would
            // ALSO match the legacy "host:port@b64u:b64p" shape on parts[0]
            // and lead us to store "user:1234" as the host. When the line
            // had a scheme prefix AND parts[1] itself looks like host:port
            // (whereas a real base64 trailer has no internal port-shaped
            // segment), it's almost certainly URL-style auth -- reject
            // with a pointed log instead of silently misparsing. (#753 audit)
            if (had_scheme && proxy_parts[1].matches(".+?:[0-9]{1,5}")) {
                LOG.log(Level.WARNING, "[Smart Proxy] skipping {0} entry with URL-style user:pass@host:port credential (not supported -- use IP:PORT@b64user:b64pass form instead): {1}",
                        new Object[]{source, raw});
                return;
            }

            into_auth.put(hostport, proxy_parts[1]);
            into_list.put(hostport, new Long[]{-1L, socks ? 1L : -1L});
            return;
        }

        // No auth trailer: drop any trailing path the scheme may have
        // brought along (e.g. http://1.2.3.4:8080/list.txt). Bare lines
        // without a scheme are not allowed to have a path -- the legacy
        // parser rejected them via the strict regex.
        if (had_scheme) {
            int slash = line.indexOf('/');
            if (slash >= 0) {
                line = line.substring(0, slash);
            }
        }
        line = line.trim();

        if (line.matches(".+?:[0-9]{1,5}")) {
            into_list.put(line, new Long[]{-1L, socks ? 1L : -1L});
        } else {
            LOG.log(Level.WARNING, "[Smart Proxy] skipping malformed {0} entry: {1}", new Object[]{source, raw});
        }
    }

    /**
     * Fetches a single proxy-list URL and merges its entries into the
     * supplied maps. Throws {@link IOException} on connect/read failure or
     * non-200 status — callers swallow the exception per-URL so a single
     * bad source can't kill the whole refresh. (#753)
     */
    private static void fetchAndMerge(String url_str,
            java.util.Map<String, Long[]> into_list,
            java.util.Map<String, String> into_auth) throws IOException {

        HttpURLConnection con = null;
        try {
            URL url = new URL(url_str);

            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                LOG.log(Level.WARNING, "Smart proxy list URL is not HTTPS ({0}); response is unauthenticated and could be MITM'd", url_str);
            }

            con = (HttpURLConnection) url.openConnection();
            con.setUseCaches(false);
            con.setRequestProperty("User-Agent", MainPanel.DEFAULT_USER_AGENT);

            // Bound the fetch. Without timeouts a hung proxy-list URL holds
            // the SmartMegaProxyManager monitor (synchronized method) and
            // blocks every getProxy() / blockProxy() call across all
            // workers -- exactly the wrong time to stall, since we're
            // already in 509 recovery. (#751)
            con.setConnectTimeout(15_000);
            con.setReadTimeout(30_000);

            int http_status = con.getResponseCode();
            if (http_status != 200) {
                MiscTools.drainAndCloseErrorStream(con);
                throw new IOException("HTTP " + http_status);
            }

            String data;
            try (InputStream is = con.getInputStream(); ByteArrayOutputStream byte_res = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[MainPanel.DEFAULT_BYTE_BUFFER_SIZE];
                int reads;
                while ((reads = is.read(buffer)) != -1) {
                    byte_res.write(buffer, 0, reads);
                }
                data = new String(byte_res.toByteArray(), "UTF-8");
            }

            for (String line : data.split("\n")) {
                parseProxyEntry(line, "URL", into_list, into_auth);
            }
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }

    /**
     * Refreshes the live proxy pool from {@code custom_proxy_list}. The
     * textarea is scanned line by line:
     * <ul>
     *   <li>Lines starting with {@code #} followed by {@code http://} or
     *       {@code https://} are treated as remote proxy-list URLs. ALL
     *       such lines are fetched and the entries aggregated. (#753)</li>
     *   <li>Other non-empty lines are parsed as inline proxy entries by
     *       {@link #parseProxyEntry}.</li>
     * </ul>
     * Inline entries and URL-sourced entries coexist; a single failed URL
     * does not invalidate the rest. The live pool is only swapped if the
     * resulting set has at least one entry — otherwise the previous list
     * is preserved and the status label is marked {@code "stale"}. (#751)
     */
    public synchronized void refreshProxyList() {

        try {
            String custom_proxy_list = DBTools.selectSettingValue("custom_proxy_list");

            LinkedHashMap<String, Long[]> new_list = new LinkedHashMap<>();
            HashMap<String, String> new_auth = new HashMap<>();
            ArrayList<String> urls = new ArrayList<>();
            boolean had_input = false;

            IKEV2_AUTH.clear();
            WIREGUARD_CONFIGS.clear();
            loadWireguardConfigs(new_list);

            if (custom_proxy_list != null) {
                for (String line : custom_proxy_list.split("\\r?\\n")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) {
                        continue;
                    }
                    had_input = true;
                    if (trimmed.startsWith("#")) {
                        // Strip the '#' and accept either '#http://...' or
                        // '# http://...' so users aren't tripped up by a
                        // stray space.
                        String url_part = trimmed.substring(1).trim();
                        String lower = url_part.toLowerCase();
                        if (lower.startsWith("http://") || lower.startsWith("https://")) {
                            urls.add(url_part);
                        } else if (!url_part.isEmpty()) {
                            LOG.log(Level.WARNING, "[Smart Proxy] skipping malformed #URL entry: {0}", line);
                        }
                    } else {
                        parseProxyEntry(line, "custom", new_list, new_auth);
                    }
                }
            }

            int urls_ok = 0;
            int urls_fail = 0;
            for (String u : urls) {
                try {
                    fetchAndMerge(u, new_list, new_auth);
                    urls_ok++;
                } catch (MalformedURLException ex) {
                    urls_fail++;
                    LOG.log(Level.SEVERE, "[Smart Proxy] proxy-list URL is malformed ({0}): {1}", new Object[]{u, ex.getMessage()});
                } catch (IOException ex) {
                    urls_fail++;
                    LOG.log(Level.WARNING, "[Smart Proxy] proxy-list URL fetch failed ({0}) -- continuing with remaining sources: {1}",
                            new Object[]{u, ex.getMessage()});
                }
            }

            if (new_list.isEmpty()) {
                // Preserve previous list. Was: clear() + populate during
                // parse, so an empty / garbage body wiped the previous list
                // before we knew whether the new one was viable. (#751)
                if (had_input) {
                    LOG.log(Level.WARNING, "[Smart Proxy] refresh produced 0 entries (URLs ok={0}, failed={1}) -- preserving previous list ({2} entries)",
                            new Object[]{urls_ok, urls_fail, _proxy_list.size()});
                    _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (" + String.valueOf(getProxyCount()) + " stale)" + (this.isForce_smart_proxy() ? " F!" : ""));
                } else {
                    _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (0 proxies!)" + (this.isForce_smart_proxy() ? " F!" : ""));
                    LOG.log(Level.INFO, "[Smart Proxy] no inline entries and no URLs configured");
                }
            } else {
                _proxy_list.clear();
                _proxy_list.putAll(new_list);
                PROXY_LIST_AUTH.clear();
                PROXY_LIST_AUTH.putAll(new_auth);

                // When SOME URLs failed but we still got a usable pool, show
                // the partial-success state so the user can tell one of
                // their providers is sick without having to read the log.
                String suffix = "";
                if (urls_fail > 0) {
                    suffix = " [" + urls_ok + "/" + (urls_ok + urls_fail) + " sources]";
                }
                _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (" + String.valueOf(getProxyCount()) + ")" + suffix + (this.isForce_smart_proxy() ? " F!" : ""));
                LOG.log(Level.INFO, "[Smart Proxy] proxy list refreshed ({0} entries; URLs ok={1}, failed={2})",
                        new Object[]{_proxy_list.size(), urls_ok, urls_fail});
            }
        } finally {
            _last_refresh_timestamp = System.currentTimeMillis();
        }
    }

    public static class SmartProxyAuthenticator extends Authenticator {

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {

            InetAddress ipaddr = getRequestingSite();
            int port = getRequestingPort();

            String auth_data;

            if ((auth_data = PROXY_LIST_AUTH.get(ipaddr.getHostAddress() + ":" + String.valueOf(port))) != null) {

                try {
                    String[] auth_data_parts = auth_data.split(":");

                    String user = new String(MiscTools.BASE642Bin(auth_data_parts[0]), "UTF-8");

                    String password = new String(MiscTools.BASE642Bin(auth_data_parts[1]), "UTF-8");

                    return new PasswordAuthentication(user, password.toCharArray());

                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(SmartMegaProxyManager.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            return null;
        }
    }

    public static final class Ikev2Credentials {

        public final String hostname;
        public final String username;
        public final String password;

        public Ikev2Credentials(String hostname, String username, String password) {
            this.hostname = hostname;
            this.username = username;
            this.password = password;
        }
    }

    public static final class WireguardConfig {

        public final String name;
        public final String sourcePath;
        public final String iface;
        public final String installedPath;

        public WireguardConfig(String name, String sourcePath, String iface, String installedPath) {
            this.name = name;
            this.sourcePath = sourcePath;
            this.iface = iface;
            this.installedPath = installedPath;
        }
    }

    private static boolean installWireguardConfig(WireguardConfig cfg) {
        if (cfg == null) {
            return false;
        }

        try {
            Path src = Paths.get(cfg.sourcePath);
            Path dst = Paths.get(cfg.installedPath);
            Files.createDirectories(dst.getParent());

            // Always overwrite to pick up changes.
            Files.copy(src, dst, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            try {
                Files.setPosixFilePermissions(dst, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignored) {
                // Best-effort.
            }

            return true;
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "[Smart Proxy] WireGuard: failed to install config {0} -> {1}: {2}", new Object[]{cfg.sourcePath, cfg.installedPath, ex.getMessage()});
            return false;
        }
    }

    private static void loadWireguardConfigs(LinkedHashMap<String, Long[]> target) {
        if (!isLinux() || target == null) {
            return;
        }
        try {
            Path dir = Paths.get("/wireguard");
            if (!Files.isDirectory(dir)) {
                return;
            }

            List<Path> confs = new ArrayList<>();
            try (java.util.stream.Stream<Path> s = Files.list(dir)) {
                s.filter(p -> Files.isRegularFile(p))
                        .filter(p -> p.getFileName() != null && p.getFileName().toString().toLowerCase().endsWith(".conf"))
                        .forEach(confs::add);
            }

            confs.sort((a, b) -> a.getFileName().toString().compareToIgnoreCase(b.getFileName().toString()));

            for (Path p : confs) {
                String fn = p.getFileName().toString();
                String name = fn.substring(0, fn.length() - ".conf".length());
                if (name.trim().isEmpty()) {
                    continue;
                }
                String key = "wireguard://" + name;
                String iface = safeWireguardInterfaceFromKey(key);
                String installed = "/etc/wireguard/" + iface + ".conf";
                target.put(key, new Long[]{-1L, 3L});
                WIREGUARD_CONFIGS.put(key, new WireguardConfig(name, p.toString(), iface, installed));
            }

        } catch (Exception ex) {
            LOG.log(Level.WARNING, "[Smart Proxy] WireGuard: failed to load /wireguard configs: {0}", ex.getMessage());
        }
    }

    private static Ikev2Credentials parseIkev2Credentials(String line) {
        if (line == null) {
            return null;
        }
        String s = line.trim();
        if (s.isEmpty()) {
            return null;
        }
        String lower = s.toLowerCase();

        // Accept: ikev2://username:password@hostname
        if (lower.startsWith("ikev2://")) {
            String rest = s.substring("ikev2://".length()).trim();
            int at = rest.lastIndexOf('@');
            if (at <= 0 || at >= rest.length() - 1) {
                return null;
            }
            String userPass = rest.substring(0, at);
            String host = rest.substring(at + 1).trim();
            if (host.isEmpty()) {
                return null;
            }
            int colon = userPass.indexOf(':');
            if (colon <= 0 || colon >= userPass.length() - 1) {
                return null;
            }
            String user = userPass.substring(0, colon).trim();
            String pass = userPass.substring(colon + 1);
            if (user.isEmpty() || pass.isEmpty()) {
                return null;
            }
            return new Ikev2Credentials(host, user, pass);
        }

        // Accept: ikev2 hostname username password
        if (lower.startsWith("ikev2 ")) {
            String[] parts = s.split("\\s+", 4);
            if (parts.length < 4) {
                return null;
            }
            String host = parts[1].trim();
            String user = parts[2].trim();
            String pass = parts[3];
            if (host.isEmpty() || user.isEmpty() || pass.isEmpty()) {
                return null;
            }
            return new Ikev2Credentials(host, user, pass);
        }

        // Accept: ikev2:hostname@BASE64(user):BASE64(pass)  (matches existing auth style)
        if (lower.startsWith("ikev2:")) {
            String rest = s.substring("ikev2:".length()).trim();
            if (!rest.contains("@")) {
                return null;
            }
            String[] hostAndAuth = rest.split("@", 2);
            if (hostAndAuth.length < 2) {
                return null;
            }
            String host = hostAndAuth[0].trim();
            String auth = hostAndAuth[1].trim();
            if (host.isEmpty() || auth.isEmpty() || !auth.contains(":")) {
                return null;
            }
            try {
                String[] authParts = auth.split(":", 2);
                String user = new String(MiscTools.BASE642Bin(authParts[0]), "UTF-8");
                String pass = new String(MiscTools.BASE642Bin(authParts[1]), "UTF-8");
                if (user.isEmpty() || pass.isEmpty()) {
                    return null;
                }
                return new Ikev2Credentials(host, user, pass);
            } catch (Exception ex) {
                return null;
            }
        }

        return null;
    }

}
