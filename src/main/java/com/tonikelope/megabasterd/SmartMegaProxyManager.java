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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
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

    public static String DEFAULT_SMART_PROXY_URL = null;
    public static final int PROXY_BLOCK_TIME = 300;
    public static final int PROXY_AUTO_REFRESH_TIME = 60;
    public static final int PROXY_AUTO_REFRESH_SLEEP_TIME = 30;
    public static final boolean RESET_SLOT_PROXY = true;
    public static final boolean RANDOM_SELECT = true;

    private static final Logger LOG = Logger.getLogger(SmartMegaProxyManager.class.getName());
    private volatile String _proxy_list_url;
    private final ConcurrentHashMap<String, Long[]> _proxy_list;
    private static final HashMap<String, String> PROXY_LIST_AUTH = new HashMap<>();
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

    public int getProxy_timeout() {
        return _proxy_timeout;
    }

    public boolean isForce_smart_proxy() {
        return _force_smart_proxy;
    }

    public SmartMegaProxyManager(String proxy_list_url, MainPanel main_panel) {
        _proxy_list_url = (proxy_list_url != null && !"".equals(proxy_list_url)) ? proxy_list_url : DEFAULT_SMART_PROXY_URL;
        _proxy_list = new ConcurrentHashMap<>();
        _main_panel = main_panel;

        refreshSmartProxySettings();

        THREAD_POOL.execute(() -> {
            refreshProxyList();

            while (true) {

                while (System.currentTimeMillis() < _last_refresh_timestamp + _autorefresh_time * 60 * 1000) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(SmartMegaProxyManager.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                if (MainPanel.isUse_smart_proxy()) {

                    refreshProxyList();
                }
            }
        });
    }

    private synchronized int countBlockedProxies() {

        int i = 0;

        Long current_time = System.currentTimeMillis();

        for (String k : _proxy_list.keySet()) {

            if (_proxy_list.get(k)[0] != -1 && _proxy_list.get(k)[0] > current_time - _ban_time * 1000) {

                i++;
            }
        }

        return i;

    }

    public synchronized void refreshSmartProxySettings() {
        String smartproxy_ban_time = DBTools.selectSettingValue("smartproxy_ban_time");

        if (smartproxy_ban_time != null) {
            _ban_time = Integer.parseInt(smartproxy_ban_time);
        } else {
            _ban_time = PROXY_BLOCK_TIME;
        }

        String smartproxy_timeout = DBTools.selectSettingValue("smartproxy_timeout");

        if (smartproxy_timeout != null) {
            _proxy_timeout = Integer.parseInt(smartproxy_timeout) * 1000;
        } else {
            _proxy_timeout = Transference.HTTP_PROXY_TIMEOUT;
        }

        String force_smart_proxy_string = DBTools.selectSettingValue("force_smart_proxy");

        if (force_smart_proxy_string != null) {

            _force_smart_proxy = force_smart_proxy_string.equals("yes");
        } else {
            _force_smart_proxy = MainPanel.FORCE_SMART_PROXY;
        }

        String autorefresh_smart_proxy_string = DBTools.selectSettingValue("smartproxy_autorefresh_time");

        if (autorefresh_smart_proxy_string != null) {
            _autorefresh_time = Integer.parseInt(autorefresh_smart_proxy_string);
        } else {
            _autorefresh_time = PROXY_AUTO_REFRESH_TIME;
        }

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

        LOG.log(Level.INFO, "SmartProxy BAN_TIME: " + String.valueOf(_ban_time) + "   TIMEOUT: " + String.valueOf(_proxy_timeout / 1000) + "   REFRESH: " + String.valueOf(_autorefresh_time) + "   FORCE: " + String.valueOf(_force_smart_proxy) + "   RANDOM: " + String.valueOf(_random_select) + "   RESET-SLOT-PROXY: " + String.valueOf(_reset_slot_proxy));
    }

    public synchronized int getProxyCount() {

        return _proxy_list.size();
    }

    public synchronized String[] getProxy(ArrayList<String> excluded) {

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

                if ((_proxy_list.get(k)[0] == -1 || _proxy_list.get(k)[0] < current_time - _ban_time * 1000) && (excluded == null || !excluded.contains(k))) {

                    return new String[]{k, protoFromFlag(_proxy_list.get(k)[1])};
                }
            }
        }

        LOG.log(Level.WARNING, "{0} Smart Proxy Manager: NO PROXYS AVAILABLE!! (Refreshing in " + String.valueOf(PROXY_AUTO_REFRESH_SLEEP_TIME) + " secs...)", new Object[]{Thread.currentThread().getName()});

        try {
            Thread.sleep(PROXY_AUTO_REFRESH_SLEEP_TIME * 1000);
        } catch (InterruptedException ex) {
            Logger.getLogger(SmartMegaProxyManager.class.getName()).log(Level.SEVERE, null, ex);
        }

        refreshProxyList();

        return getProxyCount() > 0 ? getProxy(excluded) : null;
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

            // Ensure only one tunnel type is active at a time.
            disconnectActiveIkev2();
            disconnectActiveWireguard();

            try {
                // Best-effort: bring up config.
                CommandResult upRes = runCommand(Arrays.asList("wg-quick", "up", cfg.path), Math.max(30_000, _proxy_timeout));
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
                _active_wireguard_conf = cfg.path;
                LOG.log(Level.INFO, "[Smart Proxy] WireGuard tunnel up: {0} -> {1}", new Object[]{wgKey, cfg.path});
                return true;

            } catch (Exception ex) {
                LOG.log(Level.SEVERE, "[Smart Proxy] WireGuard error: {0}", ex.getMessage());
                return false;
            }
        }
    }

    private void disconnectActiveWireguard() {
        synchronized (_ikev2_lock) {
            if (_active_wireguard_conf == null || _active_wireguard_conf.isEmpty()) {
                _active_wireguard_key = null;
                _active_wireguard_conf = null;
                return;
            }
            try {
                runCommand(Arrays.asList("wg-quick", "down", _active_wireguard_conf), 20_000);
            } catch (Exception ignored) {
            }
            LOG.log(Level.INFO, "[Smart Proxy] WireGuard tunnel down: {0}", _active_wireguard_conf);
            _active_wireguard_key = null;
            _active_wireguard_conf = null;
        }
    }

    public synchronized void blockProxy(String proxy, String cause) {

        if (_proxy_list.containsKey(proxy)) {

            if (this._ban_time == 0) {

                _proxy_list.remove(proxy);

                LOG.log(Level.WARNING, "[Smart Proxy] REMOVING PROXY {0} ({1})", new Object[]{proxy, cause});

            } else {

                Long[] proxy_data = _proxy_list.get(proxy);

                proxy_data[0] = System.currentTimeMillis();

                _proxy_list.put(proxy, proxy_data);

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

    public synchronized void refreshProxyList(String url_list) {
        if (url_list != null) {
            _proxy_list_url = url_list;
        } else {
            _proxy_list_url = null;
        }

        THREAD_POOL.execute(() -> {
            refreshProxyList();
        });
    }

    public synchronized void refreshProxyList() {

        String data;

        HttpURLConnection con = null;

        try {

            // Rebuild credential maps from scratch on every refresh.
            IKEV2_AUTH.clear();
            WIREGUARD_CONFIGS.clear();

            String custom_proxy_list = (_proxy_list_url == null ? DBTools.selectSettingValue("custom_proxy_list") : null);

            LinkedHashMap<String, Long[]> custom_clean_list = new LinkedHashMap<>();

            HashMap<String, String> custom_clean_list_auth = new HashMap<>();

            if (custom_proxy_list != null) {

                ArrayList<String> custom_list = new ArrayList<>(Arrays.asList(custom_proxy_list.split("\\r?\\n")));

                if (!custom_list.isEmpty()) {

                    for (String proxy : custom_list) {

                        if (proxy == null) {
                            continue;
                        }

                        proxy = proxy.trim();

                        if (proxy.isEmpty()) {
                            continue;
                        }

                        // IKEv2 entry format (Docker/Linux):
                        //   ikev2://username:password@hostname
                        // This is treated as a "smart proxy" entry that establishes an IKEv2 VPN tunnel.
                        if (proxy.toLowerCase().startsWith("ikev2://") || proxy.toLowerCase().startsWith("ikev2 ") || proxy.toLowerCase().startsWith("ikev2:")) {
                            Ikev2Credentials creds = parseIkev2Credentials(proxy);
                            if (creds != null) {
                                String key = "ikev2://" + creds.username + "@" + creds.hostname;
                                Long[] proxy_data = new Long[]{-1L, 2L};
                                custom_clean_list.put(key, proxy_data);
                                IKEV2_AUTH.put(key, creds);
                            }
                            continue;
                        }

                        boolean socks = false;

                        if (proxy.startsWith("*")) {
                            socks = true;

                            proxy = proxy.substring(1).trim();
                        }

                        if (proxy.contains("@")) {

                            String[] proxy_parts = proxy.split("@");

                            if (proxy_parts.length < 2) {
                                continue;
                            }

                            String proxy_key = proxy_parts[0].trim();
                            String proxy_auth = proxy_parts[1].trim();

                            if (proxy_key.isEmpty()) {
                                continue;
                            }

                            custom_clean_list_auth.put(proxy_key, proxy_auth);

                            Long[] proxy_data = new Long[]{-1L, socks ? 1L : -1L};

                            custom_clean_list.put(proxy_key, proxy_data);

                        } else if (proxy.matches(".+?:[0-9]{1,5}")) {

                            Long[] proxy_data = new Long[]{-1L, socks ? 1L : -1L};

                            custom_clean_list.put(proxy, proxy_data);
                        }
                    }
                }

                // Auto-load WireGuard configs from /wireguard (Docker volume)
                loadWireguardConfigs(custom_clean_list);

                if (!custom_clean_list.isEmpty()) {

                    _proxy_list.clear();

                    _proxy_list.putAll(custom_clean_list);
                }

                if (!custom_clean_list_auth.isEmpty()) {

                    PROXY_LIST_AUTH.clear();

                    PROXY_LIST_AUTH.putAll(custom_clean_list_auth);
                }

            }

            // If the user provided no custom list (or it was empty), we still want to surface /wireguard configs.
            if (custom_proxy_list == null) {
                loadWireguardConfigs(custom_clean_list);
                if (!custom_clean_list.isEmpty()) {
                    _proxy_list.clear();
                    _proxy_list.putAll(custom_clean_list);
                }
            }

            if (custom_clean_list.isEmpty() && _proxy_list_url != null && !"".equals(_proxy_list_url)) {

                URL url = new URL(this._proxy_list_url);

                con = (HttpURLConnection) url.openConnection();

                con.setUseCaches(false);

                con.setRequestProperty("User-Agent", MainPanel.DEFAULT_USER_AGENT);

                try (InputStream is = con.getInputStream(); ByteArrayOutputStream byte_res = new ByteArrayOutputStream()) {

                    byte[] buffer = new byte[MainPanel.DEFAULT_BYTE_BUFFER_SIZE];

                    int reads;

                    while ((reads = is.read(buffer)) != -1) {

                        byte_res.write(buffer, 0, reads);
                    }

                    data = new String(byte_res.toByteArray(), "UTF-8");
                }

                String[] proxy_list = data.split("\n");

                if (proxy_list.length > 0) {

                    LinkedHashMap<String, Long[]> url_clean_list = new LinkedHashMap<>();

                    HashMap<String, String> url_clean_list_auth = new HashMap<>();

                    for (String proxy : proxy_list) {

                        if (proxy == null) {
                            continue;
                        }

                        proxy = proxy.trim();

                        if (proxy.isEmpty()) {
                            continue;
                        }

                        if (proxy.toLowerCase().startsWith("ikev2://") || proxy.toLowerCase().startsWith("ikev2 ") || proxy.toLowerCase().startsWith("ikev2:")) {
                            Ikev2Credentials creds = parseIkev2Credentials(proxy);
                            if (creds != null) {
                                String key = "ikev2://" + creds.username + "@" + creds.hostname;
                                Long[] proxy_data = new Long[]{-1L, 2L};
                                url_clean_list.put(key, proxy_data);
                                IKEV2_AUTH.put(key, creds);
                            }
                            continue;
                        }

                        boolean socks = false;

                        if (proxy.startsWith("*")) {
                            socks = true;

                            proxy = proxy.substring(1).trim();
                        }

                        if (proxy.contains("@")) {

                            String[] proxy_parts = proxy.split("@");

                            if (proxy_parts.length < 2) {
                                continue;
                            }

                            String proxy_key = proxy_parts[0].trim();
                            String proxy_auth = proxy_parts[1].trim();

                            if (proxy_key.isEmpty()) {
                                continue;
                            }

                            url_clean_list_auth.put(proxy_key, proxy_auth);

                            Long[] proxy_data = new Long[]{-1L, socks ? 1L : -1L};

                            url_clean_list.put(proxy_key, proxy_data);

                        } else if (proxy.matches(".+?:[0-9]{1,5}")) {
                            Long[] proxy_data = new Long[]{-1L, socks ? 1L : -1L};
                            url_clean_list.put(proxy, proxy_data);
                        }

                    }

                    // Auto-load WireGuard configs from /wireguard (Docker volume)
                    loadWireguardConfigs(url_clean_list);

                    _proxy_list.clear();

                    _proxy_list.putAll(url_clean_list);

                    PROXY_LIST_AUTH.clear();

                    PROXY_LIST_AUTH.putAll(url_clean_list_auth);
                }

                _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (" + String.valueOf(getProxyCount()) + ")" + (this.isForce_smart_proxy() ? " F!" : ""));

                LOG.log(Level.INFO, "{0} Smart Proxy Manager: proxy list refreshed ({1})", new Object[]{Thread.currentThread().getName(), _proxy_list.size()});

            } else if (!custom_clean_list.isEmpty()) {

                _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (" + String.valueOf(getProxyCount()) + ")" + (this.isForce_smart_proxy() ? " F!" : ""));

                LOG.log(Level.INFO, "{0} Smart Proxy Manager: proxy list refreshed ({1})", new Object[]{Thread.currentThread().getName(), _proxy_list.size()});
            } else {
                _main_panel.getView().updateSmartProxyStatus("SmartProxy: ON (0 proxies!)" + (this.isForce_smart_proxy() ? " F!" : ""));
                LOG.log(Level.INFO, "{0} Smart Proxy Manager: NO PROXYS");
            }

        } catch (MalformedURLException ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, ex.getMessage());
        } finally {
            if (con != null) {
                con.disconnect();
            }

        }

        _last_refresh_timestamp = System.currentTimeMillis();

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
        public final String path;

        public WireguardConfig(String name, String path) {
            this.name = name;
            this.path = path;
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
                target.put(key, new Long[]{-1L, 3L});
                WIREGUARD_CONFIGS.put(key, new WireguardConfig(name, p.toString()));
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
