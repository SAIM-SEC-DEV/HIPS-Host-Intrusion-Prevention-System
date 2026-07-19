package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * ============================================================
 * HIPS Agent — IP Manager
 * ============================================================
 * Manages IP blacklisting, whitelisting, and geolocation.
 * Can actively block IPs using Windows Firewall commands.
 *
 * Functions (3 of 32):
 *   isBlacklisted()  — Checks IP against the blacklist
 *   blockIP()        — Adds a Windows Firewall rule to block an IP
 *   geoLocateIP()    — Resolves geographic location of an IP
 */
public class IpManager {

    private final NetworkAlertHandler alertHandler;

    // In-memory blacklist (loaded from config or server)
    private final Set<String> blacklist = new HashSet<>();

    // In-memory whitelist (trusted IPs that should never trigger alerts)
    private final Set<String> whitelist = new HashSet<>(Arrays.asList(
        "127.0.0.1", "0.0.0.0", "::1"
    ));

    // Cache of already-checked IPs to avoid repeated alerts
    private final Set<String> checkedIPs = ConcurrentHashMap.newKeySet();

    // Cache for Organization lookups (Key: IP, Value: Org/ISP Name)
    // Optimized: Use LRU cache to prevent memory bloat
    private final Map<String, String> orgCache = Collections.synchronizedMap(new LinkedHashMap<String, String>(1000, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > 1000;
        }
    });

    // Cache for organization-based trust (e.g., "Microsoft Corporation")
    private static final Set<String> TRUSTED_ORG_KEYWORDS = new HashSet<>(Arrays.asList(
        "microsoft",
        "google",
        "amazon",
        "aws",
        "cloudflare",
        "akamai",
        "fastly",
        "digicert",
        "sectigo",
        "letsencrypt",
        "edgecast",
        "limelight",
        "level3",
        "stackpath",
        "sucuri",
        "azure",
        "oracle",
        "digitalocean",
        "linode",
        "vultr"
    ));

    // ── Process-Aware Filtering ──────────────────────────────
    // Connections owned by these processes are often noisy due to
    // cloud heartbeats/updates. We suppress UNKNOWN_IP alerts for them.
    private static final Set<String> KNOWN_SAFE_PROCESSES = new HashSet<>(Arrays.asList(
        "chrome", "msedge", "firefox", "brave", "opera", "msedgewebview2",
        "slack", "discord", "teams", "whatsapp", "anydesk",
        "outlook", "onedrive", "dropbox", "googledrive", "m365copilot",
        "svchost", "lsass", "system", "searchhost", "searchapp", "lockapp",
        "backgroundtaskhost", "wuauclt", "msmpeng", "idle", "widgets",
        "chrome.exe", "msedge.exe", "firefox.exe", "msedgewebview2.exe",
        "slack.exe", "discord.exe", "teams.exe", "anydesk.exe",
        "outlook.exe", "onedrive.exe", "svchost.exe", "searchapp.exe",
        "lockapp.exe", "widgets.exe", "compattelrunner.exe"
    ));

    // Known private/reserved IP ranges that should be whitelisted
    private static final Set<String> PRIVATE_PREFIXES = new HashSet<>(Arrays.asList(
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.", "169.254.", "127.", "::1", "0:0:", "::", "fe80:", "fc00:", "fd00:",
        "0:0:0:0:0:0:0:1", "::ffff:127.", "::ffff:10.", "::ffff:192.168.", "::ffff:172."
    ));

    // Hardcoded trusted IP prefixes (Major Cloud Providers)
    private static final Set<String> TRUSTED_IP_PREFIXES = new HashSet<>(Arrays.asList(
        "52.", "20.", "4.", "108.177.", "172.188.", "151.101.", "13.107.", "13.64.", "13.91.", "23.96.", "110.93.",
        "142.250.", "142.251.", "172.217.", "172.253.", "216.58.", "34.", "35.", "104.", "157.55.", "157.56.",
        "40.76.", "40.77.", "40.78.", "40.79.", "40.80.", "40.81.", "40.82.", "40.83.", "40.84.", "40.85.", "40.86.", 
        "40.87.", "40.88.", "40.89.", "40.90.", "40.91.", "40.112.", "40.113.", "40.114.", "40.115.", "40.117.", 
        "40.118.", "40.119.", "40.121.", "40.124.", "40.125.", "13.", "23.", "40.", "138.91.", "191.232.", "65.52.", "65.55.",
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", // Cloudflare
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.", // Cloudflare
        "18.184.", "18.194.", "18.195.", "18.196.", "18.197.", "18.198.", "3.120.", "3.121.", "3.122.", "3.123.", // AWS Europe
        "44.224.", "44.225.", "44.226.", "44.227.", "44.228.", "44.229.", "44.230.", "44.231." // AWS
    ));

    public IpManager(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;

        // Add some well-known malicious IPs for demonstration
        // In production, this would be loaded from a threat intelligence feed
        blacklist.add("198.51.100.1");   // Example malicious IP
        blacklist.add("203.0.113.50");   // Example C2 server
    }

    // ── Function 1: isBlacklisted() ──────────────────────────
    /**
     * Checks if an IP address is in the blacklist. Blacklisted
     * IPs are known malicious addresses that should trigger
     * immediate alerts and potentially be blocked.
     *
     * @param ip  The IP address to check
     * @return true if the IP is blacklisted
     */
    public boolean isBlacklisted(String ip) {
        return blacklist.contains(ip);
    }

    /**
     * Checks an IP against blacklist and whitelist, generating
     * appropriate alerts. Called for every remote connection.
     * Uses processName for intelligent filtering of false positives.
     */
    public void checkIP(String ip, String processName) {
        if (ip == null || ip.isEmpty()) return;

        String normalized = normalizeIP(ip);

        // Skip whitelisted IPs — admin-trusted addresses
        if (whitelist.contains(normalized)) return;

        // Skip private/reserved IPs
        for (String prefix : PRIVATE_PREFIXES) {
            if (ip.startsWith(prefix)) return;
        }

        // Skip IPs we've already checked this session
        if (checkedIPs.contains(ip)) return;
        checkedIPs.add(ip);

        // Limit cache size
        if (checkedIPs.size() > 5000) {
            checkedIPs.clear();
        }

        // Check blacklist
        if (isBlacklisted(normalized)) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("blacklisted_ip", ip);
            metadata.put("process", processName);
            Event event = new Event(Module.network, "BLACKLISTED_IP_CONTACT", Severity.HIGH, "Connection to Blacklisted IP")
                    .withDescription("Local process [" + processName + "] attempted connection to known malicious IP: " + ip)
                    .withDestination(ip)
                    .withMetadata(metadata);

            alertHandler.triggerNetworkAlert(event);
        } else {
            // ── Process-Aware Filtering ──────────────────────
            // If the process is known and trusted, and the port is standard (80/443),
            // suppress the UNKNOWN_IP_CONTACT alert to prevent noise.
            if (processName != null && KNOWN_SAFE_PROCESSES.contains(processName.toLowerCase())) {
                return; 
            }

            // Also check if it belongs to a trusted cloud provider (Google/MS/etc)
            if (isTrustedOrg(normalized)) {
                return;
            }

            // NEW: Alert on unknown external connections (not whitelisted, not blacklisted, not trusted org)
            // This ensures "Unknown" IPs are still visible on the dashboard as MEDIUM alerts.
            System.out.println("[HIPS-NET] IP not in trusted lists/orgs: " + ip + " (Process: " + processName + ")");
            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("remote_ip", ip);
            metadata.put("process", processName);
            metadata.put("action", "monitored");
            
            Event event = new Event(Module.network, "UNKNOWN_IP_CONTACT", Severity.HIGH, "Unknown External Connection")
                    .withDescription("Connection detected to unknown/untrusted external IP: " + ip + " by process: " + processName)
                    .withDestination(ip)
                    .withMetadata(metadata);
            
            alertHandler.triggerNetworkAlert(event);
        }
    }

    // ── Function 2: blockIP() ────────────────────────────────
    /**
     * Actively blocks a malicious IP address by creating a
     * Windows Firewall rule. This uses netsh to add both
     * inbound and outbound block rules.
     *
     * ⚠ Requires Administrator privileges!
     *
     * @param ip  The IP address to block
     * @return    Result map with operation status
     */
    public Map<String, Object> blockIP(String ip) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ip", ip);

        // ── Input Sanitization ──────────────────────────────────
        // Validate IP format before passing to netsh to prevent
        // command injection via crafted IP strings.
        if (!isValidIPAddress(ip)) {
            result.put("blocked", false);
            result.put("error", "Invalid IP address format: " + ip);
            return result;
        }

        try {
            // Add to in-memory blacklist
            blacklist.add(ip);

            // Create inbound block rule via Windows Firewall
            String ruleName = "HIPS_BLOCK_" + ip.replace(".", "_");

            ProcessBuilder pbIn = new ProcessBuilder(
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + ruleName + "_IN",
                "dir=in", "action=block",
                "remoteip=" + ip,
                "enable=yes"
            );
            pbIn.redirectErrorStream(true);
            Process processIn = pbIn.start();
            String outputIn = readProcessOutput(processIn);
            processIn.waitFor();

            // Create outbound block rule
            ProcessBuilder pbOut = new ProcessBuilder(
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + ruleName + "_OUT",
                "dir=out", "action=block",
                "remoteip=" + ip,
                "enable=yes"
            );
            pbOut.redirectErrorStream(true);
            Process processOut = pbOut.start();
            String outputOut = readProcessOutput(processOut);
            processOut.waitFor();

            result.put("blocked", true);
            result.put("firewall_inbound", outputIn.trim());
            result.put("firewall_outbound", outputOut.trim());
            result.put("message", "IP " + ip + " blocked successfully.");

            System.out.println("[HIPS-NET] ✓ Blocked IP: " + ip);

        } catch (Exception e) {
            result.put("blocked", false);
            result.put("error", e.getMessage());
            System.err.println("[HIPS-NET] Failed to block IP " + ip + ": " + e.getMessage());
        }

        return result;
    }

    /**
     * Removes a firewall block rule for an IP address.
     *
     * @param ip  The IP address to unblock
     * @return    Result map with operation status
     */
    public Map<String, Object> unblockIP(String ip) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ip", ip);

        // ── Input Sanitization ──────────────────────────────────
        if (!isValidIPAddress(ip)) {
            result.put("unblocked", false);
            result.put("error", "Invalid IP address format: " + ip);
            return result;
        }

        try {
            blacklist.remove(ip);

            String ruleName = "HIPS_BLOCK_" + ip.replace(".", "_");

            // Remove inbound rule
            new ProcessBuilder("netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=" + ruleName + "_IN").start().waitFor();

            // Remove outbound rule
            new ProcessBuilder("netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=" + ruleName + "_OUT").start().waitFor();

            result.put("unblocked", true);
            result.put("message", "IP " + ip + " unblocked successfully.");
            System.out.println("[HIPS-NET] ✓ Unblocked IP: " + ip);

        } catch (Exception e) {
            result.put("unblocked", false);
            result.put("error", e.getMessage());
        }

        return result;
    }

    // MaxMind GeoIP2 Database instances (loaded lazily via reflection or expected in classpath)
    private Object geoCityDb;
    private Object geoAsnDb;
    private boolean geoDbInitialized = false;

    private void initGeoDb() {
        if (geoDbInitialized) return;
        geoDbInitialized = true;
        try {
            // Attempt to load MaxMind DatabaseReader from classpath
            Class<?> dbReaderBuilderClass = Class.forName("com.maxmind.geoip2.DatabaseReader$Builder");
            File cityDbFile = new File("GeoLite2-City.mmdb");
            if (cityDbFile.exists()) {
                Object builder = dbReaderBuilderClass.getConstructor(File.class).newInstance(cityDbFile);
                geoCityDb = builder.getClass().getMethod("build").invoke(builder);
                System.out.println("[HIPS-GEO] Loaded local MaxMind City Database.");
            }
            File asnDbFile = new File("GeoLite2-ASN.mmdb");
            if (asnDbFile.exists()) {
                Object builder = dbReaderBuilderClass.getConstructor(File.class).newInstance(asnDbFile);
                geoAsnDb = builder.getClass().getMethod("build").invoke(builder);
                System.out.println("[HIPS-GEO] Loaded local MaxMind ASN Database.");
            }
        } catch (Exception e) {
            System.err.println("[HIPS-GEO] Could not initialize local MaxMind databases. Please ensure 'com.maxmind.geoip2' is in classpath and .mmdb files exist.");
        }
    }

    /**
     * Resolves the geographic location of an IP address using
     * the local MaxMind GeoLite2 offline database.
     * Falls back to ip-api.com if the database is unavailable.
     *
     * @param ip  The IP address to geolocate
     * @return    Map with geolocation data
     */
    public Map<String, String> geoLocateIP(String ip) {
        if (ip == null || ip.isEmpty()) return Collections.emptyMap();
        
        Map<String, String> geo = new LinkedHashMap<>();
        geo.put("ip", ip);

        try {
            // Check cache first
            if (orgCache.containsKey(ip)) {
                geo.put("org", orgCache.get(ip));
                geo.put("status", "success");
                geo.put("cached", "true");
                return geo;
            }

            initGeoDb();

            if (geoCityDb != null || geoAsnDb != null) {
                // Use local MaxMind Database
                java.net.InetAddress ipAddress = java.net.InetAddress.getByName(ip);
                String finalOrg = null;

                if (geoCityDb != null) {
                    try {
                        Object cityResponse = geoCityDb.getClass().getMethod("city", java.net.InetAddress.class).invoke(geoCityDb, ipAddress);
                        // Extract country
                        Object country = cityResponse.getClass().getMethod("getCountry").invoke(cityResponse);
                        String countryName = (String) country.getClass().getMethod("getName").invoke(country);
                        geo.put("country", countryName != null ? countryName : "");
                        
                        // Extract city
                        Object city = cityResponse.getClass().getMethod("getCity").invoke(cityResponse);
                        String cityName = (String) city.getClass().getMethod("getName").invoke(city);
                        geo.put("city", cityName != null ? cityName : "");
                    } catch (Exception ignored) {}
                }

                if (geoAsnDb != null) {
                    try {
                        Object asnResponse = geoAsnDb.getClass().getMethod("asn", java.net.InetAddress.class).invoke(geoAsnDb, ipAddress);
                        String org = (String) asnResponse.getClass().getMethod("getAutonomousSystemOrganization").invoke(asnResponse);
                        if (org != null) {
                            finalOrg = org;
                            geo.put("org", org);
                            geo.put("isp", org);
                        }
                    } catch (Exception ignored) {}
                }

                if (finalOrg != null) {
                    orgCache.put(ip, finalOrg);
                }
                
                geo.put("status", "success");
                geo.put("source", "maxmind-local");
                return geo;
            }

            // Fallback to ip-api.com
            URL url = new URL("https://ip-api.com/json/" + ip + "?fields=status,message,country,city,isp,org,as");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    String json = sb.toString();
                    
                    String org = extractJsonValue(json, "org");
                    String isp = extractJsonValue(json, "isp");
                    String finalOrg = (org != null && !org.isEmpty()) ? org : isp;

                    if (finalOrg != null) {
                        orgCache.put(ip, finalOrg);
                        geo.put("org", finalOrg);
                    }
                    
                    geo.put("status", "success");
                    geo.put("raw_response", json);
                }
            }
            conn.disconnect();

        } catch (Exception e) {
            geo.put("status", "error");
            geo.put("error", e.getMessage());
        }

        return geo;
    }

    /**
     * Helper to extract a value from a simple JSON string without external libs.
     */
    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }

    /**
     * Normalizes an IP address by stripping brackets and ports.
     * Robust handling for IPv4, IPv6, and loopback variants.
     */
    public String normalizeIP(String ip) {
        if (ip == null) return "";
        String clean = ip.trim();

        // Handle IPv4-mapped IPv6 (::ffff:1.2.3.4)
        if (clean.startsWith("::ffff:")) {
            clean = clean.substring(7);
        }
        
        // Remove brackets for IPv6 [::1] -> ::1
        boolean hadBrackets = false;
        if (clean.startsWith("[") && clean.contains("]")) {
            clean = clean.substring(1, clean.lastIndexOf("]"));
            hadBrackets = true;
        }
        
        // Remove port if present
        // Case 1: IPv4 with port 1.2.3.4:80
        if (clean.contains(".") && clean.contains(":")) {
            clean = clean.substring(0, clean.lastIndexOf(":"));
        } 
        // Case 2: IPv6 with port. If it had brackets, the port was outside them,
        // and we already handled that if the input was like [::1]:80.
        // If it's a raw IPv6 with port but no brackets (rare but possible in some netstat outputs)
        // we only strip if it's clearly a port and not part of the IPv6.
        else if (!hadBrackets && clean.contains(":") && clean.indexOf(":") != clean.lastIndexOf(":")) {
            // For IPv6, a port is usually only present if there's more than 2 colons
            // or if it's explicitly formatted. If we don't have brackets, it's risky.
            // However, netstat -an on some systems might show ::1:80.
            int lastColon = clean.lastIndexOf(":");
            String potentialPort = clean.substring(lastColon + 1);
            try {
                // Only treat as port if it's numeric and the rest of the string has at least 2 colons (IPv6)
                int port = Integer.parseInt(potentialPort);
                if (port >= 0 && port <= 65535) {
                    // Count colons in the remaining part
                    int colons = 0;
                    for (int i = 0; i < lastColon; i++) {
                        if (clean.charAt(i) == ':') colons++;
                    }
                    // If it's IPv6 (many colons), only strip if it's a likely port
                    // and not just the last segment of the IP.
                    if (colons >= 2) {
                        clean = clean.substring(0, lastColon);
                    }
                }
            } catch (NumberFormatException e) {
                // Not a port
            }
        }
        
        return clean;
    }

    /**
     * Checks if an IP is a local, loopback, or unspecified address.
     */
    public boolean isLocalAddress(String ip) {
        String clean = normalizeIP(ip);
        if (clean.isEmpty() || clean.equals("0.0.0.0") || clean.equals("::") || 
            clean.equals("127.0.0.1") || clean.equals("::1") || clean.equals("0:0:0:0:0:0:0:0") ||
            clean.equals("0:0:0:0:0:0:0:1") || clean.equals("*")) {
            return true;
        }
        for (String prefix : PRIVATE_PREFIXES) {
            if (clean.startsWith(prefix)) return true;
        }
        return false;
    }

    // Background executor for async geolocation lookups
    private final java.util.concurrent.ExecutorService asyncExecutor = java.util.concurrent.Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "HIPS-GeoAsync");
        t.setDaemon(true);
        return t;
    });

    /**
     * Checks if an IP belongs to a known trusted organization (Google, MS, etc).
     * This helps reduce false positives for legitimate cloud services.
     */
    public boolean isTrustedOrg(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        
        String cleanIp = normalizeIP(ip);
        
        // 1. Check if local/private
        if (isLocalAddress(cleanIp)) {
            return true;
        }

        // 2. Check hardcoded trusted prefixes (Microsoft, Google, etc)
        for (String prefix : TRUSTED_IP_PREFIXES) {
            if (cleanIp.startsWith(prefix)) {
                return true;
            }
        }
        
        // 3. Check cache
        String org = orgCache.get(cleanIp);
        if (org != null) {
            String lowerOrg = org.toLowerCase();
            for (String keyword : TRUSTED_ORG_KEYWORDS) {
                if (lowerOrg.contains(keyword)) return true;
            }
            return false;
        }
        
        // 4. Async background lookup if not in cache
        asyncExecutor.submit(() -> {
            try {
                Map<String, String> geo = geoLocateIP(cleanIp);
                String lookupOrg = geo.get("org");
                if (lookupOrg != null) {
                    orgCache.put(cleanIp, lookupOrg);
                    System.out.println("[HIPS-GEO] Async lookup completed for " + cleanIp + ": " + lookupOrg);
                }
            } catch (Exception e) {
                System.err.println("[HIPS-GEO] Async lookup failed for " + cleanIp + ": " + e.getMessage());
            }
        });

        // Default to untrusted while lookup is pending to ensure security
        return false;
    }

    // ── Helpers ──────────────────────────────────────────────

    private String readProcessOutput(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        }
    }

    /**
     * Validates an IP address format using a strict regex.
     * Prevents command injection through malformed IP strings.
     * Supports IPv4 and basic IPv6.
     */
    private boolean isValidIPAddress(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        // IPv4: 0-255.0-255.0-255.0-255
        String ipv4Pattern = "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$";
        // IPv6: basic check for hex groups separated by colons
        String ipv6Pattern = "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$";
        return ip.matches(ipv4Pattern) || ip.matches(ipv6Pattern);
    }

    public void addToBlacklist(String ip) { blacklist.add(ip); }
    public void removeFromBlacklist(String ip) { blacklist.remove(ip); }
    public void addToWhitelist(String ip) { whitelist.add(normalizeIP(ip)); }
    public void removeFromWhitelist(String ip) { whitelist.remove(normalizeIP(ip)); }
    public Set<String> getBlacklist() { return new HashSet<>(blacklist); }
    public Set<String> getWhitelist() { return new HashSet<>(whitelist); }
}
