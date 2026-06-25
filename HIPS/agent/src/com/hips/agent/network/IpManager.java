package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();

    // In-memory whitelist (trusted IPs that should never trigger alerts)
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();

    // Cache of already-checked IPs to avoid repeated alerts
    private final Set<String> checkedIPs = ConcurrentHashMap.newKeySet();

    // Known private/reserved IP ranges that should be whitelisted
    private static final Set<String> PRIVATE_PREFIXES = Set.of(
        "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "0.0.0.0", "::1"
    );

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
     */
    public void checkIP(String ip) {
        if (ip == null || ip.isEmpty()) return;

        // Skip whitelisted IPs — admin-trusted addresses
        if (whitelist.contains(ip)) return;

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
        if (isBlacklisted(ip)) {
            Event event = new Event(Module.network, "BLACKLISTED_IP", Severity.CRITICAL,
                    "Connection to blacklisted IP: " + ip)
                    .withDescription("The host has established a connection to a known " +
                        "malicious IP address: " + ip + ". This could indicate malware " +
                        "communication or a compromised application.")
                    .withDestination(ip)
                    .withMetadata(Map.of("blacklisted_ip", ip));

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

    // ── Function 3: geoLocateIP() ────────────────────────────
    /**
     * Resolves the geographic location of an IP address using
     * the free ip-api.com service. Returns country, city, ISP,
     * and other metadata.
     *
     * Note: Rate-limited to 45 requests/minute on the free tier.
     *
     * @param ip  The IP address to geolocate
     * @return    Map with geolocation data
     */
    public Map<String, String> geoLocateIP(String ip) {
        Map<String, String> geo = new LinkedHashMap<>();
        geo.put("ip", ip);

        try {
            URL url = new URL("http://ip-api.com/json/" + ip + "?fields=status,message,country,city,isp,org,as");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    // Simple JSON parsing (avoid full Gson dependency here)
                    String json = sb.toString();
                    geo.put("raw_response", json);
                    geo.put("status", "success");
                }
            }
            conn.disconnect();

        } catch (Exception e) {
            geo.put("status", "error");
            geo.put("error", e.getMessage());
        }

        return geo;
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
    public void addToWhitelist(String ip) { whitelist.add(ip); }
    public void removeFromWhitelist(String ip) { whitelist.remove(ip); }
    public Set<String> getBlacklist() { return Set.copyOf(blacklist); }
    public Set<String> getWhitelist() { return Set.copyOf(whitelist); }
}
