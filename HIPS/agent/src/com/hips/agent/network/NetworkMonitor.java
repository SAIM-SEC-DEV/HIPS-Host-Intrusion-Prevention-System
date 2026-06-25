package com.hips.agent.network;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Network Monitor
 * ============================================================
 * Core network surveillance module. Periodically scans open
 * ports, tracks active connections, and delegates analysis to
 * specialized sub-modules (ConnectionTracker, PortAnalyzer,
 * IpManager, TrafficAnalyzer, DnsMonitor).
 *
 * Uses Windows netstat / PowerShell commands for data collection
 * since Java doesn't have native low-level network access.
 *
 * Functions (3 of 32 — core):
 *   startNetworkMonitor()  — Begins periodic scanning
 *   scanOpenPorts()        — Lists all open ports on host
 *   getActiveConnections() — Retrieves all active connections
 */
public class NetworkMonitor {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private final ConnectionTracker connectionTracker;
    private final PortAnalyzer portAnalyzer;
    private final IpManager ipManager;
    private final TrafficAnalyzer trafficAnalyzer;
    private final DnsMonitor dnsMonitor;
    private final NetworkAlertHandler alertHandler;

    private ScheduledExecutorService scheduler;
    private volatile boolean running = false;

    // Scan interval in seconds
    private static final int SCAN_INTERVAL = 30;

    public NetworkMonitor(AgentConfig config, ApiClient apiClient) {
        this.config            = config;
        this.apiClient         = apiClient;
        this.alertHandler      = new NetworkAlertHandler(apiClient);
        this.connectionTracker = new ConnectionTracker(alertHandler);
        this.portAnalyzer      = new PortAnalyzer(alertHandler);
        this.ipManager         = new IpManager(alertHandler);
        this.trafficAnalyzer   = new TrafficAnalyzer(alertHandler);
        this.dnsMonitor        = new DnsMonitor(alertHandler);

        // Load whitelisted IPs from config into IpManager
        for (String ip : config.getWhitelistIPs()) {
            ipManager.addToWhitelist(ip);
        }
    }

    // ── Core Function 1: startNetworkMonitor() ───────────────
    /**
     * Begins periodic scanning of the host's network state.
     * Runs every 30 seconds on a dedicated daemon thread.
     */
    public void startNetworkMonitor() {
        if (running) {
            System.out.println("[HIPS-NET] Network monitor is already running.");
            return;
        }

        running = true;
        scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "HIPS-NetworkMonitor");
            t.setDaemon(true);
            return t;
        });

        System.out.println("[HIPS-NET] Starting network monitor (interval: " + SCAN_INTERVAL + "s)");

        // Primary scan loop — connections and ports
        scheduler.scheduleAtFixedRate(this::performScan, 5, SCAN_INTERVAL, TimeUnit.SECONDS);

        // DNS monitoring loop — runs less frequently
        scheduler.scheduleAtFixedRate(() -> {
            try { dnsMonitor.monitorDNSQueries(); } catch (Exception e) {
                System.err.println("[HIPS-NET] DNS monitor error: " + e.getMessage());
            }
        }, 10, 60, TimeUnit.SECONDS);

        System.out.println("[HIPS-NET] ✓ Network monitoring started.");
    }

    /**
     * Stops the network monitor gracefully.
     */
    public void stopNetworkMonitor() {
        running = false;
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[HIPS-NET] Network monitoring stopped.");
    }

    /**
     * Performs a single scan cycle: collects connections, checks
     * ports, evaluates IPs, and analyzes traffic patterns.
     */
    private void performScan() {
        try {
            // 1. Get current active connections
            List<Map<String, String>> connections = getActiveConnections();

            // 2. Scan open ports
            List<Map<String, String>> openPorts = scanOpenPorts();

            // 2.5 Filter out whitelisted IPs from connections
            Set<String> wl = ipManager.getWhitelist();
            if (!wl.isEmpty()) {
                connections.removeIf(conn -> {
                    String remoteIP = conn.get("remote_ip");
                    return remoteIP != null && wl.contains(remoteIP);
                });
            }

            // 3. Track connections and detect anomalies
            connectionTracker.trackConnections(connections);
            connectionTracker.detectConnectionSpike();
            connectionTracker.detectBeaconing(connections);

            // 4. Analyze ports for suspicious activity
            portAnalyzer.analyzeOpenPorts(openPorts);
            portAnalyzer.detectPortScan(connections);

            // 5. Check IPs against blacklist
            for (Map<String, String> conn : connections) {
                String remoteIP = conn.get("remote_ip");
                if (remoteIP != null && !remoteIP.isEmpty()) {
                    ipManager.checkIP(remoteIP);
                }
            }

            // 6. Analyze traffic patterns
            trafficAnalyzer.analyzeTraffic(connections);

        } catch (Exception e) {
            System.err.println("[HIPS-NET] Scan cycle error: " + e.getMessage());
        }
    }

    // ── Core Function 2: scanOpenPorts() ─────────────────────
    /**
     * Lists all currently open (LISTENING) ports on this host
     * by parsing the output of 'netstat -an'. Returns a list
     * of port entries with protocol, local address, and state.
     *
     * @return List of maps with keys: protocol, local_address, local_port, state
     */
    public List<Map<String, String>> scanOpenPorts() {
        List<Map<String, String>> ports = new ArrayList<>();

        try {
            // Execute netstat to get listening ports
            ProcessBuilder pb = new ProcessBuilder("netstat", "-an");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    // Parse lines that show LISTENING state
                    if (line.contains("LISTENING") || line.contains("LISTEN")) {
                        Map<String, String> port = parseNetstatLine(line);
                        if (port != null) {
                            ports.add(port);
                        }
                    }
                }
            }

            process.waitFor();

        } catch (Exception e) {
            System.err.println("[HIPS-NET] Port scan failed: " + e.getMessage());
        }

        return ports;
    }

    // ── Core Function 3: getActiveConnections() ──────────────
    /**
     * Retrieves all active network connections using PowerShell's
     * Get-NetTCPConnection for structured data. Falls back to
     * netstat parsing if PowerShell is unavailable.
     *
     * @return List of connection maps
     */
    public List<Map<String, String>> getActiveConnections() {
        List<Map<String, String>> connections = new ArrayList<>();

        try {
            // Attempt structured retrieval via PowerShell (preferred)
            ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                "Get-NetTCPConnection -State Established,Listen,TimeWait,CloseWait -ErrorAction SilentlyContinue | " +
                "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | " +
                "ConvertTo-Csv -NoTypeInformation");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String header = reader.readLine(); // skip CSV header
                if (header != null && header.contains("LocalAddress")) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim().replace("\"", "");
                        String[] parts = line.split(",");
                        if (parts.length >= 5) {
                            Map<String, String> conn = new LinkedHashMap<>();
                            conn.put("protocol", "TCP");
                            conn.put("local_ip", parts[0]);
                            conn.put("local_port", parts[1]);
                            conn.put("remote_ip", parts[2]);
                            conn.put("remote_port", parts[3]);
                            conn.put("state", parts[4]);
                            connections.add(conn);
                        }
                    }
                    process.waitFor();
                    return connections;
                }
            }
            process.waitFor();
        } catch (Exception e) {
            // PowerShell unavailable — fall through to netstat
        }

        // ── Fallback: parse netstat output ──────────────────────
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-an");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("TCP") || line.startsWith("UDP")) {
                        Map<String, String> conn = parseNetstatLine(line);
                        if (conn != null) {
                            connections.add(conn);
                        }
                    }
                }
            }
            process.waitFor();
        } catch (Exception e) {
            System.err.println("[HIPS-NET] Connection scan failed: " + e.getMessage());
        }

        return connections;
    }

    /**
     * Parses a single netstat output line into a structured map.
     * Expected format (Windows):
     *   TCP    0.0.0.0:80       0.0.0.0:0       LISTENING
     *   TCP    192.168.1.5:49152  93.184.216.34:443  ESTABLISHED
     */
    private Map<String, String> parseNetstatLine(String line) {
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 4) return null;

            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("protocol", parts[0]);

            // Parse local address (IP:port)
            String[] localParts = splitAddress(parts[1]);
            entry.put("local_ip", localParts[0]);
            entry.put("local_port", localParts[1]);

            // Parse remote address (IP:port)
            String[] remoteParts = splitAddress(parts[2]);
            entry.put("remote_ip", remoteParts[0]);
            entry.put("remote_port", remoteParts[1]);

            // State (LISTENING, ESTABLISHED, etc.)
            entry.put("state", parts.length > 3 ? parts[3] : "UNKNOWN");

            return entry;

        } catch (Exception e) {
            return null; // Skip unparseable lines
        }
    }

    /**
     * Splits an address string (e.g., "192.168.1.5:8080") into
     * [IP, port]. Handles IPv6 bracket notation.
     */
    private String[] splitAddress(String address) {
        int lastColon = address.lastIndexOf(':');
        if (lastColon <= 0) return new String[]{address, "0"};
        return new String[]{
            address.substring(0, lastColon),
            address.substring(lastColon + 1)
        };
    }

    // ── Command handlers for server-dispatched commands ──────

    /**
     * Handles BLOCK_IP command from the server.
     */
    public Map<String, Object> handleBlockIP(String ip) {
        return ipManager.blockIP(ip);
    }

    /**
     * Handles UNBLOCK_IP command from the server.
     */
    public Map<String, Object> handleUnblockIP(String ip) {
        return ipManager.unblockIP(ip);
    }

    // ── Accessors ────────────────────────────────────────────

    public boolean isRunning()                   { return running; }
    public ConnectionTracker getConnectionTracker() { return connectionTracker; }
    public PortAnalyzer getPortAnalyzer()        { return portAnalyzer; }
    public IpManager getIpManager()              { return ipManager; }
    public TrafficAnalyzer getTrafficAnalyzer()  { return trafficAnalyzer; }
    public DnsMonitor getDnsMonitor()            { return dnsMonitor; }

    // ── Whitelist management ─────────────────────────────────

    public Map<String, Object> handleWhitelistAdd(String ip) {
        ipManager.addToWhitelist(ip);
        config.addWhitelistIP(ip);
        config.saveConfig();
        System.out.println("[HIPS-NET] ✓ Whitelisted IP: " + ip);
        return Map.of("whitelisted", true, "ip", ip, "message", "IP " + ip + " added to whitelist.");
    }

    public Map<String, Object> handleWhitelistRemove(String ip) {
        ipManager.removeFromWhitelist(ip);
        config.removeWhitelistIP(ip);
        config.saveConfig();
        System.out.println("[HIPS-NET] ✓ Removed IP from whitelist: " + ip);
        return Map.of("removed", true, "ip", ip, "message", "IP " + ip + " removed from whitelist.");
    }
}
