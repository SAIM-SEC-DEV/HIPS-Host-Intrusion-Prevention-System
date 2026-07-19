package com.hips.agent.network;
 
import com.hips.agent.anomaly.BaselineCollector;
import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;
import com.hips.agent.osquery.OsFacade;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Network Monitor (Refactored v2.0)
 * ============================================================
 * Core network surveillance module. Periodically scans open
 * ports, tracks active connections, and delegates analysis to
 * specialized sub-modules (ConnectionTracker, PortAnalyzer,
 * IpManager, TrafficAnalyzer, DnsMonitor).
 *
 * OSQUERY INTEGRATION:
 *   Connection and port data is now fetched via the OsFacade
 *   abstraction. On systems with osquery, this uses the
 *   `process_open_sockets` and `listening_ports` tables
 *   (cross-platform). Without osquery, it falls back to
 *   the original PowerShell / netstat commands.
 *
 * ALL EXISTING LOGIC PRESERVED:
 *   - IP whitelisting and blacklisting
 *   - Connection tracking and beaconing detection
 *   - Port analysis and port scan detection
 *   - Traffic pattern analysis
 *   - DNS monitoring
 *   - Server IP auto-whitelisting
 *   - All command handlers (BLOCK_IP, UNBLOCK_IP, WHITELIST_*)
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
    private final BaselineCollector baselineCollector;

    private OsFacade osFacade; // Injected telemetry source

    private ScheduledExecutorService scheduler;
    private volatile boolean running = false;

    // Scan interval in seconds
    private static final int SCAN_INTERVAL = 30;

    public NetworkMonitor(AgentConfig config, ApiClient apiClient, BaselineCollector baselineCollector) {
        this.config            = config;
        this.apiClient         = apiClient;
        this.baselineCollector = baselineCollector;
        this.alertHandler      = new NetworkAlertHandler(apiClient);
        this.ipManager         = new IpManager(alertHandler);
        this.connectionTracker = new ConnectionTracker(alertHandler, ipManager);
        this.portAnalyzer      = new PortAnalyzer(alertHandler, ipManager);
        this.trafficAnalyzer   = new TrafficAnalyzer(alertHandler);
        this.dnsMonitor        = new DnsMonitor(alertHandler);

        // Load whitelisted IPs from config into IpManager
        for (String ip : config.getWhitelistIPs()) {
            ipManager.addToWhitelist(ip);
        }

        // Dynamically whitelist the server's IP/Hostname to prevent beaconing alerts
        // to our own backend or its cloud proxy.
        try {
            URL url = new URL(config.getServerUrl());
            String host = url.getHost();
            if (host != null && !host.isEmpty()) {
                ipManager.addToWhitelist(host);
                // Also attempt to resolve IP if it's a hostname
                InetAddress[] addresses = InetAddress.getAllByName(host);
                for (InetAddress addr : addresses) {
                    ipManager.addToWhitelist(addr.getHostAddress());
                }
            }
        } catch (Exception e) {
            System.err.println("[HIPS-NET] Warning: Could not parse/resolve server URL for whitelisting.");
        }
    }

    /**
     * Injects the OsFacade for cross-platform network telemetry.
     * If not set, falls back to legacy PowerShell/netstat commands.
     */
    public void setOsFacade(OsFacade facade) {
        this.osFacade = facade;
    }

    public void setScheduler(ScheduledExecutorService scheduler) {
        this.scheduler = scheduler;
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
        if (scheduler == null) {
            scheduler = Executors.newScheduledThreadPool(2, r -> {
                Thread t = new Thread(r, "HIPS-NetworkMonitor");
                t.setDaemon(true);
                return t;
            });
        }

        System.out.println("[HIPS-NET] Starting network monitor (interval: " + SCAN_INTERVAL + "s)");
        if (osFacade != null) {
            System.out.println("[HIPS-NET] Using OsFacade backend: " + osFacade.getClass().getSimpleName());
        }

        // Primary scan loop — connections and ports
        scheduler.scheduleAtFixedRate(this::performScan, 5, SCAN_INTERVAL, TimeUnit.SECONDS);

        // DNS monitoring loop — runs less frequently
        scheduler.scheduleAtFixedRate(() -> {
            try { 
                dnsMonitor.monitorDNSQueries(); 
                // Record DNS query rate for baseline
                if (baselineCollector != null) {
                    baselineCollector.recordDnsQueryRate(dnsMonitor.getUniqueDomainCount());
                }
            } catch (Exception e) {
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
            
            // Record connection count for baseline
            if (baselineCollector != null) {
                baselineCollector.recordConnectionCount(connections.size());
            }

            // 2. Scan open ports
            List<Map<String, String>> openPorts = scanOpenPorts();
            
            // Record open ports for baseline
            if (baselineCollector != null) {
                for (Map<String, String> port : openPorts) {
                    try {
                        int p = Integer.parseInt(port.get("local_port"));
                        baselineCollector.recordPortOpen(p);
                    } catch (Exception ignored) {}
                }
            }
            
            // Analyze traffic patterns
            trafficAnalyzer.analyzeTraffic(connections);

            // 2.5 Filter out whitelisted IPs from connections
            int originalSize = connections.size();
            connections.removeIf(conn -> {
                String remoteIP = conn.get("remote_ip");
                if (remoteIP == null || remoteIP.isEmpty()) return true;
                
                String cleanIP = ipManager.normalizeIP(remoteIP);
                
                // Extra check for localhost/loopback
                if (cleanIP.isEmpty() || cleanIP.equals("127.0.0.1") || cleanIP.equals("::1") || 
                    cleanIP.equals("0.0.0.0") || cleanIP.equals("::") || cleanIP.equals("0:0:0:0:0:0:0:1")) {
                    return true;
                }

                return ipManager.isTrustedOrg(cleanIP) || ipManager.isLocalAddress(cleanIP);
            });
            
            if (connections.size() < originalSize) {
                System.out.println("[HIPS-NET] Filtered " + (originalSize - connections.size()) + " trusted/local connections.");
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
                String process  = conn.get("owning_process");
                if (remoteIP != null && !remoteIP.isEmpty()) {
                    ipManager.checkIP(remoteIP, process);
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
     * Lists all currently open (LISTENING) ports on this host.
     * Uses OsFacade if available, otherwise netstat.
     *
     * @return List of maps with keys: protocol, local_address, local_port, state
     */
    public List<Map<String, String>> scanOpenPorts() {
        // Prefer OsFacade
        if (osFacade != null) {
            return osFacade.getListeningPorts();
        }

        // Legacy fallback: netstat -an
        List<Map<String, String>> ports = new ArrayList<>();

        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-an");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {

                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.contains("LISTENING") || line.contains("LISTEN")) {
                        Map<String, String> port = parseNetstatLine(line);
                        if (port != null) {
                            ports.add(port);
                        }
                    }
                }
            }

            process.waitFor(10, TimeUnit.SECONDS);

        } catch (Exception e) {
            System.err.println("[HIPS-NET] Port scan failed: " + e.getMessage());
        }

        return ports;
    }

    // ── Core Function 3: getActiveConnections() ──────────────
    /**
     * Retrieves all active network connections. Uses OsFacade
     * if available, otherwise falls back to PowerShell / netstat.
     *
     * @return List of connection maps
     */
    public List<Map<String, String>> getActiveConnections() {
        // Prefer OsFacade
        if (osFacade != null) {
            return osFacade.getActiveConnections();
        }

        // Legacy fallback: PowerShell → netstat
        List<Map<String, String>> connections = new ArrayList<>();

        try {
            // FIX 3.1 (Process-Aware): Added OwningProcess to PowerShell query
            ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                "Get-NetTCPConnection -State Established,Listen,TimeWait,CloseWait -ErrorAction SilentlyContinue | " +
                "ForEach-Object { $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; " +
                "[PSCustomObject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;" +
                "RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=$_.State;OwningProcess=$p} } | " +
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
                        if (parts.length >= 6) {
                            Map<String, String> conn = new LinkedHashMap<>();
                            conn.put("protocol",        "TCP");
                            conn.put("local_ip",        parts[0]);
                            conn.put("local_port",      parts[1]);
                            conn.put("remote_ip",       parts[2]);
                            conn.put("remote_port",     parts[3]);
                            conn.put("state",           parts[4]);
                            conn.put("owning_process",  parts.length > 5 ? parts[5].toLowerCase() : "");
                            connections.add(conn);
                        }
                    }

                    process.waitFor(10, TimeUnit.SECONDS);
                    return connections;
                }
            }
            process.waitFor(10, TimeUnit.SECONDS);
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
            process.waitFor(10, TimeUnit.SECONDS);
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
        Map<String, Object> result = new HashMap<>();
        result.put("whitelisted", true);
        result.put("ip", ip);
        result.put("message", "IP " + ip + " added to whitelist.");
        return result;
    }

    public Map<String, Object> handleWhitelistRemove(String ip) {
        ipManager.removeFromWhitelist(ip);
        config.removeWhitelistIP(ip);
        config.saveConfig();
        System.out.println("[HIPS-NET] ✓ Removed IP from whitelist: " + ip);
        Map<String, Object> result = new HashMap<>();
        result.put("removed", true);
        result.put("ip", ip);
        result.put("message", "IP " + ip + " removed from whitelist.");
        return result;
    }
}
