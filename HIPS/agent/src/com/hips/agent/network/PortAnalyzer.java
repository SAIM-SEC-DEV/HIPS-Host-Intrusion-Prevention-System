package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — Port Analyzer
 * ============================================================
 * Analyzes open ports and detects port scanning activity.
 *
 * Functions (2 of 32):
 *   detectPortScan()   — Flags rapid multi-port connection attempts
 *   isSensitivePort()  — Checks if a port is high-risk
 */
public class PortAnalyzer {

    private final NetworkAlertHandler alertHandler;

    // Ports that are commonly targeted by attackers
    private static final Set<Integer> SENSITIVE_PORTS = Set.of(
        21,    // FTP
        22,    // SSH
        23,    // Telnet — should never be open
        25,    // SMTP
        53,    // DNS
        135,   // Windows RPC
        139,   // NetBIOS
        445,   // SMB — WannaCry attack vector
        1433,  // MS SQL Server
        1434,  // MS SQL Browser
        3306,  // MySQL
        3389,  // RDP — often brute-forced
        5432,  // PostgreSQL
        5900,  // VNC
        8080,  // Alt HTTP — common for proxies/backdoors
        8443   // Alt HTTPS
    );

    // Port scan detection: track unique ports per remote IP within a time window
    // Key = remote IP, Value = set of ports accessed + first seen timestamp
    private final Map<String, PortScanTracker> scanTrackers = new ConcurrentHashMap<>();
    private static final int PORT_SCAN_THRESHOLD = 10;       // 10+ ports from same IP
    private static final long PORT_SCAN_WINDOW_MS = 60_000;  // within 60 seconds

    // Deduplication: track ports already alerted to avoid spamming every scan cycle
    private final Set<Integer> alreadyAlertedPorts = ConcurrentHashMap.newKeySet();

    private static class PortScanTracker {
        final Set<String> ports = ConcurrentHashMap.newKeySet();
        final long firstSeen = System.currentTimeMillis();
        boolean alerted = false;
    }

    public PortAnalyzer(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // ── Function 1: detectPortScan() ─────────────────────────
    /**
     * Detects port scanning activity by monitoring how many
     * different ports a single remote IP connects to within a
     * short time window. If an IP touches 10+ ports in 60 seconds,
     * it's flagged as a port scan.
     *
     * Port scanning is a reconnaissance technique used by attackers
     * to discover which services are running on a target.
     *
     * @param connections  Current active connections
     */
    public void detectPortScan(List<Map<String, String>> connections) {
        long now = System.currentTimeMillis();

        // Clean up expired trackers
        scanTrackers.entrySet().removeIf(e ->
            (now - e.getValue().firstSeen) > PORT_SCAN_WINDOW_MS
        );

        // Track ports per remote IP
        for (Map<String, String> conn : connections) {
            String remoteIP = conn.get("remote_ip");
            String localPort = conn.get("local_port");

            if (remoteIP == null || localPort == null) continue;
            // Exclude local and unspecified addresses (listening sockets)
            if (remoteIP.equals("127.0.0.1") || remoteIP.equals("0.0.0.0") || 
                remoteIP.equals("[::]") || remoteIP.equals("::") || remoteIP.equals("*")) continue;

            PortScanTracker tracker = scanTrackers.computeIfAbsent(
                remoteIP, k -> new PortScanTracker()
            );
            tracker.ports.add(localPort);

            // Check if threshold is exceeded
            if (tracker.ports.size() >= PORT_SCAN_THRESHOLD && !tracker.alerted) {
                tracker.alerted = true;

                Event event = new Event(Module.network, "PORT_SCAN_DETECTED", Severity.CRITICAL,
                        "Port scan detected from " + remoteIP)
                        .withDescription(String.format(
                            "Remote IP %s has connected to %d different ports in %.0f seconds. " +
                            "Ports accessed: %s. This is a strong indicator of reconnaissance activity.",
                            remoteIP, tracker.ports.size(),
                            (now - tracker.firstSeen) / 1000.0,
                            tracker.ports.toString()))
                        .withDestination(remoteIP)
                        .withMetadata(Map.of(
                            "source_ip", remoteIP,
                            "ports_scanned", tracker.ports.size(),
                            "ports", new ArrayList<>(tracker.ports),
                            "window_seconds", PORT_SCAN_WINDOW_MS / 1000
                        ));

                alertHandler.triggerNetworkAlert(event);
            }
        }
    }

    // ── Function 2: isSensitivePort() ────────────────────────
    /**
     * Checks if a port number is in the high-risk list.
     * Access to sensitive ports from unexpected sources should
     * raise the severity of any associated events.
     *
     * @param port  The port number to check
     * @return true if the port is considered sensitive
     */
    public boolean isSensitivePort(int port) {
        return SENSITIVE_PORTS.contains(port);
    }

    /**
     * Analyzes all currently open ports and generates alerts
     * for any sensitive ports that are listening.
     */
    public void analyzeOpenPorts(List<Map<String, String>> openPorts) {
        // Collect currently open sensitive ports to detect when one closes
        Set<Integer> currentlyOpen = new HashSet<>();

        for (Map<String, String> port : openPorts) {
            try {
                int portNum = Integer.parseInt(port.get("local_port"));
                if (isSensitivePort(portNum)) {
                    currentlyOpen.add(portNum);

                    // Only alert if this port was NOT already reported
                    if (alreadyAlertedPorts.add(portNum)) {
                        String localAddr = port.get("local_ip") + ":" + portNum;
                        Event event = new Event(Module.network, "SENSITIVE_PORT_OPEN", Severity.HIGH,
                                "Sensitive port " + portNum + " is listening")
                                .withDescription(String.format(
                                    "Port %d is open and listening on %s. This port is commonly " +
                                    "targeted by attackers.", portNum, localAddr))
                                .withMetadata(Map.of(
                                    "port", portNum,
                                    "protocol", port.getOrDefault("protocol", "TCP"),
                                    "local_address", localAddr
                                ));

                        alertHandler.logNetworkEvent(event);
                    }
                }
            } catch (NumberFormatException ignored) {}
        }

        // If a port was previously alerted but is now closed, remove from tracked set
        // so it will be re-alerted if it opens again later
        alreadyAlertedPorts.retainAll(currentlyOpen);
    }

    public Set<Integer> getSensitivePorts() {
        return SENSITIVE_PORTS;
    }
}
