package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — Port Analyzer (Refactored v1.1)
 * ============================================================
 *
 * FIXES APPLIED:
 *   - FIX 2.4 (Slow Scan Evasion): Detection window extended
 *     from 60s → 5 minutes. Unique ports tracked per IP across
 *     ALL scan cycles (not just the current one), using a
 *     sliding window with timestamp-based eviction. This catches
 *     "Slow and Low" scans that spread over several minutes.
 *
 *   - FIX 2.5 (Alert Fatigue / Non-Risky Events): The
 *     analyzeOpenPorts() method only LOGS sensitive ports (not
 *     alerts). A port is only alerted if it has been open
 *     consistently for less than 2 scan cycles — meaning it is
 *     NEWLY opened, which is the actual threat indicator.
 *
 *   - FIX 2.5 (Process-Aware): Connections owned by
 *     KNOWN_SAFE_PROCESSES are excluded from port scan analysis
 *     to prevent Chrome/Slack/etc from triggering false positives.
 */
public class PortAnalyzer {

    private final NetworkAlertHandler alertHandler;
    private final IpManager           ipManager;

    // List of ports that are considered "sensitive" or suspicious if opened
    private static final Set<Integer> SENSITIVE_PORTS = new HashSet<>(Arrays.asList(
        21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 445, 3389, 5900, 5985, 5986, 8080
    ));

    // ── FIX 2.4: Sliding window port scan detection ───────────
    // Key = remote IP, Value = map of local_port → first_seen_timestamp
    private final Map<String, Map<String, Long>> scanPortHistory = new ConcurrentHashMap<>();
    private static final int    PORT_SCAN_THRESHOLD  = 10;
    private static final long   PORT_SCAN_WINDOW_MS  = 5 * 60 * 1000L; // 5 minutes (was 60s)

    // ── FIX 2.5: Track port open duration to find NEWLY opened ports ──
    // Key = port number, Value = consecutive scan count it's been open
    private final Map<Integer, Integer> portOpenCount = new ConcurrentHashMap<>();
    private static final int NEW_PORT_THRESHOLD = 2; // alert only in first 2 scans

    // Alert dedup set for ports (resets when port closes)
    private final Set<Integer> alreadyAlertedPorts = ConcurrentHashMap.newKeySet();

    // Common system processes that are known to open ports safely
    private static final Set<String> KNOWN_SAFE_PROCESSES = new HashSet<>(Arrays.asList(
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "System",
        "msedge.exe", "chrome.exe", "firefox.exe", "slack.exe", "discord.exe",
        "code.exe", "java.exe"
    ));

    public PortAnalyzer(NetworkAlertHandler alertHandler, IpManager ipManager) {
        this.alertHandler = alertHandler;
        this.ipManager    = ipManager;
    }

    // ── Function 1: detectPortScan() ─────────────────────────
    /**
     * FIX 2.4: Uses a 5-minute sliding window to accumulate
     * unique ports per remote IP. Timestamps older than 5 minutes
     * are evicted. This catches slow scans that bypass 60s windows.
     */
    public void detectPortScan(List<Map<String, String>> connections) {
        long now = System.currentTimeMillis();

        // Evict entire IPs whose oldest entry has expired
        scanPortHistory.entrySet().removeIf(entry -> {
            entry.getValue().values().removeIf(ts -> (now - ts) > PORT_SCAN_WINDOW_MS);
            return entry.getValue().isEmpty();
        });

        for (Map<String, String> conn : connections) {
            String state = conn.getOrDefault("state", "").toUpperCase();
            // FIX: Skip listening sockets. A port scan is an incoming connection attempt (Established/SynSent),
            // not us just waiting for a connection. This prevents false alerts from [::] or 0.0.0.0.
            if (state.contains("LISTEN")) continue;

            String remoteIP   = conn.get("remote_ip");
            String localPort  = conn.get("local_port");

            // FIX 2.5: Skip whitelisted process connections
            String owningProcess = conn.getOrDefault("owning_process", "").toLowerCase();
            if (KNOWN_SAFE_PROCESSES.contains(owningProcess)) continue;

            if (remoteIP == null || localPort == null) continue;
            
            // FIX: Use IpManager for robust normalization and trust/local status filtering
            String cleanRemoteIP = (ipManager != null) ? ipManager.normalizeIP(remoteIP) : remoteIP.trim();

            if (ipManager != null) {
                if (ipManager.isLocalAddress(cleanRemoteIP) || ipManager.isTrustedOrg(cleanRemoteIP)) {
                    continue;
                }
            }

            // Fallback for case where ipManager might be null
            if (cleanRemoteIP.isEmpty() || cleanRemoteIP.equals("127.0.0.1") || cleanRemoteIP.equals("::1") || 
                cleanRemoteIP.equals("0.0.0.0") || cleanRemoteIP.equals("::") || cleanRemoteIP.equals("*") ||
                cleanRemoteIP.equals("0:0:0:0:0:0:0:1")) {
                continue;
            }

            Map<String, Long> portTimestamps = scanPortHistory
                .computeIfAbsent(cleanRemoteIP, k -> new ConcurrentHashMap<>());

            // Record this port if not already seen in window
            portTimestamps.putIfAbsent(localPort, now);

            // Check if threshold exceeded
            if (portTimestamps.size() >= PORT_SCAN_THRESHOLD) {
                // Re-verify trust just in case (e.g. geolocation finished)
                if (ipManager != null && ipManager.isTrustedOrg(cleanRemoteIP)) {
                    System.out.println("[HIPS-NET] Skipping port scan alert for trusted IP: " + cleanRemoteIP);
                    scanPortHistory.remove(cleanRemoteIP);
                    continue;
                }

                long windowMs   = now - Collections.min(portTimestamps.values());
                double windowSec = windowMs / 1000.0;

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("source_ip",       cleanRemoteIP);
                metadata.put("ports_scanned",   portTimestamps.size());
                metadata.put("ports",           new ArrayList<>(portTimestamps.keySet()));
                metadata.put("window_seconds",  (int) windowSec);

                Event event = new Event(Module.network, "PORT_SCAN_DETECTED", Severity.CRITICAL,
                        "Port scan detected from " + remoteIP)
                        .withDescription(String.format(
                            "Remote IP %s has connected to %d different local ports in %.0f seconds " +
                            "(5-minute sliding window). Ports: %s. Strong indicator of reconnaissance.",
                            remoteIP, portTimestamps.size(), windowSec, portTimestamps.keySet()))
                        .withDestination(remoteIP)
                        .withMetadata(metadata);

                alertHandler.triggerNetworkAlert(event);
                // Remove this IP so we don't keep alerting every cycle
                scanPortHistory.remove(cleanRemoteIP);
            }
        }
    }

    // ── Function 2: analyzeOpenPorts() ───────────────────────
    /**
     * FIX 2.5: Only alerts on NEWLY opened sensitive ports.
     * A port that has been open for > NEW_PORT_THRESHOLD scan
     * cycles is considered part of normal baseline and is only
     * LOGGED (not alerted) to reduce false positive noise.
     */
    public void analyzeOpenPorts(List<Map<String, String>> openPorts) {
        Set<Integer> currentlyOpen = new HashSet<>();

        for (Map<String, String> port : openPorts) {
            try {
                int portNum = Integer.parseInt(port.get("local_port"));
                if (!isSensitivePort(portNum)) continue;

                currentlyOpen.add(portNum);
                int openCount = portOpenCount.merge(portNum, 1, Integer::sum);

                if (openCount <= NEW_PORT_THRESHOLD && alreadyAlertedPorts.add(portNum)) {
                    // ALERT: Port is newly open (within first 2 scan cycles)
                    String localAddr = port.get("local_ip") + ":" + portNum;
                    String processName = port.getOrDefault("owning_process", "Unknown");

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("local_ip", port.get("local_ip"));
                    metadata.put("local_port", portNum);
                    metadata.put("protocol", port.getOrDefault("protocol", "TCP"));
                    metadata.put("local_address", localAddr);
                    metadata.put("process_name", processName);
                    metadata.put("is_sensitive", isSensitivePort(portNum));
                    metadata.put("open_since", "Recently opened (scan cycle " + openCount + ")");

                    Event event = new Event(Module.network, "SENSITIVE_PORT_OPEN", Severity.MEDIUM,
                            "Sensitive port " + portNum + " opened by " + processName)
                            .withDescription(String.format(
                                "Port %d just started listening on %s by process %s. This is a sensitive port " +
                                "commonly targeted by attackers.",
                                portNum, localAddr, processName))
                            .withMetadata(metadata);
                    alertHandler.logNetworkEvent(event); // LOG only, not a full alert
                }
                // If port has been open long-term, it's expected — no alert needed

            } catch (NumberFormatException ignored) {}
        }

        // Reset counters for closed ports; they will re-alert if re-opened
        portOpenCount.entrySet().removeIf(e -> !currentlyOpen.contains(e.getKey()));
        alreadyAlertedPorts.retainAll(currentlyOpen);
    }

    public boolean isSensitivePort(int port) {
        return SENSITIVE_PORTS.contains(port);
    }

    public Set<Integer> getSensitivePorts() {
        return SENSITIVE_PORTS;
    }
}
