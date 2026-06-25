package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ============================================================
 * HIPS Agent — Traffic Analyzer
 * ============================================================
 * Analyzes network traffic patterns to detect spikes and
 * potential data exfiltration attempts.
 *
 * Functions (2 of 32):
 *   detectTrafficSpike()      — Alerts on sudden bandwidth/connection increases
 *   detectDataExfiltration()  — Flags large unexpected outbound transfers
 */
public class TrafficAnalyzer {

    private final NetworkAlertHandler alertHandler;

    // Traffic history — stores established connection counts per scan
    private final List<Integer> trafficHistory = new CopyOnWriteArrayList<>();
    private static final int TRAFFIC_HISTORY_SIZE = 60; // ~30 minutes at 30s intervals

    // Spike threshold multiplier
    private static final double TRAFFIC_SPIKE_MULTIPLIER = 3.0;

    // Data exfiltration: flag if an IP has many outbound-only connections
    private static final int EXFIL_OUTBOUND_THRESHOLD = 20;

    // ── Cooldown: prevent repeated alerts for the same condition ──
    // 5-minute cooldown between repeated alerts of the same type
    private static final long ALERT_COOLDOWN_MS = 5 * 60 * 1000;
    private long lastTrafficSpikeAlert = 0;
    private long lastExfilAlertTime = 0;
    private final Set<String> alertedExfilIPs = ConcurrentHashMap.newKeySet();

    public TrafficAnalyzer(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    /**
     * Analyzes the current set of connections for traffic anomalies.
     *
     * @param connections  Current active connections from NetworkMonitor
     */
    public void analyzeTraffic(List<Map<String, String>> connections) {
        // Count only ESTABLISHED connections for traffic analysis
        long established = connections.stream()
                .filter(c -> "ESTABLISHED".equals(c.get("state")))
                .count();

        trafficHistory.add((int) established);
        if (trafficHistory.size() > TRAFFIC_HISTORY_SIZE) {
            trafficHistory.remove(0);
        }

        detectTrafficSpike();
        detectDataExfiltration(connections);
    }

    // ── Function 1: detectTrafficSpike() ─────────────────────
    /**
     * Detects sudden increases in active connection count compared
     * to the rolling average. A 3x spike suggests abnormal activity
     * like botnet activation, worm spreading, or unauthorized
     * data transfer.
     */
    public void detectTrafficSpike() {
        if (trafficHistory.size() < 10) return;

        // Cooldown: skip if we recently alerted
        long now = System.currentTimeMillis();
        if ((now - lastTrafficSpikeAlert) < ALERT_COOLDOWN_MS) return;

        double average = trafficHistory.stream()
                .mapToInt(Integer::intValue)
                .average()
                .orElse(0);

        int current = trafficHistory.get(trafficHistory.size() - 1);

        if (average > 0 && current > average * TRAFFIC_SPIKE_MULTIPLIER) {
            lastTrafficSpikeAlert = now;
            Event event = new Event(Module.network, "TRAFFIC_SPIKE", Severity.MEDIUM,
                    "Network traffic spike detected")
                    .withDescription(String.format(
                        "Active connections surged to %d (avg: %.1f, threshold: %.1f). " +
                        "Investigate for unauthorized transfers or malware activity.",
                        current, average, average * TRAFFIC_SPIKE_MULTIPLIER))
                    .withMetadata(Map.of(
                        "current_established", current,
                        "average_established", Math.round(average * 10.0) / 10.0,
                        "spike_ratio", Math.round((current / average) * 10.0) / 10.0
                    ));

            alertHandler.triggerNetworkAlert(event);
        }
    }

    // ── Function 2: detectDataExfiltration() ─────────────────
    /**
     * Flags potential data exfiltration by identifying remote IPs
     * with an unusually high number of outbound connections. Large
     * amounts of outgoing data to a single destination is a strong
     * indicator of data theft.
     *
     * @param connections  Current active connections
     */
    public void detectDataExfiltration(List<Map<String, String>> connections) {
        // Count outbound ESTABLISHED connections per remote IP
        Map<String, Integer> outboundCounts = new HashMap<>();

        for (Map<String, String> conn : connections) {
            if (!"ESTABLISHED".equals(conn.get("state"))) continue;

            String remoteIP = conn.get("remote_ip");
            if (remoteIP == null || remoteIP.startsWith("127.") || remoteIP.equals("0.0.0.0")) continue;

            outboundCounts.merge(remoteIP, 1, Integer::sum);
        }

        long now = System.currentTimeMillis();

        // Flag IPs with high outbound connection counts (with deduplication)
        for (Map.Entry<String, Integer> entry : outboundCounts.entrySet()) {
            if (entry.getValue() >= EXFIL_OUTBOUND_THRESHOLD) {
                // Skip if we already alerted this IP and cooldown hasn't expired
                if (alertedExfilIPs.contains(entry.getKey()) && (now - lastExfilAlertTime) < ALERT_COOLDOWN_MS) {
                    continue;
                }

                alertedExfilIPs.add(entry.getKey());
                lastExfilAlertTime = now;

                Event event = new Event(Module.network, "DATA_EXFILTRATION", Severity.HIGH,
                        "Possible data exfiltration to " + entry.getKey())
                        .withDescription(String.format(
                            "%d concurrent outbound connections to %s detected. " +
                            "This volume is unusual and may indicate data exfiltration.",
                            entry.getValue(), entry.getKey()))
                        .withDestination(entry.getKey())
                        .withMetadata(Map.of(
                            "destination_ip", entry.getKey(),
                            "connection_count", entry.getValue(),
                            "threshold", EXFIL_OUTBOUND_THRESHOLD
                        ));

                alertHandler.triggerNetworkAlert(event);
            }
        }
    }
}
