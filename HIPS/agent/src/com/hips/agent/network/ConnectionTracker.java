package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ============================================================
 * HIPS Agent — Connection Tracker
 * ============================================================
 * Tracks all network connections over time, building a history
 * that enables spike detection and beaconing analysis.
 *
 * Functions (3 of 32):
 *   trackConnection()        — Records each connection with metadata
 *   detectConnectionSpike()  — Alerts if connections exceed baseline
 *   detectBeaconing()        — Identifies periodic malware phone-home patterns
 */
public class ConnectionTracker {

    private final NetworkAlertHandler alertHandler;

    // Connection history — stores count per scan cycle for baseline calculation
    private final List<Integer> connectionHistory = new CopyOnWriteArrayList<>();
    private static final int HISTORY_SIZE = 100; // Keep last 100 scan results

    // Track unique remote endpoints seen over time
    // Key = remote IP:port, Value = list of timestamps when seen
    private final Map<String, List<Long>> endpointTimestamps = new ConcurrentHashMap<>();

    // Beaconing detection threshold
    // If a remote endpoint connects at regular intervals (±10% variance),
    // it may be malware phoning home to a C2 server.
    private static final double BEACONING_VARIANCE_THRESHOLD = 0.15; // 15% variance
    private static final int    BEACONING_MIN_SAMPLES = 5;           // Need at least 5 intervals

    // Spike detection threshold — alert if current connections exceed
    // the historical average by more than this multiplier
    private static final double SPIKE_MULTIPLIER = 2.5;

    // Cooldown: prevent repeated spike alerts (5 minutes between repeats)
    private static final long SPIKE_COOLDOWN_MS = 5 * 60 * 1000;
    private long lastSpikeAlertTime = 0;

    public ConnectionTracker(NetworkAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // ── Function 1: trackConnections() ───────────────────────
    /**
     * Records the current set of active connections. Stores the
     * count in history for baseline calculation and tracks
     * individual remote endpoints for beaconing detection.
     *
     * @param connections  List of connection maps from NetworkMonitor
     */
    public void trackConnections(List<Map<String, String>> connections) {
        // Record total count for spike detection
        connectionHistory.add(connections.size());
        if (connectionHistory.size() > HISTORY_SIZE) {
            connectionHistory.remove(0);
        }

        // Track each remote endpoint's connection timestamps
        long now = System.currentTimeMillis();
        for (Map<String, String> conn : connections) {
            String remoteIP = conn.get("remote_ip");
            String remotePort = conn.get("remote_port");
            if (remoteIP == null || remoteIP.equals("0.0.0.0") || remoteIP.equals("[::]") || 
                remoteIP.equals("::") || remoteIP.equals("*")) continue;

            String endpoint = remoteIP + ":" + remotePort;
            endpointTimestamps.computeIfAbsent(endpoint, k -> new CopyOnWriteArrayList<>()).add(now);

            // Limit timestamp history per endpoint
            List<Long> timestamps = endpointTimestamps.get(endpoint);
            if (timestamps.size() > 50) {
                timestamps.subList(0, timestamps.size() - 30).clear();
            }
        }
    }

    // ── Function 2: detectConnectionSpike() ──────────────────
    /**
     * Compares the current connection count against the historical
     * average. If the current count exceeds the average by more
     * than 2.5x, a traffic spike alert is generated.
     *
     * This catches scenarios like:
     *   - Worm spreading and opening many outbound connections
     *   - DDoS bot activation
     *   - Unauthorized port forwarding
     */
    public void detectConnectionSpike() {
        if (connectionHistory.size() < 5) return; // Need baseline data

        // Cooldown: skip if we recently alerted
        long now = System.currentTimeMillis();
        if ((now - lastSpikeAlertTime) < SPIKE_COOLDOWN_MS) return;

        // Calculate historical average
        double average = connectionHistory.stream()
                .mapToInt(Integer::intValue)
                .average()
                .orElse(0);

        int current = connectionHistory.get(connectionHistory.size() - 1);

        if (average > 0 && current > average * SPIKE_MULTIPLIER) {
            lastSpikeAlertTime = now;
            Event event = new Event(Module.network, "CONNECTION_SPIKE", Severity.HIGH,
                    "Unusual connection spike detected")
                    .withDescription(String.format(
                        "Current connections: %d | Historical average: %.1f | Threshold: %.1f",
                        current, average, average * SPIKE_MULTIPLIER))
                    .withMetadata(Map.of(
                        "current_count", current,
                        "average", Math.round(average * 10.0) / 10.0,
                        "threshold_multiplier", SPIKE_MULTIPLIER
                    ));

            alertHandler.triggerNetworkAlert(event);
        }
    }

    // ── Function 3: detectBeaconing() ────────────────────────
    /**
     * Identifies periodic (beaconing) connections that suggest
     * malware communication. Beaconing is a hallmark of C2
     * (Command and Control) channels where malware contacts its
     * controller at regular intervals.
     *
     * Detection algorithm:
     *   1. For each remote endpoint, compute intervals between connections
     *   2. Calculate the coefficient of variation (stddev / mean)
     *   3. If CV < 15% (very regular intervals), flag as beaconing
     *
     * @param connections  Current active connections
     */
    public void detectBeaconing(List<Map<String, String>> connections) {
        for (Map.Entry<String, List<Long>> entry : endpointTimestamps.entrySet()) {
            List<Long> timestamps = entry.getValue();
            if (timestamps.size() < BEACONING_MIN_SAMPLES + 1) continue;

            // Calculate intervals between consecutive connections
            List<Long> intervals = new ArrayList<>();
            for (int i = 1; i < timestamps.size(); i++) {
                intervals.add(timestamps.get(i) - timestamps.get(i - 1));
            }

            if (intervals.size() < BEACONING_MIN_SAMPLES) continue;

            // Calculate mean and standard deviation of intervals
            double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
            if (mean == 0) continue;

            double variance = intervals.stream()
                    .mapToDouble(interval -> Math.pow(interval - mean, 2))
                    .average()
                    .orElse(0);
            double stdDev = Math.sqrt(variance);

            // Coefficient of Variation (CV) = stddev / mean
            // Low CV means very regular intervals = likely beaconing
            double cv = stdDev / mean;

            if (cv < BEACONING_VARIANCE_THRESHOLD) {
                String endpoint = entry.getKey();
                double intervalSec = mean / 1000.0;

                Event event = new Event(Module.network, "BEACONING_DETECTED", Severity.CRITICAL,
                        "Possible C2 beaconing to " + endpoint)
                        .withDescription(String.format(
                            "Remote endpoint %s shows regular connection pattern. " +
                            "Avg interval: %.1fs, CV: %.3f (threshold: %.3f). " +
                            "This may indicate malware phoning home.",
                            endpoint, intervalSec, cv, BEACONING_VARIANCE_THRESHOLD))
                        .withDestination(endpoint)
                        .withMetadata(Map.of(
                            "endpoint", endpoint,
                            "avg_interval_sec", Math.round(intervalSec * 10.0) / 10.0,
                            "coefficient_of_variation", Math.round(cv * 1000.0) / 1000.0,
                            "sample_count", intervals.size()
                        ));

                alertHandler.triggerNetworkAlert(event);

                // Reset timestamps to avoid repeated alerts
                timestamps.clear();
            }
        }
    }

    // ── Accessors ────────────────────────────────────────────

    public int getCurrentConnectionCount() {
        return connectionHistory.isEmpty() ? 0 : connectionHistory.get(connectionHistory.size() - 1);
    }

    public double getAverageConnectionCount() {
        return connectionHistory.stream().mapToInt(Integer::intValue).average().orElse(0);
    }
}
