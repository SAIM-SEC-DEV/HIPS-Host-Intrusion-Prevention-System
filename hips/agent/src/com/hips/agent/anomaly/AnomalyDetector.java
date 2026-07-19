package com.hips.agent.anomaly;

import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * ============================================================
 * HIPS Agent — Anomaly Detector
 * ============================================================
 * Compares live system metrics against the learned baselines
 * from BaselineCollector. When a metric deviates significantly
 * from the baseline, an anomaly alert is generated.
 *
 * Detection Strategies:
 * 1. Z-Score based: If (value - mean) / stddev > 3, flag anomaly
 * 2. Threshold based: If value exceeds N * baseline, flag anomaly
 * 3. Profile based: New ports or unusual hour activity
 *
 * This module only fires AFTER the 7-day baseline phase.
 */
public class AnomalyDetector {

    private final BaselineCollector baseline;
    private final ApiClient apiClient;

    // Z-score threshold: 3 standard deviations from the mean
    // In a normal distribution, values beyond 3σ occur < 0.3% of the time
    private static final double Z_SCORE_THRESHOLD = 3.0;

    // Multiplier threshold for metrics without good stddev data
    private static final double MULTIPLIER_THRESHOLD = 3.0;

    public AnomalyDetector(BaselineCollector baseline, ApiClient apiClient) {
        this.baseline = baseline;
        this.apiClient = apiClient;
    }

    /**
     * Checks if anomaly detection is ready (baseline phase complete).
     */
    public boolean isActive() {
        return baseline.isBaselineComplete();
    }

    /**
     * Analyzes the current connection count against the baseline.
     * Uses Z-score to determine if the deviation is statistically
     * significant.
     *
     * @param currentCount Current number of active connections
     * @return true if an anomaly was detected
     */
    public boolean analyzeConnectionCount(int currentCount) {
        if (!isActive())
            return false;

        double mean = baseline.getAvgConnectionCount();
        double stdDev = baseline.getStdDevConnections();

        if (stdDev == 0) {
            // If no variance in baseline, use multiplier method
            if (mean > 0 && currentCount > mean * MULTIPLIER_THRESHOLD) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("current", currentCount);
                metadata.put("baseline_mean", mean);
                metadata.put("method", "multiplier");
                fireAnomaly("CONNECTION_ANOMALY", Module.network,
                        "Anomalous connection count: " + currentCount,
                        String.format("Current connections (%d) exceed baseline (%.1f) by %.1f×. " +
                                "Z-score method unavailable (zero variance in baseline).",
                                currentCount, mean, currentCount / mean),
                        metadata);
                return true;
            }
            // FIX: If baseline mean is 0 (idle system), any connections are anomalous
            if (mean == 0 && currentCount > 0) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("current", currentCount);
                metadata.put("baseline_mean", 0);
                metadata.put("method", "zero_baseline");
                fireAnomaly("CONNECTION_ANOMALY", Module.network,
                        "Connections detected on previously idle system: " + currentCount,
                        String.format("Baseline recorded zero connections, but %d are now active. " +
                                "This system was idle during the learning phase — any network activity is suspicious.",
                                currentCount),
                        metadata);
                return true;
            }
            return false;
        }

        // Z-score = (observed - mean) / stddev
        double zScore = (currentCount - mean) / stdDev;

        if (zScore > Z_SCORE_THRESHOLD) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("current", currentCount);
            metadata.put("mean", mean);
            metadata.put("stddev", stdDev);
            metadata.put("z_score", zScore);
            fireAnomaly("CONNECTION_ANOMALY", Module.network,
                    "Statistical anomaly in connection count",
                    String.format("Connection count %d deviates significantly from baseline " +
                            "(mean=%.1f, σ=%.1f, z=%.2f). Threshold: z > %.1f.",
                            currentCount, mean, stdDev, zScore, Z_SCORE_THRESHOLD),
                    metadata);
            return true;
        }

        return false;
    }

    /**
     * Analyzes the current DNS query rate against the baseline.
     */
    public boolean analyzeDnsRate(int currentRate) {
        if (!isActive())
            return false;

        double avg = baseline.getAvgDnsQueryRate();
        if (avg <= 0)
            return false;

        double ratio = currentRate / avg;

        if (ratio > MULTIPLIER_THRESHOLD) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("current_rate", currentRate);
            metadata.put("baseline_avg", avg);
            metadata.put("ratio", ratio);
            fireAnomaly("DNS_ANOMALY", Module.network,
                    "Anomalous DNS query rate: " + currentRate,
                    String.format("DNS queries (%d) are %.1f× the baseline average (%.1f). " +
                            "This may indicate DNS tunneling or DGA malware activity.",
                            currentRate, ratio, avg),
                    metadata);
            return true;
        }

        return false;
    }

    /**
     * Analyzes file event rate for the current hour against baseline.
     */
    public boolean analyzeFileEventRate(int currentCount) {
        if (!isActive())
            return false;

        int hour = LocalDateTime.now().getHour();
        Double avgForHour = baseline.getAvgFileEventsPerHour().get(hour);

        if (avgForHour == null || avgForHour <= 0) {
            // No baseline for this hour — if there are events, flag it
            if (currentCount > 5) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("current_count", currentCount);
                metadata.put("hour", hour);
                metadata.put("baseline", 0);
                fireAnomaly("FILE_ACTIVITY_ANOMALY", Module.file,
                        "Unexpected file activity at hour " + hour,
                        String.format("Detected %d file events at hour %d, but baseline shows " +
                                "zero activity for this hour. This is unusual.",
                                currentCount, hour),
                        metadata);
                return true;
            }
            return false;
        }

        double ratio = currentCount / avgForHour;

        if (ratio > MULTIPLIER_THRESHOLD) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("current_count", currentCount);
            metadata.put("hour", hour);
            metadata.put("baseline_avg", avgForHour);
            metadata.put("ratio", ratio);
            fireAnomaly("FILE_ACTIVITY_ANOMALY", Module.file,
                    "Anomalous file activity at hour " + hour,
                    String.format("File events (%d) are %.1f× the baseline for hour %d (avg: %.1f).",
                            currentCount, ratio, hour, avgForHour),
                    metadata);
            return true;
        }

        return false;
    }

    /**
     * Checks for new ports that weren't in the baseline profile.
     * New ports appearing after the learning phase may indicate
     * backdoor installation or unauthorized service startup.
     */
    public boolean analyzeNewPort(int port) {
        if (!isActive())
            return false;

        Set<Integer> normalPorts = baseline.getNormalOpenPorts();

        // FIX: If normalPorts is empty (quiet baseline), any new port is suspicious
        if (normalPorts.isEmpty()) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("new_port", port);
            metadata.put("normal_ports", "none (quiet baseline)");
            metadata.put("method", "empty_baseline");
            fireAnomaly("NEW_PORT_ANOMALY", Module.network,
                    "New port detected on previously silent system: " + port,
                    String.format("Port %d opened, but NO ports were observed during the baseline " +
                            "learning phase. This system had no listening ports — any new port " +
                            "may indicate a backdoor or unauthorized service.", port),
                    metadata);
            return true;
        }

        if (!normalPorts.contains(port)) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("new_port", port);
            metadata.put("normal_ports", normalPorts.toString());
            fireAnomaly("NEW_PORT_ANOMALY", Module.network,
                    "New port detected: " + port,
                    String.format("Port %d was not observed during the baseline learning phase. " +
                            "Normal ports: %s. A new listening port may indicate a backdoor " +
                            "or unauthorized service.", port, normalPorts),
                    metadata);
            return true;
        }

        return false;
    }

    // ── FIX 2.6: Adaptive Baseline Drift ─────────────────────
    /**
     * Drifts the baseline toward new normal behavior to prevent
     * permanent false positives if network topology changes.
     */
    public void adaptBaseline(int currentConnCount, int currentDnsRate) {
        if (!isActive())
            return;
        baseline.adaptBaseline(currentConnCount, currentDnsRate);
    }

    /**
     * Fires an anomaly alert to the server.
     */
    private void fireAnomaly(String eventType, Module module, String title,
            String description, Map<String, Object> metadata) {

        // FIX: Null-safe description to prevent "null [WARNING: ...]" string
        if (description == null) {
            description = "Anomaly detected (no additional details).";
        }

        // FIX 2.7: Append taint warning if the baseline is known to be poisoned
        if (baseline.isBaselineTainted()) {
            description += " [WARNING: Baseline is flagged as TAINTED. This alert is based on potentially compromised learning data.]";
        }

        Event event = new Event(module, eventType, Severity.HIGH, title)
                .withDescription(description)
                .withAnomaly(true)
                .withMetadata(metadata);

        try {
            apiClient.post("report.php", event);
            System.out.println("[HIPS-ANOMALY] ⚠ " + title);
        } catch (Exception e) {
            System.err.println("[HIPS-ANOMALY] Failed to report anomaly: " + e.getMessage());
        }
    }
}
