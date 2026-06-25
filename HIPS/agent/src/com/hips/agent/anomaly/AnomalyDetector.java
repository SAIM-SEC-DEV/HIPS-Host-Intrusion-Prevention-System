package com.hips.agent.anomaly;

import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.time.LocalDateTime;
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
 *   1. Z-Score based: If (value - mean) / stddev > 3, flag anomaly
 *   2. Threshold based: If value exceeds N * baseline, flag anomaly
 *   3. Profile based: New ports or unusual hour activity
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
        this.baseline  = baseline;
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
     * @param currentCount  Current number of active connections
     * @return true if an anomaly was detected
     */
    public boolean analyzeConnectionCount(int currentCount) {
        if (!isActive()) return false;

        double mean   = baseline.getAvgConnectionCount();
        double stdDev = baseline.getStdDevConnections();

        if (stdDev == 0) {
            // If no variance in baseline, use multiplier method
            if (mean > 0 && currentCount > mean * MULTIPLIER_THRESHOLD) {
                fireAnomaly("CONNECTION_ANOMALY", Module.network,
                    "Anomalous connection count: " + currentCount,
                    String.format("Current connections (%d) exceed baseline (%.1f) by %.1f×. " +
                        "Z-score method unavailable (zero variance in baseline).",
                        currentCount, mean, currentCount / mean),
                    Map.of("current", currentCount, "baseline_mean", mean, "method", "multiplier"));
                return true;
            }
            return false;
        }

        // Z-score = (observed - mean) / stddev
        double zScore = (currentCount - mean) / stdDev;

        if (zScore > Z_SCORE_THRESHOLD) {
            fireAnomaly("CONNECTION_ANOMALY", Module.network,
                "Statistical anomaly in connection count",
                String.format("Connection count %d deviates significantly from baseline " +
                    "(mean=%.1f, σ=%.1f, z=%.2f). Threshold: z > %.1f.",
                    currentCount, mean, stdDev, zScore, Z_SCORE_THRESHOLD),
                Map.of("current", currentCount, "mean", mean,
                       "stddev", stdDev, "z_score", zScore));
            return true;
        }

        return false;
    }

    /**
     * Analyzes the current DNS query rate against the baseline.
     */
    public boolean analyzeDnsRate(int currentRate) {
        if (!isActive()) return false;

        double avg = baseline.getAvgDnsQueryRate();
        if (avg <= 0) return false;

        double ratio = currentRate / avg;

        if (ratio > MULTIPLIER_THRESHOLD) {
            fireAnomaly("DNS_ANOMALY", Module.network,
                "Anomalous DNS query rate: " + currentRate,
                String.format("DNS queries (%d) are %.1f× the baseline average (%.1f). " +
                    "This may indicate DNS tunneling or DGA malware activity.",
                    currentRate, ratio, avg),
                Map.of("current_rate", currentRate, "baseline_avg", avg, "ratio", ratio));
            return true;
        }

        return false;
    }

    /**
     * Analyzes file event rate for the current hour against baseline.
     */
    public boolean analyzeFileEventRate(int currentCount) {
        if (!isActive()) return false;

        int hour = LocalDateTime.now().getHour();
        Double avgForHour = baseline.getAvgFileEventsPerHour().get(hour);

        if (avgForHour == null || avgForHour <= 0) {
            // No baseline for this hour — if there are events, flag it
            if (currentCount > 5) {
                fireAnomaly("FILE_ACTIVITY_ANOMALY", Module.file,
                    "Unexpected file activity at hour " + hour,
                    String.format("Detected %d file events at hour %d, but baseline shows " +
                        "zero activity for this hour. This is unusual.",
                        currentCount, hour),
                    Map.of("current_count", currentCount, "hour", hour, "baseline", 0));
                return true;
            }
            return false;
        }

        double ratio = currentCount / avgForHour;

        if (ratio > MULTIPLIER_THRESHOLD) {
            fireAnomaly("FILE_ACTIVITY_ANOMALY", Module.file,
                "Anomalous file activity at hour " + hour,
                String.format("File events (%d) are %.1f× the baseline for hour %d (avg: %.1f).",
                    currentCount, ratio, hour, avgForHour),
                Map.of("current_count", currentCount, "hour", hour,
                       "baseline_avg", avgForHour, "ratio", ratio));
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
        if (!isActive()) return false;

        Set<Integer> normalPorts = baseline.getNormalOpenPorts();

        if (!normalPorts.isEmpty() && !normalPorts.contains(port)) {
            fireAnomaly("NEW_PORT_ANOMALY", Module.network,
                "New port detected: " + port,
                String.format("Port %d was not observed during the baseline learning phase. " +
                    "Normal ports: %s. A new listening port may indicate a backdoor " +
                    "or unauthorized service.", port, normalPorts),
                Map.of("new_port", port, "normal_ports", normalPorts.toString()));
            return true;
        }

        return false;
    }

    /**
     * Fires an anomaly alert to the server.
     */
    private void fireAnomaly(String eventType, Module module, String title,
                              String description, Map<String, Object> metadata) {
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
