package com.hips.agent.anomaly;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — Baseline Collector
 * ============================================================
 * Collects normal-behavior metrics during the 7-day learning
 * phase after agent registration. The baseline captures:
 *   - Average file events per hour
 *   - Average network connections per scan
 *   - Typical active hours
 *   - Normal port profile
 *   - DNS query rate baseline
 *
 * After the learning phase, the AnomalyDetector uses these
 * baselines to flag deviations as potential threats.
 */
public class BaselineCollector {

    // When the baseline collection started
    private LocalDateTime baselineStart;
    private boolean baselineComplete = false;

    // Duration of the learning phase
    private static final int BASELINE_DAYS = 7;

    // ── Collected Metrics ────────────────────────────────────

    // File events per hour (hour 0-23 → count)
    private final Map<Integer, List<Integer>> fileEventsPerHour = new ConcurrentHashMap<>();

    // Network connection counts per scan
    private final List<Integer> connectionCounts = Collections.synchronizedList(new ArrayList<>());

    // Open port profile — which ports are normally open
    private final Map<Integer, Integer> normalPortProfile = new ConcurrentHashMap<>();

    // DNS query rates
    private final List<Integer> dnsQueryRates = Collections.synchronizedList(new ArrayList<>());

    // Traffic volume history
    private final List<Integer> trafficVolumes = Collections.synchronizedList(new ArrayList<>());

    // ── Computed Baselines (calculated when learning phase ends) ──

    private double avgConnectionCount = 0;
    private double stdDevConnections = 0;
    private double avgDnsQueryRate = 0;
    private double avgTrafficVolume = 0;
    private final Map<Integer, Double> avgFileEventsPerHour = new HashMap<>();
    private final Set<Integer> normalOpenPorts = new HashSet<>();

    public BaselineCollector() {
        // Initialize hour slots
        for (int h = 0; h < 24; h++) {
            fileEventsPerHour.put(h, Collections.synchronizedList(new ArrayList<>()));
        }
    }

    /**
     * Starts the baseline collection phase.
     */
    public void startBaseline() {
        this.baselineStart = LocalDateTime.now();
        this.baselineComplete = false;
        System.out.println("[HIPS-BASELINE] Learning phase started. Will run for "
                + BASELINE_DAYS + " days until " + baselineStart.plusDays(BASELINE_DAYS));
    }

    /**
     * Records a file event for baseline calculation.
     */
    public void recordFileEvent() {
        if (baselineComplete) return;
        int hour = LocalDateTime.now().getHour();
        fileEventsPerHour.get(hour).add(1);
    }

    /**
     * Records a network connection count for baseline calculation.
     */
    public void recordConnectionCount(int count) {
        if (baselineComplete) return;
        connectionCounts.add(count);
    }

    /**
     * Records open ports for the normal port profile.
     */
    public void recordOpenPort(int port) {
        if (baselineComplete) return;
        normalPortProfile.merge(port, 1, Integer::sum);
    }

    /**
     * Records a DNS query count for baseline calculation.
     */
    public void recordDnsQueryRate(int count) {
        if (baselineComplete) return;
        dnsQueryRates.add(count);
    }

    /**
     * Records traffic volume for baseline calculation.
     */
    public void recordTrafficVolume(int volume) {
        if (baselineComplete) return;
        trafficVolumes.add(volume);
    }

    /**
     * Checks if the baseline learning phase is complete. If the
     * 7-day window has elapsed, computes the final baselines.
     *
     * @return true if baseline is complete and detection is active
     */
    public boolean checkBaselineComplete() {
        if (baselineComplete) return true;
        if (baselineStart == null) return false;

        long daysElapsed = ChronoUnit.DAYS.between(baselineStart, LocalDateTime.now());

        if (daysElapsed >= BASELINE_DAYS) {
            computeBaselines();
            baselineComplete = true;
            System.out.println("[HIPS-BASELINE] ✓ Learning phase complete! Anomaly detection is now active.");
            return true;
        }

        return false;
    }

    /**
     * Computes final baseline values from collected data.
     */
    private void computeBaselines() {
        // Average connection count and standard deviation
        if (!connectionCounts.isEmpty()) {
            avgConnectionCount = connectionCounts.stream()
                    .mapToInt(Integer::intValue).average().orElse(0);
            double variance = connectionCounts.stream()
                    .mapToDouble(c -> Math.pow(c - avgConnectionCount, 2))
                    .average().orElse(0);
            stdDevConnections = Math.sqrt(variance);
        }

        // Average DNS query rate
        if (!dnsQueryRates.isEmpty()) {
            avgDnsQueryRate = dnsQueryRates.stream()
                    .mapToInt(Integer::intValue).average().orElse(0);
        }

        // Average traffic volume
        if (!trafficVolumes.isEmpty()) {
            avgTrafficVolume = trafficVolumes.stream()
                    .mapToInt(Integer::intValue).average().orElse(0);
        }

        // Average file events per hour
        for (Map.Entry<Integer, List<Integer>> entry : fileEventsPerHour.entrySet()) {
            List<Integer> counts = entry.getValue();
            double avg = counts.isEmpty() ? 0 :
                    counts.stream().mapToInt(Integer::intValue).average().orElse(0);
            avgFileEventsPerHour.put(entry.getKey(), avg);
        }

        // Normal port profile (ports seen > 50% of the time)
        int totalScans = connectionCounts.size();
        if (totalScans > 0) {
            for (Map.Entry<Integer, Integer> entry : normalPortProfile.entrySet()) {
                if (entry.getValue() > totalScans * 0.5) {
                    normalOpenPorts.add(entry.getKey());
                }
            }
        }

        System.out.println("[HIPS-BASELINE] Computed baselines:");
        System.out.println("[HIPS-BASELINE]   Avg connections:   " + String.format("%.1f", avgConnectionCount));
        System.out.println("[HIPS-BASELINE]   Std dev:           " + String.format("%.1f", stdDevConnections));
        System.out.println("[HIPS-BASELINE]   Avg DNS queries:   " + String.format("%.1f", avgDnsQueryRate));
        System.out.println("[HIPS-BASELINE]   Normal ports:      " + normalOpenPorts);
    }

    // ── Getters for AnomalyDetector ──────────────────────────

    public boolean isBaselineComplete()               { return baselineComplete; }
    public double getAvgConnectionCount()             { return avgConnectionCount; }
    public double getStdDevConnections()              { return stdDevConnections; }
    public double getAvgDnsQueryRate()                { return avgDnsQueryRate; }
    public double getAvgTrafficVolume()               { return avgTrafficVolume; }
    public Map<Integer, Double> getAvgFileEventsPerHour() { return avgFileEventsPerHour; }
    public Set<Integer> getNormalOpenPorts()           { return normalOpenPorts; }

    public int getDaysRemaining() {
        if (baselineStart == null) return BASELINE_DAYS;
        long elapsed = ChronoUnit.DAYS.between(baselineStart, LocalDateTime.now());
        return Math.max(0, BASELINE_DAYS - (int) elapsed);
    }
}
