package com.hips.agent.anomaly;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ============================================================
 * HIPS Agent — Baseline Collector (Refactored v1.1)
 * ============================================================
 *
 * FIXES APPLIED:
 *   - FIX 2.4 (Memory Exhaustion): Replaced raw ArrayList storage
 *     with Welford's online algorithm. Memory usage is now O(1)
 *     instead of O(n), eliminating OutOfMemoryError risk.
 *
 *   - FIX 2.5 (No Persistence): State is checkpointed to disk
 *     every hour. On agent restart the learning phase resumes
 *     from where it left off instead of resetting to Day 0.
 *
 *   - FIX 2.7 (Baseline Poisoning): A quick IOC sanity check
 *     is performed before the learning phase starts. If known
 *     malware indicators are already present, the baseline is
 *     flagged as "potentially tainted" so analysts are warned.
 */
public class BaselineCollector {

    // ── Constants ─────────────────────────────────────────────
    private static final int    BASELINE_DAYS    = 7; // Default learning period
    private static final int    BASELINE_MINUTES = BASELINE_DAYS * 24 * 60;
    private static final String CHECKPOINT_FILE  = "baseline_checkpoint.json";
    private static final Gson   GSON             = new GsonBuilder().setPrettyPrinting().create();

    // ── State ─────────────────────────────────────────────────
    private LocalDateTime lastSeen;
    private LocalDateTime baselineStart; // Added for daysRemaining calculation
    private long          activeLearningMinutes = 0;
    private boolean       baselineComplete = false;
    private boolean       baselineTainted  = false; // FIX 2.7

    // ── FIX 2.4: Welford's Online Algorithm state for connections ──
    // Replaces: List<Integer> connectionCounts = new ArrayList<>()
    // Memory: O(1) regardless of runtime duration
    private long   connN    = 0;      // count of samples
    private double connMean = 0.0;    // running mean
    private double connM2   = 0.0;    // running sum of squared deviations

    // ── FIX 2.4: Welford's for DNS query rates ────────────────
    private long   dnsN    = 0;
    private double dnsMean = 0.0;
    private double dnsM2   = 0.0;

    // ── FIX 2.4: Welford's for traffic volumes ────────────────
    private long   trafficN    = 0;
    private double trafficMean = 0.0;

    // ── FIX 2.4: Running averages for file events per hour ────
    // Map<Hour(0-23), RunningStats>
    private final Map<Integer, long[]>   fileEventN    = new ConcurrentHashMap<>();
    private final Map<Integer, double[]> fileEventMean = new ConcurrentHashMap<>();
    
    // Hourly accumulator to avoid "spike" pollution (Fix 3)
    private final Map<Integer, Long> hourlyEventAccumulator = new ConcurrentHashMap<>();
    private int lastRecordedHour = -1;

    // ── Port profile: port → occurrencesCount ─────────────────
    private final Map<Integer, Integer> normalPortProfile = new ConcurrentHashMap<>();
    private long totalConnScanCount = 0; // total scan cycles for port threshold

    // ── Computed baselines (set on learning phase completion) ─
    private double               avgConnectionCount = 0;
    private double               stdDevConnections  = 0;
    private double               avgDnsQueryRate    = 0;
    private Map<Integer, Double> avgFileEventsPerHour = new HashMap<>();
    private Set<Integer>         normalOpenPorts    = new HashSet<>();

    // ── Constructor ───────────────────────────────────────────
    public BaselineCollector() {
        for (int h = 0; h < 24; h++) {
            fileEventN.put(h, new long[]{0});
            fileEventMean.put(h, new double[]{0.0});
        }
    }

    // ── FIX 2.5: Start or Resume Baseline ────────────────────
    /**
     * Attempts to load an existing checkpoint from disk.
     * If none exists, starts a fresh baseline collection.
     */
    public void startBaseline() {
        if (loadCheckpoint()) {
            backfillOfflinePeriods();
            System.out.println("[HIPS-BASELINE] Resumed from checkpoint. Active Learning: "
                + activeLearningMinutes + "/" + BASELINE_MINUTES + " minutes.");
        } else {
            // FIX 2.7: Sanity scan before starting fresh baseline
            if (runSanityScan()) {
                this.baselineTainted = true;
                System.err.println("[HIPS-BASELINE] ⚠ WARNING: IOCs detected during initial scan. Baseline marked as TAINTED.");
            }

            this.lastSeen    = LocalDateTime.now();
            this.baselineStart = this.lastSeen;
            this.activeLearningMinutes = 0;
            this.baselineComplete = false;
            System.out.println("[HIPS-BASELINE] Learning phase started. Required: " + BASELINE_MINUTES + " active minutes.");
        }
    }

    private void backfillOfflinePeriods() {
        if (lastSeen == null || baselineComplete) return;
        LocalDateTime now = LocalDateTime.now();
        long minutesOffline = ChronoUnit.MINUTES.between(lastSeen, now);
        if (minutesOffline >= 60) {
            int hoursToBackfill = (int) (minutesOffline / 60);
            System.out.println("[HIPS-BASELINE] Backfilling " + hoursToBackfill + " offline hours with zero-activity.");
            LocalDateTime runner = lastSeen.plusHours(1);
            for (int i = 0; i < hoursToBackfill; i++) {
                recordZeroActivityHour(runner.getHour());
                runner = runner.plusHours(1);
                activeLearningMinutes = Math.min(BASELINE_MINUTES, activeLearningMinutes + 60);
            }
        }
        lastSeen = now;
    }

    private void recordZeroActivityHour(int hour) {
        long[] n = fileEventN.get(hour);
        double[] mean = fileEventMean.get(hour);
        if (n != null && mean != null) {
            n[0]++;
            double delta = 0 - mean[0];
            mean[0] += delta / n[0];
        }
    }

    private boolean runSanityScan() {
        try {
            Process process = new ProcessBuilder("tasklist", "/fo", "csv", "/nh").start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String procName = line.split(",")[0].replace("\"", "").toLowerCase();
                    if (procName.equals("mimikatz.exe") || procName.equals("nc.exe")) {
                        return true;
                    }
                }
            }
            process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) { }
        return false;
    }

    // ── FIX 2.4: Welford update for connections ───────────────
    public void recordConnectionCount(int value) {
        if (baselineComplete) return;
        connN++;
        double delta  = value - connMean;
        connMean     += delta / connN;
        connM2       += delta * (value - connMean); // Uses new mean (correct Welford)
        totalConnScanCount++;
        saveCheckpointIfDue();
    }

    // ── FIX 2.4: Welford update for DNS rates ────────────────
    public void recordDnsQueryRate(int value) {
        if (baselineComplete) return;
        dnsN++;
        double delta = value - dnsMean;
        dnsMean     += delta / dnsN;
        saveCheckpointIfDue();
    }

    // ── FIX 2.4: Welford update for traffic volume ───────────
    public void recordTrafficVolume(long value) {
        if (baselineComplete) return;
        trafficN++;
        double delta = value - trafficMean;
        trafficMean += delta / trafficN;
        saveCheckpointIfDue();
    }

    // ── FIX 2.4: Running mean for file events per hour ───────
    /**
     * Increments the event counter for the current hour.
     * To avoid "spike" pollution, we accumulate events for the hour
     * and commit the total as a single data point once the hour changes.
     */
    public void recordFileEvent() {
        if (baselineComplete) return;
        int hour = LocalDateTime.now().getHour();

        // If the hour has changed since the last event, commit the accumulated data
        if (lastRecordedHour != -1 && hour != lastRecordedHour) {
            commitHourlyBaseline(lastRecordedHour);
        }

        lastRecordedHour = hour;
        hourlyEventAccumulator.merge(hour, 1L, Long::sum);
        saveCheckpointIfDue();
    }

    /**
     * Commits the accumulated events for a specific hour as a single data point
     * to the long-term baseline (Welford's algorithm).
     */
    private void commitHourlyBaseline(int hour) {
        Long totalForHour = hourlyEventAccumulator.getOrDefault(hour, 0L);
        
        long[]   n    = fileEventN.get(hour);
        double[] mean = fileEventMean.get(hour);

        n[0]++;
        double delta = totalForHour - mean[0];
        mean[0] += delta / n[0];

        // Reset the accumulator for this hour so it can start fresh tomorrow
        hourlyEventAccumulator.put(hour, 0L);
        System.out.println("[HIPS-BASELINE] Committed hourly baseline for hour " + hour + ": " + totalForHour + " events.");
    }

    public void recordPortOpen(int port) {
        if (baselineComplete) return;
        normalPortProfile.merge(port, 1, Integer::sum);
        saveCheckpointIfDue();
    }

    private void updateActiveTime() {
        if (baselineComplete || lastSeen == null) return;
        LocalDateTime now = LocalDateTime.now();
        long delta = ChronoUnit.MINUTES.between(lastSeen, now);
        if (delta >= 1) {
            activeLearningMinutes += delta;
            lastSeen = now;
        }
    }

    // ── Baseline Completion Check ─────────────────────────────
    public boolean checkBaselineComplete() {
        if (baselineComplete) return true;
        updateActiveTime();

        if (activeLearningMinutes >= BASELINE_MINUTES) {
            computeBaselines();
            baselineComplete = true;
            deleteCheckpoint(); // clean up checkpoint file
            System.out.println("[HIPS-BASELINE] ✓ Learning phase complete! Active uptime requirement met (" + activeLearningMinutes + " mins)."
                + (baselineTainted ? " ⚠ WARNING: Baseline may be tainted." : ""));
            return true;
        }
        return false;
    }

    private void computeBaselines() {
        // FIX 2.4: stddev from Welford's M2
        avgConnectionCount = connMean;
        stdDevConnections  = (connN > 1) ? Math.sqrt(connM2 / (connN - 1)) : 0.0;
        avgDnsQueryRate    = dnsMean;

        // File events per hour (using the learned Welford mean)
        for (int h = 0; h < 24; h++) {
            avgFileEventsPerHour.put(h, fileEventMean.get(h)[0]);
        }

        // Normal ports: seen in > 50% of scan cycles
        if (totalConnScanCount > 0) {
            for (Map.Entry<Integer, Integer> e : normalPortProfile.entrySet()) {
                if (e.getValue() > totalConnScanCount * 0.5) {
                    normalOpenPorts.add(e.getKey());
                }
            }
        }

        System.out.println("[HIPS-BASELINE] Computed baselines:");
        System.out.printf("[HIPS-BASELINE]   Avg connections: %.1f (σ=%.1f)%n", avgConnectionCount, stdDevConnections);
        System.out.printf("[HIPS-BASELINE]   Avg DNS queries: %.1f%n", avgDnsQueryRate);
        System.out.println("[HIPS-BASELINE]   Normal ports:   " + normalOpenPorts);
    }

    // ── FIX 2.5: Checkpoint Persistence ──────────────────────
    private long lastCheckpointTime = 0;
    private static final long CHECKPOINT_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

    private void saveCheckpointIfDue() {
        // Ensure hourly data is committed if the hour changes, even if no file events occur
        int currentHour = LocalDateTime.now().getHour();
        if (lastRecordedHour != -1 && currentHour != lastRecordedHour) {
            commitHourlyBaseline(lastRecordedHour);
            lastRecordedHour = currentHour;
        }

        long now = System.currentTimeMillis();
        if ((now - lastCheckpointTime) < CHECKPOINT_INTERVAL_MS) return;
        lastCheckpointTime = now;
        saveCheckpoint();
    }

    private void saveCheckpoint() {
        try {
            Map<String, Object> state = new HashMap<>();
            state.put("lastSeen",              lastSeen != null ? lastSeen.toString() : null);
            state.put("baselineStart",         baselineStart != null ? baselineStart.toString() : null);
            state.put("activeLearningMinutes", activeLearningMinutes);
            state.put("baselineComplete",      baselineComplete);
            state.put("baselineTainted",       baselineTainted);
            state.put("connN",                 connN);
            state.put("connMean",              connMean);
            state.put("connM2",                connM2);
            state.put("dnsN",                  dnsN);
            state.put("dnsMean",               dnsMean);
            state.put("trafficN",              trafficN);
            state.put("trafficMean",           trafficMean);
            state.put("totalConnScanCount",    totalConnScanCount);
            state.put("normalPortProfile",     normalPortProfile);
            state.put("lastRecordedHour",      lastRecordedHour);
            state.put("hourlyEventAccumulator", hourlyEventAccumulator);

            // Serialize per-hour file event stats
            Map<String, double[]> hourlyMeans = new HashMap<>();
            Map<String, long[]>   hourlyNs    = new HashMap<>();
            for (int h = 0; h < 24; h++) {
                hourlyMeans.put(String.valueOf(h), fileEventMean.get(h));
                hourlyNs.put(String.valueOf(h),    fileEventN.get(h));
            }
            state.put("fileEventMean", hourlyMeans);
            state.put("fileEventN",    hourlyNs);

            try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(CHECKPOINT_FILE)))) {
                out.print(GSON.toJson(state));
            }
            System.out.println("[HIPS-BASELINE] Checkpoint saved to disk.");
        } catch (Exception e) {
            System.err.println("[HIPS-BASELINE] Failed to save checkpoint: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private boolean loadCheckpoint() {
        Path path = Paths.get(CHECKPOINT_FILE);
        if (!Files.exists(path)) return false;

        try {
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new FileReader(path.toFile()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
            }
            Map<String, Object> state = GSON.fromJson(content.toString(), Map.class);

            String lastSeenStr = (String) state.get("lastSeen");
            if (lastSeenStr == null) return false;

            lastSeen              = LocalDateTime.parse(lastSeenStr);
            if (state.containsKey("baselineStart")) {
                baselineStart = LocalDateTime.parse((String) state.get("baselineStart"));
            } else {
                baselineStart = lastSeen;
            }
            activeLearningMinutes = ((Number) state.get("activeLearningMinutes")).longValue();
            baselineComplete      = Boolean.TRUE.equals(state.get("baselineComplete"));
            baselineTainted  = Boolean.TRUE.equals(state.get("baselineTainted"));
            connN            = ((Number) state.get("connN")).longValue();
            connMean         = ((Number) state.get("connMean")).doubleValue();
            connM2           = ((Number) state.get("connM2")).doubleValue();
            dnsN             = ((Number) state.get("dnsN")).longValue();
            dnsMean          = ((Number) state.get("dnsMean")).doubleValue();
            trafficN         = ((Number) state.get("trafficN")).longValue();
            trafficMean      = ((Number) state.get("trafficMean")).doubleValue();
            totalConnScanCount = ((Number) state.get("totalConnScanCount")).longValue();
            
            if (state.containsKey("lastRecordedHour")) {
                lastRecordedHour = ((Number) state.get("lastRecordedHour")).intValue();
            }

            // Restore port profile
            Map<String, Double> rawPorts = (Map<String, Double>) state.get("normalPortProfile");
            if (rawPorts != null) {
                rawPorts.forEach((k, v) -> normalPortProfile.put(Integer.parseInt(k), v.intValue()));
            }

            // Restore hourly accumulator
            Map<String, Double> rawAccumulator = (Map<String, Double>) state.get("hourlyEventAccumulator");
            if (rawAccumulator != null) {
                rawAccumulator.forEach((k, v) -> hourlyEventAccumulator.put(Integer.parseInt(k), v.longValue()));
            }

            // Restore file event statistics (Fix 2: Checkpoint Restore Bug)
            Map<String, List<Double>> rawMeans = (Map<String, List<Double>>) state.get("fileEventMean");
            Map<String, List<Double>> rawNs    = (Map<String, List<Double>>) state.get("fileEventN");

            if (rawMeans != null && rawNs != null) {
                for (int h = 0; h < 24; h++) {
                    String key = String.valueOf(h);
                    if (rawMeans.containsKey(key)) {
                        List<Double> mList = rawMeans.get(key);
                        if (!mList.isEmpty()) fileEventMean.get(h)[0] = mList.get(0);
                    }
                    if (rawNs.containsKey(key)) {
                        List<Double> nList = rawNs.get(key);
                        if (!nList.isEmpty()) fileEventN.get(h)[0] = nList.get(0).longValue();
                    }
                }
            }

            return true;
        } catch (Exception e) {
            System.err.println("[HIPS-BASELINE] Failed to load checkpoint (starting fresh): " + e.getMessage());
            return false;
        }
    }

    private void deleteCheckpoint() {
        try { Files.deleteIfExists(Paths.get(CHECKPOINT_FILE)); }
        catch (Exception ignored) {}
    }

    // ── FIX 2.7: Baseline Poisoning Taint Flag ───────────────
    /**
     * Called by the agent before the learning phase begins.
     * If host is already showing known-bad behavior, mark
     * the baseline as tainted so analysts are warned.
     */
    public void markAsTainted(String reason) {
        this.baselineTainted = true;
        System.err.println("[HIPS-BASELINE] ⚠ Baseline TAINTED: " + reason);
    }

    // ── FIX 2.6 (AnomalyDetector): Adaptive EMA Update ───────
    /**
     * Called periodically AFTER the baseline is complete to
     * drift the baseline toward new normal behavior.
     * alpha=0.02 means new data has only 2% weight (slow adaptation).
     */
    public void adaptBaseline(int newConnCount, int newDnsRate) {
        if (!baselineComplete) return;
        double alpha = 0.02;
        avgConnectionCount = alpha * newConnCount + (1 - alpha) * avgConnectionCount;
        avgDnsQueryRate    = alpha * newDnsRate    + (1 - alpha) * avgDnsQueryRate;
    }

    // ── Getters for AnomalyDetector ───────────────────────────
    public boolean isBaselineComplete()               { return baselineComplete; }
    public boolean isBaselineTainted()                { return baselineTainted; }
    public double  getAvgConnectionCount()            { return avgConnectionCount; }
    public double  getStdDevConnections()             { return stdDevConnections; }
    public double  getAvgDnsQueryRate()               { return avgDnsQueryRate; }
    public double  getAvgTrafficVolume()              { return trafficMean; }
    public Map<Integer, Double> getAvgFileEventsPerHour() { return avgFileEventsPerHour; }
    public Set<Integer> getNormalOpenPorts()          { return normalOpenPorts; }

    public int getDaysRemaining() {
        if (baselineStart == null) return BASELINE_DAYS;
        long elapsed = ChronoUnit.DAYS.between(baselineStart, LocalDateTime.now());
        return Math.max(0, BASELINE_DAYS - (int) elapsed);
    }
}
