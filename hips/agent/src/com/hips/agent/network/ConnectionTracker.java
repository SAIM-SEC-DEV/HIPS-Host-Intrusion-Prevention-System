package com.hips.agent.network;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * ============================================================
 * HIPS Agent — Connection Tracker (Refactored v1.1)
 * ============================================================
 *
 * FIXES APPLIED:
 *   - FIX 2.6 (Memory Leak): The endpointTimestamps map is now
 *     capped at 2000 entries and purged every 5 minutes via a
 *     background cleanup task, preventing OOM on long-running agents.
 *
 *   - FIX 2.7 (CopyOnWriteArrayList): Replaced with an ArrayDeque
 *     used as a fixed-capacity ring buffer. O(1) add/remove with
 *     proper synchronization, eliminating CPU/memory copy overhead.
 *
 *   - FIX 2.5 (Alert Fatigue): Process-aware filtering hook added.
 *     Connections owned by KNOWN_SAFE_PROCESSES are excluded from
 *     beaconing detection to eliminate false positives from apps
 *     like Chrome, Slack, Discord, etc.
 */
public class ConnectionTracker {

    private final NetworkAlertHandler alertHandler;
    private final IpManager ipManager;

    // ── FIX 2.7: Ring buffer for connection history ───────────
    // ArrayDeque with synchronized access replaces CopyOnWriteArrayList.
    // Fixed capacity prevents unbounded growth.
    private final ArrayDeque<Integer> connectionHistory = new ArrayDeque<>(110);
    private static final int HISTORY_SIZE = 100;

    // ── FIX 2.6: Capped endpoint timestamp map ────────────────
    private static final int MAX_ENDPOINT_ENTRIES = 2000;
    private final Map<String, List<Long>> endpointTimestamps = new ConcurrentHashMap<>();

    // ── FIX 2.5: Process-aware whitelist ─────────────────────
    // Connections owned by these processes are excluded from beaconing
    // detection. They perform legitimate periodic heartbeats.
    private static final Set<String> KNOWN_SAFE_PROCESSES = new HashSet<>(Arrays.asList(
        "chrome", "msedge", "firefox", "brave", "opera", "msedgewebview2",
        "slack", "discord", "teams", "whatsapp", "anydesk",
        "outlook", "onedrive", "dropbox", "googledrive", "m365copilot",
        "svchost", "lsass", "system", "searchhost", "searchapp", "lockapp",
        "backgroundtaskhost", "wuauclt", "msmpeng", "idle", "widgets",
        "chrome.exe", "msedge.exe", "firefox.exe", "msedgewebview2.exe",
        "slack.exe", "discord.exe", "teams.exe", "anydesk.exe",
        "outlook.exe", "onedrive.exe", "svchost.exe", "searchapp.exe", "lockapp.exe"
    ));

    // Beaconing detection thresholds
    private static final double BEACONING_VARIANCE_THRESHOLD = 0.15;
    private static final int    BEACONING_MIN_SAMPLES        = 10; // Increased from 5 to reduce noise

    // Spike detection
    private static final double SPIKE_MULTIPLIER     = 2.5;
    private static final long   SPIKE_COOLDOWN_MS    = 5 * 60 * 1000L;
    private long lastSpikeAlertTime = 0;

    // ── FIX 2.6: Background cleanup scheduler ────────────────
    private final ScheduledExecutorService cleanupScheduler;

    public ConnectionTracker(NetworkAlertHandler alertHandler, IpManager ipManager) {
        this.alertHandler = alertHandler;
        this.ipManager = ipManager;

        // Purge stale endpoint entries every 5 minutes
        cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HIPS-ConnTracker-Cleanup");
            t.setDaemon(true);
            return t;
        });
        cleanupScheduler.scheduleAtFixedRate(this::purgeStaleEndpoints, 5, 5, TimeUnit.MINUTES);
    }

    // ── Cleanup ───────────────────────────────────────────────
    /**
     * FIX 2.6: Removes endpoints with no recent activity (> 10 min)
     * and caps the map at MAX_ENDPOINT_ENTRIES to prevent OOM.
     */
    private void purgeStaleEndpoints() {
        long cutoff = System.currentTimeMillis() - (10 * 60 * 1000L);
        endpointTimestamps.entrySet().removeIf(entry -> {
            List<Long> ts = entry.getValue();
            if (ts.isEmpty()) return true;
            return ts.get(ts.size() - 1) < cutoff;
        });

        // Hard cap: evict oldest entries if still over limit
        if (endpointTimestamps.size() > MAX_ENDPOINT_ENTRIES) {
            List<String> keys = new ArrayList<>(endpointTimestamps.keySet());
            keys.subList(0, keys.size() - MAX_ENDPOINT_ENTRIES).forEach(endpointTimestamps::remove);
        }
    }

    // ── Function 1: trackConnections() ───────────────────────
    public void trackConnections(List<Map<String, String>> connections) {
        // FIX 2.7: Synchronized ring buffer update
        synchronized (connectionHistory) {
            connectionHistory.addLast(connections.size());
            if (connectionHistory.size() > HISTORY_SIZE) {
                connectionHistory.removeFirst();
            }
        }

        long now = System.currentTimeMillis();

        // FIX 2.6: Only track if under capacity
        if (endpointTimestamps.size() >= MAX_ENDPOINT_ENTRIES) {
            purgeStaleEndpoints();
        }

        for (Map<String, String> conn : connections) {
            String state = conn.getOrDefault("state", "").toUpperCase();
            // FIX: Skip listening sockets for beaconing/spike detection.
            if (state.contains("LISTEN")) continue;

            String remoteIP   = conn.get("remote_ip");
            String remotePort = conn.get("remote_port");

            // FIX 2.5: Skip connections owned by whitelisted processes
            String owningProcess = conn.getOrDefault("owning_process", "").toLowerCase();
            if (KNOWN_SAFE_PROCESSES.contains(owningProcess)) continue;

            if (remoteIP == null) continue;
            
            // FIX: Always normalize and check trust/local status before tracking
            String cleanRemoteIP = (ipManager != null) ? ipManager.normalizeIP(remoteIP) : remoteIP.trim();

            if (ipManager != null) {
                if (ipManager.isLocalAddress(cleanRemoteIP) || ipManager.isTrustedOrg(cleanRemoteIP)) {
                    continue;
                }
            }

            // Fallback for case where ipManager might be null during startup
            if (cleanRemoteIP.isEmpty() || cleanRemoteIP.equals("127.0.0.1") || cleanRemoteIP.equals("::1") || 
                cleanRemoteIP.equals("0.0.0.0") || cleanRemoteIP.equals("::") || cleanRemoteIP.equals("*") ||
                cleanRemoteIP.equals("0:0:0:0:0:0:0:1")) {
                continue;
            }

            // Ensure remoteIP is also normalized for the endpoint key
            String endpoint = cleanRemoteIP + ":" + remotePort;
            endpointTimestamps.computeIfAbsent(endpoint, k -> new ArrayList<>()).add(now);

            // Cap per-endpoint history at 50 entries
            List<Long> timestamps = endpointTimestamps.get(endpoint);
            if (timestamps != null && timestamps.size() > 50) {
                timestamps.subList(0, timestamps.size() - 30).clear();
            }
        }
    }

    // ── Function 2: detectConnectionSpike() ──────────────────
    public void detectConnectionSpike() {
        List<Integer> snapshot;
        synchronized (connectionHistory) {
            if (connectionHistory.size() < 5) return;
            snapshot = new ArrayList<>(connectionHistory);
        }

        long now = System.currentTimeMillis();
        if ((now - lastSpikeAlertTime) < SPIKE_COOLDOWN_MS) return;

        double average = snapshot.stream().mapToInt(Integer::intValue).average().orElse(0);
        int    current = snapshot.get(snapshot.size() - 1);

        if (average > 0 && current > average * SPIKE_MULTIPLIER) {
            lastSpikeAlertTime = now;
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("current_count", current);
            metadata.put("average", Math.round(average * 10.0) / 10.0);
            metadata.put("threshold_multiplier", SPIKE_MULTIPLIER);

            Event event = new Event(Module.network, "CONNECTION_SPIKE", Severity.HIGH,
                    "Unusual connection spike detected")
                    .withDescription(String.format(
                        "Current connections: %d | Historical average: %.1f | Threshold: %.1f",
                        current, average, average * SPIKE_MULTIPLIER))
                    .withMetadata(metadata);
            alertHandler.triggerNetworkAlert(event);
        }
    }

    // ── Function 3: detectBeaconing() ────────────────────────
    public void detectBeaconing(List<Map<String, String>> connections) {
        for (Map.Entry<String, List<Long>> entry : endpointTimestamps.entrySet()) {
            List<Long> timestamps = entry.getValue();
            if (timestamps.size() < BEACONING_MIN_SAMPLES + 1) continue;

            List<Long> intervals = new ArrayList<>();
            for (int i = 1; i < timestamps.size(); i++) {
                intervals.add(timestamps.get(i) - timestamps.get(i - 1));
            }
            if (intervals.size() < BEACONING_MIN_SAMPLES) continue;

            double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
            if (mean == 0) continue;

            double variance = intervals.stream()
                    .mapToDouble(iv -> Math.pow(iv - mean, 2))
                    .average().orElse(0);
            double stdDev = Math.sqrt(variance);
            double cv     = stdDev / mean;

            if (cv < BEACONING_VARIANCE_THRESHOLD) {
                String endpoint    = entry.getKey();
                
                // Trusted Org Check: Suppress alerts for trusted cloud endpoints
                // Endpoint is now stored as normalizedIP:port
                String remoteIP = endpoint;
                if (endpoint.contains(":")) {
                    // Since we stored it as normalizedIP:port, we just take the part before the last colon
                    remoteIP = endpoint.substring(0, endpoint.lastIndexOf(":"));
                }
                
                if (ipManager != null && ipManager.isTrustedOrg(remoteIP)) {
                    System.out.println("[HIPS-NET] Suppressed beaconing alert for trusted org/local: " + endpoint);
                    timestamps.clear();
                    continue;
                }

                double intervalSec = mean / 1000.0;

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("endpoint", endpoint);
                metadata.put("avg_interval_sec", Math.round(intervalSec * 10.0) / 10.0);
                metadata.put("coefficient_of_variation", Math.round(cv * 1000.0) / 1000.0);
                metadata.put("sample_count", intervals.size());

                Event event = new Event(Module.network, "BEACONING_DETECTED", Severity.CRITICAL,
                        "Possible C2 beaconing to " + endpoint)
                        .withDescription(String.format(
                            "Periodic traffic pattern detected to %s (Interval: %.1fs, CV: %.3f). " +
                            "Threshold: CV < %.3f. This strongly suggests automated beaconing.",
                            endpoint, intervalSec, cv, BEACONING_VARIANCE_THRESHOLD))
                        .withDestination(endpoint)
                        .withMetadata(metadata);

                alertHandler.triggerNetworkAlert(event);
                timestamps.clear(); // Reset to avoid repeated alerts
            }
        }
    }

    public void stop() {
        cleanupScheduler.shutdownNow();
    }

    // ── Accessors ─────────────────────────────────────────────
    public int getCurrentConnectionCount() {
        synchronized (connectionHistory) {
            return connectionHistory.isEmpty() ? 0 : connectionHistory.peekLast();
        }
    }

    public double getAverageConnectionCount() {
        synchronized (connectionHistory) {
            return connectionHistory.stream().mapToInt(Integer::intValue).average().orElse(0);
        }
    }
}
