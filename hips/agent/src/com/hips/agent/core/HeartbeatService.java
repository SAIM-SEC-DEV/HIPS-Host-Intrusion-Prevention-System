package com.hips.agent.core;

import com.hips.agent.config.AgentConfig;

import com.google.gson.JsonObject;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Heartbeat Service
 * ============================================================
 * Sends a periodic heartbeat (alive ping) to the server every
 * 30 seconds (configurable). This tells the server that the
 * agent is still running and responsive.
 *
 * The server uses the heartbeat_timeout_sec setting to decide
 * when to mark an agent as "offline" if heartbeats stop.
 *
 * Runs on a dedicated scheduled thread to avoid blocking the
 * main monitoring threads.
 */
public class HeartbeatService {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private ScheduledExecutorService scheduler;
    private volatile boolean running = false;

    // Track uptime since this service started
    private long startTimeMillis;

    public HeartbeatService(AgentConfig config, ApiClient apiClient) {
        this.config    = config;
        this.apiClient = apiClient;
    }

    /**
     * Starts the heartbeat scheduler. Sends the first heartbeat
     * immediately, then repeats at the configured interval.
     */
    public void start() {
        if (running) {
            System.out.println("[HIPS] Heartbeat service is already running.");
            return;
        }

        startTimeMillis = System.currentTimeMillis();
        running = true;

        // Single-thread scheduler — heartbeat doesn't need parallelism
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HIPS-Heartbeat");
            t.setDaemon(true); // Allow JVM shutdown without waiting
            return t;
        });

        int interval = config.getHeartbeatIntervalSec();
        System.out.println("[HIPS] Starting heartbeat service (interval: " + interval + "s)");

        // Schedule at fixed rate: first run immediately (0 delay),
        // then every `interval` seconds.
        scheduler.scheduleAtFixedRate(this::sendHeartbeat, 0, interval, TimeUnit.SECONDS);
    }

    /**
     * Stops the heartbeat scheduler gracefully.
     */
    public void stop() {
        running = false;
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            System.out.println("[HIPS] Heartbeat service stopped.");
        }
    }

    /**
     * Sends a single heartbeat to the server with optional
     * system metrics (uptime, CPU usage, RAM usage).
     */
    private void sendHeartbeat() {
        try {
            long uptimeSec = (System.currentTimeMillis() - startTimeMillis) / 1000;

            // Calculate rough JVM memory usage as a proxy for RAM usage
            Runtime rt = Runtime.getRuntime();
            double ramUsage = ((double)(rt.totalMemory() - rt.freeMemory()) / rt.maxMemory()) * 100.0;

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("agent_uuid", config.getAgentUuid());
            payload.put("uptime_sec", uptimeSec);
            payload.put("ram_usage",  Math.round(ramUsage * 10.0) / 10.0);

            JsonObject response = apiClient.post("heartbeat.php", payload);

            if (response != null && response.has("config")) {
                JsonObject remoteConfig = response.getAsJsonObject("config");
                if (remoteConfig.has("monitored_folders")) {
                    String folders = remoteConfig.get("monitored_folders").getAsString();
                    if (!folders.trim().isEmpty()) {
                        config.setWatchDirectories(folders.split(","));
                    }
                }
                if (remoteConfig.has("process_whitelist")) {
                    String processes = remoteConfig.get("process_whitelist").getAsString();
                    if (!processes.trim().isEmpty()) {
                        config.setProcessWhitelist(processes.split(","));
                    }
                }
            }

        } catch (Exception e) {
            // Don't crash the scheduler on transient failures.
            // The server will eventually mark us offline if
            // heartbeats stop arriving.
            System.err.println("[HIPS] Heartbeat failed: " + e.getMessage());
        }
    }

    public boolean isRunning() {
        return running;
    }
}
