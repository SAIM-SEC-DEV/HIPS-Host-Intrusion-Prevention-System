package com.hips.agent.core;

import com.google.gson.JsonObject;
import com.hips.agent.config.AgentConfig;
import com.hips.agent.model.AgentInfo;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — Registration Service
 * ============================================================
 * Handles the first step of the agent lifecycle: registering
 * with the HIPS server. On successful registration, the server
 * returns an auth token, agent ID, and UUID that are saved to
 * the local config file for all subsequent API calls.
 *
 * Lifecycle:
 *   1. On startup, check if config has a valid auth token.
 *   2. If yes → skip registration (already registered).
 *   3. If no  → collect system info and POST to /api/register.php.
 *   4. On success → save token, ID, UUID to config file.
 *   5. On failure → retry up to 5 times with exponential backoff.
 */
public class RegistrationService {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private static final int MAX_RETRIES = 5;

    public RegistrationService(AgentConfig config, ApiClient apiClient) {
        this.config    = config;
        this.apiClient = apiClient;
    }

    /**
     * Performs agent registration with the HIPS server.
     * If already registered, logs a confirmation and returns true.
     *
     * @return true if the agent is registered (new or existing)
     */
    public boolean register() {
        // ── Check if already registered ──────────────────────
        if (config.isRegistered()) {
            System.out.println("[HIPS] Agent already registered (ID: "
                    + config.getAgentId() + ", UUID: " + config.getAgentUuid() + ")");

            // Re-register to update metadata and confirm connectivity
            return reRegister();
        }

        // ── First-time registration ─────────────────────────
        System.out.println("[HIPS] Starting first-time agent registration...");

        // Collect this machine's information
        AgentInfo info = new AgentInfo();
        info.setOwner(config.getOwner());
        System.out.println("[HIPS] System info: " + info);

        // Build the registration payload
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("hostname",      info.getHostname());
        payload.put("ip_address",    info.getIpAddress());
        payload.put("os_name",       info.getOsName());
        payload.put("os_version",    info.getOsVersion());
        payload.put("os_arch",       info.getOsArch());
        payload.put("cpu_info",      info.getCpuInfo());
        payload.put("ram_total_mb",  info.getRamTotalMb());
        payload.put("agent_version", info.getAgentVersion());
        payload.put("owner",         info.getOwner());

        // ── Retry loop with exponential backoff ──────────────
        // If the server is down on boot, the agent retries with
        // increasing delays: 2s, 4s, 8s, 16s, 32s.
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            System.out.println("[HIPS] Registration attempt " + attempt + "/" + MAX_RETRIES);

            JsonObject response = apiClient.postNoAuth("register.php", payload);

            if (response != null && response.has("status")
                    && "success".equals(response.get("status").getAsString())) {

                // ── Save the credentials to config ───────────
                config.setAgentId(response.get("agent_id").getAsInt());
                config.setAgentUuid(response.get("agent_uuid").getAsString());
                config.setAuthToken(response.get("auth_token").getAsString());

                if (response.has("baseline_start")) {
                    config.setBaselineStart(response.get("baseline_start").getAsString());
                }

                config.saveConfig();

                System.out.println("[HIPS] ✓ Registration successful!");
                System.out.println("[HIPS]   Agent ID:   " + config.getAgentId());
                System.out.println("[HIPS]   Agent UUID: " + config.getAgentUuid());
                System.out.println("[HIPS]   Baseline:   " + config.getBaselineStart());
                return true;
            }

            // ── Exponential backoff before retry ─────────────
            if (attempt < MAX_RETRIES) {
                int waitSec = (int) Math.pow(2, attempt);
                System.err.println("[HIPS] Registration failed. Retrying in " + waitSec + "s...");
                try {
                    Thread.sleep(waitSec * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }

        System.err.println("[HIPS] ✗ Registration failed after " + MAX_RETRIES + " attempts.");
        return false;
    }

    /**
     * Re-registers an existing agent to update metadata and
     * confirm server connectivity on startup.
     */
    private boolean reRegister() {
        AgentInfo info = new AgentInfo();
        info.setOwner(config.getOwner());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("hostname",      info.getHostname());
        payload.put("ip_address",    info.getIpAddress());
        payload.put("os_name",       info.getOsName());
        payload.put("os_version",    info.getOsVersion());
        payload.put("os_arch",       info.getOsArch());
        payload.put("cpu_info",      info.getCpuInfo());
        payload.put("ram_total_mb",  info.getRamTotalMb());
        payload.put("agent_version", info.getAgentVersion());
        payload.put("owner",         info.getOwner());

        JsonObject response = apiClient.postNoAuth("register.php", payload);

        if (response != null && response.has("status")
                && "success".equals(response.get("status").getAsString())) {
            System.out.println("[HIPS] ✓ Re-registration successful. Server confirmed agent identity.");
            return true;
        }

        System.err.println("[HIPS] ⚠ Re-registration failed. Continuing with cached credentials.");
        return config.isRegistered(); // Still OK if we have cached credentials
    }
}
