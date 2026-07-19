package com.hips.agent.registry;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;
import com.hips.agent.osquery.OsFacade;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Registry / Persistence Integrity Monitor
 * ============================================================
 * Scans critical persistence paths to detect tampering and
 * unauthorized startup entries.
 *
 * OSQUERY INTEGRATION:
 *   Registry/persistence data is now fetched via the OsFacade
 *   abstraction:
 *     - Windows: osquery's `registry` table
 *     - Linux:   osquery's `startup_items` + `systemd_units`
 *     - macOS:   osquery's `launchd` table
 *   Without osquery, falls back to PowerShell reg queries.
 *
 * ALL EXISTING LOGIC PRESERVED:
 *   - Baseline-and-diff integrity checking
 *   - Monitored key paths (Run, RunOnce, Services, Firewall, Defender)
 *   - Severity levels per key path
 *   - Alert generation for new/modified/deleted values
 */
public class RegistryMonitor {

    private final RegistryAlertHandler alertHandler;
    private ScheduledExecutorService scheduler;
    private OsFacade osFacade; // Injected telemetry source

    // Baselines: Map<KeyPath, Map<ValueName, Data>>>
    private final ConcurrentHashMap<String, Map<String, String>> baselines = new ConcurrentHashMap<>();

    // Map of Monitored Registry Keys and their severity level/event type
    private static final Map<String, RegKeyConfig> MONITORED_KEYS = new HashMap<>();

    static {
        // Run Keys (Persistence)
        MONITORED_KEYS.put("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", new RegKeyConfig(Severity.HIGH, "REGISTRY_RUN_KEY_MODIFIED"));
        MONITORED_KEYS.put("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", new RegKeyConfig(Severity.HIGH, "REGISTRY_RUN_KEY_MODIFIED"));
        MONITORED_KEYS.put("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", new RegKeyConfig(Severity.MEDIUM, "REGISTRY_RUN_KEY_MODIFIED"));
        MONITORED_KEYS.put("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", new RegKeyConfig(Severity.MEDIUM, "REGISTRY_RUN_KEY_MODIFIED"));

        // Services (Persistence & Privilege Escalation)
        MONITORED_KEYS.put("HKLM\\SYSTEM\\CurrentControlSet\\Services", new RegKeyConfig(Severity.HIGH, "REGISTRY_SERVICE_MODIFIED"));

        // Firewall (Defense Evasion)
        MONITORED_KEYS.put("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy", new RegKeyConfig(Severity.CRITICAL, "REGISTRY_FIREWALL_MODIFIED"));

        // Defender (Defense Evasion)
        MONITORED_KEYS.put("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", new RegKeyConfig(Severity.CRITICAL, "REGISTRY_DEFENDER_TAMPERING"));
    }

    // Cross-platform persistence paths monitored on Linux/macOS
    private static final Map<String, RegKeyConfig> LINUX_PERSISTENCE_PATHS = new HashMap<>();
    static {
        LINUX_PERSISTENCE_PATHS.put("/etc/crontab", new RegKeyConfig(Severity.HIGH, "PERSISTENCE_CRONTAB_MODIFIED"));
        LINUX_PERSISTENCE_PATHS.put("/etc/systemd/system", new RegKeyConfig(Severity.HIGH, "PERSISTENCE_SYSTEMD_MODIFIED"));
        LINUX_PERSISTENCE_PATHS.put("/etc/init.d", new RegKeyConfig(Severity.MEDIUM, "PERSISTENCE_INITD_MODIFIED"));
    }

    private static final Map<String, RegKeyConfig> MACOS_PERSISTENCE_PATHS = new HashMap<>();
    static {
        MACOS_PERSISTENCE_PATHS.put("/Library/LaunchDaemons", new RegKeyConfig(Severity.HIGH, "PERSISTENCE_LAUNCHDAEMON_MODIFIED"));
        MACOS_PERSISTENCE_PATHS.put("/Library/LaunchAgents", new RegKeyConfig(Severity.MEDIUM, "PERSISTENCE_LAUNCHAGENT_MODIFIED"));
        MACOS_PERSISTENCE_PATHS.put("~/Library/LaunchAgents", new RegKeyConfig(Severity.MEDIUM, "PERSISTENCE_USER_LAUNCHAGENT_MODIFIED"));
    }

    public RegistryMonitor(RegistryAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    public RegistryMonitor(RegistryAlertHandler alertHandler, ScheduledExecutorService sharedScheduler) {
        this.alertHandler = alertHandler;
        this.scheduler = sharedScheduler;
    }

    /**
     * Injects the OsFacade for cross-platform registry/persistence queries.
     */
    public void setOsFacade(OsFacade facade) {
        this.osFacade = facade;
    }

    public void start() {
        System.out.println("[RegistryMonitor] Starting Registry/Persistence Integrity Monitoring module...");
        if (osFacade != null) {
            System.out.println("[RegistryMonitor] Using OsFacade backend: " + osFacade.getClass().getSimpleName());
            System.out.println("[RegistryMonitor] Target OS: " + osFacade.getOsType());
        }
        
        if (scheduler == null) {
            scheduler = Executors.newScheduledThreadPool(1, r -> {
                Thread t = new Thread(r, "RegistryMonitor");
                t.setDaemon(true);
                return t;
            });
        }

        // Take initial baseline of all keys
        takeBaseline();

        // FIX 3.6: Schedule periodic scanning every 20 seconds (was 45s)
        scheduler.scheduleAtFixedRate(this::scanRegistry, 20, 20, TimeUnit.SECONDS);
    }

    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            // Only shutdown if it's not the shared pool
        }
        System.out.println("[RegistryMonitor] Module stopped.");
    }

    /**
     * Returns the effective set of monitored key paths based on the OS.
     */
    private Map<String, RegKeyConfig> getEffectiveMonitoredKeys() {
        if (osFacade == null || "windows".equals(osFacade.getOsType())) {
            return MONITORED_KEYS;
        } else if ("linux".equals(osFacade.getOsType())) {
            // On Linux, monitor both traditional "Run" paths (mapped by osquery)
            // and Linux-specific persistence paths
            Map<String, RegKeyConfig> effective = new HashMap<>(LINUX_PERSISTENCE_PATHS);
            // Also query Run keys — OsFacade maps them to startup_items on Linux
            for (Map.Entry<String, RegKeyConfig> entry : MONITORED_KEYS.entrySet()) {
                if (entry.getKey().contains("Run")) {
                    effective.put(entry.getKey(), entry.getValue());
                }
            }
            return effective;
        } else if ("darwin".equals(osFacade.getOsType())) {
            Map<String, RegKeyConfig> effective = new HashMap<>(MACOS_PERSISTENCE_PATHS);
            for (Map.Entry<String, RegKeyConfig> entry : MONITORED_KEYS.entrySet()) {
                if (entry.getKey().contains("Run")) {
                    effective.put(entry.getKey(), entry.getValue());
                }
            }
            return effective;
        }
        return MONITORED_KEYS;
    }

    // ── Scanning Logic ───────────────────────────────────────

    private void takeBaseline() {
        Map<String, RegKeyConfig> keys = getEffectiveMonitoredKeys();
        for (String keyPath : keys.keySet()) {
            try {
                Map<String, String> values = queryKey(keyPath);
                baselines.put(keyPath, values);
            } catch (Exception e) {
                System.err.println("[RegistryMonitor] Failed to baseline " + keyPath + ": " + e.getMessage());
            }
        }
    }

    private void scanRegistry() {
        try {
            Map<String, RegKeyConfig> effectiveKeys = getEffectiveMonitoredKeys();
            Map<String, Map<String, String>> currentBatch = batchQueryKeys(effectiveKeys.keySet());

            for (Map.Entry<String, RegKeyConfig> entry : effectiveKeys.entrySet()) {
                String keyPath = entry.getKey();
                RegKeyConfig config = entry.getValue();
                
                Map<String, String> currentValues = currentBatch.getOrDefault(keyPath, new HashMap<>());
                Map<String, String> baselineValues = baselines.getOrDefault(keyPath, new HashMap<>());

                // Check for new or modified values
                for (Map.Entry<String, String> curr : currentValues.entrySet()) {
                    String valueName = curr.getKey();
                    String data = curr.getValue();
                    String baselineData = baselineValues.get(valueName);

                    if (baselineData == null) {
                        triggerAlert(config, keyPath, valueName, "New registry/persistence value added.", data);
                    } else if (!baselineData.equals(data)) {
                        triggerAlert(config, keyPath, valueName, "Registry/persistence value modified.", "From: " + baselineData + " To: " + data);
                    }
                }

                // Check for deleted values
                for (String valueName : baselineValues.keySet()) {
                    if (!currentValues.containsKey(valueName)) {
                        triggerAlert(config, keyPath, valueName, "Registry/persistence value deleted.", null);
                    }
                }

                baselines.put(keyPath, currentValues);
            }
        } catch (Exception e) {
            System.err.println("[RegistryMonitor] Batch scan failed: " + e.getMessage());
        }
    }

    private void triggerAlert(RegKeyConfig config, String path, String valueName, String desc, String data) {
        String fullDesc = desc + " Value: " + valueName + (data != null ? " Data: " + data : "");
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("key_path", path);
        metadata.put("value_name", valueName);
        metadata.put("data", data != null ? data : "");
        metadata.put("os_type", osFacade != null ? osFacade.getOsType() : "windows");

        Event e = new Event(Module.registry, config.eventType, config.severity, "Registry/Persistence Tampering Detected")
                    .withDescription(fullDesc)
                    .withSourcePath(path + "\\" + valueName)
                    .withMetadata(metadata);
        alertHandler.triggerAlert(e);
    }

    // ── Key Querying ─────────────────────────────────────────

    private Map<String, String> queryKey(String keyPath) {
        Set<String> singleKey = new HashSet<>();
        singleKey.add(keyPath);
        return batchQueryKeys(singleKey).getOrDefault(keyPath, new HashMap<>());
    }

    /**
     * Queries registry/persistence keys via OsFacade or legacy PowerShell.
     */
    private Map<String, Map<String, String>> batchQueryKeys(Set<String> keys) {
        // Prefer OsFacade
        if (osFacade != null) {
            try {
                return osFacade.batchGetRegistryValues(keys);
            } catch (Exception e) {
                System.err.println("[RegistryMonitor] OsFacade query failed, falling back: " + e.getMessage());
            }
        }

        // Legacy fallback: PowerShell batched query (original implementation)
        return batchQueryRegistryLegacy(keys);
    }

    private final com.google.gson.Gson gson = new com.google.gson.Gson();

    /**
     * Legacy batched PowerShell registry query (preserved for backward compat).
     */
    private Map<String, Map<String, String>> batchQueryRegistryLegacy(Set<String> keys) {
        Map<String, Map<String, String>> results = new HashMap<>();
        if (keys.isEmpty()) return results;

        try {
            StringBuilder script = new StringBuilder();
            for (String k : keys) {
                String psPath = "Registry::" + k;
                script.append("try { Get-ItemProperty -LiteralPath '").append(psPath)
                      .append("' -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, Run | ConvertTo-Json -Compress; Write-Output '---SEP---' } catch { Write-Output '{}---SEP---' }; ");
            }

            Process process = new ProcessBuilder("powershell", "-NoProfile", "-Command", script.toString())
                    .redirectErrorStream(true).start();
            
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                StringBuilder output = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                // Parse JSON blocks
                String[] blocks = output.toString().split("---SEP---");
                int i = 0;
                for (String key : keys) {
                    if (i < blocks.length) {
                        String json = blocks[i].trim();
                        Map<String, String> values = new HashMap<>();
                        if (!json.isEmpty() && !json.equals("{}")) {
                            try {
                                Map<String, Object> rawMap = gson.fromJson(json, new com.google.gson.reflect.TypeToken<Map<String, Object>>(){}.getType());
                                for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
                                    values.put(entry.getKey(), String.valueOf(entry.getValue()));
                                }
                            } catch (Exception e) {
                                System.err.println("[RegistryMonitor] JSON parse error for " + key + ": " + e.getMessage());
                            }
                        }
                        results.put(key, values);
                    }
                    i++;
                }
            }
            process.waitFor();
        } catch (Exception e) {
            System.err.println("[RegistryMonitor] Legacy batch query failed: " + e.getMessage());
            for (String key : keys) {
                results.putIfAbsent(key, new HashMap<>());
            }
        }
        return results;
    }

    static class RegKeyConfig {
        Severity severity;
        String eventType;

        RegKeyConfig(Severity severity, String eventType) {
            this.severity = severity;
            this.eventType = eventType;
        }
    }
}
