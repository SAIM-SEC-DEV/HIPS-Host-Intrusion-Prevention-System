package com.hips.agent.registry;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Windows Registry Integrity Monitor
 * ============================================================
 * Scans critical Windows Registry paths to detect persistence
 * mechanisms (Run keys, services, tasks) and tampering (firewall, defender).
 */
public class RegistryMonitor {

    private final RegistryAlertHandler alertHandler;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, r -> {
        Thread t = new Thread(r, "RegistryMonitor");
        t.setDaemon(true);
        return t;
    });

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

    public RegistryMonitor(RegistryAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    public void start() {
        System.out.println("[RegistryMonitor] Starting Registry Integrity Monitoring module...");
        
        // Take initial baseline of all keys
        takeBaseline();

        // Schedule periodic scanning every 45 seconds
        scheduler.scheduleAtFixedRate(this::scanRegistry, 45, 45, TimeUnit.SECONDS);
    }

    public void stop() {
        scheduler.shutdownNow();
        System.out.println("[RegistryMonitor] Module stopped.");
    }

    // ── Scanning Logic ───────────────────────────────────────

    private void takeBaseline() {
        for (String keyPath : MONITORED_KEYS.keySet()) {
            try {
                Map<String, String> values = queryRegistryKey(keyPath);
                baselines.put(keyPath, values);
            } catch (Exception e) {
                System.err.println("[RegistryMonitor] Failed to baseline " + keyPath + ": " + e.getMessage());
            }
        }
    }

    private void scanRegistry() {
        try {
            Map<String, Map<String, String>> currentBatch = batchQueryRegistry(MONITORED_KEYS.keySet());

            for (Map.Entry<String, RegKeyConfig> entry : MONITORED_KEYS.entrySet()) {
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
                        triggerAlert(config, keyPath, valueName, "New registry value added.", data);
                    } else if (!baselineData.equals(data)) {
                        triggerAlert(config, keyPath, valueName, "Registry value modified.", "From: " + baselineData + " To: " + data);
                    }
                }

                // Check for deleted values
                for (String valueName : baselineValues.keySet()) {
                    if (!currentValues.containsKey(valueName)) {
                        triggerAlert(config, keyPath, valueName, "Registry value deleted.", null);
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
        Event e = new Event(Module.registry, config.eventType, config.severity, "Registry Tampering Detected")
                    .withDescription(fullDesc)
                    .withSourcePath(path + "\\" + valueName)
                    .withMetadata(Map.of("key_path", path, "value_name", valueName, "data", data != null ? data : ""));
        alertHandler.triggerAlert(e);
    }

    // ── Utilities ────────────────────────────────────────────

    /**
     * Executes `reg query` individually for baselining.
     */
    private Map<String, String> queryRegistryKey(String keyPath) throws Exception {
        return batchQueryRegistry(Set.of(keyPath)).getOrDefault(keyPath, new HashMap<>());
    }

    private final com.google.gson.Gson gson = new com.google.gson.Gson();

    /**
     * Executes a single batched PowerShell script to query multiple keys simultaneously,
     * drastically reducing process spawn overhead (1 Process vs N Processes).
     */
    private Map<String, Map<String, String>> batchQueryRegistry(Set<String> keys) throws Exception {
        Map<String, Map<String, String>> results = new HashMap<>();
        if (keys.isEmpty()) return results;

        StringBuilder script = new StringBuilder();
        for (String k : keys) {
            String psPath = "Registry::" + k;
            // Get-ItemProperty returns an object; we select all properties except PS-specific ones
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
                            // Use Gson to parse the JSON into a Map
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
        return results;
    }

    private static class RegKeyConfig {
        Severity severity;
        String eventType;

        RegKeyConfig(Severity severity, String eventType) {
            this.severity = severity;
            this.eventType = eventType;
        }
    }
}
