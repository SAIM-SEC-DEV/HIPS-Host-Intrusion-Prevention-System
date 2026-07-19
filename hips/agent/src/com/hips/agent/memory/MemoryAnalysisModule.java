package com.hips.agent.memory;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;
import com.hips.agent.osquery.OsFacade;
import com.hips.agent.process.ProcessInfo;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * ============================================================
 * HIPS Agent — Memory Analysis Module (Fileless Malware Detection)
 * ============================================================
 *
 * OSQUERY INTEGRATION:
 *   Process listing for YARA memory scanning is now fetched
 *   via the OsFacade abstraction. On cross-platform hosts,
 *   osquery's `processes` table provides PIDs for all platforms.
 *   The YARA memory scan itself is platform-dependent (requires
 *   YARA binary compiled for the host OS).
 *
 * ALL EXISTING LOGIC PRESERVED:
 *   - Periodic YARA-based memory scanning every 15 minutes
 *   - PID enumeration and YARA rule matching
 *   - CRITICAL severity alerts for fileless malware detection
 *   - Graceful handling of access-denied for system processes
 */
public class MemoryAnalysisModule {
    private final AgentConfig config;
    private final ApiClient apiClient;
    private ScheduledExecutorService scheduler;
    private OsFacade osFacade; // Injected telemetry source

    public MemoryAnalysisModule(AgentConfig config, ApiClient apiClient) {
        this.config = config;
        this.apiClient = apiClient;
    }

    /**
     * Injects the OsFacade for cross-platform process enumeration.
     */
    public void setOsFacade(OsFacade facade) {
        this.osFacade = facade;
    }

    public void start() {
        System.out.println("[MemoryAnalysis] Starting Memory Analysis Module (Fileless Malware Detection)...");
        if (osFacade != null) {
            System.out.println("[MemoryAnalysis] Using OsFacade backend for PID enumeration.");
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "MemoryAnalysis");
            t.setDaemon(true);
            return t;
        });
        
        // Run full memory scan every 15 minutes
        scheduler.scheduleAtFixedRate(this::scanMemory, 1, 15, TimeUnit.MINUTES);
    }

    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        System.out.println("[MemoryAnalysis] Module stopped.");
    }

    private void scanMemory() {
        System.out.println("[MemoryAnalysis] Executing periodic memory scan...");
        List<String> activePids = getActivePids();
        
        for (String pid : activePids) {
            scanProcessMemoryWithYara(pid);
        }
    }

    /**
     * Gets active PIDs via OsFacade (preferred) or legacy tasklist (fallback).
     */
    private List<String> getActivePids() {
        List<String> pids = new ArrayList<>();

        // Prefer OsFacade
        if (osFacade != null) {
            try {
                Map<Integer, ProcessInfo> processes = osFacade.getProcesses();
                for (Integer pid : processes.keySet()) {
                    if (pid > 0) {
                        pids.add(String.valueOf(pid));
                    }
                }
                // Limit to 50 for performance
                return pids.size() > 50 ? pids.subList(0, 50) : pids;
            } catch (Exception e) {
                System.err.println("[MemoryAnalysis] OsFacade PID fetch failed, falling back: " + e.getMessage());
            }
        }

        // Legacy fallback: tasklist
        try {
            Process p = Runtime.getRuntime().exec("tasklist /FO CSV /NH");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\",\"");
                    if (parts.length > 1) {
                        String pid = parts[1].replace("\"", "").trim();
                        if (!pid.isEmpty() && !pid.equals("0")) {
                            pids.add(pid);
                        }
                    }
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[MemoryAnalysis] Failed to get PIDs: " + e.getMessage());
        }
        // Limit to a small number of processes for performance during demo, or prioritize specific ones.
        return pids.size() > 50 ? pids.subList(0, 50) : pids;
    }

    private void scanProcessMemoryWithYara(String pid) {
        String yaraBinary = config.getYaraBinaryPath();
        String yaraRules = config.getYaraRulesPath();
        
        java.io.File yaraExe = new java.io.File(yaraBinary);
        if (!yaraExe.exists()) {
            return; // Exit silently if YARA isn't configured properly
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(yaraBinary, yaraRules, pid);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            List<String> matches = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.contains("access denied")) continue; // Skip permission errors for SYSTEM processes
                    
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        matches.add(parts[0]);
                    }
                }
            }
            
            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
            }

            if (!matches.isEmpty()) {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("pid", pid);
                metadata.put("yara_matches", matches);
                metadata.put("os_type", osFacade != null ? osFacade.getOsType() : "windows");
                
                Event event = new Event(Module.memory, "FILELESS_MALWARE_DETECTED", Severity.CRITICAL, "Malware signature found in process memory")
                        .withDescription("YARA detected " + matches.size() + " signature match(es) in the memory space of PID " + pid)
                        .withMetadata(metadata);
                        
                apiClient.postAsyncChecked("report.php", event);
                System.out.println("🔴 [MemoryAnalysis] Fileless malware detected in PID: " + pid);
            }

        } catch (Exception e) {
            // Suppress errors to avoid console spam for protected processes
        }
    }
}
