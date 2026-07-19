package com.hips.agent.file;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.core.ServiceManager.ManagedService;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * ============================================================
 * HIPS Agent — Rootkit Scanner (Cross-View Check)
 * ============================================================
 * Performs a cross-view detection by comparing the standard
 * Java API file listing (which may be hooked/intercepted by 
 * user-mode rootkits) against a lower-level system command 
 * listing. Discrepancies indicate stealth/hidden files.
 */
public class RootkitScanner implements ManagedService {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private final FileAlertHandler fileAlertHandler;
    private ScheduledExecutorService scheduler;
    
    // Directory to perform deep scan on (e.g., C:\Windows\System32\drivers)
    // We restrict it to avoid massive CPU overhead on the whole C:\ drive.
    private static final String TARGET_DIR = System.getenv("SystemRoot") + "\\System32\\drivers";

    public RootkitScanner(AgentConfig config, ApiClient apiClient) {
        this.config = config;
        this.apiClient = apiClient;
        this.fileAlertHandler = new FileAlertHandler(apiClient);
    }

    public void setScheduler(ScheduledExecutorService scheduler) {
        this.scheduler = scheduler;
    }

    @Override
    public String getServiceName() {
        return "Rootkit Deep-Core Scanner";
    }

    @Override
    public void startService() {
        System.out.println("[HIPS-ROOTKIT] Starting Rootkit Scanner...");
        
        if (scheduler == null) {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "HIPS-RootkitScanner");
                t.setDaemon(true);
                return t;
            });
        }

        // Run deep scan every 6 hours
        scheduler.scheduleAtFixedRate(this::performCrossViewScan, 1, 6, TimeUnit.HOURS);
    }

    @Override
    public void stopService() {
        System.out.println("[HIPS-ROOTKIT] Rootkit Scanner stopped.");
    }

    /**
     * Executes the Cross-View detection logic.
     */
    private void performCrossViewScan() {
        System.out.println("[HIPS-ROOTKIT] Initiating Cross-View Scan on " + TARGET_DIR + "...");
        
        File targetFile = new File(TARGET_DIR);
        if (!targetFile.exists() || !targetFile.isDirectory()) {
            System.err.println("[HIPS-ROOTKIT] Target directory not found: " + TARGET_DIR);
            return;
        }

        try {
            // View 1: Standard API Listing (Hookable)
            Set<String> apiView = getApiFileListing(TARGET_DIR);
            
            // View 2: System Command Listing (Bypasses some user-mode hooks)
            Set<String> sysView = getSystemCommandListing(TARGET_DIR);
            
            // Compare Views: Find files in sysView that are NOT in apiView
            Set<String> hiddenFiles = new HashSet<>(sysView);
            hiddenFiles.removeAll(apiView);
            
            if (!hiddenFiles.isEmpty()) {
                System.err.println("[HIPS-ROOTKIT] ⚠ ROOTKIT DETECTED! Hidden files found.");
                for (String hidden : hiddenFiles) {
                    System.err.println("  -> STEALTH FILE: " + hidden);
                    reportRootkit(hidden);
                }
            } else {
                System.out.println("[HIPS-ROOTKIT] ✓ Cross-View scan clean. No stealth files detected.");
            }
            
        } catch (Exception e) {
            System.err.println("[HIPS-ROOTKIT] Scan failed: " + e.getMessage());
        }
    }

    /**
     * View 1: Gets a file list using standard Java NIO.
     */
    private Set<String> getApiFileListing(String directory) throws IOException {
        Set<String> files = new HashSet<>();
        try (Stream<Path> stream = Files.walk(Paths.get(directory))) {
            stream.filter(Files::isRegularFile)
                  .forEach(path -> files.add(path.toAbsolutePath().toString().toLowerCase()));
        }
        return files;
    }

    /**
     * View 2: Gets a file list using Windows DIR command with /A (All files including hidden/system).
     */
    private Set<String> getSystemCommandListing(String directory) {
        Set<String> files = new HashSet<>();
        // Use dir /s /b /a-d to get full paths of all files (excluding directories)
        String command = "cmd.exe /c dir /s /b /a-d \"" + directory + "\"";
        
        try {
            Process p = Runtime.getRuntime().exec(command);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        files.add(line.trim().toLowerCase());
                    }
                }
            }
            p.waitFor(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[HIPS-ROOTKIT] System command failed: " + e.getMessage());
        }
        return files;
    }

    /**
     * Reports a detected rootkit stealth file to the server.
     */
    private void reportRootkit(String filePath) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("detection_method", "Cross-View Analysis");
        metadata.put("api_visible", false);
        metadata.put("system_visible", true);
        
        Event event = new Event(Module.file, "ROOTKIT_STEALTH_FILE", Severity.CRITICAL, "Rootkit Detected: Hidden File")
                .withDescription("A stealth file was detected during a Cross-View scan. It is hidden from standard API calls but exists on disk: " + filePath)
                .withSourcePath(filePath)
                .withMetadata(metadata);
        
        fileAlertHandler.logEvent(event);
        fileAlertHandler.triggerAlert(event);
    }
}
