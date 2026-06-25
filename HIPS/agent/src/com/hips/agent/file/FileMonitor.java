package com.hips.agent.file;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;

import static java.nio.file.StandardWatchEventKinds.*;

/**
 * ============================================================
 * HIPS Agent — File Monitor
 * ============================================================
 * Core file system monitoring module using Java's WatchService
 * API. Watches registered directories for file creation,
 * modification, and deletion events.
 *
 * Architecture:
 *   - WatchService runs on a dedicated daemon thread
 *   - Each detected change is evaluated against the rule engine
 *   - Events are logged locally and reported to the server
 *   - Supports recursive directory watching
 *
 * Functions implemented (9 of 25 — core functions):
 *   startMonitoring(), stopMonitoring(), registerDirectory(),
 *   detectFileChange(), processEvent(), watchLoop(),
 *   registerDirectoryRecursive(), isExcludedPath(), getWatchedDirectories()
 */
public class FileMonitor {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private final FileIntegrity integrity;
    private final FileRuleEngine ruleEngine;
    private final FileAlertHandler alertHandler;

    private WatchService watchService;
    private Thread watchThread;
    private volatile boolean running = false;

    // Maps WatchKey → directory path for event resolution
    private final Map<WatchKey, Path> watchKeyMap = new ConcurrentHashMap<>();

    // Debounce map to prevent duplicate events for rapid successive changes
    // Key = file path, Value = timestamp of last reported event
    private final Map<String, Long> lastEventTimes = new ConcurrentHashMap<>();
    private static final long DEBOUNCE_MS = 2000; // 2 seconds

    // Excluded paths/patterns that should never trigger alerts
    private static final Set<String> EXCLUDED_PATHS = Set.of(
        "Thumbs.db", "desktop.ini", ".DS_Store", "~$"
    );

    // Agent's own audit log files — excluded to prevent self-monitoring loops.
    // IMPORTANT: Only these exact filenames are excluded, NOT all .log files.
    // This prevents attackers from hiding malicious binaries with a .log extension.
    private static final Set<String> AGENT_LOG_FILES = Set.of(
        "hips-file-audit.log",
        "hips-network-audit.log",
        "hips-process-audit.log",
        "hips-registry-audit.log"
    );

    public FileMonitor(AgentConfig config, ApiClient apiClient) {
        this.config       = config;
        this.apiClient    = apiClient;
        this.integrity    = new FileIntegrity();
        this.ruleEngine   = new FileRuleEngine(config);
        this.alertHandler = new FileAlertHandler(apiClient);

        // Periodically sync monitored directories with the dynamically updating config
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HIPS-FileConfigSync");
            t.setDaemon(true);
            return t;
        }).scheduleAtFixedRate(this::syncDirectories, 10, 30, TimeUnit.SECONDS);
    }

    // ── Core Function 1: startMonitoring() ───────────────────
    /**
     * Starts the file monitoring service. Creates a WatchService,
     * registers all configured directories, computes baseline
     * hashes, and begins the watch loop on a dedicated thread.
     */
    public void startMonitoring() {
        if (running) {
            System.out.println("[HIPS-FILE] Monitor is already running.");
            return;
        }

        try {
            watchService = FileSystems.getDefault().newWatchService();

            // Register all directories from configuration
            for (String dir : config.getWatchDirectories()) {
                Path path = Paths.get(dir.trim());
                if (Files.isDirectory(path)) {
                    registerDirectory(path);
                } else {
                    System.err.println("[HIPS-FILE] Skipping non-existent directory: " + dir);
                }
            }

            // Compute baseline hashes for all files in watched directories
            System.out.println("[HIPS-FILE] Computing baseline file hashes in background...");
            new Thread(() -> {
                for (String dir : config.getWatchDirectories()) {
                    Path path = Paths.get(dir.trim());
                    if (Files.isDirectory(path)) {
                        integrity.storeBaselineHash(path);
                    }
                }
                System.out.println("[HIPS-FILE] Baseline calculation complete: " + integrity.getBaselineCount() + " files hashed.");
            }, "HIPS-BaselineHasher").start();

            // Start the watch loop on a daemon thread
            running = true;
            watchThread = new Thread(this::watchLoop, "HIPS-FileMonitor");
            watchThread.setDaemon(true);
            watchThread.start();

            System.out.println("[HIPS-FILE] ✓ File monitoring started. Watching "
                    + watchKeyMap.size() + " directories.");

        } catch (IOException e) {
            System.err.println("[HIPS-FILE] Failed to start monitoring: " + e.getMessage());
        }
    }

    // ── Core Function 2: stopMonitoring() ────────────────────
    /**
     * Gracefully stops the monitoring service. Closes the
     * WatchService and terminates the watch thread.
     */
    public void stopMonitoring() {
        running = false;

        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException e) {
            System.err.println("[HIPS-FILE] Error closing WatchService: " + e.getMessage());
        }

        if (watchThread != null) {
            watchThread.interrupt();
            try {
                watchThread.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[HIPS-FILE] File monitoring stopped.");
    }

    private void syncDirectories() {
        if (!running) return;
        try {
            Set<String> currentWatched = new HashSet<>();
            for (Path p : watchKeyMap.values()) currentWatched.add(p.toString());

            for (String dir : config.getWatchDirectories()) {
                Path path = Paths.get(dir.trim());
                if (Files.isDirectory(path) && !currentWatched.contains(path.toString())) {
                    System.out.println("[HIPS-FILE] Found new dynamic directory: " + path);
                    registerDirectory(path);
                    integrity.storeBaselineHash(path);
                }
            }
        } catch (Exception e) {
            System.err.println("[HIPS-FILE] Sync error: " + e.getMessage());
        }
    }

    // ── Core Function 3: registerDirectory() ─────────────────
    /**
     * Registers a single directory (and all subdirectories
     * recursively) with the WatchService for CREATE, MODIFY,
     * and DELETE events.
     */
    public void registerDirectory(Path dir) {
        try {
            // Walk the directory tree and register each subdirectory
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path subDir, BasicFileAttributes attrs) {
                    registerDirectoryRecursive(subDir);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Skip directories we can't access (permission denied)
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("[HIPS-FILE] Failed to register directory " + dir + ": " + e.getMessage());
        }
    }

    /**
     * Registers a single directory (non-recursive helper).
     */
    private void registerDirectoryRecursive(Path dir) {
        try {
            WatchKey key = dir.register(watchService, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);
            watchKeyMap.put(key, dir);
        } catch (IOException e) {
            // Common for system directories we can't access
            System.err.println("[HIPS-FILE] Cannot watch " + dir + ": " + e.getMessage());
        }
    }

    // ── Core Function 4: detectFileChange() ──────────────────
    /**
     * The main watch loop. Blocks on WatchService.take() waiting
     * for file system events, then processes each event through
     * the rule engine and integrity checker.
     */
    private void watchLoop() {
        System.out.println("[HIPS-FILE] Watch loop started.");

        while (running) {
            WatchKey key;
            try {
                // Block until an event is available
                key = watchService.take();
            } catch (InterruptedException e) {
                if (!running) break;
                Thread.currentThread().interrupt();
                break;
            } catch (ClosedWatchServiceException e) {
                break; // Service was closed, exit loop
            }

            // Resolve the directory this key belongs to
            Path dir = watchKeyMap.get(key);
            if (dir == null) {
                key.cancel();
                continue;
            }

            // Process each event in this batch
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();

                // OVERFLOW means events were lost; log and continue
                if (kind == OVERFLOW) {
                    System.err.println("[HIPS-FILE] Event overflow in " + dir);
                    continue;
                }

                @SuppressWarnings("unchecked")
                WatchEvent<Path> pathEvent = (WatchEvent<Path>) event;
                Path fileName = pathEvent.context();
                Path fullPath = dir.resolve(fileName);

                // Skip excluded files (temp files, system artifacts)
                if (isExcludedPath(fullPath)) continue;

                // Debounce: skip if we reported this file very recently
                String pathStr = fullPath.toString();
                long now = System.currentTimeMillis();
                Long lastTime = lastEventTimes.get(pathStr);
                if (lastTime != null && (now - lastTime) < DEBOUNCE_MS) continue;
                lastEventTimes.put(pathStr, now);

                // Process the event
                detectFileChange(kind, fullPath);

                // If a new directory was created, register it too
                if (kind == ENTRY_CREATE && Files.isDirectory(fullPath)) {
                    registerDirectory(fullPath);
                }
            }

            // Reset the key; if the directory is no longer accessible,
            // the key becomes invalid and we remove it.
            boolean valid = key.reset();
            if (!valid) {
                watchKeyMap.remove(key);
                if (watchKeyMap.isEmpty()) {
                    System.err.println("[HIPS-FILE] All watched directories are gone!");
                    break;
                }
            }
        }

        System.out.println("[HIPS-FILE] Watch loop exited.");
    }

    /**
     * Processes a single file change event. Evaluates the event
     * against the rule engine and integrity checker, then reports
     * to the server if warranted.
     */
    private void detectFileChange(WatchEvent.Kind<?> kind, Path filePath) {
        String eventType;
        if (kind == ENTRY_CREATE)      eventType = "FILE_CREATED";
        else if (kind == ENTRY_MODIFY) eventType = "FILE_MODIFIED";
        else if (kind == ENTRY_DELETE) eventType = "FILE_DELETED";
        else return;

        System.out.println("[HIPS-FILE] " + eventType + ": " + filePath);

        // Attempt to find the modifying process name (Best effort via Handle/PowerShell or fallback)
        String processName = ruleEngine.guessModifyingProcess(filePath);

        // ── Run the rule engine against this event ───────────
        Severity severity = ruleEngine.evaluateRule(filePath, eventType);

        // ── Check file integrity (hash comparison) ───────────
        String hashValue = null;
        boolean hashMismatch = false;

        if (kind != ENTRY_DELETE && Files.isRegularFile(filePath)) {
            hashValue = integrity.computeHash(filePath);
            hashMismatch = integrity.compareHash(filePath, hashValue);

            if (hashMismatch) {
                // Hash mismatch means the file was tampered with
                severity = Severity.CRITICAL;
                System.err.println("[HIPS-FILE] ⚠ HASH MISMATCH: " + filePath);
            }
        }

        // ── Build the event ──────────────────────────────────
        String title = eventType.replace("_", " ") + ": " + filePath.getFileName();
        Event event = new Event(Module.file, eventType, severity, title)
                .withSourcePath(filePath.toString())
                .withHash(hashValue)
                .withDescription(buildDescription(eventType, filePath, hashMismatch))
                .withMetadata(Map.of(
                    "directory", filePath.getParent().toString(),
                    "is_sensitive_path", ruleEngine.isSensitivePath(filePath),
                    "is_sensitive_ext", ruleEngine.isSensitiveExtension(filePath),
                    "is_off_hours", ruleEngine.isOffHours(),
                    "is_whitelisted", ruleEngine.isWhitelisted(filePath),
                    "hash_mismatch", hashMismatch
                ));

        // ── Log and report ───────────────────────────────────
        alertHandler.logEvent(event);

        // Only report to server if the process is not whitelisted
        boolean isWhitelistedProc = ruleEngine.isWhitelistedProcess(processName);
        if (!ruleEngine.isWhitelisted(filePath) && !isWhitelistedProc) {
            alertHandler.triggerAlert(event);
        } else if (isWhitelistedProc) {
            System.out.println("[HIPS-FILE] Ignored due to Whitelisted Process: " + processName);
        }
    }

    /**
     * Builds a human-readable description for a file event.
     */
    private String buildDescription(String eventType, Path filePath, boolean hashMismatch) {
        StringBuilder sb = new StringBuilder();
        sb.append(eventType).append(" detected on: ").append(filePath);

        if (hashMismatch) {
            sb.append(" | FILE INTEGRITY VIOLATION — hash does not match baseline.");
        }
        if (ruleEngine.isSensitivePath(filePath)) {
            sb.append(" | File is in a sensitive/protected directory.");
        }
        if (ruleEngine.isSensitiveExtension(filePath)) {
            sb.append(" | File has a high-risk extension.");
        }
        if (ruleEngine.isOffHours()) {
            sb.append(" | Activity occurred outside normal working hours.");
        }

        return sb.toString();
    }

    /**
     * Checks if a path should be excluded from monitoring
     * (temp files, OS artifacts, agent's own log files, etc.)
     */
    private boolean isExcludedPath(Path path) {
        String name = path.getFileName().toString();

        // Exclude ONLY the agent's own audit log files (not all .log files)
        // This prevents a security bypass where an attacker names a binary .log
        if (AGENT_LOG_FILES.contains(name)) {
            return true;
        }

        for (String excluded : EXCLUDED_PATHS) {
            if (name.equals(excluded) || name.startsWith(excluded)) {
                return true;
            }
        }
        return false;
    }

    // ── Accessors ────────────────────────────────────────────

    public boolean isRunning() {
        return running;
    }

    public int getWatchedDirectoryCount() {
        return watchKeyMap.size();
    }

    public FileIntegrity getIntegrity() {
        return integrity;
    }

    public FileRuleEngine getRuleEngine() {
        return ruleEngine;
    }

    public Set<Path> getWatchedDirectories() {
        return new HashSet<>(watchKeyMap.values());
    }
}
