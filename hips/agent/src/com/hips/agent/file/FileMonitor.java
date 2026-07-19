package com.hips.agent.file;
 
import com.hips.agent.anomaly.BaselineCollector;
import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.malware.YaraScanner;
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
    private final YaraScanner yaraScanner;
    private final BaselineCollector baselineCollector;
    private final ExecutorService malwareScannerExecutor;

    private WatchService watchService;
    private Thread watchThread;
    private volatile boolean running = false;

    // Maps WatchKey → directory path for event resolution
    private final Map<WatchKey, Path> watchKeyMap = new ConcurrentHashMap<>();

    // Debounce map to prevent duplicate events for rapid successive changes
    // Key = file path, Value = timestamp of last reported event
    private final Map<String, Long> lastEventTimes = new ConcurrentHashMap<>();
    private static final long DEBOUNCE_MS = 2000; // 2 seconds

    // ── FIX 2.4 (Noise Reduction): Extended exclusion patterns ─
    // Includes log, temp, and OS cache files that generate high
    // volumes of legitimate MODIFY events and create alert noise.
    private static final Set<String> EXCLUDED_PATHS = new HashSet<>(Arrays.asList(
        "Thumbs.db", "desktop.ini", ".DS_Store", "~$"
    ));
    private static final Set<String> EXCLUDED_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".log", ".tmp", ".temp", ".etl", ".cache",
        ".ldf", ".mdf",  // SQL Server transaction logs
        ".pf",           // Windows prefetch
        ".db-wal", ".db-shm", // SQLite write-ahead logs
        ".part",         // Partial download files
        ".evtx",         // Windows Event Logs (high noise)
        ".map", ".btr", ".data", ".chk" // System databases (WMI, SRU, catroot)
    ));

    // Noisy system directories that should be ignored for MODIFY events
    private static final Set<String> EXCLUDED_DIR_PATTERNS = new HashSet<>(Arrays.asList(
        "\\system32\\sru",
        "\\system32\\wbem\\repository",
        "\\system32\\logfiles\\setupcln",
        "\\system32\\catroot2",
        "\\hips-oop\\"
    ));

    // Agent's own audit log files — excluded to prevent self-monitoring loops.
    private static final Set<String> AGENT_LOG_FILES = new HashSet<>(Arrays.asList(
        "hips-file-audit.log",
        "hips-network-audit.log",
        "hips-process-audit.log",
        "hips-registry-audit.log"
    ));

    // ── FIX 2.7 (Race Condition): Latch ensures watchLoop waits  ─
    // for baseline hashing to complete before processing events.
    // Prevents false "HASH MISMATCH" alerts on startup.
    private final CountDownLatch baselineLatch = new CountDownLatch(1);

    // ── FIX 2.6 (Handle Exhaustion): Max recursive depth ────────
    private static final int MAX_WATCH_DEPTH = 3;


    public FileMonitor(AgentConfig config, ApiClient apiClient, BaselineCollector baselineCollector) {
        this.config       = config;
        this.apiClient    = apiClient;
        this.baselineCollector = baselineCollector;
        this.integrity    = new FileIntegrity();
        this.ruleEngine   = new FileRuleEngine(config);
        this.alertHandler = new FileAlertHandler(apiClient);
        this.yaraScanner  = new YaraScanner(config, alertHandler);
        this.malwareScannerExecutor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "HIPS-MalwareScanner");
            t.setDaemon(true);
            return t;
        });

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

            for (String dir : config.getWatchDirectories()) {
                Path path = Paths.get(dir.trim());

                // FIX 2.1 (System32 Guard): Warn if broad system dirs are watched.
                // Monitoring System32 entirely exhausts OS watch handles.
                String pathStr = path.toString().toLowerCase();
                if (pathStr.contains("system32") || pathStr.contains("syswow64")) {
                    System.err.println("[HIPS-FILE] ⚠ WARNING: Broad system directory detected: " + path);
                    System.err.println("[HIPS-FILE]   Consider monitoring specific critical files instead.");
                    System.err.println("[HIPS-FILE]   e.g., C:\\Windows\\System32\\drivers\\etc\\hosts");
                }

                if (Files.isDirectory(path)) {
                    registerDirectory(path);
                } else {
                    System.err.println("[HIPS-FILE] Skipping non-existent directory: " + dir);
                }
            }

            // FIX 2.7 (Race Condition): Run baseline hasher FIRST, then
            // count down the latch to unblock the watchLoop.
            // This prevents false HASH MISMATCH on files modified during startup.
            Thread baselineThread = new Thread(() -> {
                System.out.println("[HIPS-FILE] Computing baseline file hashes...");
                try {
                    for (String dir : config.getWatchDirectories()) {
                        Path path = Paths.get(dir.trim());
                        if (Files.isDirectory(path)) {
                            // FIX: Custom walk that respects exclusions to avoid noise
                            baselineWithExclusions(path);
                        }
                    }
                    System.out.println("[HIPS-FILE] Baseline complete: "
                        + integrity.getBaselineCount() + " files hashed.");
                } finally {
                    // Always release latch so watchLoop can proceed
                    baselineLatch.countDown();
                }
            }, "HIPS-BaselineHasher");
            baselineThread.setDaemon(true);
            baselineThread.start();

            // Start watch loop — it will BLOCK at the latch until baseline is ready
            running = true;
            watchThread = new Thread(this::watchLoop, "HIPS-FileMonitor");
            watchThread.setDaemon(true);
            watchThread.start();

            System.out.println("[HIPS-FILE] ✓ File monitoring started. Watching "
                    + watchKeyMap.size() + " directories.");

        } catch (IOException e) {
            System.err.println("[HIPS-FILE] Failed to start monitoring: " + e.getMessage());
            baselineLatch.countDown(); // release latch on failure to prevent deadlock
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

        if (malwareScannerExecutor != null) {
            malwareScannerExecutor.shutdown();
            try {
                if (!malwareScannerExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    malwareScannerExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                malwareScannerExecutor.shutdownNow();
            }
        }

        System.out.println("[HIPS-FILE] File monitoring stopped.");
    }

    private void syncDirectories() {
        if (!running) return;
        try {
            Set<String> configDirs = new HashSet<>();
            for (String dir : config.getWatchDirectories()) configDirs.add(Paths.get(dir.trim()).toString());

            // 1. Add new directories
            for (String dir : config.getWatchDirectories()) {
                Path path = Paths.get(dir.trim());
                boolean isAlreadyWatched = false;
                for (Path watched : watchKeyMap.values()) {
                    if (watched.equals(path)) {
                        isAlreadyWatched = true;
                        break;
                    }
                }
                
                if (Files.isDirectory(path) && !isAlreadyWatched) {
                    System.out.println("[HIPS-FILE] Found new dynamic directory: " + path);
                    registerDirectory(path);
                    integrity.storeBaselineHash(path);
                }
            }

            // 2. Remove directories no longer in config
            // We iterate over a copy to avoid ConcurrentModificationException
            for (Map.Entry<WatchKey, Path> entry : new HashMap<>(watchKeyMap).entrySet()) {
                Path watchedPath = entry.getValue();
                boolean stillInConfig = false;
                
                // Check if this path or any of its parents are in the config
                // (Since we watch recursively, we only remove if the root watch is gone)
                for (String cDir : configDirs) {
                    if (watchedPath.toString().startsWith(cDir)) {
                        stillInConfig = true;
                        break;
                    }
                }

                if (!stillInConfig) {
                    System.out.println("[HIPS-FILE] Removing watch for orphaned directory: " + watchedPath);
                    entry.getKey().cancel();
                    watchKeyMap.remove(entry.getKey());
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
            // FIX 2.6 (Handle Exhaustion): Depth-limited walk to prevent
            // OS watch handle exhaustion on deep directory trees.
            Files.walkFileTree(dir, new HashSet<FileVisitOption>(Arrays.asList(FileVisitOption.FOLLOW_LINKS)), MAX_WATCH_DEPTH,
                new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path subDir, BasicFileAttributes attrs) {
                        registerDirectoryRecursive(subDir);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
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
        if (isExcludedPath(dir)) return; // Don't watch excluded dirs

        try {
            WatchKey key = dir.register(watchService, ENTRY_CREATE, ENTRY_MODIFY, ENTRY_DELETE);
            watchKeyMap.put(key, dir);
        } catch (IOException e) {
            // Common for system directories we can't access
            System.err.println("[HIPS-FILE] Cannot watch " + dir + ": " + e.getMessage());
        }
    }

    /**
     * Baseline walk that respects exclusions and handles permission errors gracefully
     */
    private void baselineWithExclusions(Path root) {
        if (!Files.exists(root) || !Files.isReadable(root)) return;

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (isExcludedPath(dir)) return FileVisitResult.SKIP_SUBTREE;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (isExcludedPath(file)) return FileVisitResult.CONTINUE;
                    
                    try {
                        if (attrs.isRegularFile() && attrs.size() <= 100 * 1024 * 1024) {
                            String hash = integrity.computeHash(file);
                            if (hash != null) {
                                integrity.getBaselineHashes().put(file.toAbsolutePath().toString(), hash);
                            }
                        }
                    } catch (Exception e) {
                        // Individual file failure shouldn't stop the walk
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Skip files/dirs we can't access without erroring out
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (Exception e) {
            System.err.println("[HIPS-FILE] Baseline walk partial failure for " + root + ": " + e.getMessage());
        }
    }

    // ── Core Function 4: detectFileChange() ──────────────────
    /**
     * The main watch loop. Blocks on WatchService.take() waiting
     * for file system events, then processes each event through
     * the rule engine and integrity checker.
     */
    private void watchLoop() {
        System.out.println("[HIPS-FILE] Watch loop started, waiting for baseline...");

        // FIX 2.7 (Race Condition): Block here until baseline hashing is done.
        // Without this, a MODIFY event arriving before baseline is stored
        // will trigger a false "HASH MISMATCH" alert.
        try {
            baselineLatch.await(5, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        System.out.println("[HIPS-FILE] Baseline ready. Watch loop active.");

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

        // ── Malware Scanning (New) ───────────────────────────
        // Trigger YARA scan on ENTRY_CREATE for suspicious extensions
        if (kind == ENTRY_CREATE && Files.isRegularFile(fullPath)) {
            String nameLower = fullPath.getFileName().toString().toLowerCase();
            if (nameLower.endsWith(".exe") || nameLower.endsWith(".dll") || 
                nameLower.endsWith(".bat") || nameLower.endsWith(".ps1")) {
                scanForMalware(fullPath);
            }
        }

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
        
        // Record event for baseline learning phase (Fix 3: Spike Pollution prevention is inside collector)
        if (baselineCollector != null) {
            baselineCollector.recordFileEvent();
        }

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
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("directory", filePath.getParent().toString());
        metadata.put("is_sensitive_path", ruleEngine.isSensitivePath(filePath));
        metadata.put("is_sensitive_ext", ruleEngine.isSensitiveExtension(filePath));
        metadata.put("is_off_hours", ruleEngine.isOffHours());
        metadata.put("is_whitelisted", ruleEngine.isWhitelisted(filePath));
        metadata.put("hash_mismatch", hashMismatch);

        Event event = new Event(Module.file, eventType, severity, title)
                .withSourcePath(filePath.toString())
                .withHash(hashValue)
                .withDescription(buildDescription(eventType, filePath, hashMismatch))
                .withMetadata(metadata);

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
     * Asynchronously scans a file for malware using YARA.
     * If matches are found, triggers a CRITICAL alert.
     */
    private void scanForMalware(Path filePath) {
        malwareScannerExecutor.submit(() -> {
            System.out.println("[HIPS-MALWARE] Scanning file: " + filePath);
            List<String> matches = yaraScanner.scanFile(filePath);

            if (!matches.isEmpty()) {
                String matchStr = String.join(", ", matches);
                System.err.println("[HIPS-MALWARE] ⚠ MALWARE DETECTED: " + filePath + " | Matches: " + matchStr);

                Map<String, Object> malwareMetadata = new HashMap<>();
                malwareMetadata.put("yara_matches", matches);
                malwareMetadata.put("scanner", "YARA");

                Event malwareEvent = new Event(Module.file, "MALWARE_THREAT_DETECTED", Severity.CRITICAL, "Malware Detected: " + filePath.getFileName())
                        .withSourcePath(filePath.toString())
                        .withDescription("YARA scan matched rules: " + matchStr + " on file " + filePath)
                        .withMetadata(malwareMetadata);

                alertHandler.logEvent(malwareEvent);
                alertHandler.triggerAlert(malwareEvent);
            } else {
                System.out.println("[HIPS-MALWARE] File clean: " + filePath);
            }
        });
    }

    /**
     * Checks if a path should be excluded from monitoring
     * (temp files, OS artifacts, agent's own log files, etc.)
     */
    private boolean isExcludedPath(Path path) {
        String name = path.getFileName().toString();
        String nameLower = name.toLowerCase();

        // Exclude agent's own log files
        if (AGENT_LOG_FILES.contains(name)) return true;

        // FIX 2.4 (Noise Reduction): Exclude noisy OS/app generated files
        // These are legitimately modified hundreds of times per hour
        for (String ext : EXCLUDED_EXTENSIONS) {
            if (nameLower.endsWith(ext)) return true;
        }

        for (String excluded : EXCLUDED_PATHS) {
            if (name.equals(excluded) || name.startsWith(excluded)) return true;
        }

        // Exclude specific noisy system directories
        String pathStrLower = path.toString().toLowerCase();
        for (String pattern : EXCLUDED_DIR_PATTERNS) {
            if (pathStrLower.contains(pattern)) return true;
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
