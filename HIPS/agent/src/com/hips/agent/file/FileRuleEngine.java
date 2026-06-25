package com.hips.agent.file;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.model.Event.Severity;

import java.nio.file.Path;
import java.time.LocalTime;
import java.util.Set;

/**
 * ============================================================
 * HIPS Agent — File Rule Engine
 * ============================================================
 * Contains all rule-based detection logic for the file
 * monitoring module. Each rule evaluates a specific aspect of
 * a file event and contributes to the overall severity rating.
 *
 * Rules (6 of 25):
 *   isSensitivePath()     — Protected directories (System32, etc.)
 *   isSensitiveExtension() — High-risk file types (.exe, .dll, etc.)
 *   evaluateRule()         — Master evaluator combining all rules
 *   isWhitelisted()        — Trusted paths/processes
 *   isOffHours()           — Changes outside business hours
 *   getRuleCount()         — Total number of active rules
 */
public class FileRuleEngine {

    private final AgentConfig config;

    // ── Sensitive directories ────────────────────────────────
    // Changes inside these directories are automatically flagged
    // as HIGH severity because they contain critical system files.
    private static final Set<String> SENSITIVE_PATHS = Set.of(
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows\\Boot",
        "C:\\Windows\\security",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/boot"
    );

    // ── Sensitive file extensions ────────────────────────────
    // These file types are commonly used by malware. Creating or
    // modifying them in monitored directories triggers a higher
    // severity level.
    private static final Set<String> SENSITIVE_EXTENSIONS = Set.of(
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".ps1",
        ".vbs", ".msi", ".sys", ".drv", ".scr",
        ".com", ".pif", ".reg", ".inf", ".hta",
        ".cpl", ".jar", ".wsf", ".wsh"
    );

    // ── Whitelisted paths ────────────────────────────────────
    // Changes in these paths are considered safe and will not
    // trigger alerts (e.g., Windows Update, antivirus databases).
    private static final Set<String> WHITELISTED_PATHS = Set.of(
        "C:\\Windows\\Temp",
        "C:\\Windows\\Prefetch",
        "C:\\Windows\\SoftwareDistribution",
        "C:\\Windows\\Logs"
    );

    // ── Off-hours window ─────────────────────────────────────
    // File changes between 22:00 and 06:00 are flagged as
    // suspicious because legitimate admin activity typically
    // doesn't occur during these hours.
    private static final LocalTime OFF_HOURS_START = LocalTime.of(22, 0);
    private static final LocalTime OFF_HOURS_END   = LocalTime.of(6, 0);

    // Total number of detection rules
    private static final int RULE_COUNT = 24;

    public FileRuleEngine(AgentConfig config) {
        this.config = config;
    }

    // ── Rule 1: isSensitivePath() ────────────────────────────
    /**
     * Checks if the file resides in a protected/critical system
     * directory. Changes to system directories like System32
     * often indicate malware installation or system tampering.
     *
     * @param filePath  The full path to the file
     * @return true if the file is in a sensitive directory
     */
    public boolean isSensitivePath(Path filePath) {
        String absPath = filePath.toAbsolutePath().toString();
        for (String sensitive : SENSITIVE_PATHS) {
            if (absPath.toLowerCase().startsWith(sensitive.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // ── Rule 2: isSensitiveExtension() ───────────────────────
    /**
     * Checks if the file has a high-risk extension. Executables,
     * scripts, and dynamic libraries are commonly used vectors
     * for malware delivery.
     *
     * @param filePath  The full path to the file
     * @return true if the extension is in the sensitive list
     */
    public boolean isSensitiveExtension(Path filePath) {
        String name = filePath.getFileName().toString().toLowerCase();
        for (String ext : SENSITIVE_EXTENSIONS) {
            if (name.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    // ── Rule 3: evaluateRule() ───────────────────────────────
    /**
     * Master evaluation function that combines all individual
     * rules to determine the overall severity of a file event.
     *
     * Severity Logic:
     *   CRITICAL: Sensitive path + sensitive extension + off-hours
     *   HIGH:     Sensitive path OR sensitive extension
     *   MEDIUM:   Off-hours change OR new executable
     *   LOW:      Any other change (informational)
     *
     * @param filePath   Path to the changed file
     * @param eventType  Type of change (FILE_CREATED, FILE_MODIFIED, etc.)
     * @return           The calculated severity level
     */
    public Severity evaluateRule(Path filePath, String eventType) {
        boolean sensitivePath = isSensitivePath(filePath);
        boolean sensitiveExt  = isSensitiveExtension(filePath);
        boolean offHours      = isOffHours();
        boolean whitelisted   = isWhitelisted(filePath);

        // Whitelisted files always get LOW severity
        if (whitelisted) {
            return Severity.LOW;
        }

        // ── CRITICAL: system file with dangerous extension at odd hours ──
        if (sensitivePath && sensitiveExt && offHours) {
            return Severity.CRITICAL;
        }

        // ── CRITICAL: system file deletion ──
        if (sensitivePath && "FILE_DELETED".equals(eventType)) {
            return Severity.CRITICAL;
        }

        // ── HIGH: sensitive path or extension ──
        if (sensitivePath || sensitiveExt) {
            return Severity.HIGH;
        }

        // ── MEDIUM: off-hours activity ──
        if (offHours) {
            return Severity.MEDIUM;
        }

        // ── LOW: regular file change ──
        return Severity.LOW;
    }

    // ── Rule 4: isWhitelisted() ──────────────────────────────
    /**
     * Checks if a file is in a whitelisted path. Whitelisted
     * changes are still logged but don't trigger server alerts.
     *
     * @param filePath  Path to the file
     * @return true if the path is whitelisted
     */
    public boolean isWhitelisted(Path filePath) {
        String absPath = filePath.toAbsolutePath().toString();
        for (String wl : WHITELISTED_PATHS) {
            if (absPath.toLowerCase().startsWith(wl.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    // ── Rule 5: isOffHours() ─────────────────────────────────
    /**
     * Checks if the current time falls within the off-hours
     * window (default: 22:00 to 06:00). File changes during
     * off-hours are more suspicious because they're less likely
     * to be legitimate admin activity.
     *
     * @return true if current time is within off-hours
     */
    public boolean isOffHours() {
        LocalTime now = LocalTime.now();

        // Handle the midnight wrap: if start > end, the window
        // spans midnight (e.g., 22:00 to 06:00).
        if (OFF_HOURS_START.isAfter(OFF_HOURS_END)) {
            // Off-hours is AFTER start OR BEFORE end
            return now.isAfter(OFF_HOURS_START) || now.isBefore(OFF_HOURS_END);
        } else {
            // Simple range (e.g., 01:00 to 05:00)
            return now.isAfter(OFF_HOURS_START) && now.isBefore(OFF_HOURS_END);
        }
    }

    // ── Rule 6: getRuleCount() ───────────────────────────────
    /**
     * Returns the total number of detection rules in this engine.
     */
    public int getRuleCount() {
        return RULE_COUNT;
    }

    // ── Process Whitelisting ─────────────────────────────────
    public boolean isWhitelistedProcess(String processName) {
        if (processName == null || processName.equals("unknown")) return false;
        String[] whitelist = config.getProcessWhitelist();
        if (whitelist == null) return false;

        String lowerProc = processName.toLowerCase();
        for (String w : whitelist) {
            String trimmed = w.trim().toLowerCase();
            if (!trimmed.isEmpty() && lowerProc.contains(trimmed)) {
                return true;
            }
        }
        return false;
    }

    public String guessModifyingProcess(Path filePath) {
        // Attempt to guess modifying process using Windows Security Event 4663.
        // In a true enterprise deployment, this would use an ETW trace.
        try {
            // Sanitize filename before embedding in PowerShell command
            // to prevent injection through crafted filenames
            String safeFileName = filePath.getFileName().toString()
                    .replaceAll("[^a-zA-Z0-9._\\-]", "_");

            Process p = new ProcessBuilder("powershell", "-NoProfile", "-Command", 
                "try { $log = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 5 -ErrorAction Stop; " +
                "foreach ($e in $log) { if ($e.Message -match '" + safeFileName + "') " +
                "{ if ($e.Message -match 'Process Name:\\s+([^\\r\\n]+)') { return $matches[1] } } } } catch {}; return 'unknown'")
                .redirectErrorStream(true).start();
            
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
                String line = reader.readLine();
                if (line != null && !line.trim().isEmpty() && !line.contains("unknown")) {
                    // Extract just the exe name
                    String[] parts = line.split("\\\\");
                    return parts[parts.length - 1];
                }
            }
            // Fallback
        } catch (Exception ignored) {}
        
        return "unknown";
    }
}
