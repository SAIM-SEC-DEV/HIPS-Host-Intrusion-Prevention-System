package com.hips.agent.file;

import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ============================================================
 * HIPS Agent — File Alert Handler
 * ============================================================
 * Handles alert firing and local audit logging for all file
 * monitoring events. Each event is:
 *   1. Logged locally to a persistent audit log file
 *   2. Reported to the HIPS server via the API client
 *
 * The local log persists even if the server is unreachable,
 * ensuring no events are lost.
 *
 * Functions (3 of 25):
 *   triggerAlert()   — Reports the event to the HIPS server
 *   logEvent()       — Writes event to local audit log
 *   generateReport() — Produces a summary of all file activity
 */
public class FileAlertHandler {

    private final ApiClient apiClient;
    private final Path logFile;
    private final DateTimeFormatter dtFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // In-memory event history for report generation
    private final List<Event> eventHistory = new CopyOnWriteArrayList<>();

    // Counters for report statistics
    private int totalEventsLogged = 0;
    private int alertsFired = 0;

    public FileAlertHandler(ApiClient apiClient) {
        this.apiClient = apiClient;

        // Create the log file in the current working directory
        this.logFile = Paths.get("hips-file-audit.log");

        // Ensure the log file exists
        try {
            if (!Files.exists(logFile)) {
                Files.createFile(logFile);
            }
        } catch (IOException e) {
            System.err.println("[HIPS-FILE-ALERT] Cannot create audit log: " + e.getMessage());
        }
    }

    // ── Function 1: triggerAlert() ───────────────────────────
    /**
     * Fires a warning by POSTing the event to the HIPS server.
     * The server will insert it into the events table and, if
     * severity is HIGH or CRITICAL, also into the alerts table.
     *
     * This function is non-blocking from the caller's perspective;
     * if the server is unreachable, the error is logged but
     * monitoring continues uninterrupted.
     *
     * @param event  The file event to report
     */
    public void triggerAlert(Event event) {
        try {
            apiClient.post("report.php", event);
            alertsFired++;
            System.out.println("[HIPS-FILE-ALERT] ✓ Alert reported to server: " + event.getTitle());
        } catch (Exception e) {
            // Don't crash monitoring if server is down. The local
            // log still has the event as a backup.
            System.err.println("[HIPS-FILE-ALERT] ⚠ Failed to report alert: " + e.getMessage());
        }
    }

    // ── Function 2: logEvent() ───────────────────────────────
    /**
     * Silently logs every file event to the local audit log file.
     * This creates a persistent, tamper-detectable record of all
     * file system activity regardless of server connectivity.
     *
     * Log format:
     *   [2026-04-14 19:15:00] [HIGH] FILE_MODIFIED | C:\Windows\... | description
     *
     * @param event  The file event to log
     */
    public void logEvent(Event event) {
        totalEventsLogged++;
        eventHistory.add(event);

        // Keep in-memory history bounded to prevent memory leak
        if (eventHistory.size() > 10000) {
            eventHistory.subList(0, eventHistory.size() - 5000).clear();
        }

        // Format the log line
        String logLine = String.format("[%s] [%s] %s | %s | %s%n",
                LocalDateTime.now().format(dtFormatter),
                event.getSeverity(),
                event.getEventType(),
                event.getSourcePath() != null ? event.getSourcePath() : "N/A",
                event.getDescription() != null ? event.getDescription() : "No description"
        );

        // Append to the audit log file
        try (BufferedWriter writer = Files.newBufferedWriter(
                logFile, StandardOpenOption.APPEND, StandardOpenOption.CREATE)) {
            writer.write(logLine);
        } catch (IOException e) {
            System.err.println("[HIPS-FILE-ALERT] Failed to write audit log: " + e.getMessage());
        }
    }

    // ── Function 3: generateReport() ─────────────────────────
    /**
     * Produces a summary report of all file monitoring activity.
     * This includes total events, breakdown by severity, and
     * the most recent events.
     *
     * @return  A formatted string report
     */
    public String generateReport() {
        StringBuilder report = new StringBuilder();
        report.append("═══════════════════════════════════════════\n");
        report.append("  HIPS FILE MONITORING — ACTIVITY REPORT\n");
        report.append("  Generated: ").append(LocalDateTime.now().format(dtFormatter)).append("\n");
        report.append("═══════════════════════════════════════════\n\n");

        report.append("  Total Events Logged:  ").append(totalEventsLogged).append("\n");
        report.append("  Alerts Sent to Server: ").append(alertsFired).append("\n\n");

        // Count by severity
        Map<Event.Severity, Integer> severityCounts = new LinkedHashMap<>();
        for (Event.Severity s : Event.Severity.values()) {
            severityCounts.put(s, 0);
        }
        for (Event e : eventHistory) {
            severityCounts.merge(e.getSeverity(), 1, Integer::sum);
        }

        report.append("  Severity Breakdown:\n");
        for (Map.Entry<Event.Severity, Integer> entry : severityCounts.entrySet()) {
            report.append("    ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }

        // Last 10 events
        report.append("\n  Recent Events (last 10):\n");
        int start = Math.max(0, eventHistory.size() - 10);
        for (int i = start; i < eventHistory.size(); i++) {
            Event e = eventHistory.get(i);
            report.append("    ").append(e.toString()).append("\n");
        }

        report.append("\n═══════════════════════════════════════════\n");
        return report.toString();
    }

    // ── Accessors ────────────────────────────────────────────

    public int getTotalEventsLogged() { return totalEventsLogged; }
    public int getAlertsFired()       { return alertsFired; }
}
