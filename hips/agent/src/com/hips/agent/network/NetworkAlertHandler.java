package com.hips.agent.network;

import com.hips.agent.core.ApiClient;
import com.hips.agent.mitre.MitreMapper;
import com.hips.agent.model.Event;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ============================================================
 * HIPS Agent — Network Alert Handler
 * ============================================================
 * Handles alert firing and local audit logging for all network
 * monitoring events. Mirrors the FileAlertHandler pattern.
 *
 * Functions (1 of 32):
 *   triggerNetworkAlert()  — Fires warning on suspicious network event
 */
public class NetworkAlertHandler {

    private final ApiClient apiClient;
    private final Path logFile;
    private final DateTimeFormatter dtFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final List<Event> eventHistory = new CopyOnWriteArrayList<>();
    private int totalEventsLogged = 0;
    private int alertsFired = 0;

    public NetworkAlertHandler(ApiClient apiClient) {
        this.apiClient = apiClient;
        this.logFile = Paths.get("hips-network-audit.log");

        try {
            if (!Files.exists(logFile)) {
                Files.createFile(logFile);
            }
        } catch (IOException e) {
            System.err.println("[HIPS-NET-ALERT] Cannot create audit log: " + e.getMessage());
        }
    }

    // ── Function: triggerNetworkAlert() ──────────────────────
    /**
     * Fires a network alert by POSTing the event to the HIPS
     * server and logging it locally. The server will classify
     * it and create an alert record if severity warrants.
     *
     * @param event  The network event to report
     */
    public void triggerNetworkAlert(Event event) {
        logNetworkEvent(event);

        // Enrich with MITRE ATT&CK technique/tactic before sending
        MitreMapper.enrichEvent(event);

        apiClient.postAsyncChecked("report.php", event).whenComplete((ok, err) -> {
            if (err != null) {
                System.err.println("[HIPS-NET-ALERT] ⚠ Failed to report: " + err.getMessage());
                return;
            }
            if (Boolean.TRUE.equals(ok)) {
                alertsFired++;
                System.out.println("[HIPS-NET-ALERT] ✓ Alert reported: " + event.getTitle());
            } else {
                System.err.println("[HIPS-NET-ALERT] ⚠ Server rejected alert: " + event.getTitle());
            }
        });
    }

    /**
     * Logs a network event to the local audit log file without
     * sending it to the server (used for LOW severity events).
     */
    public void logNetworkEvent(Event event) {
        totalEventsLogged++;
        eventHistory.add(event);

        if (eventHistory.size() > 10000) {
            eventHistory.subList(0, eventHistory.size() - 5000).clear();
        }

        String logLine = String.format("[%s] [%s] %s | %s | %s%n",
                LocalDateTime.now().format(dtFormatter),
                event.getSeverity(),
                event.getEventType(),
                event.getDestination() != null ? event.getDestination() : "N/A",
                event.getDescription() != null ? event.getDescription() : "No description"
        );

        try (BufferedWriter writer = Files.newBufferedWriter(
                logFile, StandardOpenOption.APPEND, StandardOpenOption.CREATE)) {
            writer.write(logLine);
        } catch (IOException e) {
            System.err.println("[HIPS-NET-ALERT] Failed to write log: " + e.getMessage());
        }
    }

    /**
     * Specifically reports an unknown external IP address that was
     * flagged by the IpManager.
     */
    public void reportUntrustedIP(String ip) {
        Event event = new Event();
        event.setModule(Event.Module.network);
        event.setEventType("UNKNOWN_EXTERNAL_CONN");
        event.setSeverity(com.hips.agent.model.Event.Severity.HIGH);
        event.setTitle("Unknown External Connection");
        event.setDescription("Connection detected to unknown/untrusted external IP: " + ip);
        event.setDestination(ip); // Crucial for report.php whitelist check

        triggerNetworkAlert(event);
    }

    /**
     * Generates a summary report of all network monitoring activity.
     */
    public String generateReport() {
        StringBuilder report = new StringBuilder();
        report.append("═══════════════════════════════════════════\n");
        report.append("  HIPS NETWORK MONITORING — ACTIVITY REPORT\n");
        report.append("  Generated: ").append(LocalDateTime.now().format(dtFormatter)).append("\n");
        report.append("═══════════════════════════════════════════\n\n");
        report.append("  Total Events Logged:   ").append(totalEventsLogged).append("\n");
        report.append("  Alerts Sent to Server: ").append(alertsFired).append("\n");
        report.append("═══════════════════════════════════════════\n");
        return report.toString();
    }

    public int getTotalEventsLogged() { return totalEventsLogged; }
    public int getAlertsFired()       { return alertsFired; }
}
