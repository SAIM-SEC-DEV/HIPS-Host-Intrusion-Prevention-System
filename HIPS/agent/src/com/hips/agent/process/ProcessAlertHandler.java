package com.hips.agent.process;

import com.hips.agent.core.ApiClient;
import com.hips.agent.mitre.MitreMapper;
import com.hips.agent.model.Event;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.format.DateTimeFormatter;

/**
 * Handles alerting and logging for process events.
 */
public class ProcessAlertHandler {

    private final ApiClient apiClient;
    private final Path auditLogPath;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public ProcessAlertHandler(ApiClient apiClient) {
        this.apiClient = apiClient;
        this.auditLogPath = Paths.get("hips-process-audit.log");
        ensureLogExists();
    }

    private void ensureLogExists() {
        try {
            if (!Files.exists(auditLogPath)) {
                Files.createFile(auditLogPath);
                String header = "HIPS PROCESS AUDIT LOG\n=======================\n";
                Files.writeString(auditLogPath, header, StandardOpenOption.APPEND);
            }
        } catch (IOException e) {
            System.err.println("[ProcessMonitor] Could not create audit log: " + e.getMessage());
        }
    }

    public void triggerAlert(Event event) {
        // Map to MITRE ATT&CK
        MitreMapper.enrichEvent(event);

        // Print to console
        String prefix = event.getSeverity() == Event.Severity.CRITICAL ? "🔴 " :
                        event.getSeverity() == Event.Severity.HIGH ? "🟠 " : "🟡 ";
        System.out.println(prefix + "[PROCESS] " + event.getTitle() + " | " + event.getDescription());

        // Append to local audit file
        String logEntry = String.format("[%s] [%s] %s - %s%n",
                java.time.LocalDateTime.now().format(timeFormatter),
                event.getSeverity(),
                event.getTitle(),
                event.getDescription());
        try {
            Files.writeString(auditLogPath, logEntry, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // Ignore failure to log to file
        }

        // Send to server
        apiClient.post("report.php", event);
    }
}
