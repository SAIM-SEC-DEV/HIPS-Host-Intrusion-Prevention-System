package com.hips.agent.process;

import com.hips.agent.core.ApiClient;
import com.hips.agent.mitre.MitreMapper;
import com.hips.agent.model.Event;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
                writeToLog(header);
            }
        } catch (IOException e) {
            System.err.println("[ProcessMonitor] Could not create audit log: " + e.getMessage());
        }
    }

    private void writeToLog(String content) {
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(auditLogPath.toFile(), true)))) {
            out.print(content);
        } catch (IOException e) {
            // Ignore failure to log to file
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
        writeToLog(logEntry);

        // Send to server and log delivery result
        apiClient.postAsyncChecked("report.php", event).whenComplete((ok, err) -> {
            if (err != null) {
                System.err.println("[ProcessMonitor] Failed to report alert: " + err.getMessage());
                return;
            }
            if (!Boolean.TRUE.equals(ok)) {
                System.err.println("[ProcessMonitor] Server rejected process alert: " + event.getTitle());
            }
        });
    }
}
