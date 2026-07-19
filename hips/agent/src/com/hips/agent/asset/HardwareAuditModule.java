package com.hips.agent.asset;

import com.hips.agent.core.ApiClient;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class HardwareAuditModule {
    private final ApiClient apiClient;
    private ScheduledExecutorService scheduler;

    public HardwareAuditModule(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    public void start() {
        System.out.println("[HardwareAudit] Starting Hardware Audit Module...");
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HardwareAudit");
            t.setDaemon(true);
            return t;
        });
        // Run audit every hour
        scheduler.scheduleAtFixedRate(this::performAudit, 0, 1, TimeUnit.HOURS);
    }

    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        System.out.println("[HardwareAudit] Module stopped.");
    }

    private void performAudit() {
        try {
            Map<String, Object> hardwareData = new HashMap<>();
            
            // CPU Info
            hardwareData.put("CPU", runCommand("wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors /format:list"));
            
            // RAM Info
            hardwareData.put("RAM", runCommand("wmic computersystem get TotalPhysicalMemory /format:list"));
            
            // Disk Health
            hardwareData.put("DiskHealth", runCommand("wmic diskdrive get model,status,size /format:list"));
            
            // Connected USB Devices
            hardwareData.put("USB", runCommand("powershell -Command \"Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' } | Select-Object FriendlyName\""));

            Event event = new Event(Module.asset, "HARDWARE_AUDIT", Severity.LOW, "Periodic Hardware Audit Completed")
                    .withDescription("Collected CPU, RAM, Disk, and USB device information.")
                    .withMetadata(hardwareData);

            apiClient.postAsyncChecked("report.php", event).whenComplete((ok, err) -> {
                if (err != null) {
                    System.err.println("[HardwareAudit] Failed to report audit: " + err.getMessage());
                }
            });

        } catch (Exception e) {
            System.err.println("[HardwareAudit] Audit failed: " + e.getMessage());
        }
    }

    private String runCommand(String command) {
        StringBuilder output = new StringBuilder();
        try {
            Process p = Runtime.getRuntime().exec(command);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        output.append(line.trim()).append(" | ");
                    }
                }
            }
            p.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
        return output.length() > 0 ? output.substring(0, output.length() - 3) : "None";
    }
}
