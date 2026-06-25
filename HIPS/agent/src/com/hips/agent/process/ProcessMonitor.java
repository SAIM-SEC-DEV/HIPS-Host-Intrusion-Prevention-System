package com.hips.agent.process;

import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Process & Execution Monitor
 * ============================================================
 * Scans active processes via WMI to detect suspicious executions,
 * rogue child processes, and malicious parents.
 */
public class ProcessMonitor {

    private final ProcessAlertHandler alertHandler;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, r -> {
        Thread t = new Thread(r, "ProcessMonitor");
        t.setDaemon(true);
        return t;
    });

    // Holds the previous snapshot of processes to detect newly launched ones
    private final ConcurrentHashMap<Integer, ProcessInfo> previousSnapshot = new ConcurrentHashMap<>();

    // Sets of known suspicious elements
    private static final Set<String> SUSPICIOUS_PROCESSES = Set.of(
            "mimikatz.exe", "psexec.exe", "ncat.exe", "nc.exe", "netcat.exe", 
            "rubeus.exe", "lazagne.exe", "bloodhound.exe", "procdump.exe"
    );

    private static final Set<String> SCRIPT_ENGINES = Set.of(
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    );

    private static final Set<String> OFFICE_APPS = Set.of(
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"
    );

    public ProcessMonitor(ProcessAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    public void start() {
        System.out.println("[ProcessMonitor] Starting Process & Execution Monitoring module...");
        
        // Take initial snapshot silently
        takeSnapshot();

        // Schedule periodic scanning every 15 seconds
        scheduler.scheduleAtFixedRate(this::scanProcesses, 15, 15, TimeUnit.SECONDS);

        // Schedule service scanning every 60 seconds
        scheduler.scheduleAtFixedRate(this::scanServices, 60, 60, TimeUnit.SECONDS);
    }

    public void stop() {
        scheduler.shutdownNow();
        System.out.println("[ProcessMonitor] Module stopped.");
    }

    // ── Scanning Logic ───────────────────────────────────────

    private void takeSnapshot() {
        try {
            Map<Integer, ProcessInfo> current = fetchProcesses();
            previousSnapshot.clear();
            previousSnapshot.putAll(current);
        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Initial snapshot failed: " + e.getMessage());
        }
    }

    private void scanProcesses() {
        try {
            Map<Integer, ProcessInfo> current = fetchProcesses();
            
            for (ProcessInfo proc : current.values()) {
                // If it's a new process since last scan
                if (!previousSnapshot.containsKey(proc.getPid())) {
                    analyzeNewProcess(proc);
                }
            }

            // Update snapshot
            previousSnapshot.clear();
            previousSnapshot.putAll(current);
        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Scan failed: " + e.getMessage());
        }
    }

    private void analyzeNewProcess(ProcessInfo proc) {
        String procName = proc.getName().toLowerCase();
        String parentName = proc.getParentName() != null ? proc.getParentName().toLowerCase() : "";

        // Rule 1: Suspicious Process Names (Known attackers tools)
        if (SUSPICIOUS_PROCESSES.contains(procName)) {
            Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_EXEC", Severity.CRITICAL, "Suspicious tool executed: " + proc.getName())
                        .withDescription("Detected known malicious/recon tool execution.")
                        .withSourcePath(proc.getExecutablePath())
                        .withMetadata(Map.of("pid", proc.getPid(), "command_line", proc.getCommandLine(), "parent", parentName));
            alertHandler.triggerAlert(e);
            return; // Already critical, don't flag other rules
        }

        // Rule 2: Office application launching a script engine (Macro attack)
        if (OFFICE_APPS.contains(parentName) && SCRIPT_ENGINES.contains(procName)) {
            Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_PARENT", Severity.CRITICAL, "Office app launched shell: " + proc.getName())
                        .withDescription(proc.getParentName() + " spawned " + proc.getName() + " — highly indicative of a macro attack.")
                        .withSourcePath(proc.getExecutablePath())
                        .withMetadata(Map.of("pid", proc.getPid(), "command_line", proc.getCommandLine(), "parent", proc.getParentName()));
            alertHandler.triggerAlert(e);
            return;
        }

        // Rule 3: Hidden or Suspicious PowerShell
        if (procName.contains("powershell") || procName.contains("pwsh")) {
            String cmdLine = proc.getCommandLine() != null ? proc.getCommandLine().toLowerCase() : "";
            if (cmdLine.contains("-w hidden") || cmdLine.contains("-windowstyle hidden") || 
                cmdLine.contains("-enc") || cmdLine.contains("-encodedcommand") || 
                cmdLine.contains("iex") || cmdLine.contains("invoke-expression")) {
                
                Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_EXEC", Severity.HIGH, "Suspicious PowerShell execution")
                            .withDescription("PowerShell launched with hidden window or encoded commands.")
                            .withSourcePath(proc.getExecutablePath())
                            .withMetadata(Map.of("pid", proc.getPid(), "command_line", proc.getCommandLine()));
                alertHandler.triggerAlert(e);
            }
        }
    }

    private void scanServices() {
        // Run: sc query state= all | findstr SERVICE_NAME
        // Check for suspicious service names
        // (Simplified for this project, in real-world you'd diff against a baseline)
    }

    // ── Command Line Utilities ───────────────────────────────

    /**
     * Fetches current processes natively using Java 9+ ProcessHandle API.
     * This avoids calling wmic which spikes CPU and spams WMI event logs.
     */
    private Map<Integer, ProcessInfo> fetchProcesses() {
        Map<Integer, ProcessInfo> processes = new HashMap<>();
        
        ProcessHandle.allProcesses().forEach(ph -> {
            try {
                int pid = (int) ph.pid();
                ProcessHandle.Info info = ph.info();
                
                String path = info.command().orElse("");
                String name = path.isEmpty() ? "Unknown" : path.substring(path.lastIndexOf("\\") + 1);
                
                ProcessInfo procInfo = new ProcessInfo(pid, name);
                procInfo.setExecutablePath(path);
                
                info.commandLine().ifPresent(procInfo::setCommandLine);
                
                ph.parent().ifPresent(parent -> {
                    procInfo.setParentPid((int) parent.pid());
                    parent.info().command().ifPresent(pPath -> {
                        String pName = pPath.isEmpty() ? "Unknown" : pPath.substring(pPath.lastIndexOf("\\") + 1);
                        procInfo.setParentName(pName);
                    });
                });
                
                processes.put(pid, procInfo);
            } catch (Exception ignored) {}
        });
        
        return processes;
    }
}
