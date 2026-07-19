package com.hips.agent.process;

import com.hips.agent.core.ActiveResponseEngine;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;
import com.hips.agent.osquery.OsFacade;

import java.nio.file.Paths;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Process & Execution Monitor (Refactored v2.0)
 * ============================================================
 *
 * OSQUERY INTEGRATION:
 *   Process enumeration is now delegated to the OsFacade
 *   abstraction. On systems with osquery, this uses the
 *   `processes` table (cross-platform). Without osquery,
 *   it falls back to NativeOsFacade (tasklist/wmic).
 *
 * ALL EXISTING DETECTION RULES ARE PRESERVED:
 *   - Rule 1: Known malicious tool detection (mimikatz, psexec, etc.)
 *   - Rule 2: Office macro attack detection (Office → script engine)
 *   - Rule 3: Suspicious PowerShell execution (-enc, -w hidden, iex)
 *   - Rule 4: Suspicious service name detection
 *   - Whitelisting: KNOWN_SAFE_PROCESSES with path validation
 *   - Active Response: Auto-kill for CRITICAL detections
 *
 * ALL PREVIOUS FIXES PRESERVED:
 *   - FIX 2.2: 5s polling interval
 *   - FIX 2.3: OS-agnostic file name extraction via Paths.get()
 *   - FIX 2.5: KNOWN_SAFE_PROCESSES whitelist
 *   - FIX scanServices(): Implemented (not a no-op stub)
 *   - JAVA 8 COMPATIBILITY maintained
 */
public class ProcessMonitor {

    private final ProcessAlertHandler alertHandler;
    private ScheduledExecutorService scheduler;
    private long selfPid = -1; // The PID of the HIPS agent itself
    private OsFacade osFacade; // Injected telemetry source

    // Snapshot of processes from previous scan cycle
    private final ConcurrentHashMap<Integer, ProcessInfo> previousSnapshot = new ConcurrentHashMap<>();

    // Active Response Engine — auto-kills malicious processes
    private ActiveResponseEngine activeResponseEngine;

    // ── Known malicious tools ─────────────────────────────────
    private static final Set<String> SUSPICIOUS_PROCESSES = new HashSet<>(Arrays.asList(
        "mimikatz.exe", "psexec.exe", "ncat.exe", "nc.exe", "netcat.exe",
        "rubeus.exe", "lazagne.exe", "bloodhound.exe", "procdump.exe",
        "wce.exe", "fgdump.exe", "pwdump.exe", "gsecdump.exe",
        // Cross-platform equivalents (no .exe)
        "mimikatz", "psexec", "ncat", "nc", "netcat",
        "rubeus", "lazagne", "bloodhound", "procdump"
    ));

    private static final Set<String> SCRIPT_ENGINES = new HashSet<>(Arrays.asList(
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe",
        // Cross-platform: bash/sh/python as script engines
        "powershell", "pwsh", "bash", "sh", "python", "python3", "perl"
    ));

    private static final Set<String> OFFICE_APPS = new HashSet<>(Arrays.asList(
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        // Cross-platform LibreOffice
        "soffice", "soffice.bin", "libreoffice"
    ));

    // ── FIX 2.5: Process whitelist to reduce alert fatigue ────
    // New instances of these processes are NEVER flagged.
    private static final Set<String> KNOWN_SAFE_PROCESSES = new HashSet<>(Arrays.asList(
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
        "explorer.exe", "taskmgr.exe", "notepad.exe", "code.exe",
        "slack.exe", "discord.exe", "teams.exe", "spotify.exe",
        "onedrive.exe", "dropbox.exe", "zoom.exe", "skype.exe",
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "smss.exe", "wininit.exe", "dwm.exe",
        "searchindexer.exe", "spoolsv.exe", "msiexec.exe",
        "conhost.exe", "runtimebroker.exe", "sihost.exe",
        // Cross-platform safe processes
        "chrome", "firefox", "code", "slack", "discord", "spotify",
        "systemd", "init", "kworker", "kthreadd", "ksoftirqd",
        "launchd", "WindowServer", "loginwindow"
    ));

    // Suspicious service name patterns
    private static final Set<String> SUSPICIOUS_SERVICE_PATTERNS = new HashSet<>(Arrays.asList(
        "netcat", "backdoor", "rootkit", "trojan",
        "psexecsvc", "winvnc", "remcos"
    ));

    public ProcessMonitor(ProcessAlertHandler alertHandler) {
        this.alertHandler = alertHandler;
    }

    // FIX: Accept a shared scheduler instead of creating its own
    public ProcessMonitor(ProcessAlertHandler alertHandler, ScheduledExecutorService sharedScheduler) {
        this.alertHandler = alertHandler;
        this.scheduler    = sharedScheduler;
    }

    /**
     * Injects the OsFacade for cross-platform process enumeration.
     * If not set, falls back to legacy fetchProcesses() method.
     */
    public void setOsFacade(OsFacade facade) {
        this.osFacade = facade;
    }

    /**
     * Injects the Active Response Engine for automatic threat neutralization.
     * When set, CRITICAL-severity process detections will trigger an
     * immediate auto-kill + quarantine action.
     */
    public void setActiveResponseEngine(ActiveResponseEngine engine) {
        this.activeResponseEngine = engine;
    }

    /**
     * Sets the PID of the agent itself to allow for parent-process whitelisting.
     */
    public void setSelfPid(long pid) {
        this.selfPid = pid;
    }

    public void start() {
        System.out.println("[ProcessMonitor] Starting Process & Execution Monitoring module...");
        if (osFacade != null) {
            System.out.println("[ProcessMonitor] Using OsFacade backend: " + osFacade.getClass().getSimpleName());
        } else {
            System.out.println("[ProcessMonitor] Using legacy native process enumeration.");
        }

        if (scheduler == null) {
            scheduler = Executors.newScheduledThreadPool(1, r -> {
                Thread t = new Thread(r, "ProcessMonitor");
                t.setDaemon(true);
                return t;
            });
        }

        // Take initial snapshot silently
        takeSnapshot();

        // FIX 2.2: Reduced from 15s → 5s to catch transient malware
        scheduler.scheduleAtFixedRate(this::scanProcesses, 5, 5, TimeUnit.SECONDS);

        // Service scan every 60 seconds (unchanged — less critical)
        scheduler.scheduleAtFixedRate(this::scanServices, 60, 60, TimeUnit.SECONDS);
    }

    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
        }
        System.out.println("[ProcessMonitor] Module stopped.");
    }

    // ── Scanning Logic ────────────────────────────────────────

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
                if (!previousSnapshot.containsKey(proc.getPid())) {
                    analyzeNewProcess(proc);
                }
            }

            previousSnapshot.clear();
            previousSnapshot.putAll(current);
        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Scan failed: " + e.getMessage());
        }
    }

    /**
     * Checks if a process is genuinely a known safe process based on its name and path.
     * Prevents bypasses where malware masks as "svchost.exe" from a temp directory.
     */
    private boolean isWhitelisted(ProcessInfo proc) {
        String procName = extractFileName(proc.getName()).toLowerCase();
        String exePath  = proc.getExecutablePath() != null ? proc.getExecutablePath().toLowerCase() : "";

        if (!KNOWN_SAFE_PROCESSES.contains(procName)) return false;

        // OS-aware path validation
        String osType = osFacade != null ? osFacade.getOsType() : "windows";

        if ("windows".equals(osType)) {
            // Strict path validation for critical system processes
            if (procName.equals("svchost.exe") || procName.equals("lsass.exe") || 
                procName.equals("csrss.exe")   || procName.equals("winlogon.exe") ||
                procName.equals("services.exe") || procName.equals("smss.exe") ||
                procName.equals("wininit.exe")) {
                
                return exePath.contains("\\windows\\system32\\") || 
                       exePath.contains("\\windows\\syswow64\\");
            }

            if (procName.equals("explorer.exe")) {
                return exePath.contains("\\windows\\");
            }

            // For other whitelisted apps (Chrome, Slack, etc.), allow if NOT in temp
            if (exePath.contains("\\temp\\") || exePath.contains("\\users\\public\\")) {
                return false; 
            }
        } else if ("linux".equals(osType)) {
            // Linux: system processes should be in /usr/bin, /usr/sbin, /sbin
            if (procName.equals("systemd") || procName.equals("init")) {
                return exePath.startsWith("/usr/") || exePath.startsWith("/sbin/") || exePath.equals("/sbin/init");
            }
            // Don't trust binaries in /tmp
            if (exePath.startsWith("/tmp/") || exePath.startsWith("/dev/shm/")) {
                return false;
            }
        } else if ("darwin".equals(osType)) {
            // macOS: system processes in /usr, /System, /Applications
            if (procName.equals("launchd") || procName.equals("windowserver")) {
                return exePath.startsWith("/usr/") || exePath.startsWith("/System/");
            }
            if (exePath.startsWith("/tmp/") || exePath.contains("/var/tmp/")) {
                return false;
            }
        }

        return true;
    }

    private void analyzeNewProcess(ProcessInfo proc) {
        // FIX 2.3: Use Paths.get() instead of hardcoded lastIndexOf("\\")
        String procName   = extractFileName(proc.getName()).toLowerCase();
        String parentName = extractFileName(proc.getParentName() != null ? proc.getParentName() : "").toLowerCase();

        // Hardened Whitelisting: Check both name and path legitimacy
        if (isWhitelisted(proc)) return;

        // Rule 1: Known malicious tool
        if (SUSPICIOUS_PROCESSES.contains(procName)) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("pid", proc.getPid());
            metadata.put("command_line", proc.getCommandLine() != null ? proc.getCommandLine() : "");
            metadata.put("parent", parentName);

            Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_EXEC", Severity.CRITICAL,
                        "Suspicious tool executed: " + proc.getName())
                    .withDescription("Detected known malicious/recon tool execution.")
                    .withSourcePath(proc.getExecutablePath())
                    .withMetadata(metadata);
            alertHandler.triggerAlert(e);

            // ── ACTIVE RESPONSE: Auto-kill the malicious process ──
            // Only execute active response if we're on the same OS type
            if (activeResponseEngine != null && isActiveResponseSupported()) {
                activeResponseEngine.respondToProcess(
                    proc.getPid(), proc.getName(), proc.getExecutablePath());
            }
            return;
        }

        // Rule 2: Office app launching a script engine (macro attack)
        if (OFFICE_APPS.contains(parentName) && SCRIPT_ENGINES.contains(procName)) {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("pid", proc.getPid());
            metadata.put("command_line", proc.getCommandLine() != null ? proc.getCommandLine() : "");
            metadata.put("parent", proc.getParentName() != null ? proc.getParentName() : "");

            Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_PARENT", Severity.CRITICAL,
                        "Office app launched shell: " + proc.getName())
                    .withDescription(proc.getParentName() + " spawned " + proc.getName()
                        + " — highly indicative of a macro attack.")
                    .withSourcePath(proc.getExecutablePath())
                    .withMetadata(metadata);
            alertHandler.triggerAlert(e);

            // ── ACTIVE RESPONSE: Auto-kill the macro-spawned shell ──
            if (activeResponseEngine != null && isActiveResponseSupported()) {
                activeResponseEngine.respondToProcess(
                    proc.getPid(), proc.getName(), proc.getExecutablePath());
            }
            return;
        }

        if (procName.contains("powershell") || procName.contains("pwsh")) {
            // FIX: Parent-Process Verification
            // If PowerShell is started by the HIPS Agent itself, ignore suspicious flags.
            // The agent uses PowerShell for network data collection.
            if (selfPid != -1 && proc.getParentPid() == selfPid) {
                return;
            }

            String cmdLine = proc.getCommandLine() != null ? proc.getCommandLine().toLowerCase() : "";
            if (cmdLine.contains("-w hidden")       || cmdLine.contains("-windowstyle hidden") ||
                cmdLine.contains("-enc")            || cmdLine.contains("-encodedcommand")     ||
                cmdLine.contains("iex ")            || cmdLine.contains("invoke-expression")) {

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("pid", proc.getPid());
                metadata.put("command_line", proc.getCommandLine());

                Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_EXEC", Severity.HIGH,
                            "Suspicious PowerShell execution")
                        .withDescription("PowerShell launched with hidden window or encoded commands.")
                        .withSourcePath(proc.getExecutablePath())
                        .withMetadata(metadata);
                alertHandler.triggerAlert(e);
            }
        }

        // Cross-platform: Detect suspicious bash/python reverse shell patterns
        if (osFacade != null && !"windows".equals(osFacade.getOsType())) {
            String cmdLine = proc.getCommandLine() != null ? proc.getCommandLine().toLowerCase() : "";
            if ((procName.equals("bash") || procName.equals("sh") || procName.equals("python") || procName.equals("python3"))
                && (cmdLine.contains("/dev/tcp/") || cmdLine.contains("mkfifo") ||
                    cmdLine.contains("socket.") || cmdLine.contains("subprocess"))) {

                Map<String, Object> metadata = new HashMap<>();
                metadata.put("pid", proc.getPid());
                metadata.put("command_line", proc.getCommandLine());

                Event e = new Event(Module.process, "PROCESS_SUSPICIOUS_EXEC", Severity.CRITICAL,
                            "Reverse shell pattern detected: " + proc.getName())
                        .withDescription("Shell/script launched with network redirect patterns — likely a reverse shell.")
                        .withSourcePath(proc.getExecutablePath())
                        .withMetadata(metadata);
                alertHandler.triggerAlert(e);
            }
        }
    }

    /**
     * Checks if active response (process kill) is supported on current OS.
     * On Windows, uses taskkill. On Linux/macOS, uses kill.
     */
    private boolean isActiveResponseSupported() {
        // ActiveResponseEngine handles OS-specific kill commands internally
        return true;
    }

    /**
     * FIX 2.3: Cross-platform safe file name extraction.
     * Replaces the fragile path.lastIndexOf("\\") approach.
     */
    private String extractFileName(String path) {
        if (path == null || path.isEmpty()) return "";
        try {
            // Paths.get() handles both "/" and "\" on all platforms
            String name = Paths.get(path).getFileName().toString();
            return name.isEmpty() ? path : name;
        } catch (Exception e) {
            // Fallback: manual extraction handling both separators
            int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
            return lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
        }
    }

    /**
     * Scans for suspicious services using OsFacade.
     * Falls back to PowerShell on Windows if no facade is set.
     */
    private void scanServices() {
        try {
            List<String> services;

            if (osFacade != null) {
                // Use OsFacade (osquery or native)
                services = osFacade.getRunningServices();
            } else {
                // Legacy fallback: direct PowerShell call
                services = getServicesLegacy();
            }

            for (String svcName : services) {
                String svcNameLower = svcName.trim().toLowerCase();
                for (String pattern : SUSPICIOUS_SERVICE_PATTERNS) {
                    if (svcNameLower.contains(pattern)) {
                        Map<String, Object> metadata = new HashMap<>();
                        metadata.put("service_name", svcName.trim());
                        metadata.put("matched_pattern", pattern);

                        Event e = new Event(Module.process, "SUSPICIOUS_SERVICE", Severity.HIGH,
                                    "Suspicious service detected: " + svcName.trim())
                                .withDescription("Running service '" + svcName.trim()
                                    + "' matches suspicious pattern '" + pattern + "'.")
                                .withMetadata(metadata);
                        alertHandler.triggerAlert(e);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Service scan failed: " + e.getMessage());
        }
    }

    /**
     * Legacy service scanning via PowerShell (preserved for backward compat).
     */
    private List<String> getServicesLegacy() {
        List<String> services = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "powershell", "-NoProfile", "-Command",
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name"
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String svc = line.trim();
                    if (!svc.isEmpty()) services.add(svc);
                }
            }
            p.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Legacy service scan failed: " + e.getMessage());
        }
        return services;
    }

    // ── Process Fetching ──────────────────────────────────────

    /**
     * Fetches current process snapshot via OsFacade (preferred)
     * or legacy tasklist/wmic commands (fallback).
     */
    private Map<Integer, ProcessInfo> fetchProcesses() {
        // Prefer OsFacade if available
        if (osFacade != null) {
            return osFacade.getProcesses();
        }

        // ── Legacy fallback: tasklist + wmic (original code) ──
        Map<Integer, ProcessInfo> processes = new HashMap<>();

        try {
            ProcessBuilder pb = new ProcessBuilder("tasklist", "/V", "/FO", "CSV", "/NH");
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\",\"");
                    if (parts.length < 2) continue;

                    String name = parts[0].replace("\"", "");
                    int pid = Integer.parseInt(parts[1].replace("\"", ""));

                    ProcessInfo procInfo = new ProcessInfo(pid, name);
                    processes.put(pid, procInfo);
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);

            supplementWithWmicLegacy(processes);

        } catch (Exception e) {
            System.err.println("[ProcessMonitor] Fetch processes failed: " + e.getMessage());
        }

        return processes;
    }

    /**
     * Legacy WMIC supplementation (preserved for when OsFacade is not available).
     */
    private void supplementWithWmicLegacy(Map<Integer, ProcessInfo> processes) {
        try {
            ProcessBuilder pb = new ProcessBuilder("wmic", "process", "get", "ProcessId,ParentProcessId,CommandLine,ExecutablePath", "/format:csv");
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().isEmpty() || line.toLowerCase().contains("node,commandline")) continue;
                    
                    String[] parts = line.split(",");
                    if (parts.length < 5) continue;

                    try {
                        String cmdLine = parts[1];
                        String exePath = parts[2];
                        int parentPid = Integer.parseInt(parts[3]);
                        int pid = Integer.parseInt(parts[4].trim());

                        ProcessInfo info = processes.get(pid);
                        if (info != null) {
                            info.setCommandLine(cmdLine);
                            info.setExecutablePath(exePath);
                            info.setParentPid(parentPid);
                            
                            ProcessInfo parentInfo = processes.get(parentPid);
                            if (parentInfo != null) {
                                info.setParentName(parentInfo.getName());
                            }
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {}
    }
}
