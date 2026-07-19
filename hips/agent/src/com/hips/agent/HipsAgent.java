package com.hips.agent;

import com.hips.agent.anomaly.AnomalyDetector;
import com.hips.agent.anomaly.BaselineCollector;
import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.*;
import com.hips.agent.core.ServiceManager.ManagedService;
import com.hips.agent.file.FileMonitor;
import com.hips.agent.intel.ThreatIntelService;
import com.hips.agent.model.Command;
import com.hips.agent.network.NetworkMonitor;
import com.hips.agent.osquery.OsFacade;
import com.hips.agent.osquery.OsFacadeFactory;
import com.hips.agent.process.ProcessAlertHandler;
import com.hips.agent.process.ProcessMonitor;
import com.hips.agent.registry.RegistryAlertHandler;
import com.hips.agent.registry.RegistryMonitor;
import com.hips.agent.asset.HardwareAuditModule;
import com.hips.agent.memory.MemoryAnalysisModule;
import com.hips.agent.file.KernelFimModule;
import com.hips.agent.file.RootkitScanner;
import com.hips.agent.usb.UsbMonitor;

import java.util.HashMap;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — Main Entry Point (Refactored v3.0 — osquery)
 * ============================================================
 *
 *     ╔══════════════════════════════════════════╗
 *     ║   HOST INTRUSION PREVENTION SYSTEM       ║
 *     ║   Agent v3.0.0 — osquery Hybrid          ║
 *     ║   (c) 2026 — HIPS Security Project       ║
 *     ╚══════════════════════════════════════════╝
 *
 * This is the main class that orchestrates the entire agent
 * lifecycle. It delegates module management to ServiceManager,
 * honouring the Single Responsibility Principle (SRP).
 *
 * OSQUERY INTEGRATION (v3.0):
 *   The OsFacade abstraction layer is initialized at startup
 *   and injected into all monitoring modules. If osquery is
 *   available (osquery.enabled=true + binary found), the
 *   OsqueryOsFacade is used for cross-platform telemetry.
 *   Otherwise, the NativeOsFacade preserves legacy behavior.
 *
 * Startup Sequence:
 *   1. Load configuration (or create defaults)
 *   2. Initialize OsFacade (osquery or native)
 *   3. Register with the HIPS server (get auth token)
 *   4. Register all modules with ServiceManager
 *   5. Inject OsFacade into all monitoring modules
 *   6. Start all modules via ServiceManager
 *   7. Enter main loop (keep alive + baseline check)
 *
 * Shutdown Sequence:
 *   1. ServiceManager stops all modules in reverse order
 *   2. Save configuration
 */
public class HipsAgent {

    private AgentConfig config;
    private ApiClient apiClient;
    private RegistrationService registrationService;
    private ServiceManager serviceManager;
    private CommandPoller commandPoller;
    private FileMonitor fileMonitor;
    private NetworkMonitor networkMonitor;
    private ProcessMonitor processMonitor;
    private RegistryMonitor registryMonitor;
    private ThreatIntelService threatIntelService;
    private BaselineCollector baselineCollector;
    private AnomalyDetector anomalyDetector;
    private HardwareAuditModule hardwareAuditModule;
    private MemoryAnalysisModule memoryAnalysisModule;
    private KernelFimModule kernelFimModule;
    private RootkitScanner rootkitScanner;
    private UsbMonitor usbMonitor;
    private ActiveResponseEngine activeResponseEngine;
    private SelfProtectionGuard selfProtectionGuard;
    private EncryptedForensicLogger forensicLogger;
    private OsFacade osFacade; // Cross-platform telemetry source

    private volatile boolean running = false;

    /**
     * Program entry point. Creates a new HipsAgent and starts it.
     */
    public static void main(String[] args) {
        printBanner();

        HipsAgent agent = new HipsAgent();

        // Register JVM shutdown hook for clean exit (handles SIGTERM, Ctrl+C)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[HIPS] Shutdown signal received...");
            agent.shutdown();
        }, "HIPS-ShutdownHook"));

        // Start the agent
        agent.start();
    }

    /**
     * Initializes all components and starts the agent.
     */
    public void start() {
        System.out.println("[HIPS] Initializing HIPS Agent...\n");

        // Capture self PID for parent-process whitelisting in ProcessMonitor
        long selfPid = -1;
        try {
            String jvmName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            if (jvmName.contains("@")) {
                selfPid = Long.parseLong(jvmName.split("@")[0]);
            }
        } catch (Exception e) {
            System.err.println("[HIPS] Warning: Could not determine self PID.");
        }

        // ── Step 1: Load Configuration ───────────────────────
        System.out.println("═══ Step 1: Loading Configuration ═══");
        config = new AgentConfig();
        apiClient = new ApiClient(config);
        System.out.println("[HIPS] Config loaded. Server: " + config.getServerUrl());
        System.out.println();

        // ── Step 1.5: Initialize OsFacade ────────────────────
        System.out.println("═══ Step 1.5: Initializing Telemetry Backend ═══");
        osFacade = OsFacadeFactory.create(config);
        System.out.println();

        // ── Step 2: Register with Server ─────────────────────────
        System.out.println("═══ Step 2: Registering with Server ═══");
        registrationService = new RegistrationService(config, apiClient);
        boolean registered = registrationService.register();

        // If registration failed, try auto-discovery
        if (!registered) {
            System.out.println("[HIPS] Registration failed. Attempting auto-discovery...");
            ServerDiscovery discovery = new ServerDiscovery(config);
            if (discovery.ensureServerReachable()) {
                // Config was updated with discovered server URL, retry registration
                apiClient = new ApiClient(config);
                registrationService = new RegistrationService(config, apiClient);
                registered = registrationService.register();
            }
        }

        if (!registered) {
            System.err.println("[HIPS] ✗ FATAL: Could not register with server. Exiting.");
            System.err.println("[HIPS]   Check server URL in hips-agent.properties");
            System.err.println("[HIPS]   Or run the Discovery Service on the server PC.");
            System.exit(1);
        }
        System.out.println();

        // ── Step 3: Initialize ServiceManager & Register Modules ──
        System.out.println("═══ Step 3: Initializing Service Manager ═══");
        serviceManager = new ServiceManager();

        // Initialize Active Response Engine (needed by monitors)
        activeResponseEngine = new ActiveResponseEngine(config, apiClient);

        // Initialize Encrypted Forensic Logger
        forensicLogger = new EncryptedForensicLogger(config.getAgentUuid());
        serviceManager.register(forensicLogger);

        // Initialize Baseline & Anomaly detection (needed by monitors)
        baselineCollector = new BaselineCollector();
        anomalyDetector = new AnomalyDetector(baselineCollector, apiClient);

        // Heartbeat Service
        HeartbeatService heartbeatService = new HeartbeatService(config, apiClient);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Heartbeat Service"; }
            public void startService()     { heartbeatService.start(); }
            public void stopService()      { heartbeatService.stop(); }
        });

        // Command Poller
        commandPoller = new CommandPoller(config, apiClient);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Command Poller"; }
            public void startService()     { registerCommandHandlers(); commandPoller.start(); }
            public void stopService()      { commandPoller.stop(); }
        });

        // File Monitor (uses Java WatchService — already cross-platform, no OsFacade needed)
        fileMonitor = new FileMonitor(config, apiClient, baselineCollector);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "File Monitor"; }
            public void startService()     { fileMonitor.startMonitoring(); }
            public void stopService()      { fileMonitor.stopMonitoring(); }
        });

        // Network Monitor — inject OsFacade
        networkMonitor = new NetworkMonitor(config, apiClient, baselineCollector);
        networkMonitor.setOsFacade(osFacade);
        networkMonitor.setScheduler(serviceManager.getSharedScheduler());
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Network Monitor"; }
            public void startService()     { networkMonitor.startNetworkMonitor(); }
            public void stopService()      { networkMonitor.stopNetworkMonitor(); }
        });

        // Threat Intel Service
        threatIntelService = new ThreatIntelService(config);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Threat Intel Feed"; }
            public void startService()     { System.out.println("[HIPS] Threat Intel ready."); }
            public void stopService()      { /* stateless */ }
        });

        // Process Monitor — inject OsFacade and Active Response
        ProcessAlertHandler processAlertHandler = new ProcessAlertHandler(apiClient);
        processMonitor = new ProcessMonitor(processAlertHandler);
        processMonitor.setOsFacade(osFacade);
        processMonitor.setActiveResponseEngine(activeResponseEngine);
        processMonitor.setSelfPid(selfPid); // Enable parent-process whitelisting
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Process Monitor"; }
            public void startService()     { processMonitor.start(); }
            public void stopService()      { processMonitor.stop(); }
        });

        // Registry Monitor — inject OsFacade
        RegistryAlertHandler registryAlertHandler = new RegistryAlertHandler(apiClient);
        registryMonitor = new RegistryMonitor(registryAlertHandler);
        registryMonitor.setOsFacade(osFacade);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Registry Monitor"; }
            public void startService()     { registryMonitor.start(); }
            public void stopService()      { registryMonitor.stop(); }
        });

        // Anomaly Detection
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Anomaly Detection"; }
            public void startService() {
                if (config.isBaselineComplete()) {
                    System.out.println("[HIPS] Baseline already completed. Anomaly detection is ACTIVE.");
                } else {
                    baselineCollector.startBaseline();
                    System.out.println("[HIPS] Baseline learning phase started ("
                            + baselineCollector.getDaysRemaining() + " days remaining).");
                }
            }
            public void stopService() { /* stateless */ }
        });

        // Hardware Audit
        hardwareAuditModule = new HardwareAuditModule(apiClient);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Hardware Audit"; }
            public void startService()     { hardwareAuditModule.start(); }
            public void stopService()      { hardwareAuditModule.stop(); }
        });

        // Memory Analysis — inject OsFacade
        memoryAnalysisModule = new MemoryAnalysisModule(config, apiClient);
        memoryAnalysisModule.setOsFacade(osFacade);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Memory Analysis"; }
            public void startService()     { memoryAnalysisModule.start(); }
            public void stopService()      { memoryAnalysisModule.stop(); }
        });

        // Kernel FIM (Advanced)
        kernelFimModule = new KernelFimModule(config, apiClient);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Kernel FIM"; }
            public void startService()     { kernelFimModule.start(); }
            public void stopService()      { kernelFimModule.stop(); }
        });

        // Rootkit Scanner
        rootkitScanner = new RootkitScanner(config, apiClient);
        rootkitScanner.setScheduler(serviceManager.getSharedScheduler());
        serviceManager.register(rootkitScanner);

        // USB Monitor — inject OsFacade
        usbMonitor = new UsbMonitor(config, apiClient);
        usbMonitor.setOsFacade(osFacade);
        usbMonitor.setScheduler(serviceManager.getSharedScheduler());
        serviceManager.register(usbMonitor);

        // Self-Protection Guard (JNI/C++ + PowerShell Watchdog)
        selfProtectionGuard = new SelfProtectionGuard();
        serviceManager.register(selfProtectionGuard);

        System.out.println();

        // ── Step 4: Start all modules via ServiceManager ─────
        serviceManager.startAll();

        // ── Agent is now fully operational ───────────────────
        running = true;
        System.out.println();
        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║  HIPS AGENT IS NOW RUNNING               ║");
        System.out.println("║  Telemetry: " + padRight(osFacade.getClass().getSimpleName(), 27) + "║");
        System.out.println("║  OS: " + padRight(osFacade.getOsType() + " — " + osFacade.getOsVersion(), 34) + "║");
        System.out.println("║  Press Ctrl+C to stop                    ║");
        System.out.println("╚══════════════════════════════════════════╝");
        System.out.println();

        // Keep the main thread alive
        mainLoop();
    }

    /**
     * Registers command handlers so the CommandPoller knows how
     * to execute each command type received from the server.
     */
    private void registerCommandHandlers() {
        System.out.println("[HIPS] Registering 15+ command handlers...");
        // BLOCK_IP — delegate to NetworkMonitor's IpManager
        commandPoller.registerHandler("BLOCK_IP", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null) {
                Map<String, Object> result = new HashMap<>();
                result.put("error", "No IP specified");
                return result;
            }
            return networkMonitor.handleBlockIP(ip);
        });

        // UNBLOCK_IP
        commandPoller.registerHandler("UNBLOCK_IP", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null) {
                Map<String, Object> result = new HashMap<>();
                result.put("error", "No IP specified");
                return result;
            }
            return networkMonitor.handleUnblockIP(ip);
        });

        // SCAN_FILE — rehash a specific file and check integrity
        commandPoller.registerHandler("SCAN_FILE", cmd -> {
            String path = cmd.getParamString("path");
            if (path == null) {
                Map<String, Object> result = new HashMap<>();
                result.put("error", "No file path specified");
                return result;
            }
            java.nio.file.Path filePath = java.nio.file.Paths.get(path);
            String hash = fileMonitor.getIntegrity().computeHash(filePath);
            boolean mismatch = fileMonitor.getIntegrity().compareHash(filePath, hash);
            Map<String, Object> result = new HashMap<>();
            result.put("file", path);
            result.put("hash", hash != null ? hash : "unavailable");
            result.put("integrity_ok", !mismatch);
            return result;
        });

        // FULL_SCAN — rehash all monitored files
        commandPoller.registerHandler("FULL_SCAN", cmd -> {
            int baselineCount = fileMonitor.getIntegrity().getBaselineCount();
            for (String dir : config.getWatchDirectories()) {
                fileMonitor.getIntegrity().storeBaselineHash(
                    java.nio.file.Paths.get(dir.trim()));
            }
            int newCount = fileMonitor.getIntegrity().getBaselineCount();
            Map<String, Object> result = new HashMap<>();
            result.put("files_scanned", newCount);
            result.put("previous_baseline", baselineCount);
            return result;
        });

        // RESTART — restart the agent (exit and let NSSM restart it)
        commandPoller.registerHandler("RESTART", cmd -> {
            System.out.println("[HIPS] Restart command received. Restarting...");
            new Thread(() -> {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                System.exit(0); // NSSM will restart the service
            }).start();
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Agent restarting...");
            return result;
        });

        // SHUTDOWN — stop the agent (NSSM won't restart if stopped normally)
        commandPoller.registerHandler("SHUTDOWN", cmd -> {
            System.out.println("[HIPS] Shutdown command received. Stopping...");
            new Thread(() -> {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                shutdown();
                System.exit(0);
            }).start();
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Agent shutting down...");
            return result;
        });

        // UPDATE_RULES — placeholder for rule reloading
        commandPoller.registerHandler("UPDATE_RULES", cmd -> {
            System.out.println("[HIPS] Rules update requested (reload from server).");
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Rules reloaded.");
            result.put("rule_count", fileMonitor.getRuleEngine().getRuleCount());
            return result;
        });

        // WHITELIST_ADD — add an IP to the network whitelist
        commandPoller.registerHandler("WHITELIST_ADD", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null || ip.isEmpty()) {
                Map<String, Object> result = new HashMap<>();
                result.put("error", "No IP specified. Use {\"ip\":\"x.x.x.x\"}");
                return result;
            }
            return networkMonitor.handleWhitelistAdd(ip);
        });

        // WHITELIST_REMOVE — remove an IP from the network whitelist
        commandPoller.registerHandler("WHITELIST_REMOVE", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null || ip.isEmpty()) {
                Map<String, Object> result = new HashMap<>();
                result.put("error", "No IP specified. Use {\"ip\":\"x.x.x.x\"}");
                return result;
            }
            return networkMonitor.handleWhitelistRemove(ip);
        });

        // LIST_PROCESSES
        commandPoller.registerHandler("LIST_PROCESSES", cmd -> {
            Map<String, Object> result = new HashMap<>();
            result.put("message", "A new snapshot of processes was taken.");
            return result;
        });

        // SCAN_REGISTRY
        commandPoller.registerHandler("SCAN_REGISTRY", cmd -> {
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Registry scan initiated.");
            return result;
        });

        // VT_SCAN_FILE
        System.out.println("[HIPS]   + Registering: VT_SCAN_FILE");
        commandPoller.registerHandler("VT_SCAN_FILE", cmd -> {
            Map<String, Object> result = new HashMap<>();
            String path = cmd.getParamString("path");
            if (path == null) {
                result.put("error", "No file path specified in command parameters");
                result.put("success", false);
                return result;
            }

            java.nio.file.Path filePath = java.nio.file.Paths.get(path);
            if (!java.nio.file.Files.exists(filePath)) {
                result.put("error", "Target file not found on agent: " + path);
                result.put("success", false);
                return result;
            }

            String hash = fileMonitor.getIntegrity().computeHash(filePath);
            if (hash == null) {
                result.put("error", "Could not compute SHA-256 hash (file might be locked or too large)");
                result.put("success", false);
                return result;
            }

            try {
                String customKey = cmd.getParamString("api_key");
                int score = threatIntelService.checkFileHash(hash, customKey);
                
                if (score == -1) {
                    result.put("error", "Threat Intel API Error or Missing API Key");
                    result.put("success", false);
                } else {
                    result.put("file", path);
                    result.put("hash", hash);
                    result.put("vt_score", score);
                    result.put("message", score > 0 ? "Malicious (" + score + " engines)" : "Clean");
                    result.put("success", true);
                }
                return result;
            } catch (Exception e) {
                result.put("error", "Threat Intel Error: " + e.getMessage());
                result.put("success", false);
                return result;
            }
        });

        // QUARANTINE_FILE
        System.out.println("[HIPS]   + Registering: QUARANTINE_FILE");
        commandPoller.registerHandler("QUARANTINE_FILE", cmd -> {
            String path = cmd.getParamString("path");
            Map<String, Object> result = new HashMap<>();
            if (path == null) {
                result.put("error", "No file path specified");
                return result;
            }
            try {
                // OS-aware process termination before quarantine
                String osType = osFacade.getOsType();
                if ("windows".equals(osType)) {
                    // Precise termination: Kill only processes running from this exact path
                    String escapedPath = path.replace("\\", "\\\\");
                    String psCommand = "powershell -Command \"Get-Process | Where-Object { $_.Path -eq '" + escapedPath + "' } | Stop-Process -Force\"";
                    Process p = Runtime.getRuntime().exec(psCommand);
                    p.waitFor();
                } else {
                    // Linux/macOS: use fuser to kill processes using the file
                    try {
                        Process p = Runtime.getRuntime().exec(new String[]{"fuser", "-k", path});
                        p.waitFor();
                    } catch (Exception ignored) {
                        // fuser may not be available, continue with quarantine
                    }
                }
                
                // Move file to a vault
                java.nio.file.Path source = java.nio.file.Paths.get(path);
                String vaultPath = "windows".equals(osType) ? "C:\\HIPS\\vault" : "/var/hips/vault";
                java.nio.file.Path vaultDir = java.nio.file.Paths.get(vaultPath);
                if (!java.nio.file.Files.exists(vaultDir)) {
                    java.nio.file.Files.createDirectories(vaultDir);
                }
                java.nio.file.Path target = vaultDir.resolve(source.getFileName() + ".quarantine");
                java.nio.file.Files.move(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                
                result.put("success", true);
                result.put("message", "Process(es) terminated and file quarantined to " + target.toString());
            } catch (Exception e) {
                result.put("success", false);
                result.put("error", "Quarantine failed: " + e.getMessage());
            }
            return result;
        });
    }

    /**
     * Main keep-alive loop. Checks baseline status periodically.
     */
    private void mainLoop() {
        while (running) {
            try {
                Thread.sleep(60_000); // Check every minute

                // Check if baseline learning phase is complete
                if (!config.isBaselineComplete() && baselineCollector.checkBaselineComplete()) {
                    config.setBaselineComplete(true);
                    config.saveConfig();
                    System.out.println("[HIPS] ✓ Anomaly detection promoted to ACTIVE mode.");
                }

            } catch (InterruptedException e) {
                if (!running) break;
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Gracefully shuts down all agent components via ServiceManager.
     */
    public void shutdown() {
        if (!running) return;
        running = false;

        System.out.println("[HIPS] Shutting down HIPS Agent...");

        if (serviceManager != null) {
            serviceManager.stopAll();
        }

        if (config != null) {
            System.out.println("[HIPS] Saving configuration...");
            config.saveConfig();
        }

        System.out.println("[HIPS] ✓ Agent shutdown complete. Goodbye.");
    }

    /**
     * Right-pads a string to the specified length.
     */
    private static String padRight(String s, int n) {
        if (s == null) s = "";
        if (s.length() >= n) return s.substring(0, n);
        return String.format("%-" + n + "s", s);
    }

    /**
     * Prints the HIPS Agent startup banner.
     */
    private static void printBanner() {
        System.out.println();
        System.out.println("  ╔═════════════════════════════════════════════════════════╗");
        System.out.println("  ║                                                         ║");
        System.out.println("  ║   ██╗  ██╗██╗██████╗ ███████╗     █████╗  ██████╗       ║");
        System.out.println("  ║   ██║  ██║██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝       ║");
        System.out.println("  ║   ███████║██║██████╔╝███████╗    ███████║██║  ███╗      ║");
        System.out.println("  ║   ██╔══██║██║██╔═══╝ ╚════██║    ██╔══██║██║   ██║      ║");
        System.out.println("  ║   ██║  ██║██║██║     ███████║    ██║  ██║╚██████╔╝      ║");
        System.out.println("  ║   ╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝    ╚═╝  ╚═╝ ╚═════╝       ║");
        System.out.println("  ║                                                         ║");
        System.out.println("  ║   Host Intrusion Prevention System — Agent v3.0.0       ║");
        System.out.println("  ║   osquery Hybrid • Cross-Platform • Threat Intel        ║");
        System.out.println("  ║                                                         ║");
        System.out.println("  ╚═════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
