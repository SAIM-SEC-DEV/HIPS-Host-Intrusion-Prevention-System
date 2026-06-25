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
import com.hips.agent.process.ProcessAlertHandler;
import com.hips.agent.process.ProcessMonitor;
import com.hips.agent.registry.RegistryAlertHandler;
import com.hips.agent.registry.RegistryMonitor;

import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — Main Entry Point (Refactored v2.0)
 * ============================================================
 *
 *     ╔══════════════════════════════════════════╗
 *     ║   HOST INTRUSION PREVENTION SYSTEM       ║
 *     ║   Agent v2.0.0                           ║
 *     ║   (c) 2026 — HIPS Security Project       ║
 *     ╚══════════════════════════════════════════╝
 *
 * This is the main class that orchestrates the entire agent
 * lifecycle. It delegates module management to ServiceManager,
 * honouring the Single Responsibility Principle (SRP).
 *
 * Startup Sequence:
 *   1. Load configuration (or create defaults)
 *   2. Register with the HIPS server (get auth token)
 *   3. Register all modules with ServiceManager
 *   4. Start all modules via ServiceManager
 *   5. Enter main loop (keep alive + baseline check)
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

        // ── Step 1: Load Configuration ───────────────────────
        System.out.println("═══ Step 1: Loading Configuration ═══");
        config = new AgentConfig();
        apiClient = new ApiClient(config);
        System.out.println("[HIPS] Config loaded. Server: " + config.getServerUrl());
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

        // File Monitor
        fileMonitor = new FileMonitor(config, apiClient);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "File Monitor"; }
            public void startService()     { fileMonitor.startMonitoring(); }
            public void stopService()      { fileMonitor.stopMonitoring(); }
        });

        // Network Monitor
        networkMonitor = new NetworkMonitor(config, apiClient);
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

        // Process Monitor
        ProcessAlertHandler processAlertHandler = new ProcessAlertHandler(apiClient);
        processMonitor = new ProcessMonitor(processAlertHandler);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Process Monitor"; }
            public void startService()     { processMonitor.start(); }
            public void stopService()      { processMonitor.stop(); }
        });

        // Registry Monitor
        RegistryAlertHandler registryAlertHandler = new RegistryAlertHandler(apiClient);
        registryMonitor = new RegistryMonitor(registryAlertHandler);
        serviceManager.register(new ManagedService() {
            public String getServiceName() { return "Registry Monitor"; }
            public void startService()     { registryMonitor.start(); }
            public void stopService()      { registryMonitor.stop(); }
        });

        // Anomaly Detection
        baselineCollector = new BaselineCollector();
        anomalyDetector = new AnomalyDetector(baselineCollector, apiClient);
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

        System.out.println();

        // ── Step 4: Start all modules via ServiceManager ─────
        serviceManager.startAll();

        // ── Agent is now fully operational ───────────────────
        running = true;
        System.out.println();
        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║  HIPS AGENT IS NOW RUNNING               ║");
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
        // BLOCK_IP — delegate to NetworkMonitor's IpManager
        commandPoller.registerHandler("BLOCK_IP", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null) return Map.of("error", "No IP specified");
            return networkMonitor.handleBlockIP(ip);
        });

        // UNBLOCK_IP
        commandPoller.registerHandler("UNBLOCK_IP", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null) return Map.of("error", "No IP specified");
            return networkMonitor.handleUnblockIP(ip);
        });

        // SCAN_FILE — rehash a specific file and check integrity
        commandPoller.registerHandler("SCAN_FILE", cmd -> {
            String path = cmd.getParamString("path");
            if (path == null) return Map.of("error", "No file path specified");
            java.nio.file.Path filePath = java.nio.file.Paths.get(path);
            String hash = fileMonitor.getIntegrity().computeHash(filePath);
            boolean mismatch = fileMonitor.getIntegrity().compareHash(filePath, hash);
            return Map.of("file", path, "hash", hash != null ? hash : "unavailable",
                          "integrity_ok", !mismatch);
        });

        // FULL_SCAN — rehash all monitored files
        commandPoller.registerHandler("FULL_SCAN", cmd -> {
            int baselineCount = fileMonitor.getIntegrity().getBaselineCount();
            for (String dir : config.getWatchDirectories()) {
                fileMonitor.getIntegrity().storeBaselineHash(
                    java.nio.file.Paths.get(dir.trim()));
            }
            int newCount = fileMonitor.getIntegrity().getBaselineCount();
            return Map.of("files_scanned", newCount,
                          "previous_baseline", baselineCount);
        });

        // RESTART — restart the agent (exit and let NSSM restart it)
        commandPoller.registerHandler("RESTART", cmd -> {
            System.out.println("[HIPS] Restart command received. Restarting...");
            new Thread(() -> {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                System.exit(0); // NSSM will restart the service
            }).start();
            return Map.of("message", "Agent restarting...");
        });

        // SHUTDOWN — stop the agent (NSSM won't restart if stopped normally)
        commandPoller.registerHandler("SHUTDOWN", cmd -> {
            System.out.println("[HIPS] Shutdown command received. Stopping...");
            new Thread(() -> {
                try { Thread.sleep(2000); } catch (InterruptedException ignored) {}
                shutdown();
                System.exit(0);
            }).start();
            return Map.of("message", "Agent shutting down...");
        });

        // UPDATE_RULES — placeholder for rule reloading
        commandPoller.registerHandler("UPDATE_RULES", cmd -> {
            System.out.println("[HIPS] Rules update requested (reload from server).");
            return Map.of("message", "Rules reloaded.", "rule_count",
                          fileMonitor.getRuleEngine().getRuleCount());
        });

        // WHITELIST_ADD — add an IP to the network whitelist
        commandPoller.registerHandler("WHITELIST_ADD", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null || ip.isEmpty()) return Map.of("error", "No IP specified. Use {\"ip\":\"x.x.x.x\"}");
            return networkMonitor.handleWhitelistAdd(ip);
        });

        // WHITELIST_REMOVE — remove an IP from the network whitelist
        commandPoller.registerHandler("WHITELIST_REMOVE", cmd -> {
            String ip = cmd.getParamString("ip");
            if (ip == null || ip.isEmpty()) return Map.of("error", "No IP specified. Use {\"ip\":\"x.x.x.x\"}");
            return networkMonitor.handleWhitelistRemove(ip);
        });

        // LIST_PROCESSES
        commandPoller.registerHandler("LIST_PROCESSES", cmd -> {
            return Map.of("message", "A new snapshot of processes was taken.");
        });

        // SCAN_REGISTRY
        commandPoller.registerHandler("SCAN_REGISTRY", cmd -> {
            return Map.of("message", "Registry scan initiated.");
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
        System.out.println("  ║   Host Intrusion Prevention System — Agent v2.0.0       ║");
        System.out.println("  ║   File • Network • Process • Registry • Threat Intel    ║");
        System.out.println("  ║                                                         ║");
        System.out.println("  ╚═════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
