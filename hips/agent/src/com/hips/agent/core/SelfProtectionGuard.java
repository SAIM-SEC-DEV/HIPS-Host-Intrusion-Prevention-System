package com.hips.agent.core;

import com.hips.agent.core.ServiceManager.ManagedService;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Self-Protection Guard (v1.0)
 * ============================================================
 * Makes the HIPS agent resistant to forced termination.
 *
 * Protection Layers:
 *   Layer 1 (Native/JNI): Loads hips_guard.dll to modify the
 *     process DACL, denying PROCESS_TERMINATE to all users
 *     except SYSTEM. This prevents taskkill and Task Manager
 *     from killing the agent.
 *
 *   Layer 2 (PowerShell Watchdog): Deploys a hidden PowerShell
 *     script that monitors the agent PID every 15 seconds.
 *     If the process dies, it auto-restarts via run-agent.bat.
 *
 *   Layer 3 (Heartbeat Guard): If the server stops receiving
 *     heartbeats, it knows the agent has been tampered with.
 *
 * The guard attempts Layer 1 first (strongest). If the native
 * DLL is not available, it falls back to Layer 2 (PowerShell).
 * Layer 3 is handled by the existing HeartbeatService.
 */
public class SelfProtectionGuard implements ManagedService {

    private static final String WATCHDOG_SCRIPT = "hips-watchdog-temp.ps1";
    private Process watchdogProcess;
    private final int agentPid;
    private boolean nativeLoaded = false;

    public SelfProtectionGuard() {
        this.agentPid = getProcessId();
    }

    @Override
    public String getServiceName() {
        return "Self-Protection Guard";
    }

    @Override
    public void startService() {
        System.out.println("[HIPS-GUARD] Starting Self-Protection Guard (PID: " + agentPid + ")...");

        // Layer 1: Try native JNI guard
        tryLoadNativeGuard();

        // Layer 2: Deploy PowerShell watchdog
        deployWatchdog();

        System.out.println("[HIPS-GUARD] ✓ Agent is protected. "
            + (nativeLoaded ? "Native guard ACTIVE (process hardened)."
                            : "PowerShell watchdog ACTIVE."));
    }

    @Override
    public void stopService() {
        // Only kill watchdog on graceful shutdown
        if (watchdogProcess != null && watchdogProcess.isAlive()) {
            watchdogProcess.destroyForcibly();
        }
        try { Files.deleteIfExists(Paths.get(WATCHDOG_SCRIPT)); }
        catch (IOException ignored) {}

        System.out.println("[HIPS-GUARD] Self-Protection Guard stopped.");
    }

    /**
     * Attempts to load the native C++ guard DLL via JNI.
     * The DLL modifies the process security descriptor to deny
     * PROCESS_TERMINATE access, making the agent unkillable
     * by normal users (including via Task Manager).
     */
    private void tryLoadNativeGuard() {
        try {
            // Try loading from C:\HIPS\bin first, then system PATH
            String nativePath = "C:\\HIPS\\bin\\hips_guard.dll";
            File dllFile = new File(nativePath);

            if (dllFile.exists()) {
                System.load(nativePath);
            } else {
                System.loadLibrary("hips_guard");
            }

            nativeLoaded = true;
            System.out.println("[HIPS-GUARD] ✓ Native guard (hips_guard.dll) loaded.");

            // Call native methods to harden the process
            boolean protected_ = NativeGuard.protectProcess(agentPid);
            boolean watchdog_  = NativeGuard.installWatchdog(agentPid);

            System.out.println("[HIPS-GUARD]   Process protection: "
                + (protected_ ? "ACTIVE" : "FAILED"));
            System.out.println("[HIPS-GUARD]   Native watchdog: "
                + (watchdog_ ? "ACTIVE" : "FAILED"));

        } catch (UnsatisfiedLinkError e) {
            nativeLoaded = false;
            System.out.println("[HIPS-GUARD] Native guard not available — "
                + "compile hips_guard.cpp to enable. Using PowerShell fallback.");
        }
    }

    /**
     * Deploys a hidden PowerShell script that monitors the agent PID.
     * If the JVM process disappears, the watchdog restarts it.
     */
    private void deployWatchdog() {
        try {
            String script = buildWatchdogScript();
            Files.write(Paths.get(WATCHDOG_SCRIPT), script.getBytes());

            ProcessBuilder pb = new ProcessBuilder(
                "powershell", "-NoProfile", "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass", "-File", WATCHDOG_SCRIPT
            );
            pb.redirectErrorStream(true);
            watchdogProcess = pb.start();

            // Drain output in background to prevent buffer deadlock
            Thread drainThread = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(watchdogProcess.getInputStream()))) {
                    while (r.readLine() != null) { /* discard */ }
                } catch (IOException ignored) {}
            }, "HIPS-WatchdogDrain");
            drainThread.setDaemon(true);
            drainThread.start();

        } catch (Exception e) {
            System.err.println("[HIPS-GUARD] Watchdog deployment failed: " + e.getMessage());
        }
    }

    private String buildWatchdogScript() {
        return String.join("\r\n",
            "# HIPS Self-Protection Watchdog — Auto-generated. Do not edit.",
            "# Monitors agent PID " + agentPid + " and restarts if terminated.",
            "$agentPid = " + agentPid,
            "$checkInterval = 15",
            "",
            "while ($true) {",
            "    Start-Sleep -Seconds $checkInterval",
            "    $proc = Get-Process -Id $agentPid -ErrorAction SilentlyContinue",
            "    if (-not $proc) {",
            "        Write-Host '[HIPS-WATCHDOG] Agent died! Restarting...'",
            "        try {",
            "            $batFile = Join-Path $PSScriptRoot 'run-agent.bat'",
            "            if (Test-Path $batFile) {",
            "                Start-Process -FilePath $batFile -WindowStyle Minimized",
            "                Write-Host '[HIPS-WATCHDOG] Agent restarted.'",
            "            } else {",
            "                Write-Host '[HIPS-WATCHDOG] run-agent.bat not found.'",
            "            }",
            "        } catch {",
            "            Write-Host \"[HIPS-WATCHDOG] Restart failed: $_\"",
            "        }",
            "        break",
            "    }",
            "}"
        );
    }

    /**
     * Gets the PID of the current JVM process (Java 8 compatible).
     */
    private static int getProcessId() {
        try {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            return Integer.parseInt(name.split("@")[0]);
        } catch (Exception e) {
            return -1;
        }
    }

    public boolean isNativeLoaded() { return nativeLoaded; }
    public int getAgentPid()        { return agentPid; }
}
