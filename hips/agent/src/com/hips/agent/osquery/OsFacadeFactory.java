package com.hips.agent.osquery;

import com.hips.agent.config.AgentConfig;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * ============================================================
 * HIPS Agent — OsFacade Factory (Factory Pattern)
 * ============================================================
 * Selects the appropriate OsFacade implementation based on
 * configuration and runtime availability:
 *
 *   1. If osquery.enabled=true AND osqueryi binary exists
 *      → OsqueryOsFacade (cross-platform, preferred)
 *
 *   2. Otherwise → NativeOsFacade (Windows-native fallback)
 *
 * This factory is called once at startup from HipsAgent and
 * the resulting facade is injected into all monitoring modules.
 */
public class OsFacadeFactory {

    private OsFacadeFactory() {} // Utility class

    /**
     * Creates the appropriate OsFacade implementation.
     *
     * @param config The agent configuration
     * @return A ready-to-use OsFacade implementation
     */
    public static OsFacade create(AgentConfig config) {
        boolean osqueryEnabled = config.isOsqueryEnabled();
        String osqueryPath = config.getOsqueryBinaryPath();
        int timeout = config.getOsqueryTimeoutSec();

        if (osqueryEnabled && osqueryPath != null && !osqueryPath.isEmpty()) {
            // Check if the binary actually exists
            if (Files.exists(Paths.get(osqueryPath))) {
                OsqueryOsFacade osqueryFacade = new OsqueryOsFacade(osqueryPath, timeout);

                // Verify osquery is actually functional
                if (osqueryFacade.isAvailable()) {
                    System.out.println("[OsFacade] ✓ Using osquery telemetry backend: " + osqueryPath);
                    System.out.println("[OsFacade]   Detected OS: " + osqueryFacade.getOsType());
                    System.out.println("[OsFacade]   OS Version : " + osqueryFacade.getOsVersion());
                    return osqueryFacade;
                } else {
                    System.err.println("[OsFacade] ⚠ osquery binary found but not responding. Falling back to native.");
                }
            } else {
                System.err.println("[OsFacade] ⚠ osquery binary not found at: " + osqueryPath + ". Falling back to native.");
            }
        }

        // Fallback to native OS commands
        NativeOsFacade nativeFacade = new NativeOsFacade();
        System.out.println("[OsFacade] Using native OS telemetry backend (" + nativeFacade.getOsType() + ")");
        return nativeFacade;
    }
}
