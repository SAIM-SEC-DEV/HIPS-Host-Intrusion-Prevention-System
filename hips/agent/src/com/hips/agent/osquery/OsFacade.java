package com.hips.agent.osquery;

import com.hips.agent.process.ProcessInfo;

import java.util.List;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — OS Telemetry Facade (Strategy Pattern)
 * ============================================================
 * Abstraction layer that decouples monitoring modules from the
 * underlying telemetry source. Implementations include:
 *
 *   - OsqueryOsFacade  : Reads from osquery JSON result logs
 *   - NativeOsFacade   : Uses native OS commands (Windows-only legacy)
 *
 * All existing detection rules, thresholds, and signatures in the
 * monitoring modules remain UNCHANGED. Only the data source is
 * swappable via this interface.
 *
 * Thread Safety:
 *   Implementations MUST be thread-safe. Multiple monitors will
 *   call these methods concurrently from their own scheduler threads.
 */
public interface OsFacade {

    // ── Process Telemetry ────────────────────────────────────

    /**
     * Returns a snapshot of all currently running processes.
     * Each ProcessInfo must contain at minimum: pid, name.
     * Optional fields: commandLine, executablePath, parentPid, parentName, user.
     *
     * @return Map of PID → ProcessInfo, never null (empty map on failure)
     */
    Map<Integer, ProcessInfo> getProcesses();

    /**
     * Returns a list of running service names (Windows services,
     * systemd units on Linux, launchd jobs on macOS).
     *
     * @return List of service name strings, never null
     */
    List<String> getRunningServices();

    // ── Network Telemetry ────────────────────────────────────

    /**
     * Returns all active network connections (ESTABLISHED, LISTEN, etc.).
     * Each map entry must contain keys:
     *   protocol, local_ip, local_port, remote_ip, remote_port, state, owning_process
     *
     * @return List of connection maps, never null
     */
    List<Map<String, String>> getActiveConnections();

    /**
     * Returns all listening (open) ports on this host.
     * Each map entry must contain keys:
     *   protocol, local_ip, local_port, state
     *
     * @return List of port maps, never null
     */
    List<Map<String, String>> getListeningPorts();

    // ── Registry / Persistence Telemetry ─────────────────────

    /**
     * Returns registry key values for the specified key path.
     * On non-Windows systems, returns equivalent persistence
     * locations (e.g., /etc/systemd/system, ~/Library/LaunchAgents).
     *
     * @param keyPath Registry path (e.g., "HKLM\\SOFTWARE\\...\\Run")
     *                or persistence-config path on Linux/macOS
     * @return Map of value name → data string, never null
     */
    Map<String, String> getRegistryValues(String keyPath);

    /**
     * Batch-queries multiple registry/persistence key paths.
     * More efficient than calling getRegistryValues() in a loop.
     *
     * @param keyPaths Set of key paths to query
     * @return Map of keyPath → (valueName → data), never null
     */
    Map<String, Map<String, String>> batchGetRegistryValues(java.util.Set<String> keyPaths);

    // ── USB / Hardware Telemetry ──────────────────────────────

    /**
     * Returns a list of currently connected USB devices.
     * Each map entry should contain keys:
     *   vendor, model, serial, type, removable
     *
     * @return List of USB device maps, never null
     */
    List<Map<String, String>> getUsbDevices();

    // ── File Telemetry ───────────────────────────────────────

    /**
     * Returns recent file events captured by osquery's FIM.
     * Each map entry should contain keys:
     *   target_path, action (CREATED, MODIFIED, DELETED), time
     *
     * NOTE: The FileMonitor primarily uses Java's WatchService
     * for real-time events. This method is supplementary for
     * events that WatchService may miss (e.g., during restarts).
     *
     * @return List of file event maps, never null
     */
    List<Map<String, String>> getFileEvents();

    // ── System Metadata ──────────────────────────────────────

    /**
     * Returns the detected operating system type.
     * @return "windows", "linux", or "darwin"
     */
    String getOsType();

    /**
     * Returns the OS version string.
     * @return e.g., "Windows 10 Pro 22H2", "Ubuntu 22.04", "macOS 14.2"
     */
    String getOsVersion();

    /**
     * Returns true if this facade is operational (i.e., the
     * underlying data source is available and responding).
     */
    boolean isAvailable();
}
