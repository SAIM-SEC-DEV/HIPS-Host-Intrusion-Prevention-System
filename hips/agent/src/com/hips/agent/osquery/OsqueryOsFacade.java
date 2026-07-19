package com.hips.agent.osquery;

import com.hips.agent.process.ProcessInfo;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * ============================================================
 * HIPS Agent — osquery-backed OS Facade Implementation
 * ============================================================
 * Reads telemetry from osquery by executing `osqueryi` queries
 * in JSON mode. This implementation is cross-platform: it works
 * on Windows, Linux, and macOS wherever osquery is installed.
 *
 * Data collection strategy:
 *   - Uses `osqueryi --json "SELECT ..."` for on-demand queries
 *   - Timeouts prevent blocking if osquery hangs
 *   - All JSON parsing uses OsqueryResultParser (never crashes)
 *
 * Thread Safety:
 *   All methods are thread-safe. Multiple monitors can call
 *   concurrently — each invocation runs its own osqueryi process.
 *
 * Fallback:
 *   If osquery is not installed or unavailable, all methods
 *   return empty collections and isAvailable() returns false.
 */
public class OsqueryOsFacade implements OsFacade {

    private final String osqueryi;  // Path to osqueryi binary
    private final int timeoutSec;   // Query timeout in seconds
    private final String detectedOs;
    private String cachedOsVersion;

    // Persistent Process
    private Process persistentProcess;
    private BufferedWriter processWriter;
    private BufferedReader processReader;
    private final ReentrantLock queryLock = new ReentrantLock();

    /**
     * Creates an OsqueryOsFacade with the given osqueryi binary path.
     *
     * @param osqueryiBinaryPath Full path to osqueryi executable
     * @param queryTimeoutSec    Max seconds to wait for query results
     */
    public OsqueryOsFacade(String osqueryiBinaryPath, int queryTimeoutSec) {
        this.osqueryi = osqueryiBinaryPath;
        this.timeoutSec = queryTimeoutSec;
        this.detectedOs = detectOs();
        initPersistentProcess();
    }

    private void initPersistentProcess() {
        try {
            ProcessBuilder pb = new ProcessBuilder(osqueryi);
            pb.redirectErrorStream(true);
            pb.environment().put("OSQUERY_WORKER", "1");
            
            persistentProcess = pb.start();
            processWriter = new BufferedWriter(new OutputStreamWriter(persistentProcess.getOutputStream(), StandardCharsets.UTF_8));
            processReader = new BufferedReader(new InputStreamReader(persistentProcess.getInputStream(), StandardCharsets.UTF_8));
            
            // Set JSON mode
            processWriter.write(".mode json\n");
            processWriter.flush();
            System.out.println("[OsqueryFacade] Persistent osquery process initialized.");
        } catch (Exception e) {
            System.err.println("[OsqueryFacade] Failed to initialize persistent process: " + e.getMessage());
        }
    }

    // ── Process Telemetry ────────────────────────────────────

    @Override
    public Map<Integer, ProcessInfo> getProcesses() {
        Map<Integer, ProcessInfo> processes = new HashMap<>();

        // osquery's `processes` table provides: pid, name, path, cmdline, parent, uid, etc.
        String query = "SELECT pid, name, path, cmdline, parent, uid, " +
                       "COALESCE((SELECT name FROM processes AS p2 WHERE p2.pid = processes.parent), '') AS parent_name " +
                       "FROM processes";

        List<Map<String, String>> rows = executeQuery(query);

        for (Map<String, String> row : rows) {
            try {
                int pid = OsqueryResultParser.rowGetInt(row, "pid", -1);
                if (pid <= 0) continue;

                String name = OsqueryResultParser.rowGet(row, "name");
                if (name.isEmpty()) continue;

                ProcessInfo info = new ProcessInfo(pid, name);
                info.setExecutablePath(OsqueryResultParser.rowGet(row, "path"));
                info.setCommandLine(OsqueryResultParser.rowGet(row, "cmdline"));

                int parentPid = OsqueryResultParser.rowGetInt(row, "parent", 0);
                info.setParentPid(parentPid);

                String parentName = OsqueryResultParser.rowGet(row, "parent_name");
                if (!parentName.isEmpty()) {
                    info.setParentName(parentName);
                }

                String uid = OsqueryResultParser.rowGet(row, "uid");
                if (!uid.isEmpty()) {
                    info.setUser(uid);
                }

                processes.put(pid, info);
            } catch (Exception e) {
                // Skip malformed row, don't crash
                System.err.println("[OsqueryFacade] Skipping malformed process row: " + e.getMessage());
            }
        }

        return processes;
    }

    @Override
    public List<String> getRunningServices() {
        List<String> services = new ArrayList<>();
        String query;

        switch (detectedOs) {
            case "windows":
                // Windows: services table
                query = "SELECT name FROM services WHERE status = 'RUNNING'";
                break;
            case "linux":
                // Linux: systemd_units table
                query = "SELECT id AS name FROM systemd_units WHERE active_state = 'active' AND sub_state = 'running'";
                break;
            case "darwin":
                // macOS: launchd table
                query = "SELECT label AS name FROM launchd WHERE program != '' OR program_arguments != ''";
                break;
            default:
                return services;
        }

        List<Map<String, String>> rows = executeQuery(query);
        for (Map<String, String> row : rows) {
            String name = OsqueryResultParser.rowGet(row, "name");
            if (!name.isEmpty()) {
                services.add(name);
            }
        }

        return services;
    }

    // ── Network Telemetry ────────────────────────────────────

    @Override
    public List<Map<String, String>> getActiveConnections() {
        List<Map<String, String>> connections = new ArrayList<>();

        // process_open_sockets joined with processes for process name
        String query = "SELECT s.pid, s.family, s.protocol, s.local_address, s.local_port, " +
                       "s.remote_address, s.remote_port, s.state, " +
                       "COALESCE(p.name, '') AS process_name " +
                       "FROM process_open_sockets s " +
                       "LEFT JOIN processes p ON s.pid = p.pid " +
                       "WHERE s.state != '' AND s.family IN (2, 10)";  // AF_INET and AF_INET6

        List<Map<String, String>> rows = executeQuery(query);

        for (Map<String, String> row : rows) {
            try {
                Map<String, String> conn = new LinkedHashMap<>();
                int proto = OsqueryResultParser.rowGetInt(row, "protocol", 6);
                conn.put("protocol", proto == 6 ? "TCP" : "UDP");
                conn.put("local_ip", OsqueryResultParser.rowGet(row, "local_address"));
                conn.put("local_port", OsqueryResultParser.rowGet(row, "local_port"));
                conn.put("remote_ip", OsqueryResultParser.rowGet(row, "remote_address"));
                conn.put("remote_port", OsqueryResultParser.rowGet(row, "remote_port"));

                // Normalize state names to match Windows netstat format
                String state = OsqueryResultParser.rowGet(row, "state").toUpperCase()
                        .replace("ESTABLISHED", "ESTABLISHED")
                        .replace("LISTEN", "LISTENING")
                        .replace("TIME_WAIT", "TIME_WAIT")
                        .replace("CLOSE_WAIT", "CLOSE_WAIT");
                conn.put("state", state);

                conn.put("owning_process", OsqueryResultParser.rowGet(row, "process_name").toLowerCase());
                connections.add(conn);
            } catch (Exception e) {
                // Skip malformed row
            }
        }

        return connections;
    }

    @Override
    public List<Map<String, String>> getListeningPorts() {
        List<Map<String, String>> ports = new ArrayList<>();

        String query = "SELECT lp.pid, lp.port, lp.protocol, lp.address, " +
                       "COALESCE(p.name, '') AS process_name " +
                       "FROM listening_ports lp " +
                       "LEFT JOIN processes p ON lp.pid = p.pid " +
                       "WHERE lp.port > 0";

        List<Map<String, String>> rows = executeQuery(query);

        for (Map<String, String> row : rows) {
            try {
                Map<String, String> port = new LinkedHashMap<>();
                int proto = OsqueryResultParser.rowGetInt(row, "protocol", 6);
                port.put("protocol", proto == 6 ? "TCP" : "UDP");
                port.put("local_ip", OsqueryResultParser.rowGet(row, "address"));
                port.put("local_port", OsqueryResultParser.rowGet(row, "port"));
                port.put("state", "LISTENING");
                port.put("owning_process", OsqueryResultParser.rowGet(row, "process_name"));
                ports.add(port);
            } catch (Exception e) {
                // Skip malformed row
            }
        }

        return ports;
    }

    // ── Registry / Persistence Telemetry ─────────────────────

    @Override
    public Map<String, String> getRegistryValues(String keyPath) {
        Set<String> singleKey = new HashSet<>();
        singleKey.add(keyPath);
        return batchGetRegistryValues(singleKey).getOrDefault(keyPath, new HashMap<>());
    }

    @Override
    public Map<String, Map<String, String>> batchGetRegistryValues(Set<String> keyPaths) {
        Map<String, Map<String, String>> results = new HashMap<>();

        if ("windows".equals(detectedOs)) {
            // Windows: Use osquery's registry table
            for (String keyPath : keyPaths) {
                Map<String, String> values = new HashMap<>();
                String query = "SELECT name, data FROM registry WHERE key = '" +
                               keyPath.replace("'", "''") + "'";

                List<Map<String, String>> rows = executeQuery(query);
                for (Map<String, String> row : rows) {
                    String name = OsqueryResultParser.rowGet(row, "name");
                    String data = OsqueryResultParser.rowGet(row, "data");
                    if (!name.isEmpty()) {
                        values.put(name, data);
                    }
                }
                results.put(keyPath, values);
            }
        } else if ("linux".equals(detectedOs)) {
            // Linux: Map registry paths to equivalent persistence locations
            for (String keyPath : keyPaths) {
                Map<String, String> values = new HashMap<>();
                // Map Run keys to crontab/systemd startup items
                if (keyPath.contains("Run")) {
                    String query = "SELECT name, path, source FROM startup_items";
                    List<Map<String, String>> rows = executeQuery(query);
                    for (Map<String, String> row : rows) {
                        String name = OsqueryResultParser.rowGet(row, "name");
                        String path = OsqueryResultParser.rowGet(row, "path");
                        if (!name.isEmpty()) {
                            values.put(name, path);
                        }
                    }
                }
                results.put(keyPath, values);
            }
        } else if ("darwin".equals(detectedOs)) {
            // macOS: Map to LaunchAgents/LaunchDaemons
            for (String keyPath : keyPaths) {
                Map<String, String> values = new HashMap<>();
                if (keyPath.contains("Run")) {
                    String query = "SELECT label, program FROM launchd";
                    List<Map<String, String>> rows = executeQuery(query);
                    for (Map<String, String> row : rows) {
                        String label = OsqueryResultParser.rowGet(row, "label");
                        String program = OsqueryResultParser.rowGet(row, "program");
                        if (!label.isEmpty()) {
                            values.put(label, program);
                        }
                    }
                }
                results.put(keyPath, values);
            }
        }

        // Ensure all requested keys have entries (even if empty)
        for (String key : keyPaths) {
            results.putIfAbsent(key, new HashMap<>());
        }

        return results;
    }

    // ── USB / Hardware Telemetry ──────────────────────────────

    @Override
    public List<Map<String, String>> getUsbDevices() {
        List<Map<String, String>> devices = new ArrayList<>();

        String query = "SELECT vendor, model, serial, type, removable FROM usb_devices";
        List<Map<String, String>> rows = executeQuery(query);

        for (Map<String, String> row : rows) {
            Map<String, String> device = new LinkedHashMap<>();
            device.put("vendor", OsqueryResultParser.rowGet(row, "vendor"));
            device.put("model", OsqueryResultParser.rowGet(row, "model"));
            device.put("serial", OsqueryResultParser.rowGet(row, "serial"));
            device.put("type", OsqueryResultParser.rowGet(row, "type"));
            device.put("removable", OsqueryResultParser.rowGet(row, "removable"));
            devices.add(device);
        }

        return devices;
    }

    // ── File Telemetry ───────────────────────────────────────

    @Override
    public List<Map<String, String>> getFileEvents() {
        List<Map<String, String>> events = new ArrayList<>();

        // file_events requires FIM configuration in osquery.conf
        String query = "SELECT target_path, action, time, md5 FROM file_events ORDER BY time DESC LIMIT 100";
        List<Map<String, String>> rows = executeQuery(query);

        for (Map<String, String> row : rows) {
            Map<String, String> event = new LinkedHashMap<>();
            event.put("target_path", OsqueryResultParser.rowGet(row, "target_path"));

            String action = OsqueryResultParser.rowGet(row, "action").toUpperCase();
            switch (action) {
                case "CREATED":  event.put("action", "FILE_CREATED"); break;
                case "UPDATED":  event.put("action", "FILE_MODIFIED"); break;
                case "DELETED":  event.put("action", "FILE_DELETED"); break;
                default:         event.put("action", action); break;
            }

            event.put("time", OsqueryResultParser.rowGet(row, "time"));
            event.put("md5", OsqueryResultParser.rowGet(row, "md5"));
            events.add(event);
        }

        return events;
    }

    // ── System Metadata ──────────────────────────────────────

    @Override
    public String getOsType() {
        return detectedOs;
    }

    @Override
    public String getOsVersion() {
        if (cachedOsVersion != null) return cachedOsVersion;

        String query = "SELECT name, version, major, minor, patch, platform FROM os_version LIMIT 1";
        List<Map<String, String>> rows = executeQuery(query);

        if (!rows.isEmpty()) {
            Map<String, String> row = rows.get(0);
            cachedOsVersion = OsqueryResultParser.rowGet(row, "name") + " " +
                              OsqueryResultParser.rowGet(row, "version");
        } else {
            cachedOsVersion = System.getProperty("os.name", "Unknown") + " " +
                              System.getProperty("os.version", "");
        }

        return cachedOsVersion;
    }

    @Override
    public boolean isAvailable() {
        try {
            Path binary = Paths.get(osqueryi);
            if (!Files.exists(binary)) {
                return false;
            }

            // Quick ping query
            List<Map<String, String>> result = executeQuery("SELECT 1 AS ok");
            return !result.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    // ── Internal: Query Execution ────────────────────────────

    /**
     * Executes an osquery SQL query using the persistent osqueryi process.
     * This avoids the overhead of spawning a new process for every query.
     *
     * @param sql The osquery SQL query
     * @return List of row Maps, never null
     */
    private List<Map<String, String>> executeQuery(String sql) {
        queryLock.lock();
        try {
            if (persistentProcess == null || !persistentProcess.isAlive()) {
                initPersistentProcess();
            }
            if (persistentProcess == null || !persistentProcess.isAlive()) {
                return new ArrayList<>();
            }

            // Append an EOF marker query so we know when the output is finished
            String marker = "EOF_" + System.currentTimeMillis();
            String fullCommand = sql + "; SELECT '" + marker + "' AS eof_marker;\n";
            
            processWriter.write(fullCommand);
            processWriter.flush();

            StringBuilder output = new StringBuilder();
            String line;
            boolean foundMarker = false;
            
            // Read until we see the EOF marker JSON array
            while ((line = processReader.readLine()) != null) {
                if (line.contains(marker)) {
                    foundMarker = true;
                    // The marker is in its own JSON array, so we ignore it
                    // Wait for the closing bracket of the marker array if necessary
                    if (!line.endsWith("]")) {
                        while ((line = processReader.readLine()) != null) {
                            if (line.contains("]")) break;
                        }
                    }
                    break;
                }
                output.append(line).append("\n");
            }
            
            if (!foundMarker) {
                // Process might have crashed
                initPersistentProcess();
                return new ArrayList<>();
            }

            String jsonOutput = output.toString().trim();
            // The output might contain multiple JSON arrays if there were multiple statements.
            // We just parse the first valid JSON array.
            
            if (jsonOutput.isEmpty()) {
                return new ArrayList<>();
            }
            
            // Fix: If there are multiple arrays e.g. "]\n[" we just want the first one
            int endBracket = jsonOutput.lastIndexOf("]");
            if (endBracket != -1 && endBracket < jsonOutput.length() - 1) {
                jsonOutput = jsonOutput.substring(0, endBracket + 1);
            }

            return OsqueryResultParser.parseQueryOutput(jsonOutput);

        } catch (Exception e) {
            System.err.println("[OsqueryFacade] Persistent query failed: " + e.getMessage());
            // Restart process on failure to clear any stuck state
            if (persistentProcess != null) {
                persistentProcess.destroyForcibly();
            }
            return new ArrayList<>();
        } finally {
            queryLock.unlock();
        }
    }

    // ── Internal: OS Detection ───────────────────────────────

    private static String detectOs() {
        String osName = System.getProperty("os.name", "").toLowerCase();
        if (osName.contains("win")) return "windows";
        if (osName.contains("mac") || osName.contains("darwin")) return "darwin";
        return "linux";
    }
}
