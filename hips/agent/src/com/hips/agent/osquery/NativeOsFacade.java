package com.hips.agent.osquery;

import com.hips.agent.process.ProcessInfo;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * ============================================================
 * HIPS Agent — Native OS Facade (Windows Legacy Fallback)
 * ============================================================
 * Wraps the original Windows-only commands (tasklist, wmic,
 * PowerShell, netstat, reg query) that the HIPS agent used
 * before the osquery integration. This class preserves 100%
 * backward compatibility: if osquery is unavailable, the agent
 * continues to function exactly as it did before.
 *
 * This implementation is Windows-only. On Linux/macOS without
 * osquery, monitoring will be limited to Java-native features
 * (WatchService for files, Java sockets for basic net info).
 */
public class NativeOsFacade implements OsFacade {

    private static final String OS_TYPE = detectOs();

    @Override
    public Map<Integer, ProcessInfo> getProcesses() {
        Map<Integer, ProcessInfo> processes = new HashMap<>();

        if (!"windows".equals(OS_TYPE)) {
            // On non-Windows, try /bin/ps fallback
            return getProcessesUnix(processes);
        }

        try {
            // tasklist /V /FO CSV /NH — same as original ProcessMonitor.fetchProcesses()
            ProcessBuilder pb = new ProcessBuilder("tasklist", "/V", "/FO", "CSV", "/NH");
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\",\"");
                    if (parts.length < 2) continue;

                    String name = parts[0].replace("\"", "");
                    int pid;
                    try {
                        pid = Integer.parseInt(parts[1].replace("\"", ""));
                    } catch (NumberFormatException e) {
                        continue;
                    }

                    processes.put(pid, new ProcessInfo(pid, name));
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);

            // Supplement with WMIC for command line and parent PID
            supplementWithWmic(processes);

        } catch (Exception e) {
            System.err.println("[NativeFacade] Process fetch failed: " + e.getMessage());
        }

        return processes;
    }

    private Map<Integer, ProcessInfo> getProcessesUnix(Map<Integer, ProcessInfo> processes) {
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "aux");
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                boolean headerSkipped = false;
                while ((line = reader.readLine()) != null) {
                    if (!headerSkipped) { headerSkipped = true; continue; }
                    String[] parts = line.trim().split("\\s+", 11);
                    if (parts.length < 11) continue;

                    try {
                        int pid = Integer.parseInt(parts[1]);
                        String command = parts[10];
                        String name = command.contains("/") ?
                                command.substring(command.lastIndexOf('/') + 1) : command;
                        // Truncate at first space for command args
                        if (name.contains(" ")) name = name.substring(0, name.indexOf(' '));

                        ProcessInfo info = new ProcessInfo(pid, name);
                        info.setCommandLine(command);
                        info.setUser(parts[0]);
                        processes.put(pid, info);
                    } catch (NumberFormatException ignored) {}
                }
            }
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[NativeFacade] Unix process fetch failed: " + e.getMessage());
        }
        return processes;
    }

    private void supplementWithWmic(Map<Integer, ProcessInfo> processes) {
        try {
            ProcessBuilder pb = new ProcessBuilder("wmic", "process", "get",
                    "ProcessId,ParentProcessId,CommandLine,ExecutablePath", "/format:csv");
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

    @Override
    public List<String> getRunningServices() {
        List<String> services = new ArrayList<>();

        if (!"windows".equals(OS_TYPE)) return services;

        try {
            ProcessBuilder pb = new ProcessBuilder(
                "powershell", "-NoProfile", "-Command",
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name"
            );
            pb.redirectErrorStream(true);
            Process p = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String svc = line.trim();
                    if (!svc.isEmpty()) {
                        services.add(svc);
                    }
                }
            }
            p.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[NativeFacade] Service scan failed: " + e.getMessage());
        }

        return services;
    }

    @Override
    public List<Map<String, String>> getActiveConnections() {
        List<Map<String, String>> connections = new ArrayList<>();

        if ("windows".equals(OS_TYPE)) {
            return getActiveConnectionsWindows();
        } else {
            return getActiveConnectionsUnix();
        }
    }

    private List<Map<String, String>> getActiveConnectionsWindows() {
        List<Map<String, String>> connections = new ArrayList<>();
        try {
            // Same PowerShell approach as original NetworkMonitor
            ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-Command",
                "Get-NetTCPConnection -State Established,Listen,TimeWait,CloseWait -ErrorAction SilentlyContinue | " +
                "ForEach-Object { $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; " +
                "[PSCustomObject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;" +
                "RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=$_.State;OwningProcess=$p} } | " +
                "ConvertTo-Csv -NoTypeInformation");

            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String header = reader.readLine();
                if (header != null && header.contains("LocalAddress")) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim().replace("\"", "");
                        String[] parts = line.split(",");
                        if (parts.length >= 6) {
                            Map<String, String> conn = new LinkedHashMap<>();
                            conn.put("protocol", "TCP");
                            conn.put("local_ip", parts[0]);
                            conn.put("local_port", parts[1]);
                            conn.put("remote_ip", parts[2]);
                            conn.put("remote_port", parts[3]);
                            conn.put("state", parts[4]);
                            conn.put("owning_process", parts.length > 5 ? parts[5].toLowerCase() : "");
                            connections.add(conn);
                        }
                    }
                }
            }
            process.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Fall through to netstat
        }

        if (connections.isEmpty()) {
            return getActiveConnectionsNetstat();
        }
        return connections;
    }

    private List<Map<String, String>> getActiveConnectionsNetstat() {
        List<Map<String, String>> connections = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-an");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("TCP") || line.startsWith("UDP")) {
                        Map<String, String> conn = parseNetstatLine(line);
                        if (conn != null) {
                            connections.add(conn);
                        }
                    }
                }
            }
            process.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[NativeFacade] Netstat fallback failed: " + e.getMessage());
        }
        return connections;
    }

    private List<Map<String, String>> getActiveConnectionsUnix() {
        List<Map<String, String>> connections = new ArrayList<>();
        try {
            // Use ss on Linux for connection listing
            ProcessBuilder pb = new ProcessBuilder("ss", "-tnp");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                boolean headerSkipped = false;
                while ((line = reader.readLine()) != null) {
                    if (!headerSkipped) { headerSkipped = true; continue; }
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length < 5) continue;

                    Map<String, String> conn = new LinkedHashMap<>();
                    conn.put("protocol", "TCP");
                    String[] local = splitAddress(parts[3]);
                    conn.put("local_ip", local[0]);
                    conn.put("local_port", local[1]);
                    String[] remote = splitAddress(parts[4]);
                    conn.put("remote_ip", remote[0]);
                    conn.put("remote_port", remote[1]);
                    conn.put("state", parts[0].toUpperCase());
                    conn.put("owning_process", parts.length > 5 ? parts[5] : "");
                    connections.add(conn);
                }
            }
            process.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[NativeFacade] Unix connection scan failed: " + e.getMessage());
        }
        return connections;
    }

    @Override
    public List<Map<String, String>> getListeningPorts() {
        List<Map<String, String>> ports = new ArrayList<>();

        List<Map<String, String>> allConns = getActiveConnections();
        for (Map<String, String> conn : allConns) {
            String state = conn.getOrDefault("state", "");
            if (state.contains("LISTEN")) {
                ports.add(conn);
            }
        }

        return ports;
    }

    @Override
    public Map<String, String> getRegistryValues(String keyPath) {
        Set<String> singleKey = new HashSet<>();
        singleKey.add(keyPath);
        return batchGetRegistryValues(singleKey).getOrDefault(keyPath, new HashMap<>());
    }

    @Override
    public Map<String, Map<String, String>> batchGetRegistryValues(Set<String> keyPaths) {
        Map<String, Map<String, String>> results = new HashMap<>();

        if (!"windows".equals(OS_TYPE)) {
            // Non-Windows: return empty maps for all keys
            for (String key : keyPaths) {
                results.put(key, new HashMap<>());
            }
            return results;
        }

        // Same batched PowerShell approach as original RegistryMonitor
        try {
            StringBuilder script = new StringBuilder();
            for (String k : keyPaths) {
                String psPath = "Registry::" + k;
                script.append("try { Get-ItemProperty -LiteralPath '").append(psPath)
                      .append("' -ErrorAction Stop | Select-Object * -ExcludeProperty PS*, Run | ConvertTo-Json -Compress; Write-Output '---SEP---' } catch { Write-Output '{}---SEP---' }; ");
            }

            Process process = new ProcessBuilder("powershell", "-NoProfile", "-Command", script.toString())
                    .redirectErrorStream(true).start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                String[] blocks = output.toString().split("---SEP---");
                int i = 0;
                for (String key : keyPaths) {
                    Map<String, String> values = new HashMap<>();
                    if (i < blocks.length) {
                        String json = blocks[i].trim();
                        if (!json.isEmpty() && !json.equals("{}")) {
                            try {
                                com.google.gson.Gson gson = new com.google.gson.Gson();
                                Map<String, Object> rawMap = gson.fromJson(json,
                                        new com.google.gson.reflect.TypeToken<Map<String, Object>>(){}.getType());
                                for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
                                    values.put(entry.getKey(), String.valueOf(entry.getValue()));
                                }
                            } catch (Exception e) {
                                // Skip malformed JSON block
                            }
                        }
                    }
                    results.put(key, values);
                    i++;
                }
            }
            process.waitFor(15, TimeUnit.SECONDS);
        } catch (Exception e) {
            System.err.println("[NativeFacade] Registry batch query failed: " + e.getMessage());
            for (String key : keyPaths) {
                results.putIfAbsent(key, new HashMap<>());
            }
        }

        return results;
    }

    @Override
    public List<Map<String, String>> getUsbDevices() {
        // Not directly available via native commands without WMI
        // Return empty — USB detection still works via File.listRoots() in UsbMonitor
        return new ArrayList<>();
    }

    @Override
    public List<Map<String, String>> getFileEvents() {
        // Native file events come from WatchService, not this facade
        return new ArrayList<>();
    }

    @Override
    public String getOsType() {
        return OS_TYPE;
    }

    @Override
    public String getOsVersion() {
        return System.getProperty("os.name", "Unknown") + " " + System.getProperty("os.version", "");
    }

    @Override
    public boolean isAvailable() {
        // Native facade is always available on Windows
        return true;
    }

    // ── Utilities ────────────────────────────────────────────

    private Map<String, String> parseNetstatLine(String line) {
        try {
            String[] parts = line.trim().split("\\s+");
            if (parts.length < 4) return null;

            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("protocol", parts[0]);

            String[] localParts = splitAddress(parts[1]);
            entry.put("local_ip", localParts[0]);
            entry.put("local_port", localParts[1]);

            String[] remoteParts = splitAddress(parts[2]);
            entry.put("remote_ip", remoteParts[0]);
            entry.put("remote_port", remoteParts[1]);

            entry.put("state", parts.length > 3 ? parts[3] : "UNKNOWN");
            entry.put("owning_process", "");

            return entry;
        } catch (Exception e) {
            return null;
        }
    }

    private String[] splitAddress(String address) {
        int lastColon = address.lastIndexOf(':');
        if (lastColon <= 0) return new String[]{address, "0"};
        return new String[]{
            address.substring(0, lastColon),
            address.substring(lastColon + 1)
        };
    }

    private static String detectOs() {
        String osName = System.getProperty("os.name", "").toLowerCase();
        if (osName.contains("win")) return "windows";
        if (osName.contains("mac") || osName.contains("darwin")) return "darwin";
        return "linux";
    }
}
