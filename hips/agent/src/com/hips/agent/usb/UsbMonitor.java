package com.hips.agent.usb;

import com.hips.agent.config.AgentConfig;
import com.hips.agent.core.ApiClient;
import com.hips.agent.core.ServiceManager.ManagedService;
import com.hips.agent.file.FileAlertHandler;
import com.hips.agent.malware.YaraScanner;
import com.hips.agent.model.Event;
import com.hips.agent.model.Event.Module;
import com.hips.agent.model.Event.Severity;
import com.hips.agent.osquery.OsFacade;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * ============================================================
 * HIPS Agent — USB & Removable Media Monitor (Refactored v2.0)
 * ============================================================
 * Detects newly inserted USB drives and triggers an immediate
 * YARA scan on their contents.
 *
 * OSQUERY INTEGRATION:
 *   USB device detection can now optionally use osquery's
 *   `usb_devices` table for richer metadata (vendor, model,
 *   serial number). The drive-letter polling via File.listRoots()
 *   is preserved as the primary detection mechanism since it's
 *   already cross-platform via Java's File API.
 *
 * ALL EXISTING LOGIC PRESERVED:
 *   - Drive polling every 5 seconds
 *   - Automatic YARA scan on new drives
 *   - CRITICAL alert for malware found on USB
 *   - Serial number retrieval
 */
public class UsbMonitor implements ManagedService {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private final FileAlertHandler fileAlertHandler;
    private final YaraScanner yaraScanner;
    
    private ScheduledExecutorService scheduler;
    private Set<String> knownDrives = new HashSet<>();
    private OsFacade osFacade; // Injected telemetry source

    // Track previously known USB devices for osquery-based detection
    private Set<String> knownUsbSerials = new HashSet<>();

    public UsbMonitor(AgentConfig config, ApiClient apiClient) {
        this.config = config;
        this.apiClient = apiClient;
        this.fileAlertHandler = new FileAlertHandler(apiClient);
        this.yaraScanner = new YaraScanner(config, fileAlertHandler);
    }

    /**
     * Injects the OsFacade for enhanced USB device metadata.
     */
    public void setOsFacade(OsFacade facade) {
        this.osFacade = facade;
    }

    public void setScheduler(ScheduledExecutorService scheduler) {
        this.scheduler = scheduler;
    }

    @Override
    public String getServiceName() {
        return "USB Monitor";
    }

    @Override
    public void startService() {
        System.out.println("[HIPS-USB] Starting USB Monitor...");
        if (osFacade != null) {
            System.out.println("[HIPS-USB] Using OsFacade for enhanced USB device metadata.");
        }
        
        // Initialize the known drives list
        knownDrives = getConnectedDrives();

        // Initialize known USB serials if osquery is available
        if (osFacade != null) {
            try {
                List<Map<String, String>> devices = osFacade.getUsbDevices();
                for (Map<String, String> device : devices) {
                    String serial = device.getOrDefault("serial", "");
                    if (!serial.isEmpty()) {
                        knownUsbSerials.add(serial);
                    }
                }
            } catch (Exception e) {
                System.err.println("[HIPS-USB] Could not initialize USB device list: " + e.getMessage());
            }
        }
        
        if (scheduler == null) {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "HIPS-UsbMonitor");
                t.setDaemon(true);
                return t;
            });
        }

        // Optimized: Event-Driven Monitoring on Windows using WMI
        String osType = osFacade != null ? osFacade.getOsType() : System.getProperty("os.name").toLowerCase();
        if (osType.contains("win")) {
            System.out.println("[HIPS-USB] Using event-driven WMI listener (No polling).");
            startWmiListener();
        } else {
            // Poll every 5 seconds for hardware changes (Fallback for non-Windows)
            scheduler.scheduleAtFixedRate(this::pollForNewDrives, 5, 5, TimeUnit.SECONDS);
        }
    }

    @Override
    public void stopService() {
        // If we injected a shared scheduler, we shouldn't shut it down here.
        // It will be shut down by ServiceManager.
        // If we created it ourselves, we can shut it down.
        // For safety, we'll just leave it to ServiceManager.
        System.out.println("[HIPS-USB] USB Monitor stopped.");
    }

    /**
     * Starts a background PowerShell process to listen for WMI VolumeChange events.
     * This eliminates the need for 5-second polling, significantly reducing idle CPU usage.
     */
    private void startWmiListener() {
        new Thread(() -> {
            try {
                String psCommand = "Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier VolChange; " +
                        "while($true) { $e = Wait-Event -SourceIdentifier VolChange; " +
                        "if ($e.SourceEventArgs.NewEvent.EventType -eq 2) { Write-Output $e.SourceEventArgs.NewEvent.DriveName }; " +
                        "Remove-Event -EventIdentifier $e.EventIdentifier }";
                        
                ProcessBuilder pb = new ProcessBuilder("powershell", "-NoProfile", "-Command", psCommand);
                Process p = pb.redirectErrorStream(true).start();
                
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.length() >= 2 && line.contains(":")) {
                            String drivePath = line.substring(0, 2) + "\\";
                            if (!knownDrives.contains(drivePath)) {
                                handleNewDrive(drivePath);
                                knownDrives.add(drivePath);
                                
                                if (osFacade != null) {
                                    checkOsqueryUsbDevices();
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("[HIPS-USB] WMI Listener failed, falling back to polling: " + e.getMessage());
                scheduler.scheduleAtFixedRate(this::pollForNewDrives, 5, 5, TimeUnit.SECONDS);
            }
        }, "HIPS-UsbWmiListener").start();
    }

    /**
     * Polls the system for current drives and compares against the known list.
     */
    private void pollForNewDrives() {
        try {
            Set<String> currentDrives = getConnectedDrives();
            
            // Find newly added drives
            for (String drive : currentDrives) {
                if (!knownDrives.contains(drive)) {
                    handleNewDrive(drive);
                }
            }
            
            // Update known drives
            knownDrives = currentDrives;

            // If osquery is available, also check for new USB devices
            // (provides richer metadata even if drive letter isn't assigned)
            if (osFacade != null) {
                checkOsqueryUsbDevices();
            }
            
        } catch (Exception e) {
            System.err.println("[HIPS-USB] Error polling for drives: " + e.getMessage());
        }
    }

    /**
     * Checks for new USB devices via osquery (supplementary to drive polling).
     */
    private void checkOsqueryUsbDevices() {
        try {
            List<Map<String, String>> devices = osFacade.getUsbDevices();
            for (Map<String, String> device : devices) {
                String serial = device.getOrDefault("serial", "");
                if (!serial.isEmpty() && !knownUsbSerials.contains(serial)) {
                    knownUsbSerials.add(serial);
                    // Report the new USB device with rich metadata
                    String vendor = device.getOrDefault("vendor", "Unknown");
                    String model = device.getOrDefault("model", "Unknown");
                    String removable = device.getOrDefault("removable", "");

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("vendor", vendor);
                    metadata.put("model", model);
                    metadata.put("serial_number", serial);
                    metadata.put("removable", removable);
                    metadata.put("detection_source", "osquery");

                    Event event = new Event(Module.asset, "USB_DEVICE_DETECTED", Severity.MEDIUM,
                            "New USB Device: " + vendor + " " + model)
                            .withDescription("A new USB device was detected: " + vendor + " " + model +
                                    " (S/N: " + serial + ")")
                            .withMetadata(metadata);

                    apiClient.postAsyncChecked("report.php", event);
                    System.out.println("[HIPS-USB] osquery detected new USB: " + vendor + " " + model);
                }
            }
        } catch (Exception e) {
            // Suppress — osquery USB detection is supplementary
        }
    }

    /**
     * Gets a set of all current root directories (e.g., "C:\", "D:\").
     */
    private Set<String> getConnectedDrives() {
        File[] roots = File.listRoots();
        if (roots == null) return new HashSet<>();
        return Arrays.stream(roots)
                .map(File::getAbsolutePath)
                .collect(Collectors.toSet());
    }

    /**
     * Handles a newly detected drive insertion.
     */
    private void handleNewDrive(String drivePath) {
        System.out.println("[HIPS-USB] ⚠ New Drive Detected: " + drivePath);
        
        // Get USB Serial Number
        String serialNumber = getDriveSerialNumber(drivePath);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("drive_letter", drivePath);
        metadata.put("serial_number", serialNumber);
        metadata.put("os_type", osFacade != null ? osFacade.getOsType() : "windows");
        
        Event event = new Event(Module.asset, "USB_INSERTED", Severity.MEDIUM, "USB Drive Inserted: " + drivePath)
                .withDescription("A new removable drive was detected and is being scanned.")
                .withSourcePath(drivePath)
                .withMetadata(metadata);
        
        // Log the insertion event
        fileAlertHandler.logEvent(event);
        apiClient.postAsyncChecked("report.php", event);
        
        // Trigger YARA scan on the new drive
        scanDriveForMalware(drivePath);
    }
    
    /**
     * Scans the drive contents for malware.
     */
    private void scanDriveForMalware(String drivePath) {
        System.out.println("[HIPS-USB] Initiating YARA scan on " + drivePath + "...");
        File drive = new File(drivePath);
        if (!drive.exists()) return;
        
        // Perform the scan asynchronously to not block the polling thread
        new Thread(() -> {
            try {
                // Perform a scan on the root directory of the drive
                List<String> matches = yaraScanner.scanFile(drive.toPath());
                
                if (!matches.isEmpty()) {
                    String matchStr = String.join(", ", matches);
                    System.err.println("[HIPS-USB] ⚠ MALWARE DETECTED ON USB: " + drivePath + " | Matches: " + matchStr);

                    Map<String, Object> malwareMetadata = new HashMap<>();
                    malwareMetadata.put("yara_matches", matches);
                    malwareMetadata.put("drive_letter", drivePath);

                    Event malwareEvent = new Event(Module.file, "USB_MALWARE_DETECTED", Severity.CRITICAL, "Malware Detected on USB: " + drivePath)
                            .withSourcePath(drivePath)
                            .withDescription("YARA scan matched rules: " + matchStr + " on USB drive " + drivePath)
                            .withMetadata(malwareMetadata);

                    fileAlertHandler.logEvent(malwareEvent);
                    fileAlertHandler.triggerAlert(malwareEvent);
                } else {
                    System.out.println("[HIPS-USB] ✓ USB Drive " + drivePath + " is clean.");
                }
            } catch (Exception e) {
                System.err.println("[HIPS-USB] Error scanning USB drive: " + e.getMessage());
            }
        }, "HIPS-UsbScanner-" + drivePath.charAt(0)).start();
    }

    /**
     * Gets the volume serial number of the drive.
     * Uses OS-appropriate commands.
     */
    private String getDriveSerialNumber(String drivePath) {
        String osType = osFacade != null ? osFacade.getOsType() : "windows";

        if ("windows".equals(osType)) {
            return getWindowsDriveSerial(drivePath);
        } else if ("linux".equals(osType)) {
            return getLinuxDriveSerial(drivePath);
        } else {
            return getDarwinDriveSerial(drivePath);
        }
    }

    private String getWindowsDriveSerial(String drivePath) {
        String driveLetter = drivePath.replace("\\", "");
        String command = "cmd.exe /c vol " + driveLetter;
        try {
            Process p = Runtime.getRuntime().exec(command);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                String serial = "Unknown";
                while ((line = reader.readLine()) != null) {
                    if (line.toLowerCase().contains("serial number")) {
                        String[] parts = line.split("is");
                        if (parts.length > 1) {
                            serial = parts[1].trim();
                        }
                    }
                }
                p.waitFor(2, TimeUnit.SECONDS);
                return serial;
            }
        } catch (Exception e) {
            return "Error retrieving SN";
        }
    }

    private String getLinuxDriveSerial(String drivePath) {
        try {
            // Use udevadm or blkid on Linux
            Process p = Runtime.getRuntime().exec(new String[]{"blkid", "-s", "UUID", "-o", "value", drivePath});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String uuid = reader.readLine();
                p.waitFor(2, TimeUnit.SECONDS);
                return uuid != null ? uuid.trim() : "Unknown";
            }
        } catch (Exception e) {
            return "Unknown";
        }
    }

    private String getDarwinDriveSerial(String drivePath) {
        try {
            // Use diskutil on macOS
            Process p = Runtime.getRuntime().exec(new String[]{"diskutil", "info", drivePath});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("Volume UUID")) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            return parts[1].trim();
                        }
                    }
                }
                p.waitFor(2, TimeUnit.SECONDS);
            }
        } catch (Exception e) {
            // Ignore
        }
        return "Unknown";
    }
}
