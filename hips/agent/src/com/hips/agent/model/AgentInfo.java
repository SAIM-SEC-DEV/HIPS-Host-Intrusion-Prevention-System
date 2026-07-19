package com.hips.agent.model;

/**
 * ============================================================
 * HIPS Agent — AgentInfo Model
 * ============================================================
 * Represents the local machine's hardware and OS information.
 * This data is collected on startup and sent to the server
 * during registration.
 */
public class AgentInfo {

    private String hostname;
    private String ipAddress;
    private String osName;
    private String osVersion;
    private String osArch;
    private String cpuInfo;
    private int ramTotalMb;
    private String agentVersion;
    private String owner;

    /**
     * Constructs an AgentInfo by auto-detecting system properties.
     * Java's System.getProperty() provides OS details, and
     * Runtime gives us available memory information.
     */
    public AgentInfo() {
        this.osName    = System.getProperty("os.name", "Unknown");
        this.osVersion = System.getProperty("os.version", "Unknown");
        this.osArch    = System.getProperty("os.arch", "Unknown");
        this.agentVersion = "1.0.0";

        // Detect hostname
        try {
            this.hostname = java.net.InetAddress.getLocalHost().getHostName();
        } catch (java.net.UnknownHostException e) {
            this.hostname = "UNKNOWN-HOST";
        }

        // Detect primary IP address (non-loopback)
        this.ipAddress = detectPrimaryIP();

        // Better CPU and RAM info extraction using native OS MXBean
        try {
            com.sun.management.OperatingSystemMXBean osBean = 
                (com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            
            String cpuModel = System.getenv("PROCESSOR_IDENTIFIER");
            if (cpuModel == null || cpuModel.trim().isEmpty()) {
                cpuModel = this.osArch;
            }
            this.cpuInfo = cpuModel + " / " + Runtime.getRuntime().availableProcessors() + " cores";
            
            try {
                // Java 14+ method
                this.ramTotalMb = (int) (osBean.getTotalMemorySize() / (1024 * 1024));
            } catch (NoSuchMethodError e) {
                // Legacy Java method
                this.ramTotalMb = (int) (osBean.getTotalPhysicalMemorySize() / (1024 * 1024));
            }
        } catch (Exception | Error e) {
            this.cpuInfo = this.osArch + " / " + Runtime.getRuntime().availableProcessors() + " cores";
            this.ramTotalMb = (int) (Runtime.getRuntime().maxMemory() / (1024 * 1024));
        }
    }

    /**
     * Detects the primary non-loopback IP address of this machine.
     * Iterates through all network interfaces to find one that is
     * up, not a loopback, and has an IPv4 address.
     */
    private String detectPrimaryIP() {
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface ni = interfaces.nextElement();
                if (ni.isLoopback() || !ni.isUp()) continue;

                java.util.Enumeration<java.net.InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    java.net.InetAddress addr = addresses.nextElement();
                    if (addr instanceof java.net.Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (java.net.SocketException e) {
            System.err.println("[HIPS] Failed to detect IP: " + e.getMessage());
        }
        return "127.0.0.1";
    }

    // ── Getters and Setters ──────────────────────────────────

    public String getHostname()     { return hostname; }
    public String getIpAddress()    { return ipAddress; }
    public String getOsName()       { return osName; }
    public String getOsVersion()    { return osVersion; }
    public String getOsArch()       { return osArch; }
    public String getCpuInfo()      { return cpuInfo; }
    public int    getRamTotalMb()   { return ramTotalMb; }
    public String getAgentVersion() { return agentVersion; }
    public String getOwner()        { return owner; }

    public void setHostname(String hostname)         { this.hostname = hostname; }
    public void setIpAddress(String ipAddress)       { this.ipAddress = ipAddress; }
    public void setOsName(String osName)             { this.osName = osName; }
    public void setOsVersion(String osVersion)       { this.osVersion = osVersion; }
    public void setOsArch(String osArch)             { this.osArch = osArch; }
    public void setCpuInfo(String cpuInfo)            { this.cpuInfo = cpuInfo; }
    public void setRamTotalMb(int ramTotalMb)         { this.ramTotalMb = ramTotalMb; }
    public void setAgentVersion(String agentVersion) { this.agentVersion = agentVersion; }
    public void setOwner(String owner)               { this.owner = owner; }

    @Override
    public String toString() {
        return "AgentInfo{" +
               "hostname='" + hostname + '\'' +
               ", ip='" + ipAddress + '\'' +
               ", os='" + osName + ' ' + osVersion + '\'' +
               ", arch='" + osArch + '\'' +
               ", cpu='" + cpuInfo + '\'' +
               ", ram=" + ramTotalMb + "MB" +
               '}';
    }
}
