package com.hips.agent.core;

import com.hips.agent.config.AgentConfig;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;

/**
 * ============================================================
 * HIPS Agent — Server Discovery (UDP Broadcast)
 * ============================================================
 * Enables zero-config deployment by discovering the HIPS server
 * on the local network using UDP broadcast.
 *
 * Protocol:
 *   1. Agent sends "HIPS_DISCOVER" to broadcast address (port 41900)
 *   2. Discovery service on the server responds with the HTTP URL
 *   3. Agent updates its config with the new URL
 *
 * This allows agents to automatically find the server even when
 * the server's IP changes (e.g., DHCP, network switch).
 */
public class ServerDiscovery {

    private static final int DISCOVERY_PORT = 41900;
    private static final String DISCOVERY_MSG = "HIPS_DISCOVER";
    private static final int TIMEOUT_MS = 3000; // 3 seconds per attempt
    private static final int MAX_ATTEMPTS = 3;

    private final AgentConfig config;

    public ServerDiscovery(AgentConfig config) {
        this.config = config;
    }

    /**
     * Attempts to discover the HIPS server on the local network
     * using UDP broadcast. Tries up to 3 times.
     *
     * @return The discovered server URL, or null if not found
     */
    public String discover() {
        System.out.println("[HIPS-DISCOVERY] Searching for HIPS server on local network...");

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            System.out.println("[HIPS-DISCOVERY] Attempt " + attempt + "/" + MAX_ATTEMPTS + "...");

            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                socket.setSoTimeout(TIMEOUT_MS);

                // Send broadcast discovery message
                byte[] sendData = DISCOVERY_MSG.getBytes(StandardCharsets.UTF_8);
                DatagramPacket sendPacket = new DatagramPacket(
                    sendData, sendData.length,
                    InetAddress.getByName("255.255.255.255"),
                    DISCOVERY_PORT
                );
                socket.send(sendPacket);

                // Also try sending to all subnet broadcast addresses
                try {
                    java.util.Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
                    while (interfaces.hasMoreElements()) {
                        NetworkInterface ni = interfaces.nextElement();
                        if (ni.isLoopback() || !ni.isUp()) continue;
                        for (InterfaceAddress addr : ni.getInterfaceAddresses()) {
                            InetAddress broadcast = addr.getBroadcast();
                            if (broadcast != null) {
                                DatagramPacket subnetPacket = new DatagramPacket(
                                    sendData, sendData.length, broadcast, DISCOVERY_PORT
                                );
                                socket.send(subnetPacket);
                            }
                        }
                    }
                } catch (SocketException ignored) {}

                // Wait for response
                byte[] receiveData = new byte[512];
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

                socket.receive(receivePacket);
                String response = new String(receivePacket.getData(), 0, receivePacket.getLength(), StandardCharsets.UTF_8).trim();

                // Expected response format: "HIPS_SERVER|http://192.168.x.x/hips"
                if (response.startsWith("HIPS_SERVER|")) {
                    String serverUrl = response.substring("HIPS_SERVER|".length()).trim();
                    System.out.println("[HIPS-DISCOVERY] ✓ Server found: " + serverUrl);
                    return serverUrl;
                }

            } catch (SocketTimeoutException e) {
                System.out.println("[HIPS-DISCOVERY] No response (timeout).");
            } catch (IOException e) {
                System.err.println("[HIPS-DISCOVERY] Discovery error: " + e.getMessage());
            }
        }

        System.out.println("[HIPS-DISCOVERY] ✗ Server not found on local network.");
        return null;
    }

    /**
     * Tries to reach the currently configured server. If unreachable,
     * attempts auto-discovery and updates the config if successful.
     *
     * @return true if the server is reachable (existing or discovered)
     */
    public boolean ensureServerReachable() {
        // First try the existing configured URL
        if (isServerReachable(config.getServerUrl())) {
            return true;
        }

        System.out.println("[HIPS-DISCOVERY] Configured server unreachable: " + config.getServerUrl());

        // Try auto-discovery
        String discovered = discover();
        if (discovered != null) {
            config.setServerUrl(discovered);
            config.saveConfig();
            System.out.println("[HIPS-DISCOVERY] ✓ Config updated with discovered server: " + discovered);
            return true;
        }

        return false;
    }

    /**
     * Quick connectivity check to see if the server is responding.
     */
    private boolean isServerReachable(String serverUrl) {
        try {
            String testUrl = serverUrl.endsWith("/") ? serverUrl + "api/heartbeat.php" : serverUrl + "/api/heartbeat.php";
            HttpURLConnection conn = (HttpURLConnection) new URL(testUrl).openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            int code = conn.getResponseCode();
            conn.disconnect();
            return code > 0 && code < 500;
        } catch (Exception e) {
            return false;
        }
    }

    // ── Static: Run as a Discovery Responder (Server-Side) ───

    /**
     * Starts a UDP listener that responds to agent discovery broadcasts.
     * This runs on the SERVER machine to help agents find it.
     *
     * Usage: java -cp ... com.hips.agent.core.ServerDiscovery --listen
     */
    public static void runResponder(String serverUrl) {
        System.out.println("╔═══════════════════════════════════════════╗");
        System.out.println("║  HIPS Discovery Service                   ║");
        System.out.println("║  Listening on UDP port " + DISCOVERY_PORT + "              ║");
        System.out.println("║  Server URL: " + serverUrl);
        System.out.println("║  Press Ctrl+C to stop                     ║");
        System.out.println("╚═══════════════════════════════════════════╝");
        System.out.println();

        try (DatagramSocket socket = new DatagramSocket(DISCOVERY_PORT)) {
            byte[] receiveData = new byte[512];

            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                socket.receive(receivePacket);

                String message = new String(receivePacket.getData(), 0, receivePacket.getLength(), StandardCharsets.UTF_8).trim();

                if (DISCOVERY_MSG.equals(message)) {
                    InetAddress clientAddress = receivePacket.getAddress();
                    int clientPort = receivePacket.getPort();

                    System.out.println("[DISCOVERY] Agent discovery request from " + clientAddress.getHostAddress() + ":" + clientPort);

                    // Send response with server URL
                    String response = "HIPS_SERVER|" + serverUrl;
                    byte[] sendData = response.getBytes(StandardCharsets.UTF_8);
                    DatagramPacket sendPacket = new DatagramPacket(
                        sendData, sendData.length, clientAddress, clientPort
                    );
                    socket.send(sendPacket);

                    System.out.println("[DISCOVERY] ✓ Responded with: " + serverUrl);
                }
            }
        } catch (IOException e) {
            System.err.println("[DISCOVERY] Fatal error: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Can be run standalone as a discovery responder.
     * Usage: java -cp ... com.hips.agent.core.ServerDiscovery http://192.168.x.x/hips
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            // Auto-detect server URL using local IP
            String localIP = getLocalIP();
            String url = "http://" + localIP + "/hips";
            System.out.println("[DISCOVERY] Auto-detected server URL: " + url);
            runResponder(url);
        } else {
            runResponder(args[0]);
        }
    }

    /**
     * Gets the primary local IP address of this machine.
     */
    private static String getLocalIP() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            return socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }
}
