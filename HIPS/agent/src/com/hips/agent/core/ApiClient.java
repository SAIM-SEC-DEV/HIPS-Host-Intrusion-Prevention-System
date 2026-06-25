package com.hips.agent.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.hips.agent.config.AgentConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * ============================================================
 * HIPS Agent — API Client
 * ============================================================
 * Centralized HTTP client for all communication with the HIPS
 * server. Uses Java 11's built-in HttpClient (no external
 * dependencies needed for HTTP).
 *
 * All requests include:
 *   - Content-Type: application/json
 *   - Authorization: Bearer <token>  (except for registration)
 *
 * Security Notes:
 *   - Timeout of 15 seconds prevents hanging on unresponsive servers
 *   - Auth token is attached automatically from AgentConfig
 *   - All payloads are serialized via Gson to prevent injection
 */
public class ApiClient {

    private final HttpClient httpClient;
    private final Gson gson;
    private final AgentConfig config;

    // Connection timeout for all requests
    private static final int TIMEOUT_SECONDS = 15;

    public ApiClient(AgentConfig config) {
        this.config = config;
        this.gson = new GsonBuilder().setPrettyPrinting().create();

        // Build a reusable HttpClient with a connection timeout.
        // Java 11's HttpClient is thread-safe and can be shared.
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .build();
    }

    // ── POST request WITH authentication ─────────────────────
    /**
     * Sends an authenticated POST request to the given API endpoint.
     * The Bearer token is automatically read from AgentConfig.
     *
     * @param endpoint  API endpoint (e.g., "heartbeat.php")
     * @param payload   Object to serialize as JSON body
     * @return          Parsed JSON response as JsonObject, or null on failure
     */
    public JsonObject post(String endpoint, Object payload) {
        try {
            String url  = config.apiUrl(endpoint);
            String json = gson.toJson(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + config.getAuthToken())
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            System.out.println("[HIPS] POST " + url);

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            return handleResponse(url, response);

        } catch (Exception e) {
            System.err.println("[HIPS] POST " + endpoint + " failed: " + e.getMessage());
            return null;
        }
    }

    // ── POST request WITHOUT authentication (for registration) ─
    /**
     * Sends an unauthenticated POST request. Used exclusively
     * for the initial registration call where the agent doesn't
     * have a token yet.
     *
     * @param endpoint  API endpoint (e.g., "register.php")
     * @param payload   Object to serialize as JSON body
     * @return          Parsed JSON response as JsonObject, or null on failure
     */
    public JsonObject postNoAuth(String endpoint, Object payload) {
        try {
            String url  = config.apiUrl(endpoint);
            String json = gson.toJson(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            System.out.println("[HIPS] POST (no auth) " + url);

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            return handleResponse(url, response);

        } catch (Exception e) {
            System.err.println("[HIPS] POST " + endpoint + " failed: " + e.getMessage());
            return null;
        }
    }

    // ── GET request WITH authentication ──────────────────────
    /**
     * Sends an authenticated GET request (used for polling commands).
     *
     * @param endpoint  API endpoint (e.g., "commands.php")
     * @return          Parsed JSON response as JsonObject, or null on failure
     */
    public JsonObject get(String endpoint) {
        try {
            String url = config.apiUrl(endpoint);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                    .header("Authorization", "Bearer " + config.getAuthToken())
                    .GET()
                    .build();

            System.out.println("[HIPS] GET " + url);

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString()
            );

            return handleResponse(url, response);

        } catch (Exception e) {
            System.err.println("[HIPS] GET " + endpoint + " failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Processes an HTTP response: logs the status code and
     * parses the body as JSON.
     *
     * @param url       The full URL (for logging)
     * @param response  The HTTP response
     * @return          Parsed JsonObject, or null if parsing fails
     */
    private JsonObject handleResponse(String url, HttpResponse<String> response) {
        int statusCode = response.statusCode();
        String body = response.body();

        if (statusCode >= 200 && statusCode < 300) {
            System.out.println("[HIPS] Response " + statusCode + " OK");
        } else {
            System.err.println("[HIPS] Response " + statusCode + " from " + url);
            System.err.println("[HIPS] Body: " + body);
        }

        try {
            return JsonParser.parseString(body).getAsJsonObject();
        } catch (Exception e) {
            System.err.println("[HIPS] Failed to parse JSON response: " + body);
            return null;
        }
    }

    /**
     * Reports the result of a command execution back to the server.
     *
     * @param commandId  The command's database ID
     * @param status     "completed" or "failed"
     * @param result     Result data to include in the response
     */
    public void reportCommandResult(int commandId, String status, Map<String, Object> result) {
        Map<String, Object> payload = Map.of(
                "command_id", commandId,
                "status", status,
                "result", result != null ? result : Map.of()
        );
        post("result.php", payload);
    }
}
