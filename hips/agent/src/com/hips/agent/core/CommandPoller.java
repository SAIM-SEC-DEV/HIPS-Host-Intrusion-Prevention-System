package com.hips.agent.core;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.hips.agent.config.AgentConfig;
import com.hips.agent.model.Command;

import java.util.*;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Command Poller
 * ============================================================
 * Polls the server every 10 seconds (configurable) for pending
 * commands dispatched by the admin. When commands are received,
 * they are executed and results are reported back.
 *
 * Supported Commands:
 *   BLOCK_IP          — Adds firewall rule to block an IP
 *   UNBLOCK_IP        — Removes a firewall block rule
 *   SCAN_FILE         — Hash check on a specific file
 *   FULL_SCAN         — Re-hash all monitored files
 *   RESTART           — Restart the agent process
 *   SHUTDOWN          — Stop the agent gracefully
 *   UPDATE_RULES      — Reload detection rules
 *   WHITELIST_ADD     — Add a whitelist entry
 *   WHITELIST_REMOVE  — Remove a whitelist entry
 */
public class CommandPoller {

    private final AgentConfig config;
    private final ApiClient apiClient;
    private final Gson gson = new Gson();
    private ScheduledExecutorService scheduler;
    private volatile boolean running = false;

    // Command handlers registered by other modules
    private final Map<String, CommandHandler> handlers = new ConcurrentHashMap<>();

    /**
     * Functional interface for command handlers.
     * Each monitoring module can register handlers for specific
     * command types (e.g., FileMonitor registers SCAN_FILE).
     */
    @FunctionalInterface
    public interface CommandHandler {
        /**
         * Executes a command and returns a result map.
         *
         * @param command  The command to execute
         * @return         Result data (will be serialized to JSON and sent to server)
         */
        Map<String, Object> execute(Command command);
    }

    public CommandPoller(AgentConfig config, ApiClient apiClient) {
        this.config    = config;
        this.apiClient = apiClient;
    }

    /**
     * Registers a handler for a specific command type.
     * Example: poller.registerHandler("BLOCK_IP", cmd -> networkMonitor.blockIP(cmd));
     */
    public void registerHandler(String commandType, CommandHandler handler) {
        handlers.put(commandType.toUpperCase(), handler);
        System.out.println("[HIPS] Registered command handler: " + commandType);
    }

    /**
     * Starts polling the server for commands at the configured interval.
     */
    public void start() {
        if (running) return;
        running = true;

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "HIPS-CommandPoller");
            t.setDaemon(true);
            return t;
        });

        int interval = config.getPollIntervalSec();
        System.out.println("[HIPS] Starting command poller (interval: " + interval + "s)");

        // Start polling after a 5-second initial delay to let
        // other modules finish initialization first.
        scheduler.scheduleAtFixedRate(this::pollCommands, 5, interval, TimeUnit.SECONDS);
    }

    /**
     * Stops the command poller gracefully.
     */
    public void stop() {
        running = false;
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
            System.out.println("[HIPS] Command poller stopped.");
        }
    }

    // Executor for concurrent command processing
    private final ExecutorService commandExecutor = Executors.newFixedThreadPool(3, r -> {
        Thread t = new Thread(r, "HIPS-CommandWorker");
        t.setDaemon(true);
        return t;
    });

    /**
     * Polls the server for pending commands and executes each one.
     */
    private void pollCommands() {
        try {
            JsonObject response = apiClient.get("commands.php");

            if (response == null || !response.has("commands")) {
                return;
            }

            JsonArray commandsArray = response.getAsJsonArray("commands");

            if (commandsArray.isEmpty()) {
                return; // No pending commands
            }

            System.out.println("[HIPS] Received " + commandsArray.size() + " command(s) from server.");

            // Deserialize commands
            List<Command> commands = gson.fromJson(
                    commandsArray,
                    new TypeToken<List<Command>>(){}.getType()
            );

            // Execute each command in parallel worker threads
            for (Command cmd : commands) {
                commandExecutor.submit(() -> executeCommand(cmd));
            }

        } catch (Exception e) {
            System.err.println("[HIPS] Command polling failed: " + e.getMessage());
        }
    }

    /**
     * Executes a single command by dispatching it to the
     * registered handler for its command type.
     */
    private void executeCommand(Command cmd) {
        String type = cmd.getCommandType().toUpperCase();
        System.out.println("[HIPS] Executing command: " + cmd);

        CommandHandler handler = handlers.get(type);

        if (handler == null) {
            System.err.println("[HIPS] No handler registered for command type: " + type);
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", "No handler for command type: " + type);
            apiClient.reportCommandResult(cmd.getId(), "failed", errorResult);
            return;
        }

        try {
            // Execute the handler and collect the result
            Map<String, Object> result = handler.execute(cmd);

            // Report success back to the server
            if (result == null) {
                result = new HashMap<>();
                result.put("message", "Command executed successfully.");
            }
            apiClient.reportCommandResult(cmd.getId(), "completed", result);

            System.out.println("[HIPS] ✓ Command " + cmd.getId() + " completed successfully.");

        } catch (Exception e) {
            System.err.println("[HIPS] ✗ Command " + cmd.getId() + " failed: " + e.getMessage());
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", e.getMessage());
            apiClient.reportCommandResult(cmd.getId(), "failed", errorResult);
        }
    }

    public boolean isRunning() {
        return running;
    }
}
