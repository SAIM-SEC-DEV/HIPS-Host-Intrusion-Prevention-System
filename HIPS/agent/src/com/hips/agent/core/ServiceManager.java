package com.hips.agent.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * ============================================================
 * HIPS Agent — Service Manager (SRP Refactor)
 * ============================================================
 * Manages the lifecycle of all agent modules. Each module
 * implements the {@link ManagedService} interface and is
 * registered here. The manager starts them in insertion order
 * and stops them in reverse order for clean shutdown.
 *
 * Design Pattern: Service Locator + Lifecycle Management
 *
 * This decouples HipsAgent (the orchestrator) from the
 * concrete monitor implementations, honouring the Single
 * Responsibility Principle (SRP) and Open/Closed Principle
 * (OCP) — new modules can be added without modifying HipsAgent.
 */
public class ServiceManager {

    /**
     * Contract every HIPS module must implement to participate
     * in the managed lifecycle.
     */
    public interface ManagedService {
        /** Human-readable service name for logging */
        String getServiceName();

        /** Start the service. Called once during agent startup. */
        void startService();

        /** Stop the service gracefully. Called during shutdown. */
        void stopService();
    }

    private final List<ManagedService> services = new ArrayList<>();

    /**
     * Registers a module for lifecycle management.
     * Services are started in the order they are registered
     * and stopped in reverse order.
     *
     * @param service  The service to manage
     */
    public void register(ManagedService service) {
        services.add(service);
        System.out.println("[ServiceManager] Registered: " + service.getServiceName());
    }

    /**
     * Starts all registered services in order.
     */
    public void startAll() {
        System.out.println("[ServiceManager] Starting " + services.size() + " services...");
        for (int i = 0; i < services.size(); i++) {
            ManagedService svc = services.get(i);
            System.out.println("\n═══ Step " + (i + 1) + "/" + services.size()
                    + ": " + svc.getServiceName() + " ═══");
            try {
                svc.startService();
                System.out.println("[ServiceManager] ✓ " + svc.getServiceName() + " started.");
            } catch (Exception e) {
                System.err.println("[ServiceManager] ✗ Failed to start "
                        + svc.getServiceName() + ": " + e.getMessage());
            }
        }
    }

    /**
     * Stops all registered services in reverse order for
     * clean dependency teardown.
     */
    public void stopAll() {
        System.out.println("[ServiceManager] Stopping " + services.size() + " services...");
        List<ManagedService> reversed = new ArrayList<>(services);
        Collections.reverse(reversed);

        for (ManagedService svc : reversed) {
            try {
                System.out.println("[ServiceManager] Stopping " + svc.getServiceName() + "...");
                svc.stopService();
            } catch (Exception e) {
                System.err.println("[ServiceManager] Error stopping "
                        + svc.getServiceName() + ": " + e.getMessage());
            }
        }
        System.out.println("[ServiceManager] All services stopped.");
    }

    /**
     * Returns the number of registered services.
     */
    public int getServiceCount() {
        return services.size();
    }
}
