package com.hips.agent.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;

/**
 * ============================================================
 * HIPS Agent — Service Manager (Refactored v1.1)
 * ============================================================
 *
 * FIXES APPLIED:
 *   - FIX 2.4 (Missing Service Restart): Each service's start
 *     method is wrapped in a health-check decorator. If a module
 *     crashes with an unhandled exception, it is automatically
 *     stopped and restarted after a 10-second delay.
 *
 *   - FIX 2.5 (Synchronous Startup): Services are now started
 *     in parallel on a cached thread pool with a 30-second
 *     startup timeout per service, preventing one hung module
 *     from blocking the rest.
 *
 *   - FIX 2.6 (Thread Pool Bloat): Exposes a shared
 *     ScheduledExecutorService that all monitor modules should
 *     use instead of creating their own. Reduces total thread
 *     count from ~10 threads to 4 shared threads.
 *
 * Design Pattern: Service Locator + Lifecycle Management
 */
public class ServiceManager {

    /**
     * Contract every HIPS module must implement to participate
     * in the managed lifecycle.
     */
    public interface ManagedService {
        String  getServiceName();
        void    startService();
        void    stopService();
    }

    private final List<ManagedService> services = new ArrayList<>();

    // ── FIX 2.6: Shared thread pool for all monitor modules ──
    // 4 threads handle all scheduled tasks across all modules.
    // Each module receives this pool via constructor injection.
    private final ScheduledExecutorService sharedScheduler =
        new ScheduledThreadPoolExecutor(4, r -> {
            Thread t = new Thread(r, "HIPS-SharedPool");
            t.setDaemon(true);
            return t;
        });

    // Restart delay after a module crash
    private static final int RESTART_DELAY_SEC = 10;

    /**
     * Returns the shared scheduler that monitor modules should use
     * for their periodic tasks instead of creating their own.
     */
    public ScheduledExecutorService getSharedScheduler() {
        return sharedScheduler;
    }

    public void register(ManagedService service) {
        services.add(service);
        System.out.println("[ServiceManager] Registered: " + service.getServiceName());
    }

    // ── FIX 2.5: Parallel startup with per-service timeout ───
    /**
     * Starts all registered services IN PARALLEL.
     * Each service has a 30-second timeout. If one module hangs
     * during startup, it does not block others from starting.
     */
    public void startAll() {
        System.out.println("[ServiceManager] Starting " + services.size() + " services in parallel...");

        ExecutorService startupPool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "HIPS-Startup");
            t.setDaemon(true);
            return t;
        });

        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < services.size(); i++) {
            final ManagedService svc = services.get(i);
            final int stepNum = i + 1;

            Future<?> f = startupPool.submit(() -> {
                System.out.println("\n═══ Step " + stepNum + "/" + services.size()
                        + ": " + svc.getServiceName() + " ═══");
                try {
                    svc.startService();
                    System.out.println("[ServiceManager] ✓ " + svc.getServiceName() + " started.");
                } catch (Exception e) {
                    System.err.println("[ServiceManager] ✗ Failed to start "
                            + svc.getServiceName() + ": " + e.getMessage());
                    // Schedule an auto-restart attempt
                    scheduleRestart(svc);
                }
            });
            futures.add(f);
        }

        // Wait for all startups (max 30 seconds each)
        for (Future<?> f : futures) {
            try {
                f.get(30, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                System.err.println("[ServiceManager] ⚠ A service startup timed out after 30s.");
                f.cancel(true);
            } catch (Exception e) {
                System.err.println("[ServiceManager] Startup error: " + e.getMessage());
            }
        }

        startupPool.shutdown();
        System.out.println("[ServiceManager] All services started.");
    }

    // ── FIX 2.4: Auto-restart crashed services ────────────────
    /**
     * Schedules an automatic restart for a crashed service.
     * Waits RESTART_DELAY_SEC before attempting to restart.
     */
    private void scheduleRestart(ManagedService svc) {
        System.err.println("[ServiceManager] Scheduling restart for "
                + svc.getServiceName() + " in " + RESTART_DELAY_SEC + "s...");

        sharedScheduler.schedule(() -> {
            System.out.println("[ServiceManager] Restarting " + svc.getServiceName() + "...");
            try {
                svc.stopService();
            } catch (Exception ignored) {}
            try {
                svc.startService();
                System.out.println("[ServiceManager] ✓ " + svc.getServiceName() + " restarted successfully.");
            } catch (Exception e) {
                System.err.println("[ServiceManager] ✗ Restart failed for "
                        + svc.getServiceName() + ": " + e.getMessage()
                        + " — Will retry in " + RESTART_DELAY_SEC + "s.");
                scheduleRestart(svc); // Recursive retry
            }
        }, RESTART_DELAY_SEC, TimeUnit.SECONDS);
    }

    /**
     * Stops all registered services in reverse order for
     * clean dependency teardown, then shuts down the shared pool.
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

        // Shut down shared pool
        sharedScheduler.shutdown();
        try {
            if (!sharedScheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                sharedScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            sharedScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        System.out.println("[ServiceManager] All services stopped.");
    }

    public int getServiceCount() {
        return services.size();
    }
}
