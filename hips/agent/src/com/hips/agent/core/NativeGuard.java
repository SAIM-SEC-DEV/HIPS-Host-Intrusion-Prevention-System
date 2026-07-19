package com.hips.agent.core;

/**
 * ============================================================
 * HIPS Agent — JNI Native Guard Bridge
 * ============================================================
 * Java-side declarations for the native C++ protection module.
 *
 * The native library (hips_guard.dll) provides OS-level process
 * protection that is impossible to achieve in pure Java:
 *
 *   - Modifies the process DACL to deny PROCESS_TERMINATE
 *   - Installs a kernel-aware watchdog thread
 *   - Prevents the agent from appearing in some process lists
 *
 * Build Instructions:
 *   1. Generate JNI header:
 *      javac -h . NativeGuard.java
 *
 *   2. Compile the DLL (Visual Studio Developer Command Prompt):
 *      cl /LD /EHsc hips_guard.cpp /Fe:hips_guard.dll
 *         /I"%JAVA_HOME%\include" /I"%JAVA_HOME%\include\win32"
 *         advapi32.lib
 *
 *   3. Place hips_guard.dll in C:\HIPS\bin\ or on the system PATH.
 *
 * If the DLL is not available, SelfProtectionGuard falls back
 * to a PowerShell-based watchdog (weaker but functional).
 */
public class NativeGuard {

    /**
     * Hardens the process security descriptor to deny
     * PROCESS_TERMINATE access to all users except SYSTEM.
     * After this call, taskkill and Task Manager cannot kill
     * the agent without elevated SYSTEM privileges.
     *
     * @param pid The process ID to protect
     * @return true if the DACL was modified successfully
     */
    public static native boolean protectProcess(int pid);

    /**
     * Installs a native watchdog thread inside the process.
     * This thread monitors for termination signals and spawns
     * a restart helper before the process exits.
     *
     * @param pid The process ID to watch
     * @return true if the watchdog was installed
     */
    public static native boolean installWatchdog(int pid);

    /**
     * Returns the native guard version string for diagnostics.
     *
     * @return Version string (e.g., "1.0.0") or "unavailable"
     */
    public static native String getVersion();
}
