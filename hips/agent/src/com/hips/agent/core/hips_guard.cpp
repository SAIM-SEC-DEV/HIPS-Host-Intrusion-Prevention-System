/**
 * ============================================================
 * HIPS Agent — Native Self-Protection Guard (hips_guard.cpp)
 * ============================================================
 *
 * Windows C++ module that provides kernel-level process protection
 * via JNI. When loaded by the Java agent, it:
 *
 *   1. Modifies the process DACL to deny PROCESS_TERMINATE
 *      to all users except NT AUTHORITY\SYSTEM.
 *   2. Installs a watchdog thread that monitors for kill signals
 *      and triggers a restart before the process dies.
 *
 * BUILD (Visual Studio Developer Command Prompt):
 *   cl /LD /EHsc hips_guard.cpp /Fe:hips_guard.dll ^
 *      /I"%JAVA_HOME%\include" /I"%JAVA_HOME%\include\win32" ^
 *      advapi32.lib
 *
 * DEPLOY:
 *   Copy hips_guard.dll to C:\HIPS\bin\
 *
 * (c) 2026 — HIPS Security Project
 */

#include <jni.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

// ── Forward declarations ─────────────────────────────────────
static BOOL DenyTerminateAccess(DWORD pid);
static DWORD WINAPI WatchdogThread(LPVOID param);

// Global state for watchdog
static DWORD g_watchedPid = 0;
static char  g_restartCommand[512] = {0};

// ── JNI: protectProcess ──────────────────────────────────────
// Modifies the process DACL to deny PROCESS_TERMINATE to
// the Everyone group. Only SYSTEM can kill it after this.
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jboolean JNICALL Java_com_hips_agent_core_NativeGuard_protectProcess
  (JNIEnv *env, jclass cls, jint pid)
{
    HANDLE hProcess = OpenProcess(WRITE_DAC | READ_CONTROL, FALSE, (DWORD)pid);
    if (hProcess == NULL) {
        fprintf(stderr, "[HIPS-NATIVE] Cannot open process %d: error %lu\n",
                pid, GetLastError());
        return JNI_FALSE;
    }

    // Build a DACL that denies PROCESS_TERMINATE to Everyone (S-1-1-0)
    // but allows all access to SYSTEM (S-1-5-18)
    PSECURITY_DESCRIPTOR pSD = NULL;
    BOOL result = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(D;;0x0001;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)",  // Deny terminate to World, Allow all to SYSTEM & Admin
        SDDL_REVISION_1,
        &pSD,
        NULL
    );

    if (!result || pSD == NULL) {
        fprintf(stderr, "[HIPS-NATIVE] SDDL conversion failed: error %lu\n",
                GetLastError());
        CloseHandle(hProcess);
        return JNI_FALSE;
    }

    // Extract the DACL from the security descriptor
    PACL pDacl = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted);

    if (bDaclPresent && pDacl != NULL) {
        // Apply the DACL to the process
        DWORD dwResult = SetSecurityInfo(
            hProcess,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL,
            pDacl, NULL
        );

        if (dwResult != ERROR_SUCCESS) {
            fprintf(stderr, "[HIPS-NATIVE] SetSecurityInfo failed: error %lu\n",
                    dwResult);
            LocalFree(pSD);
            CloseHandle(hProcess);
            return JNI_FALSE;
        }
    }

    LocalFree(pSD);
    CloseHandle(hProcess);

    printf("[HIPS-NATIVE] Process %d is now protected against termination.\n", pid);
    return JNI_TRUE;
}

// ── JNI: installWatchdog ─────────────────────────────────────
// Spawns a background thread that monitors the agent process.
// If the process is about to die, it triggers a restart.
JNIEXPORT jboolean JNICALL Java_com_hips_agent_core_NativeGuard_installWatchdog
  (JNIEnv *env, jclass cls, jint pid)
{
    g_watchedPid = (DWORD)pid;

    // Build the restart command (run-agent.bat in the working directory)
    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    snprintf(g_restartCommand, sizeof(g_restartCommand),
             "cmd.exe /c \"%s\\run-agent.bat\"", cwd);

    // Create the watchdog thread
    HANDLE hThread = CreateThread(
        NULL, 0, WatchdogThread, NULL, 0, NULL
    );

    if (hThread == NULL) {
        fprintf(stderr, "[HIPS-NATIVE] Watchdog thread creation failed: error %lu\n",
                GetLastError());
        return JNI_FALSE;
    }

    // Don't need the thread handle; let it run independently
    CloseHandle(hThread);

    printf("[HIPS-NATIVE] Native watchdog installed for PID %d.\n", pid);
    return JNI_TRUE;
}

// ── JNI: getVersion ──────────────────────────────────────────
JNIEXPORT jstring JNICALL Java_com_hips_agent_core_NativeGuard_getVersion
  (JNIEnv *env, jclass cls)
{
    return (*env)->NewStringUTF(env, "1.0.0");
}

#ifdef __cplusplus
}
#endif

// ── Watchdog Thread Implementation ───────────────────────────
// This thread opens a handle to the agent process and waits for
// it to signal. If the process is terminated externally, the
// thread spawns a restart command before the DLL unloads.
static DWORD WINAPI WatchdogThread(LPVOID param) {
    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, g_watchedPid);
    if (hProcess == NULL) {
        fprintf(stderr, "[HIPS-NATIVE] Watchdog cannot open process: error %lu\n",
                GetLastError());
        return 1;
    }

    // Wait indefinitely for the process to terminate
    DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
    CloseHandle(hProcess);

    if (waitResult == WAIT_OBJECT_0) {
        // Process was terminated — attempt restart
        printf("[HIPS-NATIVE] Agent process terminated! Restarting...\n");

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_MINIMIZE;
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA(
                NULL, g_restartCommand, NULL, NULL, FALSE,
                CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[HIPS-NATIVE] Agent restart initiated (PID %lu).\n",
                   pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            fprintf(stderr, "[HIPS-NATIVE] Restart failed: error %lu\n",
                    GetLastError());
        }
    }

    return 0;
}
