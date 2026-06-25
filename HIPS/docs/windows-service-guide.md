# HIPS Agent — Windows Service Conversion Guide

Complete step-by-step procedure for converting the HIPS Java Agent into a Windows Service that starts automatically on boot.

---

## Overview

The conversion pipeline is:

```
Java Project → .jar file → .exe file (Launch4j) → Windows Service (NSSM)
```

| Step | Tool | Purpose |
|------|------|---------|
| 1 | IntelliJ / Eclipse | Export project as runnable `.jar` |
| 2 | Launch4j | Wrap `.jar` inside a native `.exe` |
| 3 | NSSM | Register `.exe` as a Windows Service |

---

## Prerequisites

Before you begin, make sure you have:

- [x] **Java JRE 11+** installed (verify: `java -version`)
- [x] **IntelliJ IDEA** or **Eclipse** IDE
- [x] **Gson library** (gson-2.10.1.jar) in your project build path
- [x] **Launch4j** — Download from https://launch4j.sourceforge.net/
- [x] **NSSM** — Download from https://nssm.cc/download
- [x] **Administrator privileges** on the target Windows machine

---

## Step 1: Export the Java Project as a Runnable JAR

### Using IntelliJ IDEA

1. **Open** the HIPS agent project in IntelliJ IDEA.

2. Go to **File → Project Structure → Artifacts**.

3. Click **+ → JAR → From modules with dependencies**.

4. Set the **Main Class** to:
   ```
   com.hips.agent.HipsAgent
   ```

5. Select **Extract to the target JAR** to bundle all dependencies (Gson) into a single fat JAR.

6. Click **OK** to save the artifact configuration.

7. Go to **Build → Build Artifacts → hips-agent → Build**.

8. The JAR file will be created at:
   ```
   out/artifacts/hips_agent_jar/hips-agent.jar
   ```

9. **Test** the JAR by running:
   ```cmd
   java -jar hips-agent.jar
   ```
   You should see the HIPS banner and the agent attempting to connect to the server.

### Using Eclipse

1. **Right-click** the project → **Export → Java → Runnable JAR file**.

2. Set the **Launch configuration** to `HipsAgent`.

3. Set the **Export destination** to `C:\HIPS\hips-agent.jar`.

4. Select **Package required libraries into generated JAR**.

5. Click **Finish**.

6. **Test** as above with `java -jar hips-agent.jar`.

> **Important**: Make sure the JAR includes `gson-2.10.1.jar` inside it. If you get `ClassNotFoundException` for Gson, the library wasn't bundled correctly.

---

## Step 2: Convert JAR to EXE using Launch4j

Launch4j wraps your `.jar` inside a native Windows executable, making it behave like a standard `.exe` program. This is required for NSSM to manage it as a service.

### Procedure

1. **Download and install** Launch4j from https://launch4j.sourceforge.net/.

2. **Open Launch4j** and configure the following:

### Basic Tab

| Field | Value |
|-------|-------|
| Output file | `C:\HIPS\hips-agent.exe` |
| Jar | `C:\HIPS\hips-agent.jar` |
| Icon | *(optional)* — path to a `.ico` file for the service |
| Don't wrap the jar, launch only | ☐ **Unchecked** |
| Change dir | `.` (current directory) |

### JRE Tab

| Field | Value |
|-------|-------|
| Min JRE version | `11.0.0` |
| Max JRE version | *(leave empty)* |
| Prefer JDK | ☐ No |
| JRE/JDK path | *(leave empty — auto-detect)* |
| Bundled JRE path | *(leave empty, OR set to a bundled JRE directory)* |

### Header Tab

| Field | Value |
|-------|-------|
| Header type | **Console** ← Important for services! |

> **⚠ Critical**: You **must** set the Header type to **Console**, not **GUI**. Windows Services need a console application. If you set it to GUI, NSSM won't be able to capture the output.

3. Click the **Build** button (⚙ gear icon).

4. A `hips-agent.exe` file will be created at `C:\HIPS\hips-agent.exe`.

5. **Test** by double-clicking the EXE. The HIPS banner should appear in a console window.

---

## Step 3: Register as a Windows Service using NSSM

NSSM (Non-Sucking Service Manager) is a tool that can manage any executable as a Windows Service, handling start/stop, restart on failure, and log redirection.

### Installation

1. **Download NSSM** from https://nssm.cc/download.

2. **Extract** the zip file.

3. Copy `nssm.exe` (from the `win64` folder for 64-bit Windows) to `C:\HIPS\nssm.exe` or add it to your system PATH.

### Register the Service

Open **Command Prompt as Administrator** (right-click → Run as administrator):

```cmd
cd C:\HIPS
nssm install HIPSAgent
```

This opens the NSSM GUI. Configure:

### Application Tab

| Field | Value |
|-------|-------|
| Path | `C:\HIPS\hips-agent.exe` |
| Startup directory | `C:\HIPS` |
| Arguments | *(leave empty)* |

### Details Tab

| Field | Value |
|-------|-------|
| Display name | `HIPS Security Agent` |
| Description | `Host Intrusion Prevention System — Monitoring Agent` |
| Startup type | `Automatic` |

### Log on Tab

| Field | Value |
|-------|-------|
| Log on as | `Local System account` ☑ |
| Allow service to interact with desktop | ☐ (leave unchecked) |

### I/O Tab (Log Redirection)

| Field | Value |
|-------|-------|
| Output (stdout) | `C:\HIPS\logs\service-stdout.log` |
| Error (stderr) | `C:\HIPS\logs\service-stderr.log` |

> Create the `C:\HIPS\logs\` directory first:
> ```cmd
> mkdir C:\HIPS\logs
> ```

### Exit Actions Tab

| Field | Value |
|-------|-------|
| Restart action | `Restart application` |
| Restart delay | `5000` milliseconds |
| Throttle | `1500` milliseconds |

This ensures the agent automatically restarts if it crashes.

4. Click **Install Service**.

### Start the Service

```cmd
nssm start HIPSAgent
```

### Verify

```cmd
nssm status HIPSAgent
```

Expected output: `SERVICE_RUNNING`

You can also check in the Windows Services panel:
1. Press `Win + R`, type `services.msc`, press Enter.
2. Find **"HIPS Security Agent"** in the list.
3. Verify status shows **Running** and startup type shows **Automatic**.

---

## Step 4: Manage the Service

### Common NSSM Commands

```cmd
:: Check service status
nssm status HIPSAgent

:: Stop the service
nssm stop HIPSAgent

:: Start the service
nssm start HIPSAgent

:: Restart the service
nssm restart HIPSAgent

:: Edit service configuration
nssm edit HIPSAgent

:: Remove the service entirely
nssm remove HIPSAgent confirm
```

### View Logs

```cmd
:: View stdout log
type C:\HIPS\logs\service-stdout.log

:: View stderr log (errors)
type C:\HIPS\logs\service-stderr.log

:: Follow logs in real-time (PowerShell)
Get-Content C:\HIPS\logs\service-stdout.log -Wait
```

---

## Step 5: File Structure on the Target Machine

After setup, your `C:\HIPS\` directory should look like:

```
C:\HIPS\
├── hips-agent.exe          ← The Launch4j-wrapped executable
├── hips-agent.jar          ← Original JAR (kept as backup)
├── hips-agent.properties   ← Agent configuration (auto-generated)
├── nssm.exe                ← NSSM service manager
├── hips-file-audit.log     ← File monitoring audit log
├── hips-network-audit.log  ← Network monitoring audit log
└── logs\
    ├── service-stdout.log  ← Service standard output
    └── service-stderr.log  ← Service error output
```

---

## Troubleshooting

### Service Won't Start

| Symptom | Solution |
|---------|----------|
| `SERVICE_FAILED` | Check `service-stderr.log` for Java errors |
| "Cannot find JRE" | Install Java 11+ and ensure `JAVA_HOME` is set |
| Connection refused | Verify XAMPP Apache is running and the server URL in `hips-agent.properties` is correct |
| Access denied | Run NSSM commands as Administrator |

### Service Keeps Restarting

The agent saves its state in `hips-agent.properties`. If registration keeps failing (wrong server URL), the agent will exit and NSSM will restart it in a loop.

**Fix**: Stop the service, edit `hips-agent.properties` manually, then restart.

```cmd
nssm stop HIPSAgent
notepad C:\HIPS\hips-agent.properties
:: Fix the server.url value
nssm start HIPSAgent
```

### Uninstall Completely

```cmd
nssm stop HIPSAgent
nssm remove HIPSAgent confirm
rmdir /s /q C:\HIPS
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────┐
│         HIPS AGENT — SERVICE QUICK REF          │
├─────────────────────────────────────────────────┤
│  Install:   nssm install HIPSAgent              │
│  Start:     nssm start HIPSAgent                │
│  Stop:      nssm stop HIPSAgent                 │
│  Restart:   nssm restart HIPSAgent              │
│  Status:    nssm status HIPSAgent               │
│  Edit:      nssm edit HIPSAgent                 │
│  Remove:    nssm remove HIPSAgent confirm       │
│  Logs:      C:\HIPS\logs\service-stdout.log     │
│  Config:    C:\HIPS\hips-agent.properties       │
└─────────────────────────────────────────────────┘
```
