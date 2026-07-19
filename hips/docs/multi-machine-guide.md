# HIPS Multi-Machine Deployment Guide

## Overview

This guide explains how to deploy the HIPS Agent on multiple computers so they all report to a single HIPS Server (your main computer running XAMPP).

## Architecture

```
   ┌─────────────────────┐
   │   HIPS Server (PC1) │  ← Your main computer (XAMPP + Dashboard)
   │   192.168.x.x       │
   │   + Discovery Svc   │
   └────────┬────────────┘
            │ HTTP + UDP
   ┌────────┼────────────────────┐
   │        │                    │
┌──▼──┐  ┌──▼──┐           ┌──▼──┐
│Agent│  │Agent│    ...     │Agent│  ← Other computers on the network
│ PC2 │  │ PC3 │           │ PCn │
└─────┘  └─────┘           └─────┘
```

## Prerequisites

- **Java 11+** must be installed on every target computer
- All computers must be on the **same local network**
- **XAMPP Apache** must be running on the server computer

---

## Step 1: Package the Agent (On Your Server PC)

Run the packaging script from the HIPS root directory:

```cmd
deploy-package.bat
```

This creates a `dist/` folder containing everything needed:
- `agent/` — Compiled Java agent
- `run-agent.bat` — Launch script
- `setup-agent.bat` — Configuration tool
- `hips-agent.properties` — Config file

## Step 2: Start the Discovery Service (On Your Server PC)

Run the discovery service so agents can find you automatically:

```cmd
discovery-service.bat
```

> **Leave this running!** It listens for agents searching for the server.
> You can install it as a Windows Service with NSSM for permanent operation.

## Step 3: Deploy to Target Computers

### Option A: Auto-Discovery (Recommended)

1. Copy the entire `dist/` folder to the target computer (USB, network share, etc.)
2. Run `run-agent.bat`
3. The agent will **automatically discover** the server on the network
4. No manual configuration needed!

### Option B: Manual Setup

1. Copy the `dist/` folder to the target computer
2. Run `setup-agent.bat`
3. Enter the server's IP address when prompted
4. Run `run-agent.bat`

## Step 4: Verify Connection

1. Open the HIPS Dashboard on your server: `http://localhost/hips/dashboard/`
2. Go to the **Dashboard** page
3. You should see new agents appearing in the **Agent Status** panel
4. Each agent will register with a unique hostname and IP

## Step 5: Install as a Windows Service (Optional)

For permanent, always-on monitoring that starts at boot:

1. Download [NSSM](https://nssm.cc/download) on the target computer
2. Run as Administrator:

```cmd
nssm install HIPSAgent
```

3. Configure NSSM:
   - **Path**: `C:\path\to\java.exe`
   - **Arguments**: `-cp "agent\bin;agent\lib\gson-2.10.1.jar" com.hips.agent.HipsAgent`
   - **Startup directory**: The folder where you placed the agent files

4. Start the service:

```cmd
nssm start HIPSAgent
```

---

## Troubleshooting

### Agent can't find the server
- Ensure `discovery-service.bat` is running on the server
- Check that both computers are on the same Wi-Fi / LAN
- Windows Firewall may block UDP port 41900 — add an exception

### Agent registers but goes offline
- Check Apache is running on the server
- The heartbeat interval is 30 seconds — wait a moment

### If you change networks
- The Discovery Service will automatically provide the new IP
- Restart the agents — they will rediscover the server
- Or run `setup-agent.bat` on each machine to manually update
