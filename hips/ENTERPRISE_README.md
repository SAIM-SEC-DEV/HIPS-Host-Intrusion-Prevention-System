# HIPS-OOP Enterprise Edition — v2.0.0

## 🛡 Security & Architecture Overhaul

The HIPS-OOP project has been refactored to meet enterprise-grade standards for security, portability, and maintainability.

### 1. Decoupled Architecture (Service Manager Pattern)
The `HipsAgent` has been refactored to eliminate the "God Object" anti-pattern. Orchestration is now handled by a centralized `ServiceManager` that manages the lifecycle (start/stop) of all modules independently.
- **Improved Stability**: Modules are started in sequence and stopped in reverse order for clean teardown.
- **Extensibility**: New monitoring modules can be added by implementing the `ManagedService` interface without modifying the core agent logic.

### 2. Security Hardening
- **Authentication Enforcement**: Default admin accounts now carry a `must_change_password` flag. Upon first login, users are redirected to the settings page to update their credentials.
- **Log Isolation**: Broad `.log` file exclusions in `FileMonitor` have been replaced with a precise whitelist of agent-specific logs. This prevents attackers from evading detection by simply renaming malicious files with a `.log` extension.
- **Input Sanitization**:
    - `IpManager` validates IP formats using regex before passing them to system commands (`netsh`), preventing command injection.
    - `FileRuleEngine` sanitizes filenames before embedding them in PowerShell queries for process attribution.
- **Credential Security**: Database credentials in `server/config/db_connect.php` are now externalized via environment variables.

### 3. Enterprise Portability
- **Auto-Detection**: All deployment `.bat` scripts now auto-detect XAMPP installation paths across multiple common drive letters (C:, D:, E:), falling back to user prompts only if necessary.
- **Intelligent Discovery**: The `discovery-service.bat` now uses PowerShell to filter out virtual network adapters (VirtualBox, VMware, WSL, VPN), ensuring the agent registers with the correct physical network IP.
- **Config Overrides**: The agent now supports custom configuration paths via the `-Dhips.config` system property, enabling multi-tenant or multi-instance deployments.

### 4. Performance & Reliability
- **Structured Parsing**: `NetworkMonitor` now uses PowerShell's `Get-NetTCPConnection` to retrieve structured CSV data, eliminating the fragility of parsing raw `netstat` text.
- **Robust JSON Handling**: `RegistryMonitor` now utilizes Google Gson for registry value parsing, ensuring data integrity across complex registry keys.
- **Atomic Operations**: The server-side `report.php` uses database transactions to ensure events and alerts are recorded atomically.

---
**HIPS Security Project — 2026**
