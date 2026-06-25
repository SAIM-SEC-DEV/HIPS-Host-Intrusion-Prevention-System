-- ============================================================
-- HIPS — Host Intrusion Prevention System
-- Database Schema: hips_db
-- Version: 2.0 (Unified — includes process, registry, MITRE)
-- Engine: MySQL 8.0+
-- ============================================================

-- Create the database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS `hips_db`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE `hips_db`;

-- ============================================================
-- TABLE: agents
-- Purpose: Stores all registered monitoring agents.
--          Each agent represents a single monitored host machine.
-- ============================================================
CREATE TABLE IF NOT EXISTS `agents` (
    `id`              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    `agent_uuid`      CHAR(36)            NOT NULL COMMENT 'Unique agent identifier (UUID v4)',
    `hostname`        VARCHAR(255)        NOT NULL COMMENT 'Machine hostname',
    `ip_address`      VARCHAR(45)         NOT NULL COMMENT 'IPv4 or IPv6 address of the agent',
    `os_name`         VARCHAR(100)        DEFAULT NULL COMMENT 'Operating system name (e.g., Windows 11)',
    `os_version`      VARCHAR(100)        DEFAULT NULL COMMENT 'OS version string',
    `os_arch`         VARCHAR(20)         DEFAULT NULL COMMENT 'Architecture (e.g., amd64)',
    `cpu_info`        VARCHAR(255)        DEFAULT NULL COMMENT 'CPU model description',
    `ram_total_mb`    INT UNSIGNED        DEFAULT NULL COMMENT 'Total RAM in megabytes',
    `agent_version`   VARCHAR(20)         DEFAULT '1.0.0' COMMENT 'Version of the HIPS agent software',
    `owner`           VARCHAR(100)        DEFAULT NULL COMMENT 'Machine owner / responsible admin',
    `auth_token`      VARCHAR(128)        NOT NULL COMMENT 'Token for authenticating API requests',
    `status`          ENUM('online','offline','unknown')
                                          NOT NULL DEFAULT 'unknown'
                                          COMMENT 'Current agent status',
    `last_heartbeat`  DATETIME            DEFAULT NULL COMMENT 'Timestamp of the last heartbeat ping',
    `baseline_start`  DATETIME            DEFAULT NULL COMMENT 'When the 7-day baseline learning phase began',
    `baseline_complete` TINYINT(1)        NOT NULL DEFAULT 0 COMMENT '1 = baseline phase finished',
    `registered_at`   DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Agent registration timestamp',
    `updated_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_agent_uuid` (`agent_uuid`),
    INDEX `idx_status` (`status`),
    INDEX `idx_last_heartbeat` (`last_heartbeat`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Registered HIPS monitoring agents';


-- ============================================================
-- TABLE: events
-- Purpose: Central audit log for ALL file, network, process,
--          and registry events reported by every agent.
-- ============================================================
CREATE TABLE IF NOT EXISTS `events` (
    `id`              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `agent_id`        INT UNSIGNED        NOT NULL COMMENT 'FK → agents.id',
    `module`          ENUM('file','network','process','registry')
                                          NOT NULL COMMENT 'Which monitoring module generated this',
    `event_type`      VARCHAR(100)        NOT NULL COMMENT 'e.g., FILE_CREATED, PORT_SCAN, DNS_TUNNEL',
    `severity`        ENUM('CRITICAL','HIGH','MEDIUM','LOW')
                                          NOT NULL DEFAULT 'LOW',
    `title`           VARCHAR(255)        NOT NULL COMMENT 'Short human-readable event title',
    `description`     TEXT                DEFAULT NULL COMMENT 'Detailed description / context',
    `source_path`     VARCHAR(500)        DEFAULT NULL COMMENT 'File path or source IP:port',
    `destination`     VARCHAR(500)        DEFAULT NULL COMMENT 'Destination IP:port (network events)',
    `hash_value`      VARCHAR(128)        DEFAULT NULL COMMENT 'File hash (SHA-256 / MD5) if applicable',
    `metadata_json`   JSON                DEFAULT NULL COMMENT 'Extra structured data for the event',
    `is_anomaly`      TINYINT(1)          NOT NULL DEFAULT 0 COMMENT '1 = flagged by anomaly detection',
    `mitre_technique_id` VARCHAR(20)      DEFAULT NULL COMMENT 'MITRE ATT&CK technique ID (e.g., T1547.001)',
    `mitre_tactic`    VARCHAR(50)         DEFAULT NULL COMMENT 'MITRE ATT&CK tactic (e.g., Persistence)',
    `created_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    INDEX `idx_agent_id` (`agent_id`),
    INDEX `idx_module` (`module`),
    INDEX `idx_severity` (`severity`),
    INDEX `idx_event_type` (`event_type`),
    INDEX `idx_created_at` (`created_at`),
    INDEX `idx_mitre` (`mitre_technique_id`),
    CONSTRAINT `fk_events_agent`
        FOREIGN KEY (`agent_id`) REFERENCES `agents` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Master event log for all monitoring events';


-- ============================================================
-- TABLE: alerts
-- Purpose: Stores only the events that crossed severity
--          thresholds and require admin attention.
-- ============================================================
CREATE TABLE IF NOT EXISTS `alerts` (
    `id`              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `event_id`        BIGINT UNSIGNED     NOT NULL COMMENT 'FK → events.id (the triggering event)',
    `agent_id`        INT UNSIGNED        NOT NULL COMMENT 'FK → agents.id',
    `severity`        ENUM('CRITICAL','HIGH','MEDIUM','LOW')
                                          NOT NULL,
    `module`          ENUM('file','network','process','registry')
                                          NOT NULL,
    `title`           VARCHAR(255)        NOT NULL,
    `description`     TEXT                DEFAULT NULL,
    `mitre_technique_id` VARCHAR(20)      DEFAULT NULL COMMENT 'MITRE ATT&CK technique ID',
    `mitre_tactic`    VARCHAR(50)         DEFAULT NULL COMMENT 'MITRE ATT&CK tactic',
    `status`          ENUM('new','read','dismissed','resolved')
                                          NOT NULL DEFAULT 'new'
                                          COMMENT 'Alert lifecycle status',
    `acknowledged_by` VARCHAR(100)        DEFAULT NULL COMMENT 'Admin who acknowledged the alert',
    `acknowledged_at` DATETIME            DEFAULT NULL,
    `created_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    INDEX `idx_alert_agent` (`agent_id`),
    INDEX `idx_alert_severity` (`severity`),
    INDEX `idx_alert_status` (`status`),
    INDEX `idx_alert_created` (`created_at`),
    CONSTRAINT `fk_alerts_event`
        FOREIGN KEY (`event_id`) REFERENCES `events` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT `fk_alerts_agent`
        FOREIGN KEY (`agent_id`) REFERENCES `agents` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Actionable alerts requiring admin attention';


-- ============================================================
-- TABLE: commands
-- Purpose: Server-to-agent command queue.
-- ============================================================
CREATE TABLE IF NOT EXISTS `commands` (
    `id`              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `agent_id`        INT UNSIGNED        NOT NULL COMMENT 'FK → agents.id (target agent)',
    `command_type`    VARCHAR(50)         NOT NULL
                                          COMMENT 'e.g., BLOCK_IP, SCAN_FILE, RESTART, UPDATE_RULES, FULL_SCAN, UNBLOCK_IP, WHITELIST_ADD, WHITELIST_REMOVE, SHUTDOWN',
    `parameters_json` JSON               DEFAULT NULL COMMENT 'JSON payload with command-specific params',
    `priority`        ENUM('normal','high','critical')
                                          NOT NULL DEFAULT 'normal',
    `admin_note`      TEXT                DEFAULT NULL COMMENT 'Reason / context for dispatching this command',
    `status`          ENUM('pending','sent','executing','completed','failed','cancelled')
                                          NOT NULL DEFAULT 'pending',
    `result_json`     JSON                DEFAULT NULL COMMENT 'Execution result returned by the agent',
    `issued_by`       VARCHAR(100)        DEFAULT NULL COMMENT 'Admin username who issued the command',
    `issued_at`       DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `executed_at`     DATETIME            DEFAULT NULL COMMENT 'When the agent began executing',
    `completed_at`    DATETIME            DEFAULT NULL COMMENT 'When execution finished',

    PRIMARY KEY (`id`),
    INDEX `idx_cmd_agent` (`agent_id`),
    INDEX `idx_cmd_status` (`status`),
    INDEX `idx_cmd_priority` (`priority`),
    INDEX `idx_cmd_issued` (`issued_at`),
    CONSTRAINT `fk_commands_agent`
        FOREIGN KEY (`agent_id`) REFERENCES `agents` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Command queue for server-to-agent instructions';


-- ============================================================
-- TABLE: dashboard_users
-- Purpose: Admin accounts that can log into the web dashboard.
-- ============================================================
CREATE TABLE IF NOT EXISTS `dashboard_users` (
    `id`              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    `username`        VARCHAR(50)         NOT NULL,
    `password_hash`   VARCHAR(255)        NOT NULL COMMENT 'bcrypt hash of the admin password',
    `display_name`    VARCHAR(100)        DEFAULT NULL,
    `role`            ENUM('admin','viewer')
                                          NOT NULL DEFAULT 'admin',
    `api_token`       VARCHAR(128)        NOT NULL COMMENT 'API token for this admin session',
    `must_change_password` TINYINT(1)     NOT NULL DEFAULT 1 COMMENT '1 = force password change on next login',
    `last_login`      DATETIME            DEFAULT NULL,
    `created_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_username` (`username`),
    UNIQUE KEY `uq_api_token` (`api_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Dashboard administrator accounts';


-- ============================================================
-- TABLE: settings
-- Purpose: Key-value configuration store for system settings.
-- ============================================================
CREATE TABLE IF NOT EXISTS `settings` (
    `id`              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    `setting_key`     VARCHAR(100)        NOT NULL,
    `setting_value`   TEXT                DEFAULT NULL,
    `category`        VARCHAR(50)         NOT NULL DEFAULT 'general'
                                          COMMENT 'Tab grouping: general, security, notifications, database, api, backup',
    `description`     VARCHAR(255)        DEFAULT NULL,
    `updated_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='System configuration key-value pairs';


-- ============================================================
-- SEED DATA: Default admin account and initial settings
-- ============================================================

-- Default admin: username = admin
--Password must be changed during initial setup.
-- The hash below is a bcrypt hash of '<set during installation>'
INSERT INTO `dashboard_users` (`username`, `password_hash`, `display_name`, `role`, `api_token`, `must_change_password`)
VALUES (
    'admin',
    '$2y$12$LJ3m4yPZqPGN6Y5K1bFzZOQhOx6k8XKlZ9YxVJTxRq5nVJD3K5Xmu',
    'System Administrator',
    'admin',
    -- Generate a secure random token for the default admin
    SHA2(CONCAT('hips-default-', UUID(), UNIX_TIMESTAMP()), 256),
    1
) ON DUPLICATE KEY UPDATE `id` = `id`;

-- Default system settings
INSERT INTO `settings` (`setting_key`, `setting_value`, `category`, `description`) VALUES
    ('server_name',         'HIPS Central Server',  'general',       'Display name for this HIPS server'),
    ('poll_interval_sec',   '10',                   'general',       'How often agents poll for commands (seconds)'),
    ('heartbeat_timeout_sec','90',                  'general',       'Mark agent offline after N seconds without heartbeat'),
    ('log_retention_days',  '90',                   'general',       'Auto-delete events older than N days'),
    ('baseline_duration_days','7',                  'general',       'Duration of the anomaly detection learning phase'),
    ('file_monitor_enabled','1',                    'security',      'Enable/disable file monitoring module'),
    ('network_monitor_enabled','1',                 'security',      'Enable/disable network monitoring module'),
    ('process_monitor_enabled','1',                 'security',      'Enable/disable process monitoring module'),
    ('registry_monitor_enabled','1',                'security',      'Enable/disable registry integrity monitoring'),
    ('hash_algorithm',      'SHA-256',              'security',      'Hashing algorithm for file integrity checks'),
    ('sensitive_extensions', '.exe,.dll,.bat,.sh,.ps1,.vbs,.cmd,.msi,.sys,.drv', 'security', 'Comma-separated list of high-risk file extensions'),
    ('sensitive_ports',     '22,23,3306,3389,445,135,139,1433,5432', 'security', 'Comma-separated list of high-risk network ports'),
    ('off_hours_start',     '22:00',                'security',      'Start of off-hours window (HH:MM)'),
    ('off_hours_end',       '06:00',                'security',      'End of off-hours window (HH:MM)'),
    ('threat_intel_enabled','1',                    'security',      'Enable/disable external threat intelligence lookups'),
    ('mitre_mapping_enabled','1',                   'security',      'Enable MITRE ATT&CK technique mapping on events'),
    ('email_notifications', '0',                    'notifications', 'Enable email alerts for critical events'),
    ('smtp_host',           '',                     'notifications', 'SMTP server hostname'),
    ('smtp_port',           '587',                  'notifications', 'SMTP server port'),
    ('alert_email',         '',                     'notifications', 'Email address to receive critical alerts'),
    ('virustotal_api_key',  '',                     'api',           'VirusTotal API key for hash reputation checks (free tier)'),
    ('abuseipdb_api_key',   '',                     'api',           'AbuseIPDB API key for IP reputation checks (free tier)')
ON DUPLICATE KEY UPDATE `id` = `id`;
