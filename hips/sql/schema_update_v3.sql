-- ============================================================
-- HIPS — Schema Update v3: IP Whitelist Table
-- ============================================================
-- Run this migration to add the ip_whitelist table to an
-- existing hips_db installation.
--
-- For new installations, add this table to the main schema.sql.
-- ============================================================

USE `hips_db`;

CREATE TABLE IF NOT EXISTS `ip_whitelist` (
    `id`              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    `ip_address`      VARCHAR(45)         NOT NULL COMMENT 'IPv4 or IPv6 address to whitelist',
    `label`           VARCHAR(100)        DEFAULT NULL COMMENT 'Friendly label (e.g., "Office VPN Gateway")',
    `added_by`        VARCHAR(100)        DEFAULT NULL COMMENT 'Admin who added this entry',
    `created_at`      DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_whitelist_ip` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Whitelisted IPs excluded from network threat analysis';
