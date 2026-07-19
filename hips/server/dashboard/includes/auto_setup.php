<?php
/**
 * HIPS — Safe Auto-Setup
 * This script initializes the IP Whitelist schema if it's missing.
 * It is only included in dashboard pages for maximum safety.
 */
try {
    // 1. Ensure ip_whitelist table exists
    $pdo->exec("CREATE TABLE IF NOT EXISTS ip_whitelist (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL UNIQUE,
        label VARCHAR(100) DEFAULT NULL,
        added_by VARCHAR(100) DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

    // 2. Ensure ip_whitelist_enabled setting exists
    $check = $pdo->prepare("SELECT COUNT(*) FROM settings WHERE setting_key = 'ip_whitelist_enabled'");
    $check->execute();
    if ($check->fetchColumn() == 0) {
        $pdo->prepare("INSERT INTO settings (setting_key, setting_value, category, description) 
                       VALUES ('ip_whitelist_enabled', '0', 'security', 'Enable IP address whitelisting for dashboard access')")
            ->execute();
    }

    // 3. Ensure localhost failsafe
    $pdo->prepare("INSERT IGNORE INTO ip_whitelist (ip_address, label, added_by) VALUES ('127.0.0.1', 'Localhost (Failsafe)', 'system')")->execute();
    $pdo->prepare("INSERT IGNORE INTO ip_whitelist (ip_address, label, added_by) VALUES ('::1', 'Localhost (Failsafe)', 'system')")->execute();

} catch (PDOException $e) {
    error_log("[HIPS Safe Setup] Failed: " . $e->getMessage());
}
?>
