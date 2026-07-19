<?php
require_once 'config/db_connect.php';

try {
    // 1. Add the toggle setting if it doesn't exist
    $check = $pdo->prepare("SELECT COUNT(*) FROM settings WHERE setting_key = 'ip_whitelist_enabled'");
    $check->execute();
    if ($check->fetchColumn() == 0) {
        $pdo->prepare("INSERT INTO settings (setting_key, setting_value, category, description) 
                       VALUES ('ip_whitelist_enabled', '0', 'security', 'Enable IP address whitelisting for dashboard access (0=disabled, 1=enabled)')")
            ->execute();
        echo "Added ip_whitelist_enabled setting.\n";
    }

    // 2. Ensure localhost is in the whitelist to prevent lockout
    $localhosts = ['127.0.0.1', '::1'];
    foreach ($localhosts as $ip) {
        $checkIp = $pdo->prepare("SELECT COUNT(*) FROM ip_whitelist WHERE ip_address = :ip");
        $checkIp->execute([':ip' => $ip]);
        if ($checkIp->fetchColumn() == 0) {
            $pdo->prepare("INSERT INTO ip_whitelist (ip_address, label, added_by) 
                           VALUES (:ip, 'Localhost (Failsafe)', 'system')")
                ->execute();
            echo "Whitelisted localhost: $ip\n";
        }
    }
    
    echo "Migration completed successfully.\n";
} catch (PDOException $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
}
?>
