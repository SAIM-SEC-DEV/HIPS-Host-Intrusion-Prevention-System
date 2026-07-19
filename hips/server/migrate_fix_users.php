<?php
require_once 'config/db_connect.php';

try {
    // Check if column exists
    $stmt = $pdo->query("SHOW COLUMNS FROM dashboard_users LIKE 'must_change_password'");
    if (!$stmt->fetch()) {
        $pdo->exec("ALTER TABLE dashboard_users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1 = force password change on next login' AFTER api_token");
        echo "Column 'must_change_password' added successfully.\n";
    } else {
        echo "Column 'must_change_password' already exists.\n";
    }
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
