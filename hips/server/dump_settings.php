<?php
require_once 'config/db_connect.php';
$rows = $pdo->query("SELECT setting_key, setting_value, category FROM settings")->fetchAll();
foreach ($rows as $row) {
    echo "Key: " . $row['setting_key'] . " | Value: " . $row['setting_value'] . " | Category: " . $row['category'] . "\n";
}
?>
