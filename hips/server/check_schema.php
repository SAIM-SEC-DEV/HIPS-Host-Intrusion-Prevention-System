<?php
require_once 'config/db_connect.php';
$tables = ['agents', 'events', 'alerts', 'ip_whitelist', 'settings'];
$schema = [];
foreach ($tables as $t) {
    try {
        $stmt = $pdo->query("DESCRIBE $t");
        $schema[$t] = $stmt->fetchAll(PDO::FETCH_COLUMN);
    } catch (Exception $e) {
        $schema[$t] = "ERROR: " . $e->getMessage();
    }
}
echo json_encode($schema, JSON_PRETTY_PRINT);
?>
