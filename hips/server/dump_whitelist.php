<?php
require_once 'config/db_connect.php';
$stmt = $pdo->query("SELECT * FROM ip_whitelist");
echo json_encode($stmt->fetchAll(), JSON_PRETTY_PRINT);
?>
