<?php
require_once 'config/db_connect.php';
$stmt = $pdo->query("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10");
echo json_encode($stmt->fetchAll(), JSON_PRETTY_PRINT);
?>
