<?php
require_once 'config/db_connect.php';
$stmt = $pdo->query("DESCRIBE alerts");
$cols = $stmt->fetchAll(PDO::FETCH_COLUMN);
echo implode(', ', $cols);
?>
