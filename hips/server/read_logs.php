<?php
$logPath = ini_get('error_log');
if (!$logPath) {
    echo "Error: No log path configured in php.ini";
    exit;
}
if (!file_exists($logPath)) {
    echo "Error: Log file not found at $logPath";
    exit;
}
$lines = array_slice(file($logPath), -100);
echo implode('', $lines);
?>
