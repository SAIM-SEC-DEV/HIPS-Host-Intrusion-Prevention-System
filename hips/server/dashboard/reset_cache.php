<?php
// Reset OPcache completely
if (function_exists('opcache_reset')) {
    opcache_reset();
    echo "OPcache RESET done. ";
}
// Also invalidate the specific file
$file = __DIR__ . '/dashboard.php';
if (function_exists('opcache_invalidate')) {
    opcache_invalidate($file, true);
    echo "Invalidated: $file. ";
}
echo "Now go to <a href='dashboard.php'>dashboard.php</a>";
?>
