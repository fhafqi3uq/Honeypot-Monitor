<?php
// Hourly session/temp-file cleanup - run from crontab as www-data
$sessionDir = session_save_path() ?: '/tmp';
$now = time();
foreach (glob($sessionDir . '/sess_*') as $file) {
    if (is_file($file) && $now - filemtime($file) >= 3600) {
        unlink($file);
    }
}
foreach (glob('/var/www/html/uploads/tmp/*') as $file) {
    unlink($file);
}
echo "Cleanup completed: " . date('Y-m-d H:i:s') . "\n";
