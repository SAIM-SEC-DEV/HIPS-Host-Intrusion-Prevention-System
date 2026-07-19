<?php
$currentPage = 'usb-monitor';
require_once 'includes/session.php';

// Fetch USB events
$usbEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'usb'
     ORDER BY e.created_at DESC LIMIT 25"
)->fetchAll();

// Count stats
$totalUsbEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='usb'")->fetchColumn();
$recentUsb = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='usb' AND DATE(created_at) = CURDATE()")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — USB Monitor</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>USB Monitor</h1><span class="breadcrumb">HIPS / Monitoring / USB</span></div>
        </div>

        <!-- Status Strip -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">USB Guard Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Detections</span><span class="value"><?= $totalUsbEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">New Today</span><span class="value" style="color:var(--severity-high);"><?= $recentUsb ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Scan Mode</span><span class="value">Auto-YARA</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-usb"></i></span> Recent USB Connections</div>
                <table class="data-table">
                    <thead><tr><th>Time</th><th>Agent</th><th>Device</th><th>Status</th></tr></thead>
                    <tbody>
                        <?php if (empty($usbEvents)): ?>
                        <tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:30px;">No USB events recorded.</td></tr>
                        <?php else: foreach ($usbEvents as $e): ?>
                        <tr>
                            <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                            <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['title']) ?></td>
                            <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-shield-halved"></i></span> USB Protection Rules</div>
                <div style="max-height:260px;overflow-y:auto;">
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);">
                        <span>Auto-scan new drives</span>
                        <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                    </div>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);">
                        <span>Block unauthorized vendors</span>
                        <label class="toggle-switch"><input type="checkbox"><span class="toggle-slider"></span></label>
                    </div>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);">
                        <span>Log serial numbers</span>
                        <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                    </div>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);">
                        <span>Alert on mass storage</span>
                        <label class="toggle-switch"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>
</body>
</html>
