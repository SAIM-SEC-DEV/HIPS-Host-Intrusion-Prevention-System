<?php
$currentPage = 'hardware-assets';
require_once 'includes/session.php';

// Fetch asset events
$assetEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'asset'
     ORDER BY e.created_at DESC LIMIT 20"
)->fetchAll();

// Count stats
$totalAssetEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='asset'")->fetchColumn();
$recentAudits = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='asset' AND DATE(created_at) = CURDATE()")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Hardware Assets</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Hardware Assets</h1><span class="breadcrumb">HIPS / Management / Assets</span></div>
        </div>

        <!-- Status Strip -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Asset Audit Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Audits</span><span class="value"><?= $totalAssetEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Audits Today</span><span class="value" style="color:var(--severity-low);"><?= $recentAudits ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Component</span><span class="value">WMI & PowerShell</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Audited Components -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-microchip"></i></span> Monitored Hardware Components</div>
                <table class="data-table">
                    <thead><tr><th>Component</th><th>Status</th><th>Last Scan</th></tr></thead>
                    <tbody>
                        <tr><td>CPU Core & Threads</td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Verified</td><td style="font-size:12px;color:var(--text-muted);">Hourly</td></tr>
                        <tr><td>Physical Memory (RAM)</td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Verified</td><td style="font-size:12px;color:var(--text-muted);">Hourly</td></tr>
                        <tr><td>Disk Drives (Health)</td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Verified</td><td style="font-size:12px;color:var(--text-muted);">Hourly</td></tr>
                        <tr><td>USB Plug-and-Play Devices</td><td style="color:var(--severity-low);"><i class="fa-solid fa-check"></i> Verified</td><td style="font-size:12px;color:var(--text-muted);">Hourly</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Asset Rules -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-clipboard-check"></i></span> Hardware Audit Configurations</div>
                <div style="max-height:260px;overflow-y:auto;">
                    <?php
                    $rules = [
                        ['USB Device Tracking', true], 
                        ['CPU/RAM Change Alerts', true],
                        ['Disk Health Monitoring', true], 
                        ['PnP Peripheral Audit', true],
                    ];
                    foreach ($rules as $r):
                    ?>
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-color);font-size:13px;">
                        <span style="color:var(--text-primary);"><?= $r[0] ?></span>
                        <span class="badge low" style="font-size:9px;"><i class="fa-solid fa-check"></i> ENABLED</span>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>

        </div>

        <!-- Recent Asset Events -->
        <div class="card animate-fadeIn delay-3">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-file-invoice"></i></span> Recent Hardware Audits</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>Extracted Hardware Info (JSON)</th></tr></thead>
                <tbody>
                    <?php if (empty($assetEvents)): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No hardware audits recorded yet.</td></tr>
                    <?php else: foreach ($assetEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= htmlspecialchars($e['metadata_json'] ?? 'N/A') ?></td>
                    </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            </div>
        </div>
    </main>
</div>
</body>
</html>
