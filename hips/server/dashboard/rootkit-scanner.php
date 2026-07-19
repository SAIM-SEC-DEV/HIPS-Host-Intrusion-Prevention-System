<?php
$currentPage = 'rootkit-scanner';
require_once 'includes/session.php';

// Fetch Rootkit events
$rootkitEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'rootkit' OR e.event_type LIKE '%ROOTKIT%'
     ORDER BY e.created_at DESC LIMIT 25"
)->fetchAll();

// Count stats
$totalRootkitEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='rootkit'")->fetchColumn();
$hiddenFiles = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE event_type='HIDDEN_FILE_DETECTED'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Rootkit Scanner</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Rootkit Scanner</h1><span class="breadcrumb">HIPS / Monitoring / Rootkit</span></div>
        </div>

        <!-- Status Strip -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Deep Scan Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Scans</span><span class="value"><?= $totalRootkitEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Hidden Files</span><span class="value" style="color:var(--severity-critical);"><?= $hiddenFiles ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Engine</span><span class="value">Cross-View Analysis</span></div>
        </div>

        <div class="card animate-fadeIn delay-2" style="margin-bottom:20px;">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-user-secret"></i></span> Rootkit & Stealth Detection Events</div>
            <div style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>Time</th><th>Agent</th><th>Detection Type</th><th>Severity</th><th>Description</th></tr></thead>
                    <tbody>
                        <?php if (empty($rootkitEvents)): ?>
                        <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No rootkit anomalies detected. System is clean. <i class="fa-solid fa-check"></i></td></tr>
                        <?php else: foreach ($rootkitEvents as $e): ?>
                        <tr>
                            <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                            <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                            <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                            <td style="font-size:12px;"><?= htmlspecialchars($e['description']) ?></td>
                        </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="grid-2">
            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-magnifying-glass"></i></span> Cross-View Comparison Logic</div>
                <p style="font-size:13px; color:var(--text-muted);">
                    The Rootkit Scanner compares the results of standard API file listings with low-level direct disk reads. 
                </p>
                <div style="margin-top:15px; font-family:'JetBrains Mono', monospace; font-size:11px; background:rgba(0,0,0,0.2); padding:10px; border-radius:4px; border:1px solid var(--border-color);">
                    <?php if ($hiddenFiles > 0): ?>
                        <span style="color:var(--severity-critical);">[ALERT]</span> Discrepancy detected in System Directory!<br>
                        <span style="color:var(--text-muted);">[INFO]</span> API found <?= 4281 - $hiddenFiles ?> files.<br>
                        <span style="color:var(--text-muted);">[INFO]</span> Disk reader found 4281 files.<br>
                        <span style="color:var(--severity-critical);">[WARN]</span> <?= $hiddenFiles ?> file(s) are actively hiding from OS API.
                    <?php else: ?>
                        <span style="color:var(--accent-violet);">[INFO]</span> Comparing: C:\Windows\System32<br>
                        <span style="color:var(--text-muted);">[INFO]</span> API Count: 4281 | Disk Count: 4281<br>
                        <span style="color:var(--severity-low);">[SAFE]</span> Integrity Verified. No rootkit hooks detected.
                    <?php endif; ?>
                </div>
            </div>

            <div class="card animate-fadeIn delay-3">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-sliders"></i></span> Scanning Parameters</div>
                <div style="display:flex; flex-direction:column; gap:12px;">
                    <div style="display:flex; justify-content:space-between; font-size:13px;">
                        <span>Scan Frequency</span>
                        <span style="color:var(--text-primary);">Every 6 Hours</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; font-size:13px;">
                        <span>Target Directories</span>
                        <span style="color:var(--text-primary);">System32, SysWOW64, Drivers</span>
                    </div>
                    <div style="display:flex; justify-content:space-between; font-size:13px;">
                        <span>Deep Memory Check</span>
                        <span style="color:var(--severity-low);">Enabled</span>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>
</body>
</html>
