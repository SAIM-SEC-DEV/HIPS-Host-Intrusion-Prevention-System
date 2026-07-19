<?php
$currentPage = 'network-monitor';
require_once 'includes/session.php';

// ── Handle IP Whitelist Actions ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection Check
    if (!CsrfHandler::validate($_POST['csrf_token'] ?? null)) {
        die("Security violation: CSRF token invalid or missing.");
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'whitelist_add') {
        $ip    = trim($_POST['ip'] ?? '');
        $label = trim($_POST['label'] ?? '');
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            try {
                $stmt = $pdo->prepare("INSERT INTO ip_whitelist (ip_address, label, added_by) VALUES (:ip, :label, :user)");
                $stmt->execute([':ip' => $ip, ':label' => $label, ':user' => $adminUsername]);
                
                // BROADCAST: Send WHITELIST_ADD command to all online agents
                $agents = $pdo->query("SELECT id FROM agents WHERE status = 'online'")->fetchAll();
                $cmdStmt = $pdo->prepare("INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by) VALUES (:aid, 'WHITELIST_ADD', :params, 'high', 'Global Whitelist Sync', :user)");
                $params = json_encode(['ip' => $ip]);
                foreach ($agents as $ag) {
                    $cmdStmt->execute([':aid' => $ag['id'], ':params' => $params, ':user' => $adminUsername]);
                }
                AuditLogger::log("IP Whitelist Add", "IP", $ip, ['label' => $label]);
            } catch (PDOException $e) {
                // Duplicate IP — silently ignore
            }
        }
        header('Location: network-monitor.php'); exit;
    }

    if ($action === 'whitelist_delete') {
        $wlId = (int)($_POST['whitelist_id'] ?? 0);
        if ($wlId > 0) {
            // Get IP before deleting to send command
            $stmt = $pdo->prepare("SELECT ip_address FROM ip_whitelist WHERE id = :id");
            $stmt->execute([':id' => $wlId]);
            $ip = $stmt->fetchColumn();
            
            if ($ip) {
                $pdo->prepare("DELETE FROM ip_whitelist WHERE id = :id")->execute([':id' => $wlId]);
                
                // BROADCAST: Send WHITELIST_REMOVE command to all online agents
                $agents = $pdo->query("SELECT id FROM agents WHERE status = 'online'")->fetchAll();
                $cmdStmt = $pdo->prepare("INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by) VALUES (:aid, 'WHITELIST_REMOVE', :params, 'normal', 'Global Whitelist Removal', :user)");
                $params = json_encode(['ip' => $ip]);
                foreach ($agents as $ag) {
                    $cmdStmt->execute([':aid' => $ag['id'], ':params' => $params, ':user' => $adminUsername]);
                }
                AuditLogger::log("IP Whitelist Delete", "ID", (string)$wlId);
            }
        }
        header('Location: network-monitor.php'); exit;
    }

    if ($action === 'blacklist_add') {
        $ip     = trim($_POST['ip'] ?? '');
        $reason = trim($_POST['reason'] ?? 'Manual block');
        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            try {
                $stmt = $pdo->prepare(
                    "INSERT INTO ip_blacklist (ip_address, reason, added_by) VALUES (:ip, :reason, :user)"
                );
                $stmt->execute([':ip' => $ip, ':reason' => $reason, ':user' => $adminUsername]);
                
                // BROADCAST: Send BLOCK_IP command to all online agents
                $agents = $pdo->query("SELECT id FROM agents WHERE status = 'online'")->fetchAll();
                $cmdStmt = $pdo->prepare("INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by) VALUES (:aid, 'BLOCK_IP', :params, 'high', 'Global Blacklist Sync', :user)");
                $params = json_encode(['ip' => $ip]);
                foreach ($agents as $ag) {
                    $cmdStmt->execute([':aid' => $ag['id'], ':params' => $params, ':user' => $adminUsername]);
                }
                AuditLogger::log("IP Blacklist Add", "IP", $ip, ['reason' => $reason]);
            } catch (PDOException $e) {}
        }
        header('Location: network-monitor.php'); exit;
    }

    if ($action === 'blacklist_delete') {
        $blId = (int)($_POST['blacklist_id'] ?? 0);
        if ($blId > 0) {
            // Get IP before deleting to send UNBLOCK command
            $stmt = $pdo->prepare("SELECT ip_address FROM ip_blacklist WHERE id = :id");
            $stmt->execute([':id' => $blId]);
            $ip = $stmt->fetchColumn();
            
            if ($ip) {
                $pdo->prepare("DELETE FROM ip_blacklist WHERE id = :id")->execute([':id' => $blId]);
                
                // BROADCAST: Send UNBLOCK_IP to all online agents
                $agents = $pdo->query("SELECT id FROM agents WHERE status = 'online'")->fetchAll();
                $cmdStmt = $pdo->prepare("INSERT INTO commands (agent_id, command_type, parameters_json, priority, admin_note, issued_by) VALUES (:aid, 'UNBLOCK_IP', :params, 'normal', 'Global Blacklist Removal', :user)");
                $params = json_encode(['ip' => $ip]);
                foreach ($agents as $ag) {
                    $cmdStmt->execute([':aid' => $ag['id'], ':params' => $params, ':user' => $adminUsername]);
                }
                AuditLogger::log("IP Blacklist Delete", "IP", $ip);
            }
        }
        header('Location: network-monitor.php'); exit;
    }
}

// ── Fetch Data ───────────────────────────────────────────────
$networkEvents = $pdo->query(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE e.module = 'network'
     ORDER BY e.created_at DESC LIMIT 20"
)->fetchAll();

$totalNetEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='network'")->fetchColumn();
$todayNetEvents = (int) $pdo->query("SELECT COUNT(*) FROM events WHERE module='network' AND DATE(created_at) = CURDATE()")->fetchColumn();

// Fetch whitelisted IPs
$whitelistIPs = [];
try {
    $whitelistIPs = $pdo->query("SELECT * FROM ip_whitelist ORDER BY created_at DESC")->fetchAll();
} catch (PDOException $e) {
    // Table may not exist yet
}
$whitelistCount = count($whitelistIPs);

// Fetch blacklisted IPs
$blacklistIPs = [];
try {
    $blacklistIPs = $pdo->query("SELECT * FROM ip_blacklist ORDER BY created_at DESC")->fetchAll();
} catch (PDOException $e) {}
$blacklistCount = count($blacklistIPs);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Network Monitor</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        .whitelist-card { margin-top: 0; }
        .whitelist-form {
            display: flex; gap: 8px; margin-top: 12px;
            align-items: flex-end;
        }
        .whitelist-form .form-group { margin-bottom: 0; flex: 1; }
        .whitelist-form .form-group:first-child { flex: 1.2; }
        .whitelist-item {
            display: flex; align-items: center; justify-content: space-between;
            padding: 10px 14px; border-bottom: 1px solid var(--border-color);
            transition: all 0.2s ease;
        }
        .whitelist-item:last-child { border-bottom: none; }
        .whitelist-item:hover { background: var(--bg-table-hover); }
        .whitelist-ip {
            font-family: 'JetBrains Mono', monospace; font-size: 13px;
            color: var(--accent-violet); font-weight: 600;
        }
        .whitelist-label {
            font-size: 11px; color: var(--text-muted); margin-left: 12px;
        }
        .whitelist-meta {
            font-size: 10px; color: var(--text-muted);
            display: flex; align-items: center; gap: 8px;
        }
    </style>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Network Monitor</h1><span class="breadcrumb">HIPS / Monitoring / Network</span></div>
        </div>

        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="status-dot online"></span><span class="value">Monitor Active</span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Total Events</span><span class="value"><?= $totalNetEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Today</span><span class="value"><?= $todayNetEvents ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Whitelisted IPs</span><span class="value"><?= $whitelistCount ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Interface</span><span class="value">Ethernet (Primary)</span></div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- Active Connections -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-link"></i></span> Active Connections (Sample)</div>
                <div style="overflow-x:auto;">
                <table class="data-table">
                    <thead><tr><th>Local</th><th>Remote</th><th>Protocol</th><th>Status</th><th>Threat</th></tr></thead>
                    <tbody>
                        <tr><td style="font-size:12px;">0.0.0.0:80</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-low);">LISTENING</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td style="font-size:12px;">0.0.0.0:443</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-low);">LISTENING</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td style="font-size:12px;">0.0.0.0:3306</td><td style="font-size:12px;">0.0.0.0:0</td><td>TCP</td><td style="color:var(--severity-medium);">LISTENING</td><td><span class="badge high">High</span></td></tr>
                    </tbody>
                </table>
                </div>
            </div>

            <!-- Open Ports -->
            <div class="card animate-fadeIn delay-2">
                <div class="card-title"><span class="icon"><i class="fa-solid fa-door-open"></i></span> Open Ports</div>
                <table class="data-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead>
                    <tbody>
                        <tr><td>80</td><td>HTTP (Apache)</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td>443</td><td>HTTPS</td><td><span class="badge low">Low</span></td></tr>
                        <tr><td>3306</td><td>MySQL</td><td><span class="badge high">High</span></td></tr>
                        <tr><td>3389</td><td>RDP</td><td><span class="badge critical">Critical</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="grid-2" style="margin-bottom:20px;">
            <!-- IP Whitelist Management -->
            <div class="card animate-fadeIn delay-3 whitelist-card">
                <div class="card-title" style="justify-content:space-between;">
                    <span><span class="icon"><i class="fa-solid fa-check-double"></i></span> IP Whitelist</span>
                    <span style="font-size:11px;color:var(--text-muted);"><?= $whitelistCount ?> entries</span>
                </div>

                <?php if (empty($whitelistIPs)): ?>
                <div style="text-align:center; padding:24px; color:var(--text-muted); font-size:13px;">
                    <div style="font-size:32px; margin-bottom:8px;"><i class="fa-solid fa-lock-open"></i></div>
                    No whitelisted IPs yet. Add trusted IPs below.
                </div>
                <?php else: ?>
                <div style="max-height:240px; overflow-y:auto;">
                    <?php foreach ($whitelistIPs as $wl): ?>
                    <div class="whitelist-item">
                        <div>
                            <span class="whitelist-ip"><?= htmlspecialchars($wl['ip_address']) ?></span>
                            <?php if (!empty($wl['label'])): ?>
                            <span class="whitelist-label"><?= htmlspecialchars($wl['label']) ?></span>
                            <?php endif; ?>
                        </div>
                        <div style="display:flex; align-items:center; gap:12px;">
                            <span class="whitelist-meta">
                                <span><i class="fa-solid fa-user"></i> <?= htmlspecialchars($wl['added_by'] ?? 'system') ?></span>
                                <span><?= date('M j', strtotime($wl['created_at'])) ?></span>
                            </span>
                            <form method="POST" style="display:inline;">
                                <?php CsrfHandler::insertField(); ?>
                                <input type="hidden" name="action" value="whitelist_delete">
                                <input type="hidden" name="whitelist_id" value="<?= $wl['id'] ?>">
                                <button type="submit" class="btn btn-danger btn-sm" title="Remove from whitelist" onclick="return confirm('Remove this IP from the whitelist?')"><i class="fa-solid fa-trash-can"></i></button>
                            </form>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>

                <!-- Add to Whitelist Form -->
                <form method="POST" class="whitelist-form">
                    <?php CsrfHandler::insertField(); ?>
                    <input type="hidden" name="action" value="whitelist_add">
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="ip" class="form-control" placeholder="e.g. 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>Label (optional)</label>
                        <input type="text" name="label" class="form-control" placeholder="e.g. Office Gateway">
                    </div>
                    <button type="submit" class="btn btn-primary btn-sm" style="height:38px;"><i class="fa-solid fa-plus"></i> Whitelist</button>
                </form>
            </div>

            <!-- IP Blacklist -->
            <div class="card animate-fadeIn delay-3">
                <div class="card-title" style="justify-content:space-between;">
                    <span><span class="icon"><i class="fa-solid fa-ban"></i></span> IP Blacklist</span>
                    <span style="font-size:11px;color:var(--text-muted);"><?= $blacklistCount ?> entries</span>
                </div>
                <div style="max-height:200px; overflow-y:auto;">
                <table class="data-table">
                    <thead><tr><th>IP Address</th><th>Reason</th><th>Action</th></tr></thead>
                    <tbody>
                        <?php foreach ($blacklistIPs as $bl): ?>
                        <tr>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($bl['ip_address']) ?></td>
                            <td style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($bl['reason']) ?></td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <?php CsrfHandler::insertField(); ?>
                                    <input type="hidden" name="action" value="blacklist_delete">
                                    <input type="hidden" name="blacklist_id" value="<?= $bl['id'] ?>">
                                    <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Unblock this IP?')"><i class="fa-solid fa-trash-can"></i></button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if (empty($blacklistIPs)): ?>
                        <tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:20px;">No IPs blacklisted.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
                </div>
                <form method="POST" style="margin-top:12px;display:flex;gap:8px;align-items:flex-end;">
                    <?php CsrfHandler::insertField(); ?>
                    <input type="hidden" name="action" value="blacklist_add">
                    <div class="form-group" style="flex:1;margin-bottom:0;">
                        <label style="font-size:10px;">IP Address</label>
                        <input type="text" name="ip" class="form-control form-control-sm" placeholder="IP to block..." required>
                    </div>
                    <div class="form-group" style="flex:1.2;margin-bottom:0;">
                        <label style="font-size:10px;">Reason</label>
                        <input type="text" name="reason" class="form-control form-control-sm" placeholder="e.g. C2 Server">
                    </div>
                    <button type="submit" class="btn btn-primary btn-sm" style="height:32px;"><i class="fa-solid fa-plus"></i> Block</button>
                </form>
            </div>
        </div>

        <!-- Traffic Chart -->
        <div class="card animate-fadeIn delay-4" style="margin-bottom:20px;">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-chart-column"></i></span> Inbound vs Outbound Traffic</div>
            <div class="chart-container">
                <canvas id="trafficChart"></canvas>
            </div>
        </div>

        <!-- Recent Network Events -->
        <div class="card animate-fadeIn delay-4">
            <div class="card-title"><span class="icon"><i class="fa-solid fa-globe"></i></span> Recent Network Events</div>
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>Time</th><th>Agent</th><th>Event Type</th><th>Severity</th><th>Destination</th></tr></thead>
                <tbody>
                    <?php if (empty($networkEvents)): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No network events recorded yet.</td></tr>
                    <?php else: foreach ($networkEvents as $e): ?>
                    <tr>
                        <td style="font-size:12px;color:var(--text-muted);"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['destination'] ?? 'N/A') ?></td>
                    </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
            </div>
        </div>
    </main>
</div>

<?php
// Fetch hourly network traffic data (last 24 hours)
$hourlyNet = $pdo->query(
    "SELECT HOUR(created_at) as hr, COUNT(*) as cnt 
     FROM events WHERE module='network' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
     GROUP BY HOUR(created_at) ORDER BY hr"
)->fetchAll(PDO::FETCH_KEY_PAIR);

$labels = []; $values = [];
for ($i = 0; $i < 24; $i++) {
    $labels[] = sprintf('%02d:00', $i);
    $values[] = $hourlyNet[$i] ?? 0;
}
?>
<script>
new Chart(document.getElementById('trafficChart').getContext('2d'), {
    type: 'line',
    data: {
        labels: <?= json_encode($labels) ?>,
        datasets: [{
            label: 'Network Events',
            data: <?= json_encode($values) ?>,
            borderColor: 'rgba(139, 92, 246, 1)',
            backgroundColor: 'rgba(139, 92, 246, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true,
            pointRadius: 3,
            pointBackgroundColor: 'rgba(139, 92, 246, 1)'
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { ticks: { color: '#64748b', maxRotation: 0, autoSkip: true, maxTicksLimit: 12 }, grid: { display: false } },
            y: { beginAtZero: true, ticks: { color: '#64748b', precision: 0 }, grid: { color: 'rgba(139,92,246,0.05)' } }
        }
    }
});
</script>

</body>
</html>
