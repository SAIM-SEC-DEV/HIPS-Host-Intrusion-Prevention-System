<?php
$currentPage = 'agents';
require_once 'includes/session.php';

$agents = $pdo->query(
    "SELECT a.*,
            IF(TIMESTAMPDIFF(SECOND, a.last_heartbeat, NOW()) > 180, 'offline', 'online') as status,
            (SELECT COUNT(*) FROM alerts WHERE agent_id = a.id AND status = 'new') as alert_count,
            (SELECT COUNT(*) FROM events WHERE agent_id = a.id AND DATE(created_at) = CURDATE()) as events_today
     FROM agents a ORDER BY IF(TIMESTAMPDIFF(SECOND, a.last_heartbeat, NOW()) > 180, 'offline', 'online') DESC, a.hostname"
)->fetchAll();

$totalAgents  = count($agents);
$onlineCount  = count(array_filter($agents, fn($a) => $a['status'] === 'online'));
$offlineCount = $totalAgents - $onlineCount;
$alertsToday  = array_sum(array_column($agents, 'alert_count'));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Agents</title>
    <link rel="stylesheet" href="assets/css/style.css?v=5.2">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Registered Agents</h1><span class="breadcrumb">HIPS / Management / Agents</span></div>
        </div>

        <div class="stat-grid">
            <div class="stat-card animate-fadeIn delay-1"><div class="stat-icon"><i class="fa-solid fa-desktop"></i></div><div class="stat-value"><?= $totalAgents ?></div><div class="stat-label">Total Registered</div></div>
            <div class="stat-card animate-fadeIn delay-2"><div class="stat-icon"><i class="fa-solid fa-circle-check"></i></div><div class="stat-value"><?= $onlineCount ?></div><div class="stat-label">Online</div></div>
            <div class="stat-card animate-fadeIn delay-3"><div class="stat-icon"><i class="fa-solid fa-circle-pause"></i></div><div class="stat-value"><?= $offlineCount ?></div><div class="stat-label">Offline</div></div>
            <div class="stat-card animate-fadeIn delay-4"><div class="stat-icon"><i class="fa-solid fa-bell"></i></div><div class="stat-value"><?= $alertsToday ?></div><div class="stat-label">Alerts Today</div></div>
        </div>

        <div class="grid-2">
            <?php if (empty($agents)): ?>
            <div class="card animate-fadeIn" style="grid-column:span 2;text-align:center;padding:60px;">
                <div style="font-size:48px;margin-bottom:16px; color:var(--text-muted);"><i class="fa-solid fa-computer"></i></div>
                <h3>No Agents Registered</h3>
                <p style="color:var(--text-muted);margin-top:8px;">Start the Java agent on a host machine to register it with this server.</p>
            </div>
            <?php else: foreach ($agents as $i => $ag): ?>
            <div class="card animate-fadeIn delay-<?= min($i + 1, 5) ?>" style="border-left:4px solid <?= $ag['status']==='online' ? 'var(--accent-violet)' : 'var(--status-offline)' ?>;">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
                    <div>
                        <h3 style="font-size:16px;margin-bottom:2px;"><?= htmlspecialchars($ag['hostname']) ?></h3>
                        <span style="font-size:12px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;"><?= htmlspecialchars($ag['ip_address']) ?></span>
                    </div>
                    <span class="badge <?= $ag['status'] ?>"><span class="status-dot <?= $ag['status'] ?>"></span><?= ucfirst($ag['status']) ?></span>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;margin-bottom:12px;">
                    <div><span style="color:var(--text-muted);">Agent ID:</span> <span style="font-family:'JetBrains Mono',monospace;"><?= $ag['id'] ?></span></div>
                    <div><span style="color:var(--text-muted);">OS:</span> <?= htmlspecialchars($ag['os_name'] ?? 'N/A') ?></div>
                    <div><span style="color:var(--text-muted);">CPU:</span> <?= htmlspecialchars($ag['cpu_info'] ?? 'N/A') ?></div>
                    <div><span style="color:var(--text-muted);">RAM:</span> <?= $ag['ram_total_mb'] ? $ag['ram_total_mb'] . ' MB' : 'N/A' ?></div>
                    <div><span style="color:var(--text-muted);">Version:</span> <?= htmlspecialchars($ag['agent_version']) ?></div>
                    <div><span style="color:var(--text-muted);">Owner:</span> <?= htmlspecialchars($ag['owner'] ?? 'N/A') ?></div>
                    <div><span style="color:var(--text-muted);">Last Seen:</span> <?= $ag['last_heartbeat'] ? date('M j, H:i', strtotime($ag['last_heartbeat'])) : 'Never' ?></div>
                    <div><span style="color:var(--text-muted);">Alerts:</span> <span style="color:var(--severity-critical);"><?= $ag['alert_count'] ?></span></div>
                </div>
                <div style="display:flex;gap:8px;">
                    <a href="events.php?agent=<?= $ag['id'] ?>" class="btn btn-secondary btn-sm"><i class="fa-solid fa-clipboard-list"></i> View Logs</a>
                    <a href="commands.php?agent=<?= $ag['id'] ?>" class="btn btn-secondary btn-sm"><i class="fa-solid fa-terminal"></i> Send Command</a>
                </div>
            </div>
            <?php endforeach; endif; ?>
        </div>
    </main>
</div>
</body>
</html>
