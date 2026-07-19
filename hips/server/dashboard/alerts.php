<?php
$currentPage = 'alerts';
require_once 'includes/session.php';

// Handle alert actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $alertId = (int)($_POST['alert_id'] ?? 0);
    $action  = $_POST['action'] ?? '';

    // Bulk action
    if ($action === 'bulk_dismiss') {
        $pdo->prepare("UPDATE alerts SET status='dismissed', acknowledged_by=:user, acknowledged_at=NOW() WHERE status='new'")
            ->execute([':user' => $adminUsername]);
        header('Location: alerts.php'); exit;
    }
    if ($action === 'bulk_read') {
        $pdo->prepare("UPDATE alerts SET status='read', acknowledged_by=:user, acknowledged_at=NOW() WHERE status='new'")
            ->execute([':user' => $adminUsername]);
        header('Location: alerts.php'); exit;
    }
    if ($action === 'bulk_delete') {
        $pdo->prepare("DELETE FROM alerts WHERE status IN ('dismissed', 'read')")->execute();
        header('Location: alerts.php'); exit;
    }

    if ($alertId > 0) {
        if ($action === 'read') {
            $pdo->prepare("UPDATE alerts SET status='read', acknowledged_by=:user, acknowledged_at=NOW() WHERE id=:id")
                ->execute([':user' => $adminUsername, ':id' => $alertId]);
        } elseif ($action === 'dismiss') {
            $pdo->prepare("UPDATE alerts SET status='dismissed', acknowledged_by=:user, acknowledged_at=NOW() WHERE id=:id")
                ->execute([':user' => $adminUsername, ':id' => $alertId]);
        } elseif ($action === 'delete') {
            $pdo->prepare("DELETE FROM alerts WHERE id=:id")
                ->execute([':id' => $alertId]);
        }
    }
    header('Location: alerts.php'); exit;
}

// Fetch alerts with filters
$severity = $_GET['severity'] ?? '';
$status   = $_GET['status'] ?? '';
$search   = $_GET['search'] ?? '';

$where = "1=1";
$params = [];

if ($severity && in_array($severity, ['CRITICAL','HIGH','MEDIUM','LOW'])) {
    $where .= " AND a.severity = :severity";
    $params[':severity'] = $severity;
}
if ($status && in_array($status, ['new','read','dismissed'])) {
    $where .= " AND a.status = :status";
    $params[':status'] = $status;
}
if ($search) {
    $where .= " AND (a.title LIKE :search OR ag.hostname LIKE :search2 OR a.description LIKE :search3)";
    $params[':search']  = "%$search%";
    $params[':search2'] = "%$search%";
    $params[':search3'] = "%$search%";
}

$stmt = $pdo->prepare(
    "SELECT a.*, ag.hostname FROM alerts a
     LEFT JOIN agents ag ON a.agent_id = ag.id
     WHERE $where
     ORDER BY a.created_at DESC LIMIT 100"
);
$stmt->execute($params);
$alerts = $stmt->fetchAll();

// Severity counts
$critCount = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status='new'")->fetchColumn();
$highCount = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND status='new'")->fetchColumn();
$medCount  = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM' AND status='new'")->fetchColumn();
$lowCount  = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE severity='LOW' AND status='new'")->fetchColumn();
$totalNew  = $critCount + $highCount + $medCount + $lowCount;
$totalAll  = (int)$pdo->query("SELECT COUNT(*) FROM alerts")->fetchColumn();
$readCount = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE status='read'")->fetchColumn();
$dismissedCount = (int)$pdo->query("SELECT COUNT(*) FROM alerts WHERE status='dismissed'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Live Alerts</title>
    <link rel="stylesheet" href="assets/css/style.css?v=10.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
    <style>
        .alert-stats-grid {
            display:grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap:12px; margin-bottom:20px;
        }
        .alert-stat-card {
            background: var(--glass-card-bg); border:1px solid var(--glass-border);
            border-radius: var(--radius-md); padding:16px; text-align:center;
            backdrop-filter: blur(12px); transition: all 0.3s ease;
        }
        .alert-stat-card:hover {
            transform:translateY(-2px); box-shadow:var(--shadow-glow);
        }
        .alert-stat-card .as-value {
            font-size:28px; font-weight:800; line-height:1;
            font-family:'JetBrains Mono',monospace;
        }
        .alert-stat-card .as-label {
            font-size:10px; text-transform:uppercase; letter-spacing:1px;
            color:var(--text-muted); margin-top:6px;
        }
        .bulk-actions {
            display:flex; gap:8px; align-items:center; padding:10px 14px;
            background: var(--glass-card-bg); border:1px solid var(--glass-border);
            border-radius:var(--radius-sm); margin-bottom:16px;
            backdrop-filter:blur(12px);
        }
        .bulk-actions span { font-size:12px; color:var(--text-muted); }
        .status-filter {
            display:flex; gap:6px; margin-left:auto; align-items:center;
        }
        .status-filter a {
            font-size:11px; padding:4px 10px; border-radius:var(--radius-sm);
            border:1px solid var(--glass-border); color:var(--text-secondary);
            transition:all 0.2s ease; text-decoration:none;
        }
        .status-filter a:hover { border-color:var(--accent-violet); color:var(--accent-violet); }
        .status-filter a.active { background:var(--accent-violet); color:white; border-color:var(--accent-violet); }
        .alert-card-enhanced {
            display:grid; grid-template-columns:auto 1fr auto; gap:16px;
            align-items:start; padding:16px; margin-bottom:10px;
            background:var(--glass-card-bg); border:1px solid var(--glass-border);
            border-left:4px solid var(--glass-border); border-radius:var(--radius-md);
            backdrop-filter:blur(12px); transition:all 0.35s cubic-bezier(0.25,0.46,0.45,0.94);
        }
        .alert-card-enhanced:hover {
            transform:translateX(4px); box-shadow:var(--shadow-md);
            border-color:rgba(139,92,246,0.2);
        }
        .alert-card-enhanced.sev-critical { border-left-color:var(--severity-critical); }
        .alert-card-enhanced.sev-high { border-left-color:var(--severity-high); }
        .alert-card-enhanced.sev-medium { border-left-color:var(--severity-medium); }
        .alert-card-enhanced.sev-low { border-left-color:var(--severity-low); }
        .alert-card-enhanced .alert-sev { min-width:70px; text-align:center; }
        .alert-card-enhanced .alert-body h4 {
            font-size:14px; font-weight:600; color:var(--text-heading);
            margin-bottom:4px;
        }
        .alert-card-enhanced .alert-body p {
            font-size:12px; color:var(--text-secondary); line-height:1.5;
            margin-bottom:6px;
        }
        .alert-card-enhanced .alert-meta-row {
            display:flex; gap:16px; font-size:11px; color:var(--text-muted);
        }
        .alert-card-enhanced .alert-actions-col { display:flex; gap:6px; }
        .empty-state {
            text-align:center; padding:60px 20px;
        }
        .empty-state .empty-icon { font-size:56px; margin-bottom:16px; }
        .empty-state h3 { font-size:18px; margin-bottom:8px; }
    </style>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>

    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div>
                <h1>Live Alerts</h1>
                <span class="breadcrumb">HIPS / Monitoring / Live Alerts</span>
            </div>
            <div class="header-actions" style="display:flex;gap:12px;align-items:center;">
                <div class="refresh-bar active" id="refreshBar">
                    <label class="toggle-switch" style="margin:0;">
                        <input type="checkbox" id="refreshToggle" checked>
                        <span class="toggle-slider"></span>
                    </label>
                    <span>Auto-refresh</span>
                    <span class="refresh-countdown" id="countdown">20</span>
                    <div class="refresh-progress">
                        <div class="refresh-progress-fill" id="progressFill" style="width:100%;"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Alert Statistics -->
        <div class="alert-stats-grid animate-fadeIn delay-1">
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--text-heading);"><?= $totalAll ?></div>
                <div class="as-label">Total Alerts</div>
            </div>
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--severity-critical);"><?= $critCount ?></div>
                <div class="as-label"><i class="fa-solid fa-circle-radiation"></i> Critical</div>
            </div>
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--severity-high);"><?= $highCount ?></div>
                <div class="as-label"><i class="fa-solid fa-fire"></i> High</div>
            </div>
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--severity-medium);"><?= $medCount ?></div>
                <div class="as-label"><i class="fa-solid fa-triangle-exclamation"></i> Medium</div>
            </div>
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--severity-low);"><?= $lowCount ?></div>
                <div class="as-label"><i class="fa-solid fa-circle-info"></i> Low</div>
            </div>
            <div class="alert-stat-card">
                <div class="as-value" style="color:var(--accent-violet);"><?= $totalNew ?></div>
                <div class="as-label"><i class="fa-solid fa-bolt"></i> Unresolved</div>
            </div>
        </div>

        <!-- Bulk Actions + Status Filter -->
        <!-- Alert Control Center -->
        <div class="card animate-fadeIn delay-1" style="margin-bottom:24px; padding:0; overflow:hidden; border:1px solid var(--border-color);">
            <!-- Top Bar: Bulk Actions & Status -->
            <div style="padding:16px 20px; background:rgba(0,0,0,0.02); border-bottom:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
                <div style="display:flex; align-items:center; gap:12px;">
                    <span style="font-size:11px; color:var(--text-muted); font-weight:700; text-transform:uppercase; letter-spacing:1px;">Bulk Actions:</span>
                    <form method="POST" style="display:flex; gap:8px;">
                        <input type="hidden" name="action" value="bulk_read">
                        <button type="submit" class="btn btn-secondary btn-sm" style="font-size:11px;"><i class="fa-solid fa-check-double"></i> Mark Read</button>
                    </form>
                    <form method="POST" style="display:flex; gap:8px;">
                        <input type="hidden" name="action" value="bulk_dismiss">
                        <button type="submit" class="btn btn-secondary btn-sm" style="font-size:11px;"><i class="fa-solid fa-eye-slash"></i> Dismiss All</button>
                    </form>
                    <form method="POST" style="display:flex; gap:8px;">
                        <input type="hidden" name="action" value="bulk_delete">
                        <button type="submit" class="btn btn-danger btn-sm" style="font-size:11px;"><i class="fa-solid fa-trash-can"></i> Purge</button>
                    </form>
                </div>

                <div style="display:flex; align-items:center; gap:12px;">
                    <span style="font-size:11px; color:var(--text-muted); font-weight:700; text-transform:uppercase; letter-spacing:1px;">Status:</span>
                    <div style="display:flex; background:var(--bg-input); padding:3px; border-radius:var(--radius-md); border:1px solid var(--border-color);">
                        <a href="alerts.php?status=all" class="filter-link <?= !$status?'active':'' ?>">All</a>
                        <a href="alerts.php?status=new" class="filter-link <?= $status==='new'?'active':'' ?>">New (<?= $totalNew ?>)</a>
                        <a href="alerts.php?status=read" class="filter-link <?= $status==='read'?'active':'' ?>">Read</a>
                        <a href="alerts.php?status=dismissed" class="filter-link <?= $status==='dismissed'?'active':'' ?>">Dismissed</a>
                    </div>
                </div>
            </div>

            <!-- Bottom Bar: Severity & Search -->
            <div style="padding:16px 20px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
                <div style="display:flex; align-items:center; gap:12px;">
                    <span style="font-size:11px; color:var(--text-muted); font-weight:700; text-transform:uppercase; letter-spacing:1px;">Severity:</span>
                    <div style="display:flex; gap:8px;">
                        <a href="alerts.php" class="sev-tag <?= !$severity?'active':'' ?>">All</a>
                        <a href="alerts.php?severity=CRITICAL" class="sev-tag crit <?= $severity==='CRITICAL'?'active':'' ?>">Critical</a>
                        <a href="alerts.php?severity=HIGH" class="sev-tag high <?= $severity==='HIGH'?'active':'' ?>">High</a>
                        <a href="alerts.php?severity=MEDIUM" class="sev-tag med <?= $severity==='MEDIUM'?'active':'' ?>">Medium</a>
                    </div>
                </div>

                <form method="GET" style="position:relative; width:100%; max-width:350px;">
                    <i class="fa-solid fa-magnifying-glass" style="position:absolute; left:12px; top:50%; transform:translateY(-50%); color:var(--text-muted); font-size:12px;"></i>
                    <input type="text" name="search" placeholder="Search events, IPs, or titles..." value="<?= htmlspecialchars($search ?? '') ?>" style="width:100%; padding:10px 10px 10px 36px; border-radius:var(--radius-md); background:var(--bg-input); border:1px solid var(--border-color); color:var(--text-primary); font-size:13px;">
                </form>
            </div>
        </div>

        <style>
            .filter-link { padding:6px 12px; font-size:11px; font-weight:600; text-decoration:none; color:var(--text-muted); border-radius:var(--radius-sm); transition:all 0.2s; }
            .filter-link:hover { color:var(--text-primary); }
            .filter-link.active { background:var(--bg-card); color:var(--accent-violet) !important; box-shadow:var(--shadow-sm); }
            
            .sev-tag { padding:5px 14px; border-radius:20px; font-size:11px; font-weight:700; text-decoration:none; color:var(--text-muted); border:1px solid var(--border-color); transition:all 0.2s; }
            .sev-tag.crit { border-color:var(--severity-critical); color:var(--severity-critical); }
            .sev-tag.high { border-color:var(--severity-high); color:var(--severity-high); }
            .sev-tag.med { border-color:var(--severity-medium); color:var(--severity-medium); }
            .sev-tag.active { background:var(--accent-violet-dim); border-color:var(--accent-violet); color:var(--accent-violet); }
            .sev-tag.crit.active { background:rgba(255,69,58,0.1); border-color:var(--severity-critical); }
        </style>

        <!-- Alert Cards -->
        <div id="alertContainer">
            <?php if (empty($alerts)): ?>
            <div class="card scroll-reveal reveal-scale empty-state">
                <div class="empty-icon"><i class="fa-solid fa-circle-check" style="color:var(--severity-low);"></i></div>
                <h3>No Alerts Found</h3>
                <p style="color:var(--text-muted);">All systems operating normally. No threats matching your filters.</p>
            </div>
            <?php else: foreach ($alerts as $i => $alert): ?>
            <div class="alert-card-enhanced sev-<?= strtolower($alert['severity']) ?> scroll-reveal" style="transition-delay:<?= min($i * 0.04, 0.4) ?>s;">
                <div class="alert-sev">
                    <span class="badge <?= strtolower($alert['severity']) ?>"><?= $alert['severity'] ?></span>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:6px;"><?= ucfirst($alert['status']) ?></div>
                </div>
                <div class="alert-body">
                    <h4><?= htmlspecialchars($alert['title']) ?></h4>
                    <p><?= htmlspecialchars($alert['description'] ?? 'No additional details available.') ?></p>
                    <div class="alert-meta-row">
                        <span><i class="fa-solid fa-desktop"></i> <?= htmlspecialchars($alert['hostname'] ?? 'Unknown') ?></span>
                        <span><i class="fa-solid fa-box"></i> <?= ucfirst($alert['module']) ?></span>
                        <?php if (!empty($alert['mitre_technique_id'])): ?>
                        <span><i class="fa-solid fa-shield-halved"></i> <?= htmlspecialchars($alert['mitre_technique_id']) ?> | <?= htmlspecialchars($alert['mitre_tactic']) ?></span>
                        <?php endif; ?>
                        <span><i class="fa-solid fa-clock"></i> <?= date('M j, H:i:s', strtotime($alert['created_at'])) ?></span>
                        <?php if ($alert['acknowledged_by']): ?>
                        <span><i class="fa-solid fa-user-check"></i> <?= htmlspecialchars($alert['acknowledged_by']) ?></span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="alert-actions-col">
                    <?php if ($alert['status'] === 'new'): ?>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="alert_id" value="<?= $alert['id'] ?>">
                        <input type="hidden" name="action" value="read">
                        <button type="submit" class="btn btn-secondary btn-sm" title="Mark as Read"><i class="fa-solid fa-check"></i></button>
                    </form>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="alert_id" value="<?= $alert['id'] ?>">
                        <input type="hidden" name="action" value="dismiss">
                        <button type="submit" class="btn btn-secondary btn-sm" title="Dismiss"><i class="fa-solid fa-xmark"></i></button>
                    </form>
                    <?php endif; ?>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="alert_id" value="<?= $alert['id'] ?>">
                        <input type="hidden" name="action" value="delete">
                        <button type="submit" class="btn btn-danger btn-sm" title="Delete permanently" onclick="return confirm('Permanently delete this alert?')"><i class="fa-solid fa-trash-can"></i></button>
                    </form>
                </div>
            </div>
            <?php endforeach; endif; ?>
        </div>

        <!-- Results summary -->
        <?php if (!empty($alerts)): ?>
        <div style="text-align:center;padding:16px;font-size:11px;color:var(--text-muted);">
            Showing <?= count($alerts) ?> of <?= $totalAll ?> alerts · Last updated: <?= date('H:i:s') ?>
        </div>
        <?php endif; ?>
    </main>
</div>

<script>
/* ── Auto-Refresh with Toggle ─────────────────────────────────── */
(function() {
    const INTERVAL = 20;
    let remaining = INTERVAL;
    let enabled = true;
    let timer = null;

    const toggle      = document.getElementById('refreshToggle');
    const countdownEl  = document.getElementById('countdown');
    const progressFill = document.getElementById('progressFill');
    const refreshBar   = document.getElementById('refreshBar');

    function tick() {
        remaining--;
        countdownEl.textContent = remaining;
        progressFill.style.width = ((remaining / INTERVAL) * 100) + '%';
        if (remaining <= 0) location.reload();
    }

    function start() {
        remaining = INTERVAL;
        countdownEl.textContent = remaining;
        progressFill.style.width = '100%';
        timer = setInterval(tick, 1000);
    }

    function stop() {
        clearInterval(timer);
        timer = null;
        countdownEl.textContent = '—';
        progressFill.style.width = '0%';
    }

    toggle.addEventListener('change', function() {
        enabled = this.checked;
        if (enabled) { refreshBar.classList.add('active'); start(); }
        else { refreshBar.classList.remove('active'); stop(); }
    });

    start();
})();
</script>
</body>
</html>
