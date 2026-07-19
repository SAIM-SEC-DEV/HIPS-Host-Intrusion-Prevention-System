<?php
$currentPage = 'events';
require_once 'includes/session.php';

// ── Pagination ───────────────────────────────────────────────
$page    = max(1, (int)($_GET['page'] ?? 1));
$perPage = 25;
$offset  = ($page - 1) * $perPage;

// ── Filters ──────────────────────────────────────────────────
$agentFilter    = $_GET['agent'] ?? '';
$moduleFilter   = $_GET['module'] ?? '';
$severityFilter = $_GET['severity'] ?? '';
$dateFrom       = $_GET['date_from'] ?? '';
$dateTo         = $_GET['date_to'] ?? '';

$where  = "1=1";
$params = [];

if ($agentFilter) {
    $where .= " AND e.agent_id = :agent";
    $params[':agent'] = (int)$agentFilter;
}
if ($moduleFilter && in_array($moduleFilter, ['file','network'])) {
    $where .= " AND e.module = :module";
    $params[':module'] = $moduleFilter;
}
if ($severityFilter && in_array($severityFilter, ['CRITICAL','HIGH','MEDIUM','LOW'])) {
    $where .= " AND e.severity = :severity";
    $params[':severity'] = $severityFilter;
}
if ($dateFrom) { $where .= " AND e.created_at >= :date_from"; $params[':date_from'] = $dateFrom . ' 00:00:00'; }
if ($dateTo)   { $where .= " AND e.created_at <= :date_to";   $params[':date_to']   = $dateTo   . ' 23:59:59'; }

// Get total count
$countStmt = $pdo->prepare("SELECT COUNT(*) FROM events e WHERE $where");
$countStmt->execute($params);
$totalEvents = (int)$countStmt->fetchColumn();
$totalPages  = max(1, (int)ceil($totalEvents / $perPage));

// Get events
$stmt = $pdo->prepare(
    "SELECT e.*, ag.hostname FROM events e
     LEFT JOIN agents ag ON e.agent_id = ag.id
     WHERE $where ORDER BY e.created_at DESC LIMIT $perPage OFFSET $offset"
);
$stmt->execute($params);
$events = $stmt->fetchAll();

// Agent list for filter dropdown
$agentList = $pdo->query("SELECT id, hostname FROM agents ORDER BY hostname")->fetchAll();

// Severity counts
$critCount = (int)$pdo->query("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'")->fetchColumn();
$highCount = (int)$pdo->query("SELECT COUNT(*) FROM events WHERE severity='HIGH'")->fetchColumn();
$medCount  = (int)$pdo->query("SELECT COUNT(*) FROM events WHERE severity='MEDIUM'")->fetchColumn();
$lowCount  = (int)$pdo->query("SELECT COUNT(*) FROM events WHERE severity='LOW'")->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Event History</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Event History</h1><span class="breadcrumb">HIPS / Management / Events</span></div>
            <span style="font-size:13px;color:var(--text-muted);">Total: <strong style="color:var(--text-primary);"><?= $totalEvents ?></strong> events</span>
        </div>

        <!-- Filter Bar -->
        <form method="GET" class="filter-bar animate-fadeIn delay-1">
            <input type="date" name="date_from" class="form-control" value="<?= htmlspecialchars($dateFrom) ?>" style="width:150px;">
            <span style="color:var(--text-muted);">to</span>
            <input type="date" name="date_to" class="form-control" value="<?= htmlspecialchars($dateTo) ?>" style="width:150px;">
            <select name="agent" class="form-control"><option value="">All Agents</option>
                <?php foreach ($agentList as $a): ?><option value="<?= $a['id'] ?>" <?= $agentFilter==$a['id']?'selected':'' ?>><?= htmlspecialchars($a['hostname']) ?></option><?php endforeach; ?>
            </select>
            <select name="module" class="form-control"><option value="">All Modules</option>
                <option value="file" <?=$moduleFilter==='file'?'selected':''?>>File</option>
                <option value="network" <?=$moduleFilter==='network'?'selected':''?>>Network</option></select>
            <select name="severity" class="form-control"><option value="">All Severities</option>
                <option value="CRITICAL" <?=$severityFilter==='CRITICAL'?'selected':''?>>Critical</option>
                <option value="HIGH" <?=$severityFilter==='HIGH'?'selected':''?>>High</option>
                <option value="MEDIUM" <?=$severityFilter==='MEDIUM'?'selected':''?>>Medium</option>
                <option value="LOW" <?=$severityFilter==='LOW'?'selected':''?>>Low</option></select>
            <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-filter"></i> Apply</button>
            <a href="events.php" class="btn btn-secondary btn-sm"><i class="fa-solid fa-rotate-left"></i> Reset</a>
        </form>

        <!-- Stats Bar -->
        <div class="status-strip animate-fadeIn delay-1">
            <div class="strip-item"><span class="label">Critical</span><span class="value" style="color:var(--severity-critical);"><?= $critCount ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">High</span><span class="value" style="color:var(--severity-high);"><?= $highCount ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Medium</span><span class="value" style="color:var(--severity-medium);"><?= $medCount ?></span></div>
            <div class="divider"></div>
            <div class="strip-item"><span class="label">Low</span><span class="value" style="color:var(--severity-low);"><?= $lowCount ?></span></div>
        </div>

        <!-- Events Table -->
        <div class="card animate-fadeIn delay-2">
            <div style="overflow-x:auto;">
            <table class="data-table">
                <thead><tr><th>ID</th><th>Timestamp</th><th>Agent</th><th>Module</th><th>Event Type</th><th>Severity</th><th>Details</th></tr></thead>
                <tbody>
                    <?php foreach ($events as $e): ?>
                    <tr style="<?= in_array($e['severity'], ['CRITICAL','HIGH']) ? 'background:rgba(239,68,68,0.03);' : '' ?>">
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-muted);">#<?= $e['id'] ?></td>
                        <td style="font-size:12px;white-space:nowrap;"><?= date('M j, H:i:s', strtotime($e['created_at'])) ?></td>
                        <td><?= htmlspecialchars($e['hostname'] ?? 'N/A') ?></td>
                        <td><span class="badge <?= $e['module']==='file' ? 'low' : 'medium' ?>"><?= ucfirst($e['module']) ?></span></td>
                        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;"><?= htmlspecialchars($e['event_type']) ?></td>
                        <td><span class="badge <?= strtolower($e['severity']) ?>"><?= $e['severity'] ?></span></td>
                        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--text-secondary);"><?= htmlspecialchars($e['title']) ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (empty($events)): ?>
                    <tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px;">No events match your filters.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
            </div>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?><a href="?<?= http_build_query(array_merge($_GET, ['page'=>$page-1])) ?>" class="page-btn">←</a><?php endif; ?>
                <?php for ($p = max(1, $page - 3); $p <= min($totalPages, $page + 3); $p++): ?>
                <a href="?<?= http_build_query(array_merge($_GET, ['page'=>$p])) ?>" class="page-btn <?= $p===$page?'active':'' ?>"><?= $p ?></a>
                <?php endfor; ?>
                <?php if ($page < $totalPages): ?><a href="?<?= http_build_query(array_merge($_GET, ['page'=>$page+1])) ?>" class="page-btn">→</a><?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </main>
</div>
</body>
</html>
