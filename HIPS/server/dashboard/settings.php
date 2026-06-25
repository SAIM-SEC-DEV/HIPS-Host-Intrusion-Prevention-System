<?php
$currentPage = 'settings';
require_once 'includes/session.php';

// Handle settings update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tab = $_POST['tab'] ?? 'general';
    
    if ($tab === 'account') {
        // Handle password change
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword     = $_POST['new_password']     ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (!empty($newPassword) && $newPassword === $confirmPassword) {
            // Verify current password
            $stmt = $pdo->prepare("SELECT password_hash FROM dashboard_users WHERE id = :id");
            $stmt->execute([':id' => $adminId]);
            $user = $stmt->fetch();

            if ($user && password_verify($currentPassword, $user['password_hash'])) {
                // Update password
                $newHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
                $update = $pdo->prepare("UPDATE dashboard_users SET password_hash = :hash, must_change_password = 0 WHERE id = :id");
                $update->execute([':hash' => $newHash, ':id' => $adminId]);
                $passwordSuccess = "Password updated successfully.";
                // Clear session flag
                $_SESSION['hips_must_change_password'] = false;
            } else {
                $passwordError = "Current password incorrect.";
            }
        } else if (!empty($newPassword)) {
            $passwordError = "New passwords do not match.";
        }
    } else {
        // Handle system settings update
        foreach ($_POST as $key => $value) {
            if ($key === 'tab') continue;
            $stmt = $pdo->prepare("UPDATE settings SET setting_value = :val WHERE setting_key = :key");
            $stmt->execute([':val' => $value, ':key' => $key]);
        }
        $settingsSaved = true;
    }
}

// Load all settings grouped by category
$settings = [];
$rows = $pdo->query("SELECT * FROM settings ORDER BY category, id")->fetchAll();
foreach ($rows as $row) {
    $settings[$row['category']][$row['setting_key']] = $row;
}

// Dashboard user info
$adminUser = $pdo->prepare("SELECT * FROM dashboard_users WHERE id = :id");
$adminUser->execute([':id' => $adminId]);
$adminData = $adminUser->fetch();
$activeTab = $_GET['tab'] ?? 'general';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIPS — Settings</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script>(function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();</script>
</head>
<body>
<div class="app-layout">
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <div class="page-header animate-fadeIn">
            <div><h1>Settings</h1><span class="breadcrumb">HIPS / Configuration / Settings</span></div>
        </div>

        <?php if (isset($settingsSaved)): ?>
        <div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-low);font-size:13px;">✓ Settings saved successfully.</div>
        <?php endif; ?>

        <?php if (isset($passwordSuccess)): ?>
        <div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-low);font-size:13px;">✓ <?= $passwordSuccess ?></div>
        <?php endif; ?>

        <?php if (isset($passwordError)): ?>
        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-critical);font-size:13px;">✗ <?= $passwordError ?></div>
        <?php endif; ?>

        <?php if (isset($_GET['force_password_change'])): ?>
        <div style="background:rgba(234,179,8,0.1);border:1px solid rgba(234,179,8,0.3);border-radius:var(--radius-sm);padding:12px;margin-bottom:16px;color:var(--severity-medium);font-size:13px;">⚠️ <strong>Security Action Required:</strong> You are using a default password. Please update it to continue using the dashboard.</div>
        <?php endif; ?>

        <!-- Tab Navigation -->
        <div class="tab-nav animate-fadeIn delay-1">
            <a href="?tab=general" class="tab-btn <?= $activeTab==='general'?'active':'' ?>">General</a>
            <a href="?tab=security" class="tab-btn <?= $activeTab==='security'?'active':'' ?>">Security Rules</a>
            <a href="?tab=notifications" class="tab-btn <?= $activeTab==='notifications'?'active':'' ?>">Notifications</a>
            <a href="?tab=api" class="tab-btn <?= $activeTab==='api'?'active':'' ?>">API Tokens</a>
            <a href="?tab=account" class="tab-btn <?= $activeTab==='account'?'active':'' ?>">Account</a>
        </div>

        <!-- General Settings -->
        <?php if ($activeTab === 'general'): ?>
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">⚙</span> General Configuration</div>
            <form method="POST">
                <input type="hidden" name="tab" value="general">
                <?php if (isset($settings['general'])): foreach ($settings['general'] as $key => $s): ?>
                <div class="form-group">
                    <label><?= htmlspecialchars($s['description'] ?? $key) ?></label>
                    <input type="text" name="<?= $key ?>" class="form-control" value="<?= htmlspecialchars($s['setting_value']) ?>">
                </div>
                <?php endforeach; endif; ?>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="submit" class="btn btn-primary">💾 Save Changes</button>
                    <button type="reset" class="btn btn-secondary">↩ Reset</button>
                </div>
            </form>
        </div>

        <!-- Security Rules -->
        <?php elseif ($activeTab === 'security'): ?>
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">🛡</span> Security Rule Configuration</div>
            <form method="POST">
                <input type="hidden" name="tab" value="security">
                <?php if (isset($settings['security'])): foreach ($settings['security'] as $key => $s):
                    $isToggle = in_array($key, ['file_monitor_enabled', 'network_monitor_enabled']);
                ?>
                <div class="form-group" style="<?= $isToggle ? 'display:flex;align-items:center;justify-content:space-between;' : '' ?>">
                    <label style="<?= $isToggle ? 'margin-bottom:0;' : '' ?>"><?= htmlspecialchars($s['description'] ?? $key) ?></label>
                    <?php if ($isToggle): ?>
                    <label class="toggle-switch">
                        <input type="hidden" name="<?= $key ?>" value="0">
                        <input type="checkbox" name="<?= $key ?>" value="1" <?= $s['setting_value'] ? 'checked' : '' ?>>
                        <span class="toggle-slider"></span>
                    </label>
                    <?php else: ?>
                    <input type="text" name="<?= $key ?>" class="form-control" value="<?= htmlspecialchars($s['setting_value']) ?>">
                    <?php endif; ?>
                </div>
                <?php endforeach; endif; ?>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="submit" class="btn btn-primary">💾 Save Changes</button>
                    <button type="reset" class="btn btn-secondary">↩ Reset</button>
                </div>
            </form>
        </div>

        <!-- Notifications -->
        <?php elseif ($activeTab === 'notifications'): ?>
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">🔔</span> Notification Settings</div>
            <form method="POST">
                <input type="hidden" name="tab" value="notifications">
                <?php if (isset($settings['notifications'])): foreach ($settings['notifications'] as $key => $s):
                    $isToggle = $key === 'email_notifications';
                ?>
                <div class="form-group" style="<?= $isToggle ? 'display:flex;align-items:center;justify-content:space-between;' : '' ?>">
                    <label style="<?= $isToggle ? 'margin-bottom:0;' : '' ?>"><?= htmlspecialchars($s['description'] ?? $key) ?></label>
                    <?php if ($isToggle): ?>
                    <label class="toggle-switch">
                        <input type="hidden" name="<?= $key ?>" value="0">
                        <input type="checkbox" name="<?= $key ?>" value="1" <?= $s['setting_value'] ? 'checked' : '' ?>>
                        <span class="toggle-slider"></span>
                    </label>
                    <?php else: ?>
                    <input type="text" name="<?= $key ?>" class="form-control" value="<?= htmlspecialchars($s['setting_value']) ?>">
                    <?php endif; ?>
                </div>
                <?php endforeach; endif; ?>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="submit" class="btn btn-primary">💾 Save Changes</button>
                    <button type="reset" class="btn btn-secondary">↩ Reset</button>
                </div>
            </form>
        </div>

        <!-- API Tokens -->
        <?php elseif ($activeTab === 'api'): ?>
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">🔑</span> API Token Management</div>
            <div style="margin-bottom:20px;">
                <h4 style="font-size:14px;margin-bottom:8px;">Your API Token</h4>
                <div style="display:flex;gap:8px;align-items:center;">
                    <input type="password" class="form-control" id="tokenField" value="<?= htmlspecialchars($adminData['api_token'] ?? '') ?>" readonly style="font-family:'JetBrains Mono',monospace;font-size:12px;">
                    <button class="btn btn-secondary btn-sm" onclick="toggleToken()">👁 Show</button>
                </div>
                <p style="font-size:11px;color:var(--text-muted);margin-top:6px;">This token is used for API authentication. Keep it safe.</p>
            </div>
            <div>
                <h4 style="font-size:14px;margin-bottom:8px;">Agent Tokens</h4>
                <table class="data-table">
                    <thead><tr><th>Agent</th><th>Token (masked)</th><th>Status</th></tr></thead>
                    <tbody>
                        <?php
                        $agentTokens = $pdo->query("SELECT hostname, auth_token, status FROM agents ORDER BY hostname")->fetchAll();
                        foreach ($agentTokens as $at):
                        ?>
                        <tr>
                            <td><?= htmlspecialchars($at['hostname']) ?></td>
                            <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-muted);"><?= substr($at['auth_token'], 0, 12) ?>...<?= substr($at['auth_token'], -8) ?></td>
                            <td><span class="badge <?= $at['status'] ?>"><?= ucfirst($at['status']) ?></span></td>
                        </tr>
                        <?php endforeach; ?>
                        <?php if (empty($agentTokens)): ?>
                        <tr><td colspan="3" style="text-align:center;color:var(--text-muted);">No agents registered.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php elseif ($activeTab === 'account'): ?>
        <div class="card animate-fadeIn delay-2">
            <div class="card-title"><span class="icon">👤</span> Account & Security</div>
            <form method="POST">
                <input type="hidden" name="tab" value="account">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" class="form-control" value="<?= htmlspecialchars($adminData['username']) ?>" readonly style="background:rgba(0,0,0,0.1);color:var(--text-muted);">
                </div>
                <div class="form-group">
                    <label>Current Password</label>
                    <input type="password" name="current_password" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>New Password</label>
                    <input type="password" name="new_password" class="form-control" required minlength="8">
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" name="confirm_password" class="form-control" required minlength="8">
                </div>
                <div style="display:flex;gap:10px;margin-top:16px;">
                    <button type="submit" class="btn btn-primary">🔐 Update Password</button>
                </div>
            </form>
        </div>
        <?php endif; ?>
    </main>
</div>

<script>
function toggleToken() {
    const field = document.getElementById('tokenField');
    field.type = field.type === 'password' ? 'text' : 'password';
}
</script>
</body>
</html>
