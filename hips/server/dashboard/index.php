<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="HIPS — Host Intrusion Prevention System Dashboard Login">
    <title>HIPS — Login</title>
    <link rel="stylesheet" href="assets/css/style.css?v=7.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <script>
        // Apply theme before first paint to prevent flash
        (function(){var t=localStorage.getItem('hips-theme')||'dark';document.documentElement.setAttribute('data-theme',t);})();
    </script>
</head>
<body>
<!-- Preloader -->
<div class="preloader" id="pagePreloader">
    <div class="loader-spinner"></div>
</div>
<script>
    window.addEventListener('load', function() {
        const preloader = document.getElementById('pagePreloader');
        if (preloader) {
            preloader.classList.add('hidden');
            setTimeout(() => preloader.style.display = 'none', 600);
        }
    });
</script>

<div class="login-page">
    <div class="login-card animate-scaleIn">
        <div class="login-header">
            <div class="shield"><i class="fa-solid fa-shield-halved"></i></div>
            <h1>HIPS Dashboard</h1>
            <p>Host Intrusion Prevention System</p>
        </div>

        <?php
        $error = $_GET['error'] ?? '';
        if ($error === 'invalid_credentials'): ?>
            <div class="login-error"><i class="fa-solid fa-triangle-exclamation"></i> Invalid username or password. Please try again.</div>
        <?php elseif ($error === 'ip_blocked'): ?>
            <div class="login-error" style="background:rgba(239,68,68,0.15); border:1px solid var(--severity-critical);"><i class="fa-solid fa-ban"></i> Access Denied. Your IP address is not whitelisted.</div>
        <?php elseif ($error === 'invalid_token'): ?>
            <div class="login-error"><i class="fa-solid fa-triangle-exclamation"></i> Invalid API token. Please verify your token.</div>
        <?php elseif ($error === 'missing_credentials'): ?>
            <div class="login-error"><i class="fa-solid fa-triangle-exclamation"></i> Please fill in all required fields.</div>
        <?php elseif ($error === 'server_error'): ?>
            <div class="login-error"><i class="fa-solid fa-triangle-exclamation"></i> Server error. Please check XAMPP services.</div>
        <?php endif; ?>

        <form action="../api/auth.php" method="POST" id="loginForm">
            <div class="form-group">
                <label for="server_url">Server Address</label>
                <input type="text" class="form-control" id="server_url" name="server_url"
                       value="http://localhost/hips" placeholder="http://localhost/hips">
            </div>

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" id="username" name="username"
                       placeholder="Enter your username" required autocomplete="username">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password"
                       placeholder="Enter your password" required autocomplete="current-password">
            </div>

            <div class="form-group">
                <label for="api_token">API Token <span style="color:var(--text-muted); font-weight:400; text-transform:none;">(optional)</span></label>
                <input type="password" class="form-control" id="api_token" name="api_token"
                       placeholder="Paste your API token">
            </div>

            <button type="submit" class="btn btn-primary">
                <i class="fa-solid fa-right-to-bracket"></i> Sign In
            </button>
        </form>

        <div style="text-align:center; margin-top:20px; font-size:11px; color:var(--text-muted);">
            HIPS v1.0 &middot; Secure Authentication &middot; AES-256
        </div>
    </div>
</div>

<script>
    // Focus username field on load
    document.getElementById('username').focus();

    // Add subtle input focus animations
    document.querySelectorAll('.form-control').forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.transform = 'translateY(-1px)';
            input.parentElement.style.transition = 'transform 0.2s ease';
        });
        input.addEventListener('blur', () => {
            input.parentElement.style.transform = 'translateY(0)';
        });
    });
</script>
</body>
</html>
