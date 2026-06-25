<?php
/**
 * HIPS Dashboard — Sidebar Navigation
 * Includes preloader, floating particles, scroll-reveal JS, theme toggle, and sidebar nav.
 *
 * @var string $currentPage — Set by the including page to mark the active nav item
 */
$currentPage = $currentPage ?? '';

// Fetch alert count for badge
$alertCount = 0;
try {
    $alertStmt = $pdo->query("SELECT COUNT(*) FROM alerts WHERE status = 'new'");
    $alertCount = (int) $alertStmt->fetchColumn();
} catch (PDOException $e) {
    // Silently ignore if DB is unavailable
}
?>

<!-- Preloader -->
<div class="preloader" id="pagePreloader">
    <div class="loader-spinner"></div>
    <div class="loader-text">Securing</div>
</div>

<!-- Floating Particles -->
<div class="particles-container" id="particles"></div>

<aside class="sidebar">
    <div class="sidebar-brand">
        <div class="shield-icon">🛡</div>
        <div class="brand-text">
            <h2>HIPS</h2>
            <span>Security Dashboard</span>
        </div>
    </div>

    <nav class="sidebar-nav">
        <div class="nav-section-title">Overview</div>

        <a href="dashboard.php" class="nav-item <?= $currentPage === 'dashboard' ? 'active' : '' ?>">
            <span class="nav-icon">📊</span>
            <span>Dashboard</span>
        </a>

        <a href="alerts.php" class="nav-item <?= $currentPage === 'alerts' ? 'active' : '' ?>">
            <span class="nav-icon">🔔</span>
            <span>Live Alerts</span>
            <?php if ($alertCount > 0): ?>
            <span class="nav-badge"><?= $alertCount ?></span>
            <?php endif; ?>
        </a>

        <div class="nav-section-title">Monitoring</div>

        <a href="file-monitor.php" class="nav-item <?= $currentPage === 'file-monitor' ? 'active' : '' ?>">
            <span class="nav-icon">📁</span>
            <span>File Monitor</span>
        </a>

        <a href="network-monitor.php" class="nav-item <?= $currentPage === 'network-monitor' ? 'active' : '' ?>">
            <span class="nav-icon">🌐</span>
            <span>Network Monitor</span>
        </a>

        <a href="process-monitor.php" class="nav-item <?= $currentPage === 'process-monitor' ? 'active' : '' ?>">
            <span class="nav-icon">🔄</span>
            <span>Process Monitor</span>
        </a>

        <a href="registry-monitor.php" class="nav-item <?= $currentPage === 'registry-monitor' ? 'active' : '' ?>">
            <span class="nav-icon">📝</span>
            <span>Registry Monitor</span>
        </a>

        <div class="nav-section-title">Management</div>

        <a href="agents.php" class="nav-item <?= $currentPage === 'agents' ? 'active' : '' ?>">
            <span class="nav-icon">🖥</span>
            <span>Agents</span>
        </a>

        <a href="events.php" class="nav-item <?= $currentPage === 'events' ? 'active' : '' ?>">
            <span class="nav-icon">📋</span>
            <span>Event History</span>
        </a>

        <a href="commands.php" class="nav-item <?= $currentPage === 'commands' ? 'active' : '' ?>">
            <span class="nav-icon">⌨</span>
            <span>Send Command</span>
        </a>

        <div class="nav-section-title">Analytics</div>

        <a href="reports.php" class="nav-item <?= $currentPage === 'reports' ? 'active' : '' ?>">
            <span class="nav-icon">📈</span>
            <span>Reports</span>
        </a>

        <a href="settings.php" class="nav-item <?= $currentPage === 'settings' ? 'active' : '' ?>">
            <span class="nav-icon">⚙</span>
            <span>Settings</span>
        </a>
    </nav>

    <div class="sidebar-footer">
        <!-- Theme Toggle -->
        <button class="theme-toggle-btn" id="themeToggle" title="Switch theme">
            <span class="theme-icon" id="themeIcon">🌙</span>
            <span id="themeLabel">Dark Mode</span>
        </button>
        <div style="display:flex; align-items:center; justify-content:space-between; margin-top:12px;">
            <span>👤 <?= htmlspecialchars($adminName) ?></span>
            <a href="logout.php" style="color:var(--text-muted); font-size:12px;">Logout</a>
        </div>
    </div>
</aside>

<script>
/* ── Theme Toggle ─────────────────────────────────────────────── */
(function initTheme() {
    const toggle = document.getElementById('themeToggle');
    const icon   = document.getElementById('themeIcon');
    const label  = document.getElementById('themeLabel');
    const stored = localStorage.getItem('hips-theme') || 'dark';

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        if (theme === 'light') {
            icon.textContent = '☀️';
            label.textContent = 'Light Mode';
        } else {
            icon.textContent = '🌙';
            label.textContent = 'Dark Mode';
        }
        localStorage.setItem('hips-theme', theme);
    }

    applyTheme(stored);

    toggle.addEventListener('click', function() {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        applyTheme(current === 'dark' ? 'light' : 'dark');
    });
})();

/* ── Preloader dismiss ───────────────────────────────────────── */
window.addEventListener('load', function() {
    const preloader = document.getElementById('pagePreloader');
    if (preloader) {
        setTimeout(() => {
            preloader.classList.add('hidden');
            setTimeout(() => preloader.style.display = 'none', 600);
        }, 300);
    }
});

/* ── Floating Particle Generator ─────────────────────────────── */
(function initParticles() {
    const container = document.getElementById('particles');
    if (!container) return;
    const types = ['particle--dot', 'particle--ring', 'particle--glow'];
    const count = 30;
    for (let i = 0; i < count; i++) {
        const p = document.createElement('div');
        const type = types[Math.floor(Math.random() * types.length)];
        p.className = 'particle ' + type;
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDelay = (Math.random() * 20).toFixed(1) + 's';
        p.style.animationDuration = (15 + Math.random() * 15).toFixed(1) + 's';
        container.appendChild(p);
    }
})();

/* ── Scroll-Reveal Observer ──────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    const elements = document.querySelectorAll('.scroll-reveal');
    if (!elements.length) return;

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.05, rootMargin: '50px 0px 0px 0px' });

    elements.forEach(function(el) { observer.observe(el); });
});

/* ── Stat Number Count-Up Animation ──────────────────────────── */
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.stat-value[data-count]').forEach(function(el) {
        const target = parseInt(el.getAttribute('data-count'), 10);
        if (isNaN(target) || target === 0) return;
        let current = 0;
        const duration = 1200;
        const step = Math.max(1, Math.ceil(target / (duration / 16)));
        const timer = setInterval(function() {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            el.textContent = current;
        }, 16);
    });
});
</script>
