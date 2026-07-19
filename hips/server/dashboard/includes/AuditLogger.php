<?php
/**
 * HIPS — Audit Logger
 * Records administrative actions for accountability and security forensic auditing.
 */
class AuditLogger {
    /**
     * Logs an administrative action to the database.
     */
    public static function log(string $action, ?string $targetType = null, ?string $targetId = null, ?array $details = null): void {
        global $pdo;
        
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $userId   = $_SESSION['admin_user_id'] ?? 0;
        $username = $_SESSION['admin_username'] ?? 'system';
        $ip       = getClientIP();
        $detailsJson = $details ? json_encode($details) : null;

        try {
            $stmt = $pdo->prepare(
                "INSERT INTO dashboard_audit_log (user_id, username, action, target_type, target_id, details, ip_address)
                 VALUES (:uid, :uname, :action, :ttype, :tid, :details, :ip)"
            );
            $stmt->execute([
                ':uid'     => $userId,
                ':uname'   => $username,
                ':action'  => $action,
                ':ttype'   => $targetType,
                ':tid'     => $targetId,
                ':details' => $detailsJson,
                ':ip'      => $ip
            ]);
        } catch (PDOException $e) {
            // Silently fail to avoid breaking the UI if audit logging fails
            error_log("Audit Logger Error: " . $e->getMessage());
        }
    }
}
?>
