<?php
/**
 * HIPS — CSRF Protection Handler
 * Implements Synchronizer Token Pattern to prevent Cross-Site Request Forgery.
 */
class CsrfHandler {
    /**
     * Generates a CSRF token if one doesn't exist, and returns it.
     */
    public static function getToken(): string {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    /**
     * Validates the provided token against the session token.
     */
    public static function validate(?string $token): bool {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $storedToken = $_SESSION['csrf_token'] ?? '';
        if (empty($storedToken) || empty($token)) {
            return false;
        }
        return hash_equals($storedToken, $token);
    }

    /**
     * Generates a hidden input field for forms.
     */
    public static function insertField(): void {
        echo '<input type="hidden" name="csrf_token" value="' . self::getToken() . '">';
    }
}
?>
