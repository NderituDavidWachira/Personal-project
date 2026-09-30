<?php
/**
 * bootstrap.php - session, error handling, security headers, DB.
 * require_once this first in every page (student.php, enroll.php ...).
 */
require_once __DIR__ . '/Config.php';

ini_set('session.use_strict_mode', '1');
$isSecure = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off');
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'domain' => '',
    'secure' => $isSecure, 'httponly' => true, 'samesite' => 'Lax',
]);
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Never show PHP errors to visitors in production (set APP_DEBUG=true locally only)
$appDebug = filter_var(cfg('APP_DEBUG', 'false'), FILTER_VALIDATE_BOOLEAN);
ini_set('display_errors', $appDebug ? '1' : '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; img-src 'self' https: data:; "
     . "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
     . "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
     . "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com;");

require_once __DIR__ . '/db.php';   // must define $pdo