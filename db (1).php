<?php
$envPath = __DIR__ . '/.env';
if (!file_exists($envPath)) {
    die("No .env file found at: $envPath");
}

$env = parse_ini_file($envPath);
if ($env === false) {
    die("Found .env but failed to parse it — check syntax.");
}

$host = $env['DB_HOST'] ?? 'localhost';
$port = $env['DB_PORT'] ?? 3306;

if (empty($env['DB_USER']) || !isset($env['DB_PASS']) || empty($env['DB_NAME'])) {
    die("Missing required DB credentials in .env file.");
}

$user = $env['DB_USER'];
$pass = $env['DB_PASS'];
$db   = $env['DB_NAME'];

$dsn = "mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::ATTR_TIMEOUT            => 5,
    ]);
} catch (PDOException $e) {
    error_log("DB connection failed: " . $e->getMessage());
    die("Database connection failed. Please try again later.");
}