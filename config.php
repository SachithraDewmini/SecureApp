<?php
// Load environment variables from .env file
require_once __DIR__ . '/vendor/autoload.php'; // Ensure you have Composer's autoload file
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Secure session settings (must be set before session_start)
if (session_status() == PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS'])); // Set to 1 if using HTTPS
    ini_set('session.use_strict_mode', 1);

    session_start();
}

// Regenerate session ID every 30 mins
if (!isset($_SESSION['CREATED'])) {
    $_SESSION['CREATED'] = time();
} elseif (time() - $_SESSION['CREATED'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['CREATED'] = time();
}

// Database connection
$host = $_ENV['DB_HOST'] ;
$dbname = $_ENV['DB_NAME'] ;
$username = $_ENV['DB_USER'] ;
$password = $_ENV['DB_PASS'] ;

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);                          // SQL injection protection
} catch (PDOException $e) {
    error_log($e->getMessage(), 0);                                                   // Log error message
    die("Database connection failed. Please try again later.");                    // User-friendly error message
}

// Role-based access control
function checkUserRole($role) {
    if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== $role) {
        header("Location: login.php");
        exit();
    }
}
?>
