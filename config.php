<?php
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
$host = 'mysql-25c165a8-sdpanditha123-53de.c.aivencloud.com';
$port = '28759';  // Add your database port
$dbname = 'secureapp_db';
$username = 'avnadmin';
$password = 'AVNS_k5GLZnpRS6KhTJgSY0q';


try {
   
    // Establish connection using PDO with SSL
    $conn = new PDO("mysql:host=$host;port=$port;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); // Error handling mode
    $conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);         // Protect against SQL injection

} catch (PDOException $e) {
    // Log detailed error for debugging
    error_log($e->getMessage(), 0);

    // User-friendly error message
    die("Database connection failed. Please try again later.");
}

// Role-based access control function
function checkUserRole($role) {
    if (!isset($_SESSION['user_role']) || $_SESSION['user_role'] !== $role) {
        header("Location: login.php");
        exit();
    }
}
?>
