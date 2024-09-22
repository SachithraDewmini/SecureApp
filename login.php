<?php
require 'config.php'; // Include configuration file for secure database connection

// Check if session is already started
if (session_status() === PHP_SESSION_NONE) {
    // Session Management: Secure session initialization with HttpOnly and Secure flags for cookies
    ini_set('session.cookie_httponly', 1); // Helps protect against XSS attacks
    ini_set('session.cookie_secure', 1);   // Ensures cookies are sent only over HTTPS
    session_start();
    session_regenerate_id(true); // Regenerates session ID to prevent session fixation attacks
}

// Function to log user activity
// AAA (Accounting): Logs user actions for accountability
function logUserActivity($userId, $activity) {
    global $conn;
    // SQL Injection Protection: Using parameterized queries to prevent SQL injection
    $stmt = $conn->prepare("INSERT INTO user_activity (user_id, activity, timestamp) VALUES (?, ?, NOW())");
    $stmt->execute([$userId, $activity]);
}

// Function to generate a CSRF token
// Security: Protects against Cross-Site Request Forgery (CSRF) attacks
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Generates a secure CSRF token
    }
    return $_SESSION['csrf_token'];
}

// Function to check CSRF token validity
// Security: Ensures the CSRF token is valid
function verifyCsrfToken($token) {
    return $token === $_SESSION['csrf_token']; // Verifies token matches session token
}

// Function to handle account lockout after failed login attempts
// Password Management: Lockout mechanism to prevent brute force attacks
function handleAccountLockout($userId) {
    global $conn;
    $lockoutTime = new DateTime();
    $lockoutTime->add(new DateInterval('PT3M')); // 3 minutes lockout for security

    // SQL Injection Protection: Parameterized query to securely update lockout time
    $stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, lockout_time = ? WHERE id = ?");
    $stmt->execute([$lockoutTime->format('Y-m-d H:i:s'), $userId]);
}

$remainingLockoutTime = null;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF Protection: Ensures that the request comes from the authenticated user
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        die('CSRF token validation failed.'); // Secure error handling with a generic message
    }

    // Sanitization and Validation: Sanitize and validate user inputs
    $username_or_email = htmlspecialchars(trim($_POST['username_or_email'])); // Prevents XSS by escaping HTML
    $password = htmlspecialchars($_POST['password']); // Escapes HTML to prevent XSS attacks

    // Server-side validation: Ensure fields are not empty
    if (empty($username_or_email) || empty($password)) {
        echo "<script>alert('Please fill in all fields.');</script>"; // Client-side validation with JavaScript alert
        exit;
    }

    // Sanitization and Validation: Determine if input is a valid email or username
    $field = filter_var($username_or_email, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

    // SQL Injection Protection: Use parameterized query to prevent SQL injection
    $stmt = $conn->prepare("SELECT id, username, email, password, role, otp_verified, failed_attempts, lockout_time FROM users WHERE $field = ?");
    $stmt->execute([$username_or_email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Access Control: Implement account lockout mechanism based on failed login attempts
        if ($user['lockout_time'] && new DateTime() < new DateTime($user['lockout_time'])) {
            // Calculates remaining lockout time for user
            $lockoutEnd = new DateTime($user['lockout_time']);
            $remainingLockoutTime = $lockoutEnd->getTimestamp() - (new DateTime())->getTimestamp();
            echo "<script>
                    var remainingTime = $remainingLockoutTime;
                    document.addEventListener('DOMContentLoaded', function() {
                        updateLockoutTimer(remainingTime);
                    });
                  </script>";
            echo "<script>alert('Your account is temporarily locked due to multiple failed login attempts. Please try again later.');</script>";
            exit;
        }

        // Password Management: Verifying the password using password_hash() and password_verify()
        if (password_verify($password, $user['password'])) {
            // Reset failed attempts and unlock account if login is successful
            $stmt = $conn->prepare("UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE id = ?");
            $stmt->execute([$user['id']]);

            // Access Control: Ensure OTP verification before allowing login
            if ($user['otp_verified'] == 1) {
                // AAA (Authentication, Authorization): Authenticate user and store session details
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_role'] = $user['role'];

                logUserActivity($user['id'], 'Login'); // Logs user activity for security and accountability

                // Redirect based on user role (Access Control)
                if ($user['role'] === 'admin') {
                    header("Location: admin_dashboard.php"); // Admin access
                } else {
                    header("Location: user_dashboard.php"); // User access
                }
                exit();
            } else {
                // Secure error handling: Inform the user if their account is not verified
                echo "<script>alert('Your account has not been verified. Please verify your account via OTP.');</script>";
            }
        } else {
            // Password Management: Lock account after 3 failed attempts to mitigate brute force attacks
            $failedAttempts = $user['failed_attempts'] + 1;

            if ($failedAttempts >= 3) {
                handleAccountLockout($user['id']); // Lockout the account after 3 failed attempts
                echo "<script>alert('Your account has been locked due to multiple failed login attempts. Please try again after 3 minutes.');</script>";
            } else {
                // SQL Injection Protection: Use parameterized queries to update failed attempts
                $stmt = $conn->prepare("UPDATE users SET failed_attempts = ? WHERE id = ?");
                $stmt->execute([$failedAttempts, $user['id']]);
                echo "<script>alert('Invalid password. Please try again.');</script>"; // Secure error handling
            }
        }
    } else {
        // Secure error handling: Generic error message to avoid information leakage
        echo "<script>alert('Invalid username, email, or password.');</script>";
    }
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #000000; /* Black background for the entire page */
            margin: 0;
        }
        .container {
            background-color: #f8f9fa; /* Light gray background for the form container */
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            width: 360px;
            max-width: 100%;
            text-align: center;
        }
        h1 {
            margin: 0 0 20px;
            font-size: 28px;
            color: #000000; /* Black text for heading */
        }
        input[type="text"], input[type="password"] {
            width: calc(100% - 20px);
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ced4da; /* Light border color */
            border-radius: 4px;
            box-sizing: border-box;
            display: inline-block;
            font-size: 16px;
        }
        .password-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }
        .password-wrapper input {
            width: calc(100% - 40px); /* Adjust width for the icon */
        }
        .password-wrapper .toggle-password {
            position: absolute;
            right: 10px;
            cursor: pointer;
            font-size: 18px;
            color: #ff0000; /* Red color for the eye icon */
        }
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 4px;
            background-color: #ff0000; /* Red color for the button */
            color: #ffffff;
            font-size: 16px;
            cursor: pointer;
            margin-top: 10px;
        }
        button:hover {
            background-color: #cc0000; /* Darker red on hover */
        }
        .links {
            margin-top: 15px;
        }
        .links a {
            color: #0000FF; /* Red color for the links */
            text-decoration: none;
            font-size: 14px;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .lockout-timer {
            font-size: 14px;
            color: #000000; /* Black color for lockout message */
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <form method="POST" onsubmit="return validateForm()">
            <input type="text" name="username_or_email" id="username_or_email" placeholder="Username or Email" required>
            <div class="password-wrapper">
                <input type="password" name="password" id="password" placeholder="Password" required>
                <span class="toggle-password" id="password-icon" onclick="togglePassword()">👁️</span>
            </div>
            <input type="hidden" name="csrf_token" value="<?php echo generateCsrfToken(); ?>">
            <button type="submit">Login</button>
        </form>

        <div class="lockout-timer" id="lockout-timer">
            <?php
            if ($remainingLockoutTime) {
                echo "<p>Your account is locked. Please try again after <span id='remaining-time'>$remainingLockoutTime</span> seconds.</p>";
            }
            ?>
        </div>

        <div class="links">
            <a href="forgot_password.php" class="forgot">Forgot Password</a><br>
            <p>Don't have an account?<a href="register.php" class="signup">Sign Up</a></p>
        </div>
    </div>

    <script>
        function validateForm() {
            const usernameOrEmail = document.getElementById('username_or_email').value;
            const password = document.getElementById('password').value;

            if (usernameOrEmail.trim() === '' || password.trim() === '') {
                alert('All fields are required.');
                return false;
            }

            return true;
        }

        function togglePassword() {
            const passwordField = document.getElementById('password');
            const passwordIcon = document.getElementById('password-icon');
            const passwordFieldType = passwordField.getAttribute('type');

            if (passwordFieldType === 'password') {
                passwordField.setAttribute('type', 'text');
                passwordIcon.textContent = '🙈'; // Changed to an eye-off emoji
            } else {
                passwordField.setAttribute('type', 'password');
                passwordIcon.textContent = '👁️'; // Changed to an eye emoji
            }
        }

        function updateLockoutTimer(remainingTime) {
            const timerElement = document.getElementById('remaining-time');
            const timerInterval = setInterval(() => {
                if (remainingTime <= 0) {
                    clearInterval(timerInterval);
                    timerElement.textContent = '0';
                    return;
                }
                remainingTime--;
                timerElement.textContent = remainingTime;
            }, 1000);
        }
    </script>
</body>
</html>
