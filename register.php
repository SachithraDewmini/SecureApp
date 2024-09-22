<?php
require 'config.php';  // Database configuration and management (CIA: Confidentiality - Only authorized access to the database)
use PHPMailer\PHPMailer\PHPMailer;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitization and Validation: Clean and validate input to prevent XSS and SQL Injection (CIA: Integrity)
    $username = htmlspecialchars(trim($_POST['username']));              // Sanitize to prevent XSS attacks
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL); // Sanitize email input
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    // Server-side validation (AAA: Authentication & Authorization, CIA: Integrity)
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email format.');window.location.href='register.php';</script>";
        exit(); // Stop further execution on invalid data
    }
    if ($password !== $confirmPassword) {
        echo "<script>alert('Passwords do not match.');window.location.href='register.php';</script>";
        exit(); // Stop further execution if passwords don't match
    }
    if (strlen($password) < 8 || !preg_match("/[A-Z]/", $password) || !preg_match("/[a-z]/", $password) || !preg_match("/[0-9]/", $password) || !preg_match("/[\W_]/", $password)) {
        echo "<script>alert('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.');window.location.href='register.php';</script>";
        exit(); // Stop further execution if password doesn't meet the security standards
    }

    // Use of Parameterized Queries (SQL Injection protection)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$username, $email]); // Prevents SQL Injection by using bound parameters
    $count = $stmt->fetchColumn();

    if ($count > 0) {
        echo "<script>alert('Username or email already exists.');window.location.href='register.php';</script>";
        exit();
    }

    
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT); 


    $otp = rand(100000, 999999);  
    

    // SQL Injection protection via prepared statements (SQL Protection)
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, otp, role) VALUES (?, ?, ?, ?, 'user')");
    if ($stmt->execute([$username, $email, $hashedPassword, $otp])) {
        // Send OTP via email (CIA: Confidentiality - Ensuring email transport security)
        require 'vendor/autoload.php';
        $mail = new PHPMailer();
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com'; // SMTP host (ensure secure email server)
        $mail->SMTPAuth = true;
        $mail->Username = 'sdpanditha123@gmail.com'; // Sensitive data, consider storing in environment variables
        $mail->Password = 'novi djyp uasu hzwd'; // Never hard-code credentials in production
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Use strong encryption for email communication (CIA: Confidentiality)
        $mail->Port = 465; // Secure port for email transmission
        $mail->setFrom('from@example.com', 'Mailer'); // Set a valid sender email
        $mail->addAddress($email); // Recipient email
        $mail->Subject = 'OTP Verification'; // Subject of the email
        $mail->Body = "Your OTP is: $otp"; // OTP for account verification (AAA: Authentication)
        $mail->send(); // Send the email securely

        // Session Management (CIA: Confidentiality & Integrity)
        session_start(); // Ensure session is started securely for storing sensitive session data
        $_SESSION['otp_email'] = $email; // Store email in session for OTP verification

        // Redirect to OTP verification page (CIA: Availability)
        header("Location: otp_verify.php");
        exit(); // Ensure no further script execution
    } else {
        // Secure error handling (no sensitive details exposed) (CIA: Confidentiality)
        echo "<script>alert('Registration failed.');</script>";
    }
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <style>
        /* General CSS styling for form and UI (CIA: Availability - Good UX) */
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #000; /* Set background color to black */
            margin: 0;
        }
        .container {
            background-color: #f4f4f4; /* Light gray background */
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 300px;
            max-width: 100%;
            position: relative;
        }
        h1 {
            margin-top: 0;
            font-size: 24px;
            text-align: center;
            color: #000000; /* White text for the header */
        }
        input[type="text"], input[type="email"], input[type="password"] {
            width: calc(100% - 20px);
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            background-color: #fff; /* White background for input fields */
            color: #000; /* Black text for input fields */
        }
        button {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 4px;
            background-color: #ff0000; /* Red background for buttons */
            color: #fff; /* White text for buttons */
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background-color: #cc0000; /* Darker red for hover state */
        }
        .toggle-password {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #ff0000; /* Red eye icon color */
        }
        .password-container {
            position: relative;
        }
        .password-strength {
            margin-top: 5px;
            font-size: 12px;
            color: #fff; /* White text for password strength */
        }
        .password-instructions {
            margin-top: 10px;
            font-size: 14px;
            color: #000000; /* Light gray for password instructions */
        }
        .strength-weak {
            color: #ff4d4d;
        }
        .strength-moderate {
            color: #ffcc00;
        }
        .strength-strong {
            color: #00cc00;
        }
        .alert-box {
            display: none;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid transparent;
            border-radius: 4px;
            position: absolute;
            width: 90%;
            top: 10px;
            left: 5%;
        }
        .alert-box.error {
            color: #f44336;
            background-color: #fdd;
            border-color: #f44336;
        }
        .alert-box.success {
            color: #4CAF50;
            background-color: #ddffdd;
            border-color: #4CAF50;
        }
    </style>
    <script>
        // Toggle Password Visibility (Improves UX)
        function togglePassword(id) {
            const passwordField = document.getElementById(id);
            const passwordFieldType = passwordField.getAttribute('type');
            if (passwordFieldType === 'password') {
                passwordField.setAttribute('type', 'text');
                document.getElementById(id + '_icon').textContent = '🙈';
            } else {
                passwordField.setAttribute('type', 'password');
                document.getElementById(id + '_icon').textContent = '👁️';
            }
        }

        // Check Password Strength (Client-side validation)
        function checkPasswordStrength(password) {
            let strength = "Weak";
            if (password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password) && /[\W_]/.test(password)) {
                strength = "Strong";
            } else if (password.length >= 6) {
                strength = "Moderate";
            }
            return strength;
        }

        // Update Password Strength Indicator
        function updatePasswordStrength() {
            const password = document.getElementById("password").value;
            const strength = checkPasswordStrength(password);
            const strengthText = document.getElementById("password-strength-text");
            if (strength === "Weak") {
                strengthText.textContent = "Weak";
                strengthText.classList.add("strength-weak");
            } else if (strength === "Moderate") {
                strengthText.textContent = "Moderate";
                strengthText.classList.add("strength-moderate");
            } else if (strength === "Strong") {
                strengthText.textContent = "Strong";
                strengthText.classList.add("strength-strong");
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Register</h1>
        <form method="POST" action="register.php" onsubmit="return validateForm()">
            <input type="text" name="username" placeholder="Username" required>
            <input type="email" name="email" placeholder="Email" required>
            <div class="password-container">
                <input type="password" name="password" id="password" placeholder="Password" oninput="updatePasswordStrength()" required>
                <span id="password_icon" class="toggle-password" onclick="togglePassword('password')">👁️</span>
            </div>
            <div class="password-container">
                <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirm Password" required>
                <span id="confirm_password_icon" class="toggle-password" onclick="togglePassword('confirm_password')">👁️</span>
            </div>
            <div id="password-strength-text" class="password-strength"></div>
            <div class="password-instructions">
                Password must be at least 8 characters long, contain uppercase and lowercase letters, numbers, and special characters.
            </div>
            <button type="submit">Register</button>
        </form>
    </div>
</body>
</html>
