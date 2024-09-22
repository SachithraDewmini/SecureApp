<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $otp = htmlspecialchars(trim($_POST['otp']));
    $newPassword = htmlspecialchars(trim($_POST['new_password']));
    $confirmPassword = htmlspecialchars(trim($_POST['confirm_password']));

    if (empty($otp) || empty($newPassword) || empty($confirmPassword)) {
        echo "<script>alert('Please fill in all fields.');window.location.href='reset_password.php';</script>";
        exit;
    }

    if ($newPassword !== $confirmPassword) {
        echo "<script>alert('Passwords do not match.');window.location.href='reset_password.php';</script>";
        exit;
    }

    if (!preg_match('/[A-Z]/', $newPassword) || !preg_match('/[a-z]/', $newPassword) || !preg_match('/\d/', $newPassword) || !preg_match('/[\W_]/', $newPassword) || strlen($newPassword) < 8) {
        echo "<script>alert('Password must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters.');window.location.href='reset_password.php';</script>";
        exit;
    }

    // Check OTP validity and verification status
    $stmt = $conn->prepare("SELECT user_id, otp_expiry, otp_verified FROM password_resets WHERE otp = ?");
    $stmt->execute([$otp]);
    $reset = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($reset) {
        if ($reset['otp_verified'] == 1) {
            echo "<script>alert('OTP has already been verified and used.');window.location.href='forgot_password.php';</script>";
            exit;
        }

        // Mark OTP as verified
        $stmt = $conn->prepare("UPDATE password_resets SET otp_verified = 1 WHERE otp = ?");
        $stmt->execute([$otp]);

        // Store user_id in session
        session_start();
        $_SESSION['user_id'] = $reset['user_id'];

        // Hash the new password
        $newPasswordHash = password_hash($newPassword, PASSWORD_BCRYPT);

        // Update the user's password
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$newPasswordHash, $_SESSION['user_id']]);

        // Remove the OTP record (optional for security reasons)
        $stmt = $conn->prepare("DELETE FROM password_resets WHERE otp = ?");
        $stmt->execute([$otp]);

        echo "<script>alert('Password has been reset successfully. You can now login.');window.location.href='login.php';</script>";
    } else {
        echo "<script>alert('Invalid or expired OTP.');window.location.href='reset_password.php';</script>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: black;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #f0f0f0;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 300px;
            max-width: 100%;
        }
        h1 {
            text-align: center;
            font-size: 24px;
            color: black;
            margin-bottom: 20px;
        }
        input[type="text"], input[type="password"] {
            width: calc(100% - 40px);
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: white;
            color: black;
        }
        input[type="password"] {
            padding-right: 40px;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: red;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #cc0000;
        }
        .instructions {
            font-size: 14px;
            color: black;
            margin-bottom: 10px;
            text-align: left;
        }
        .password-strength {
            font-size: 14px;
            color: black;
            margin-bottom: 10px;
            text-align: left;
        }
        .password-strength span {
            font-weight: bold;
            color: green;
        }
        .password-strength span.weak {
            color: red;
        }
        .password-strength span.moderate {
            color: orange;
        }
        .password-strength span.strong {
            color: green;
        }
        .view-icon {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            font-size: 18px;
            color: black;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reset Password</h1>
        <form action="reset_password.php" method="POST">
            <input type="text" name="otp" placeholder="Enter OTP" required>
            <div style="position: relative;">
                <input type="password" id="new_password" name="new_password" placeholder="New Password" required oninput="showPasswordStrength()">
                <span class="view-icon" id="new_password_icon" onclick="togglePassword('new_password')">👁️</span>
            </div>
            
            <div style="position: relative;">
                <input type="password" id="confirm_password" name="confirm_password" placeholder="Confirm Password" required>
                <span class="view-icon" id="confirm_password_icon" onclick="togglePassword('confirm_password')">👁️</span>
            </div>
            <div id="passwordStrength" class="password-strength"></div>
            <div class="instructions">
                Password must be at least 8 characters long and include uppercase letters, lowercase letters, numbers, and special characters.
            </div>
            <button type="submit">Reset Password</button>
        </form>
    </div>

    <script>
        function showPasswordStrength() {
            var newPassword = document.getElementById('new_password').value;
            var strength = getPasswordStrength(newPassword);
            var passwordStrength = document.getElementById('passwordStrength');
            passwordStrength.innerHTML = ' <span class="' + strength.toLowerCase() + '">' + strength + '</span>';
        }

        function getPasswordStrength(password) {
            var strength = 'Weak';
            var regex = {
                lower: /[a-z]/,
                upper: /[A-Z]/,
                digit: /\d/,
                special: /[\W_]/,
                length: /.{8,}/
            };
            if (regex.lower.test(password) && regex.upper.test(password) && regex.digit.test(password) && regex.special.test(password) && regex.length.test(password)) {
                strength = 'Strong';
            } else if (regex.length.test(password)) {
                strength = 'Moderate';
            }
            return strength;
        }

        function togglePassword(id) {
            const passwordField = document.getElementById(id);
            const passwordFieldType = passwordField.getAttribute('type');
            const viewIcon = document.getElementById(id + '_icon');
            
            if (passwordFieldType === 'password') {
                passwordField.setAttribute('type', 'text');
                viewIcon.textContent = '🙈';
            } else {
                passwordField.setAttribute('type', 'password');
                viewIcon.textContent = '👁️';
            }
        }
    </script>
</body>
</html>

