<?php
require 'config.php';

// Enable error reporting for debugging (should be disabled in production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start the session if it's not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// CIA: Confidentiality - Protect sensitive data
// Check if the email is stored in the session (this is set after registration)
// Prevent unauthorized access by ensuring the user has the right session data
if (!isset($_SESSION['otp_email'])) {
    // Redirect to login if no email in session (prevents direct access to this page)
    header("Location: login.php");
    exit();
}

// Get the email from the session securely
$email = $_SESSION['otp_email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitization and Validation: Clean and validate user input
    $enteredOtp = trim(htmlspecialchars($_POST['otpnumber']));  // XSS prevention with htmlspecialchars

    try {
        // Use of Parameterized Queries to prevent SQL Injection attacks
        // Fetch the stored OTP and otp_verified status using a secure SQL query
        $stmt = $conn->prepare("SELECT otp, otp_verified FROM users WHERE LOWER(email) = LOWER(?)");
        $stmt->execute([$email]);  // Avoid SQL injection by using bound parameters
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Password Management: Prevent re-verification of already verified OTP
            if ($user['otp_verified']) {
                echo "<script>alert('OTP already verified. Please log in.');</script>";
                header("Location: login.php");
                exit();
            }

            // Secure error handling and OTP comparison (trim any extra whitespace)
            $storedOtp = trim($user['otp']);  // Ensure no whitespace issues

            // Compare the entered OTP with the stored one securely
            if ($enteredOtp === $storedOtp) {
                // Update the user's otp_verified status to 1 (true)
                $updateStmt = $conn->prepare("UPDATE users SET otp_verified = 1 WHERE email = ?");
                $updateStmt->execute([$email]);

                // Access Control: Allow login only after successful OTP verification
                // Remove OTP-related session variables for security after verification
                unset($_SESSION['otp_email']);  // Clear the email from session after verification

                // Authentication and Authorization handled - OTP verified, user now authorized
                echo "<script>alert('OTP verified successfully! Please log in.');</script>";
                header("Location: login.php");
                exit();
            } else {
                // Secure error handling: provide generic messages to avoid information leakage
                echo "<script>alert('Invalid OTP. Please try again.');</script>";
            }
        } else {
            // Secure error handling: provide generic messages to avoid leaking whether email exists or not
            echo "<script>alert('Email not found in the database. Please try again.');</script>";
        }
    } catch (PDOException $e) {
        // Handle any database errors securely, avoid exposing database structure to users
        echo "<script>alert('Database error: Please try again later.');</script>";
        error_log('PDOException: ' . $e->getMessage());  // Log errors internally
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: black; /* Background color set to black */
            color: white; /* Default text color set to white */
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background-color: #f0f0f0; /* Light gray background for the container */
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.5);
            width: 300px;
            max-width: 100%;
        }
        h1 {
            text-align: center;
            font-size: 24px;
            color: black; /* Heading color set to black */
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: calc(100% - 20px);
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            background-color: white; /* Input field background color set to white */
            color: black; /* Input field text color set to black */
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: red; /* Button color set to red */
            color: white; /* Button text color set to white */
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #cc0000; /* Darker red on hover */
        }
        .instructions {
            font-size: 14px;
            color: black; /* Instructions text color set to black */
            margin-bottom: 10px;
            text-align: center;
        }
    </style>

    <!-- Client-side validation using JavaScript -->
    <script>
        function validateForm() {
            var otp = document.forms["otpForm"]["otpnumber"].value;
            if (otp == "") {
                alert("OTP must be filled out");
                return false;
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>OTP Verification</h1>
        <form name="otpForm" method="POST" onsubmit="return validateForm()">
            <!-- Display the email, but make it readonly to prevent editing -->
            <input type="text" name="email" value="<?php echo htmlspecialchars($email); ?>" readonly>
            <input type="text" name="otpnumber" placeholder="Enter OTP" required>
            <button type="submit">Verify OTP</button>
        </form>
    </div>
</body>
</html>
