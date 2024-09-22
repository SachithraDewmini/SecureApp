<?php
require 'config.php';
checkUserRole('user'); // Access Control: Verify user has the required role

// Secure session management: Ensure session is started and only the right user is logged in.
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Sanitize and validate user input for security (even though we use session data, always validate)
$user_id = filter_var($_SESSION['user_id'], FILTER_VALIDATE_INT); 

if (!$user_id) {
    // If user ID is not valid, redirect or throw an error securely
    echo "<script>alert('Invalid user session.'); window.location.href = 'login.php';</script>";
    exit();
}

// Use of Parameterized Queries to prevent SQL Injection for fetching user details
$userStmt = $conn->prepare("SELECT username, email FROM users WHERE id = ?");
$userStmt->execute([$user_id]); // SQL Injection prevention
$user = $userStmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    // Secure error handling for missing user data
    echo "<script>alert('User not found.'); window.location.href = 'login.php';</script>";
    exit();
}

// Use of Parameterized Queries to prevent SQL Injection for fetching user activities
$activityStmt = $conn->prepare("SELECT * FROM user_activity WHERE user_id = ?");
$activityStmt->execute([$user_id]); // SQL Injection prevention
$activities = $activityStmt->fetchAll(PDO::FETCH_ASSOC);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
            color: #333;
        }
        h1, h2 {
            text-align: center;
            color: #000;
        }
        h2 {
            color: #dc3545;
            border-bottom: 2px solid #dc3545;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .activ {
            color: #007bff; /* Blue color for the "Your Activities" heading */
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .container {
            width: 80%;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
            position: relative; /* Added for positioning logout button */
        }
        .profile {
            margin-bottom: 20px;
            padding: 20px;
            background-color: #000;
            color: #fff;
            border-radius: 8px;
            border: 1px solid #ddd;
            position: relative; /* Added for positioning logout button */
        }
        .profile p {
            margin: 10px 0;
        }
        .logout-button {
            position: absolute; /* Changed to absolute for positioning */
            top: 20px;
            right: 20px;
            display: block;
            width: 120px;
            text-align: center;
            padding: 10px;
            background-color: #dc3545;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }
        .logout-button:hover {
            background-color: #c82333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #000;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #000;
            color: #fff;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #e6e6e6;
        }
    </style>
</head>
<body>
    <div class="container">
        
        <h1>Welcome to your Dashboard</h1>
        
        <!-- User Profile -->
        <div class="profile">
            <h2>Your Profile</h2>
            <a href="logout.php" class="logout-button">Logout</a>
            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); // XSS Prevention ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); // XSS Prevention ?></p>
        </div>
        
        <!-- User Activities -->
        <h2 class="activ">Your Activities</h2>
        <table>
            <tr>
                <th>Activity</th>
                <th>Timestamp</th>
            </tr>
            <?php foreach ($activities as $activity): ?>
                <tr>
                    <td><?php echo htmlspecialchars($activity['activity']); // XSS Prevention ?></td>
                    <td><?php echo htmlspecialchars($activity['timestamp']); // XSS Prevention ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
    </div>
</body>
</html>

<?php
// Password Management: Ensure strong passwords and hashing (this would be elsewhere in the user registration system).
// CIA (Confidentiality, Integrity, Availability) principles: Ensure secure communication (e.g., HTTPS), data integrity, and availability.
// AAA (Authentication, Authorization, Accounting): Implement access controls like role-based access, log user activities, and track sessions.
?>
