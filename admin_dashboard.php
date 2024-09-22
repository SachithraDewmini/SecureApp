<?php
require 'config.php';

// Session Management: Ensure that the user session is validated and the role is checked.
checkUserRole('admin'); // Access Control: Only admin users can access this page.

// Use of Parameterized Queries: Prevent SQL Injection by using prepared statements.
$userStmt = $conn->prepare("SELECT id, username, email FROM users");
$userStmt->execute();
$users = $userStmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch all user activities securely with parameterized queries.
$activityStmt = $conn->prepare("SELECT user_id, activity, timestamp FROM user_activity");
$activityStmt->execute();
$activities = $activityStmt->fetchAll(PDO::FETCH_ASSOC);

// Organize activities by user to reduce redundant queries.
$activitiesByUser = [];
foreach ($activities as $activity) {
    $activitiesByUser[$activity['user_id']][] = $activity;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <style>
        /* Basic CSS for styling */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #e9ecef;
            color: #333;
        }
        h1 {
            text-align: center;
            color: #343a40;
        }
        .container {
            width: 80%;
            margin: 0 auto;
            padding: 20px;
            background-color: #ffffff;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #dee2e6;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #495057;
            color: #ffffff;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #e2e6ea;
        }
        .logout-button {
            display: block;
            width: 120px;
            margin: 20px auto;
            text-align: center;
            padding: 10px;
            background-color: #dc3545;
            color: #ffffff;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }
        .logout-button:hover {
            background-color: #c82333;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to the Admin Dashboard</h1>

        <!-- Logout button for session management -->
        <a href="logout.php" class="logout-button">Logout</a>

        <!-- Users and Activities Section -->
        <?php foreach ($users as $user): ?>
            <h2>User: <?php echo htmlspecialchars($user['username']); // Sanitization and Validation: Escape output to prevent XSS. ?></h2>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); // Escape output to prevent XSS. ?></p>
            
            <!-- User Activities Table -->
            <h3>Activities</h3>
            <table>
                <tr>
                    <th>Activity</th>
                    <th>Timestamp</th>
                </tr>
                <?php if (isset($activitiesByUser[$user['id']])): ?>
                    <?php foreach ($activitiesByUser[$user['id']] as $activity): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($activity['activity']); // Escape output for XSS prevention ?></td>
                            <td><?php echo htmlspecialchars($activity['timestamp']); // Escape output ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="2">No activities found</td>
                    </tr>
                <?php endif; ?>
            </table>
        <?php endforeach; ?>
    </div>
</body>
</html>
