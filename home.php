<?php
session_start();

if (!isset($_SESSION['token'])) {
    header('Location: login.php');
    exit();
}

$token = $_SESSION['token'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://localhost/loginsystem/api.php/getSecurityKeys");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Content-Type: application/json',
    'Authorization: Bearer ' . $token
));
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
    'logRef' => 'testuser', // Replace with a valid login_name
]));

$response = curl_exec($ch);

if (curl_errno($ch)) {
    $error = 'Curl error: ' . curl_error($ch);
    error_log($error);
    echo "Error: " . $error;
    curl_close($ch);
    exit();
}

curl_close($ch);

if ($response === false) {
    error_log("API call failed: no response received");
    echo "Error: No response from API";
    session_destroy();
    header('Location: login.php');
    exit();
}

$result = json_decode($response, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    error_log("API response is not valid JSON: " . $response);
    echo "Error: Invalid API response";
    session_destroy();
    header('Location: login.php');
    exit();
}

if (!isset($result['status']) || $result['status'] !== 'success') {
    error_log("API error: " . print_r($result, true));
    echo "Error: " . ($result['message'] ?? 'Unknown error');
    session_destroy();
    header('Location: login.php');
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Home</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Home</h1>
        <p>Welcome! You are logged in.</p>
        <pre><?php print_r($result['data']); ?></pre>
        <form id="logoutForm" method="post" action="logout.php">
            <input type="hidden" name="loginName" value="testuser"> <!-- Replace with dynamic value if available -->
            <button type="submit" class="btn btn-danger">Logout</button>
        </form>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
