<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $loginName = $_POST['loginName'] ?? '';
    $password = $_POST['password'] ?? '';

    // Logging the login attempt
    error_log("Attempting login for user: " . $loginName);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://localhost/loginsystem/api.php/login");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
        'loginName' => $loginName,
        'password' => $password,
    ]));

    $response = curl_exec($ch);

    if (curl_errno($ch)) {
        $error = 'Curl error: ' . curl_error($ch);
        error_log($error);
    }

    curl_close($ch);

    $result = json_decode($response, true);

    // Logging the response
    error_log("API response: " . print_r($result, true));

    if (is_array($result) && isset($result['status']) && $result['status'] === 'success') {
        $_SESSION['token'] = $result['token'];
        header('Location: home.php');
        exit();
    } else {
        $error = $result['message'] ?? 'Invalid credentials';
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Login</h1>
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="post" action="login.php" autocomplete="on" class="mt-4">
            <div class="form-group">
                <label for="loginName">Username:</label>
                <input type="text" id="loginName" name="loginName" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
