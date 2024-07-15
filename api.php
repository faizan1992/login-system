<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

header("Content-Type: application/json");

$host = 'localhost';
$db = 'myapp';
$user = 'root';
$pass = '';

$jwtKey = "6c5091021f51650402f745b0751083ee761d05d736ac01cd23f6e78f80102e15";


try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database connection failed: ' . $e->getMessage()]);
    exit();
}

function generateToken()
{
    return bin2hex(random_bytes(32)); // Generates a 64-character hexadecimal string
}

function getSecurityKeys($loginName)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT security_token, session_identifier FROM users WHERE login_name = ?");
        $stmt->execute([$loginName]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            return [
                'SecurityToken' => $user['security_token'],
                'SessionIdentifier' => $user['session_identifier']
            ];
        } else {
            return null;
        }
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Database query failed: ' . $e->getMessage()]);
        exit();
    }
}

function loginUser($loginName, $password)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE login_name = ?");
        $stmt->execute([$loginName]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Generate SecurityToken and SessionIdentifier
            $securityToken = generateToken();
            $sessionIdentifier = generateToken();

            // Update user with new tokens
            $updateStmt = $pdo->prepare("UPDATE users SET security_token = ?, session_identifier = ? WHERE login_name = ?");
            $updateStmt->execute([$securityToken, $sessionIdentifier, $loginName]);

            // Update user array with new tokens
            $user['security_token'] = $securityToken;
            $user['session_identifier'] = $sessionIdentifier;

            return $user;
        } else {
            return null;
        }
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Login failed: ' . $e->getMessage()]);
        exit();
    }
}

function authenticate()
{
    global $jwtKey;

    if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {
        http_response_code(401);
        echo json_encode(['status' => 'fail', 'message' => 'Unauthorized: No token provided']);
        exit();
    }

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
    list($jwt) = sscanf($authHeader, 'Bearer %s');

    if (!$jwt) {
        http_response_code(401);
        echo json_encode(['status' => 'fail', 'message' => 'Unauthorized: Malformed token']);
        exit();
    }

    try {
        $decoded = JWT::decode($jwt, new Key($jwtKey, 'HS256'));
        return (array) $decoded;
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['status' => 'fail', 'message' => 'Unauthorized: ' . $e->getMessage()]);
        exit();
    }
}

$requestMethod = $_SERVER["REQUEST_METHOD"];
$path = $_SERVER['PATH_INFO'] ?? '/';

if ($path === '/login' && $requestMethod === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $loginName = $input['loginName'] ?? '';
    $password = $input['password'] ?? '';

    $user = loginUser($loginName, $password);
    if ($user) {
        $payload = [
            'iss' => "http://localhost/loginsystem",// isuuer
            'aud' => "http://localhost/loginsystem",// audience
            'iat' => time(), //when
            'exp' => time() + (60 * 60),//expiretimes
            'loginName' => $user['login_name']
        ];

        $jwt = JWT::encode($payload, $jwtKey, 'HS256');
        echo json_encode(['status' => 'success', 'token' => $jwt]);
    } else {
        http_response_code(401);
        echo json_encode(['status' => 'fail', 'message' => 'Invalid credentials']);
    }
    exit();
}

if ($path === '/getSecurityKeys' && $requestMethod === 'POST') {
    $decodedToken = authenticate();
    $input = json_decode(file_get_contents('php://input'), true);
    $loginName = $input['logRef'] ?? '';

    $response = getSecurityKeys($loginName);
    if ($response) {
        echo json_encode(['status' => 'success', 'data' => $response]);
    } else {
        http_response_code(404);
        echo json_encode(['status' => 'fail', 'message' => 'User not found']);
    }
    exit();
}

if ($path === '/logout' && $requestMethod === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $loginName = $input['loginName'] ?? '';

    try {
        // Remove tokens from the database
        $stmt = $pdo->prepare("UPDATE users SET security_token = NULL, session_identifier = NULL WHERE login_name = ?");
        $stmt->execute([$loginName]);
        echo json_encode(['status' => 'success', 'message' => 'Logged out successfully']);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Logout failed: ' . $e->getMessage()]);
    }
    exit();
}

http_response_code(400);
echo json_encode(['status' => 'fail', 'message' => 'Invalid endpoint or method']);
?>