<?php 
// Include the database connection file
require_once '../../database/db_connect.php';
// error_reporting(0);
require_once '../../vendor/autoload.php';

use \Firebase\JWT\JWT;

// Your access token secret key
$accessTokenSecret = 'kjhgfdfg';
$refreshTokenSecret = 'hgfdsdfg';

// Generate an access token
function generateAccessToken($userId) {
    global $accessTokenSecret;

    $tokenId = base64_encode(random_bytes(32));
    $issuedAt = time();
    $expireAt = $issuedAt + 3600; // Token will expire in 1 hour

    $data = [
        'iat' => $issuedAt,
        'exp' => $expireAt,
        'jti' => $tokenId,
        'sub' => $userId
        // Add any additional claims or data as needed
    ];

    $accessToken = JWT::encode($data, $accessTokenSecret, 'HS256');

    return $accessToken;
}

// Generate a refresh token
function generateRefreshToken($userId) {
    global $refreshTokenSecret;

    $tokenId = base64_encode(random_bytes(32));
    $issuedAt = time();
    $expireAt = $issuedAt + 86400 * 30; // Token will expire in 30 days

    $data = [
        'iat' => $issuedAt,
        'exp' => $expireAt,
        'jti' => $tokenId,
        'sub' => $userId
        // Add any additional claims or data as needed
    ];

    $refreshToken = JWT::encode($data, $refreshTokenSecret, 'HS256');

    return $refreshToken;
}

// Login API endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Retrieve JSON data from the request body
    $requestData = json_decode(file_get_contents('php://input'), true);

    // Retrieve user input from the request data
    $email = filter_var($requestData['email'], FILTER_SANITIZE_EMAIL);
    $password = filter_var($requestData['password'], FILTER_SANITIZE_STRING);

    // Validate user input (perform additional validation based on your requirements)
    if (empty($email) || empty($password)) {
        // Return a bad request error response indicating missing fields
        http_response_code(400);
        echo json_encode(['status' => 400, 'error' => 'Missing fields']);
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Return an error response if the email is not in the correct format
        http_response_code(400);
        echo json_encode(['status' => 400, 'error' => 'Invalid email format']);
        exit;
    }

    // Sanitize inputs
    $email = $conn->real_escape_string($email);
    $password = $conn->real_escape_string($password);

    // Check if the email exists in the database
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 0) {
        // Return an error response if the email does not exist
        http_response_code(404);
        echo json_encode(['status' => 404, 'error' => 'Email not found']);
        exit;
    }

    // Retrieve the user's ID and hashed password
    $stmt->bind_result($userId, $hashedPassword);
    $stmt->fetch();

    // Verify the password
    if (!password_verify($password, $hashedPassword)) {
        // Return an error response if the password is incorrect
        http_response_code(401);
        echo json_encode(['status' => 401, 'error' => 'Invalid password']);
        exit;
    }

    // Generate an access token and refresh token for the authenticated user
    $accessToken = generateAccessToken($userId);
    $refreshToken = generateRefreshToken($userId);

    // Store the refresh token in the database
    $refreshTokenStmt = $conn->prepare("UPDATE users SET refresh_token = ? WHERE id = ?");
    $refreshTokenStmt->bind_param("si", $refreshToken, $userId);
    $refreshTokenStmt->execute();

    // Return a success response with the access token and refresh token
    http_response_code(200);
    echo json_encode(['status' => 200, 'data' => ['email' => $email, 'tokens' => ['accessToken' => $accessToken, 'refreshToken' => $refreshToken]]]);

    // Close the statements
    $stmt->close();
    $refreshTokenStmt->close();
} else {
    http_response_code(405);
    echo json_encode(['status' => 405, 'error' => 'Invalid Method']);
}

// Close the database connection
$conn->close();

?>