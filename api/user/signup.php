<?php
require_once '../../database/db_connect.php';
// error_reporting(0);
require_once '../../vendor/autoload.php';

use \Firebase\JWT\JWT;

// Your access token secret key
$accessTokenSecret = 'kjhgfdfg';

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

// Create a new user registration API endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Retrieve JSON data from the request body
    $requestData = json_decode(file_get_contents('php://input'), true);

    // Retrieve user input from the request data
    $email = filter_var($requestData['email'], FILTER_SANITIZE_EMAIL);
    $password = filter_var($requestData['password'], FILTER_SANITIZE_STRING);
    $name = filter_var($requestData['name'], FILTER_SANITIZE_STRING);

    // Validate user input (perform additional validation based on your requirements)
    if (empty($email) || empty($password) || empty($name)) {
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

    // Validate name format (allow alphabets and space)
    if (!preg_match('/^[a-zA-Z ]+$/', $name)) {
        // Return an error response if the name contains characters other than alphabets and space
        http_response_code(400);
        echo json_encode(['status' => 400, 'error' => 'Invalid name format']);
        exit;
    }

    // Check if the email already exists
    $checkStmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $checkStmt->bind_param("s", $email);
    $checkStmt->execute();
    $checkStmt->store_result();

    if ($checkStmt->num_rows > 0) {
        // Return an error response if the email already exists
        http_response_code(409);
        echo json_encode(['status' => 409, 'error' => 'Email already exists']);
        exit;
    }

    // Hash the password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Prepare the SQL statement to insert a new user
    $insertStmt = $conn->prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)");
    $insertStmt->bind_param("sss", $email, $hashedPassword, $name);

    // Execute the statement
    if ($insertStmt->execute()) {
        // Generate an access token for the newly registered user
        $userId = $insertStmt->insert_id;
        $accessToken = generateAccessToken($userId);

        // Store the access token in the database
        $tokenStmt = $conn->prepare("UPDATE users SET access_token = ? WHERE id = ?");
        $tokenStmt->bind_param("si", $accessToken, $userId);
        $tokenStmt->execute();

        // Return a success response with the access token
        http_response_code(200);
        echo json_encode(['status' => 200, 'data' => ['accessToken' => $accessToken]]);
    } else {
        // Return an error response if the execution fails
        http_response_code(500);
        echo json_encode(['status' => 500, 'error' => 'User registration failed']);
    }

    // Close the statements
    $insertStmt->close();
    $checkStmt->close();
    $tokenStmt->close();
} else {
    http_response_code(405);
    echo json_encode(['status' => 405, 'error' => 'Invalid Method']);
}

// Close the database connection
$conn->close();