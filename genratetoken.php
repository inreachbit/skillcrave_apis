<?php

require_once 'vendor/autoload.php';

use \Firebase\JWT\JWT;

// Your access token secret key
$accessTokenSecret = 'aasdfsadf234';

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

// Example usage
$userId = 123;
$accessToken = generateAccessToken($userId);
echo $accessToken;