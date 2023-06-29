<?php
require_once '../../database/db_connect.php';
require_once '../../vendor/autoload.php';
error_reporting(0);
use \Firebase\JWT\JWT;

// Your access token secret key
$accessTokenSecret = 'kjhgfdfg';

// Generate an access token
function generateAccessToken($userId)
{
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
    $username = $requestData['username'];
    $email = $requestData['email'];
    $password = password_hash($requestData['password'], PASSWORD_DEFAULT); // Hash the password
    $uid = $requestData['uid'];
    $profile = $requestData['profile'];
    $name = $requestData['name'];
    $phone_number = $requestData['phone_number'];
    $gender = $requestData['gender'];
    $born_year = $requestData['born_year'];
    $location = $requestData['location'];
    $college = $requestData['education']['college'];
    $year_graduation = $requestData['education']['year_graduation'];
    $role = $requestData['role'];
    $skills_development = implode(",", $requestData['skills']['development']);
    $skills_tech = implode(",", $requestData['skills']['tech']);
    $skills_design = implode(",", $requestData['skills']['design']);
    $skills_marketing = implode(",", $requestData['skills']['marketing']);
    $skills_video_editing = implode(",", $requestData['skills']['video_editing']);
    $skills_product = implode(",", $requestData['skills']['product']);
    $skills_writing = implode(",", $requestData['skills']['writing']);
    $skills_business_finance = implode(",", $requestData['skills']['business_finance']);
    $skills_sales_ops = implode(",", $requestData['skills']['sales_ops']);
    $categories_exploring = implode(",", $requestData['categories']['exploring']);
    $categories_currently_learning = implode(",", $requestData['categories']['currently_learning']);
    $categories_used_in_project = implode(",", $requestData['categories']['used_in_project']);
    $categories_work_experience = implode(",", $requestData['categories']['work_experience']);
    $headline = $requestData['headline'];
    $about_me = $requestData['about_me'];
    $short_intro = $requestData['short_intro'];
    $instagram = $requestData['social']['instagram'];
    $twitter = $requestData['social']['twitter'];
    $linkedin = $requestData['social']['linkedin'];
    $facebook = $requestData['social']['facebook'];

    // Validate user input (perform additional validation based on your requirements)
    if (empty($email) || empty($name)) {
        // Return a bad request error response indicating missing fields
        http_response_code(400);
        echo json_encode(['status' => 400, 'error' => 'Missing fields']);
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Return a bad request error response indicating invalid email format
        http_response_code(400);
        echo json_encode(['status' => 400, 'error' => 'Invalid email format']);
        exit;
    }

    // Insert the user into the database
    $stmt = $conn->prepare("INSERT INTO users (username, email, password, uid, profile, name, phone_number, gender, born_year, location, college, year_graduation, role, skills_development, skills_tech, skills_design, skills_marketing, skills_video_editing, skills_product, skills_writing, skills_business_finance, skills_sales_ops, categories_exploring, categories_currently_learning, categories_used_in_project, categories_work_experience, headline, about_me, short_intro, instagram, twitter, linkedin, facebook) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

    if ($stmt) {
        // Bind the parameters to the insert statement
        $stmt->bind_param("ssssssssssssssssssssssssssssssss", $username, $email, $password, $uid, $profile, $name, $phone_number, $gender, $born_year, $location, $college, $year_graduation, $role, $skills_development, $skills_tech, $skills_design, $skills_marketing, $skills_video_editing, $skills_product, $skills_writing, $skills_business_finance, $skills_sales_ops, $categories_exploring, $categories_currently_learning, $categories_used_in_project, $categories_work_experience, $headline, $about_me, $short_intro, $instagram, $twitter, $linkedin, $facebook);

        // Execute the prepared statement
        $stmt->execute();

        // Generate an access token for the newly registered user
        $accessToken = generateAccessToken($conn->insert_id);

        // Build the response data
        $responseData = [
            'status' => 200,
            'data' => [
                'username' => $username,
                'email' => $email,
                'password' => $password,
                'uid' => $uid,
                'profile' => $profile,
                'name' => $name,
                'phone_number' => $phone_number,
                'gender' => $gender,
                'born_year' => $born_year,
                'location' => $location,
                'education' => [
                    'college' => $college,
                    'year_graduation' => $year_graduation
                ],
                'role' => $role,
                'skills' => [
                    'development' => [$skills_development],
                    'tech' => [$skills_tech],
                    'design' => [$skills_design],
                    'marketing' => [$skills_marketing],
                    'video_editing' => [$skills_video_editing],
                    'product' => [$skills_product],
                    'writing' => [$skills_writing],
                    'business_finance' => [$skills_business_finance],
                    'sales_ops' => [$skills_sales_ops]
                ],
                'categories' => [
                    'exploring' => [$categories_exploring],
                    'currently_learning' => [$categories_currently_learning],
                    'used_in_project' => [$categories_used_in_project],
                    'work_experience' => [$categories_work_experience]
                ],
                'headline' => $headline,
                'about_me' => $about_me,
                'short_intro' => $short_intro,
                'social' => [
                    'instagram' => $instagram,
                    'twitter' => $twitter,
                    'linkedin' => $linkedin,
                    'facebook' => $facebook
                ]
            ],
            'timestamp' => date('Y-m-d\TH:i:s\.u\Z')
        ];

        // Return the success response with the access token and data
        http_response_code(200);
        echo json_encode($responseData);
    } else {
        // Return an error response if the prepare statement fails
        http_response_code(500);
        echo json_encode(['status' => 500, 'error' => 'Prepare statement error: ' . $conn->error]);
    }

    // Close the prepared statement
    $stmt->close();
} else {
    // Return an error response for invalid request method
    http_response_code(405);
    echo json_encode(['status' => 405, 'error' => 'Invalid request method']);
}

// Close the database connection
$conn->close();