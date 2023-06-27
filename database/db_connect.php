<?php

// Your database connection details
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "skillcrave";

// Create a new database connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}