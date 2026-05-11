<?php
// TODO: Fix SQL injection before production - deadline Friday!!!
$conn = mysqli_connect("10.0.0.5", "root", "Sup3rS3cr3t_Prod!", "payment_db");
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
$result = mysqli_query($conn, $query);
?>
