<?php
// TODO: Add authentication check - currently open for internal use only
// WARNING: Do not expose this endpoint publicly!
header('Content-Type: application/json');
$conn = mysqli_connect("10.0.0.5", "root", "Sup3rS3cr3t_Prod!", "payment_db");
$result = mysqli_query($conn, "SELECT id,username,email,role FROM users");
$users = mysqli_fetch_all($result, MYSQLI_ASSOC);
echo json_encode($users);
?>
