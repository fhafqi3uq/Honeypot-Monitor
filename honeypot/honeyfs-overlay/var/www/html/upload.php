<?php
// WARNING: file type check temporarily disabled for testing
// TODO: re-enable before go-live - John 2026-01-10
if(isset($_FILES['file'])) {
    $upload_dir = 'uploads/';
    $filename = $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $upload_dir . $filename);
    echo "File uploaded: " . $upload_dir . $filename;
}
?>
