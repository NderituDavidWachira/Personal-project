<?php
/** helpers.php - shared small helpers (moved out of student.php) */

const DOC_MIMES = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png'];

function validateCsrf(): void
{
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])
        || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die('Invalid CSRF token. Request blocked.');
    }
}

function flash_redirect(string $message, string $section, string $to = 'student.php')
{
    $_SESSION['flash'] = $message;
    $_SESSION['active_section'] = $section;
    header('Location: ' . $to);
    exit;
}

function secureFileUpload(string $fieldName, int $userId, string $prefix, array $allowedMimes, int $maxBytes = 5 * 1024 * 1024): array
{
    if (!isset($_FILES[$fieldName]) || $_FILES[$fieldName]['error'] === UPLOAD_ERR_NO_FILE) {
        return ['ok' => true, 'filename' => null];
    }
    if ($_FILES[$fieldName]['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'error' => 'File upload failed.'];
    }
    $file = $_FILES[$fieldName];
    if ($file['size'] > $maxBytes) {
        return ['ok' => false, 'error' => 'File is too large.'];
    }
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if (!$mime || !isset($allowedMimes[$mime])) {
        return ['ok' => false, 'error' => 'Invalid file type.'];
    }
    $filename = $prefix . '_' . $userId . '_' . bin2hex(random_bytes(8)) . '.' . $allowedMimes[$mime];
    $destDir  = __DIR__ . '/uploads';
    if (!is_dir($destDir)) { mkdir($destDir, 0755, true); }
    $ht = $destDir . '/.htaccess';
    if (!file_exists($ht)) {
        file_put_contents($ht,
            "php_flag engine off\n<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar)$\">\n  Require all denied\n</FilesMatch>\n");
    }
    if (!move_uploaded_file($file['tmp_name'], $destDir . '/' . $filename)) {
        return ['ok' => false, 'error' => 'Failed to save uploaded file.'];
    }
    return ['ok' => true, 'filename' => $filename];
}