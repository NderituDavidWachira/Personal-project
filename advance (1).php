<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!isset($_SESSION['user_id'])) {
    die("Unauthorized access");
}

include "db.php";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token");
    }

    $_SESSION['active_section'] = 'studentsSection';

    if (isset($_POST['reset_student_password'])) {
        $student_id = filter_input(INPUT_POST, 'student_id', FILTER_VALIDATE_INT);
        $new_password = trim($_POST['new_password'] ?? '');

        if ($student_id && strlen($new_password) >= 6 && strlen($new_password) <= 100) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare("
                UPDATE users
                SET password = :password
                WHERE id = :id
                LIMIT 1
            ");
            $stmt->bindParam(':password', $hashed_password, PDO::PARAM_STR);
            $stmt->bindParam(':id', $student_id, PDO::PARAM_INT);
            $stmt->execute();

            $_SESSION['success'] = "Password updated successfully.";
        }
        header("Location: " . $_SERVER['PHP_SELF'] . "#studentsSection");
        exit;
    }

    /* ====
       STUDENT ACTION 
    ==== */
    if (isset($_POST['student_action'])) {
        $student_id = filter_input(INPUT_POST, 'student_id', FILTER_VALIDATE_INT);
        $allowed_actions = ['activate', 'suspend', 'delete'];
        $action = $_POST['action'] ?? '';

        if ($student_id && in_array($action, $allowed_actions, true)) {
            if ($action === "activate") {
                $stmt = $pdo->prepare("
                    UPDATE users
                    SET status='active'
                    WHERE id=:id
                    LIMIT 1
                ");
                $stmt->bindParam(':id', $student_id, PDO::PARAM_INT);
                $stmt->execute();

                $_SESSION['success'] = "Student activated successfully.";
            } elseif ($action === "suspend") {
                $stmt = $pdo->prepare("
                    UPDATE users
                    SET status='suspended'
                    WHERE id=:id
                    LIMIT 1
                ");
                $stmt->bindParam(':id', $student_id, PDO::PARAM_INT);
                $stmt->execute();

                $_SESSION['success'] = "Student suspended successfully.";
            } elseif ($action === "delete") {
                if (isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] === (int)$student_id) {
                    die("You cannot delete your own account");
                }
                $stmt = $pdo->prepare("
                    DELETE FROM users
                    WHERE id=:id
                    LIMIT 1
                ");
                $stmt->bindParam(':id', $student_id, PDO::PARAM_INT);
                $stmt->execute();

                $_SESSION['success'] = "Student deleted successfully.";
            }
        }

        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

/* =====
   CREATE COURSE SECTION
===== */
$user_id = $_SESSION['user_id'] ?? 0;
$user_role = strtolower(trim($_SESSION['role'] ?? ''));

if (!$user_id) {
    die("Unauthorized");
}

function isValidVideo($tmpFile) {
    $allowed = ['video/mp4', 'video/webm', 'video/ogg'];
    return in_array(mime_content_type($tmpFile), $allowed, true);
}

function convertDriveLink($url) {
    if (strpos($url, 'drive.google.com') !== false) {
        preg_match('/\/d\/(.*?)\//', $url, $m);
        if (!empty($m[1])) {
            return "https://drive.google.com/file/d/{$m[1]}/preview";
        }
    }
    return $url;
}

/* ====
   EDIT FETCH
==== */
$editVideo = null;

if (isset($_GET['edit'])) {
    $id = (int)$_GET['edit'];

    $stmt = $pdo->prepare("SELECT * FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    $editVideo = $stmt->fetch();
}

/* ====
   UPLOAD VIDEO
==== */
if (isset($_POST['upload_video'])) {
    if (!in_array($user_role, ['admin', 'teacher'], true)) {
        die("Unauthorized");
    }

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF Error");
    }

    $course_id = (int)($_POST['course_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $access_type = $_POST['access_type'] ?? 'free';
    $cloud_url = trim($_POST['cloud_url'] ?? '');

    $local_path = null;
    $file_size = 0;
    $mime_type = null;
    $upload_status = 'cloud';

    /* FILE UPLOAD */
    if (!empty($_FILES['video']['name'])) {
        if (!isValidVideo($_FILES['video']['tmp_name'])) {
            die("Only MP4, WEBM, OGG allowed");
        }

        $upload_dir = "uploads/videos/";
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }

        $filename = time() . "_" . basename($_FILES['video']['name']);
        $local_path = $upload_dir . $filename;

        move_uploaded_file($_FILES['video']['tmp_name'], $local_path);

        $file_size = $_FILES['video']['size'];
        $mime_type = mime_content_type($local_path);
        $upload_status = 'local';
    }

    $stmt = $pdo->prepare("
        INSERT INTO course_videos
        (course_id, title, local_path, cloud_url, upload_status, file_size, mime_type, access_type, uploaded_by, description)
        VALUES (:course_id, :title, :local_path, :cloud_url, :upload_status, :file_size, :mime_type, :access_type, :uploaded_by, :description)
    ");

    $stmt->bindParam(':course_id', $course_id, PDO::PARAM_INT);
    $stmt->bindParam(':title', $title, PDO::PARAM_STR);
    $stmt->bindParam(':local_path', $local_path, PDO::PARAM_STR);
    $stmt->bindParam(':cloud_url', $cloud_url, PDO::PARAM_STR);
    $stmt->bindParam(':upload_status', $upload_status, PDO::PARAM_STR);
    $stmt->bindParam(':file_size', $file_size, PDO::PARAM_INT);
    $stmt->bindParam(':mime_type', $mime_type, PDO::PARAM_STR);
    $stmt->bindParam(':access_type', $access_type, PDO::PARAM_STR);
    $stmt->bindParam(':uploaded_by', $user_id, PDO::PARAM_INT);
    $stmt->bindParam(':description', $description, PDO::PARAM_STR);

    $stmt->execute();

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ====
   UPDATE VIDEO
==== */
if (isset($_POST['update_video'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF Error");
    }

    $id = (int)($_POST['video_id'] ?? 0);
    $course_id = (int)($_POST['course_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $cloud_url = trim($_POST['cloud_url'] ?? '');
    $access_type = $_POST['access_type'] ?? 'free';

    /* NEW FILE UPLOAD */
    if (!empty($_FILES['video']['name'])) {
        $stmt = $pdo->prepare("SELECT local_path FROM course_videos WHERE id=:id");
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        $old = $stmt->fetch();

        if (!empty($old['local_path']) && file_exists($old['local_path'])) {
            unlink($old['local_path']);
        }

        if (!isValidVideo($_FILES['video']['tmp_name'])) {
            die("Invalid video file");
        }
        $upload_dir = "uploads/videos/";
        $filename = time() . "_" . basename($_FILES['video']['name']);
        $local_path = $upload_dir . $filename;

        move_uploaded_file($_FILES['video']['tmp_name'], $local_path);

        $stmt = $pdo->prepare("
            UPDATE course_videos
            SET local_path=:local_path, upload_status='local'
            WHERE id=:id
        ");
        $stmt->bindParam(':local_path', $local_path, PDO::PARAM_STR);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
    }

    $stmt = $pdo->prepare("
        UPDATE course_videos
        SET course_id=:course_id, title=:title, description=:description, cloud_url=:cloud_url, access_type=:access_type
        WHERE id=:id
    ");

    $stmt->bindParam(':course_id', $course_id, PDO::PARAM_INT);
    $stmt->bindParam(':title', $title, PDO::PARAM_STR);
    $stmt->bindParam(':description', $description, PDO::PARAM_STR);
    $stmt->bindParam(':cloud_url', $cloud_url, PDO::PARAM_STR);
    $stmt->bindParam(':access_type', $access_type, PDO::PARAM_STR);
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ====
   DELETE VIDEO
==== */
if (isset($_POST['delete_video'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF Error");
    }
    $id = (int)($_POST['video_id'] ?? 0);
    $stmt = $pdo->prepare("SELECT local_path FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $video = $stmt->fetch();

    if (!empty($video['local_path']) && file_exists($video['local_path'])) {
        unlink($video['local_path']);
    }

    $stmt = $pdo->prepare("DELETE FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ====
   VIEW VIDEO
==== */
if (isset($_GET['view'])) {
    $id = (int)$_GET['view'];

    $stmt = $pdo->prepare("SELECT * FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    $video = $stmt->fetch();

    if (!$video) {
        die("Video not found");
    }

    /* PAID ACCESS CHECK */
    if ($video['access_type'] === 'paid') {
        $check = $pdo->prepare("
            SELECT 1 FROM enrollments
            WHERE user_id=:user_id
            AND course_id=:course_id
        ");
        $check->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $check->bindParam(':course_id', $video['course_id'], PDO::PARAM_INT);
        $check->execute();

        if ($check->rowCount() === 0 && !in_array($user_role, ['admin', 'teacher'], true)) {
            die("You are not enrolled in this course");
        }
    }
}

error_reporting(E_ALL);
ini_set('display_errors', 1);

/* =====
   FETCH COURSES 
===== */
$stmt = $pdo->prepare("SELECT * FROM courses ORDER BY id DESC");
$stmt->execute();
$courses = $stmt->fetchAll();

/* =====
   FETCH TEACHERS 
===== */
$stmt2 = $pdo->prepare("SELECT id, full_name FROM users WHERE role = :role");
$role = "teacher";
$stmt2->bindParam(':role', $role, PDO::PARAM_STR);
$stmt2->execute();
$teachers = $stmt2->fetchAll();

/* =====
   CREATE COURSE
===== */
if (!isset($_SESSION['course_submission_id'])) {
    $_SESSION['course_submission_id'] = '';
}

if (isset($_POST['create_course'])) {
    if (
        !isset($_POST['csrf_token']) ||
        $_POST['csrf_token'] !== $_SESSION['csrf_token']
    ) {
        die("Invalid CSRF token");
    }

    /* =====
       PREVENT DUPLICATE SUBMIT
    ===== */
    $submission_id = md5(
        ($_POST['title'] ?? '') .
        ($_POST['description'] ?? '') .
        ($_POST['teacher_id'] ?? '') .
        session_id()
    );

    if ($_SESSION['course_submission_id'] === $submission_id) {
        $success = "Course already saved.";
    } else {
        $title = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $category = trim($_POST['category'] ?? '');
        $custom_category = trim($_POST['custom_category'] ?? '');
        $course_type = trim($_POST['course_type'] ?? 'Free');
        $status = trim($_POST['status'] ?? 'Active');
        $price = (float)($_POST['price'] ?? 0);
        $teacher_id = (int)($_POST['teacher_id'] ?? 0);

        /* =====
           THUMBNAIL UPLOAD
        ===== */
        $thumbnail = "";
        if (
            isset($_FILES['thumbnail']) &&
            !empty($_FILES['thumbnail']['name'])
        ) {
            $allowed = ['image/jpeg', 'image/png', 'image/webp'];
            $mime = mime_content_type($_FILES['thumbnail']['tmp_name']);

            if (!in_array($mime, $allowed, true)) {
                die("Invalid image type");
            }

            if ($_FILES['thumbnail']['size'] > 2 * 1024 * 1024) {
                die("Image too large");
            }

            $dir = "uploads/";
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            switch ($mime) {
                case 'image/jpeg':
                    $extension = 'jpg';
                    break;
                case 'image/png':
                    $extension = 'png';
                    break;
                case 'image/webp':
                    $extension = 'webp';
                    break;
                default:
                    $extension = 'jpg';
                    break;
            }

            $fileName = time() . "_" . bin2hex(random_bytes(5)) . "." . $extension;
            $thumbnail = $dir . $fileName;

            if (!move_uploaded_file($_FILES['thumbnail']['tmp_name'], $thumbnail)) {
                die("Failed to upload image");
            }
        }

        /* =====
           INSERT COURSE 
        ===== */
        $stmt = $pdo->prepare("
            INSERT INTO courses
            (
                title,
                description,
                category,
                custom_category,
                thumbnail,
                course_type,
                status,
                price,
                teacher_id
            )
            VALUES (:title, :description, :category, :custom_category, :thumbnail, :course_type, :status, :price, :teacher_id)
        ");

        $stmt->bindParam(':title', $title, PDO::PARAM_STR);
        $stmt->bindParam(':description', $description, PDO::PARAM_STR);
        $stmt->bindParam(':category', $category, PDO::PARAM_STR);
        $stmt->bindParam(':custom_category', $custom_category, PDO::PARAM_STR);
        $stmt->bindParam(':thumbnail', $thumbnail, PDO::PARAM_STR);
        $stmt->bindParam(':course_type', $course_type, PDO::PARAM_STR);
        $stmt->bindParam(':status', $status, PDO::PARAM_STR);
        $stmt->bindParam(':price', $price);
        $stmt->bindParam(':teacher_id', $teacher_id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            $_SESSION['course_submission_id'] = $submission_id;
            $success = "Course created successfully.";
        } else {
            $error = "Failed to create course.";
        }
    }
}

/* =====
   DELETE / ARCHIVE COURSE
===== */
if (isset($_POST['delete_course'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token");
    }

    $id = (int)($_POST['course_id'] ?? 0);
    $action = $_POST['action'] ?? '';

    if ($action === "delete") {
        $stmt = $pdo->prepare("DELETE FROM courses WHERE id=:id");
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $status = "Inactive";
        $stmt = $pdo->prepare("UPDATE courses SET status=:status WHERE id=:id");
        $stmt->bindParam(':status', $status, PDO::PARAM_STR);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
    }
}