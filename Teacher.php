<?php
/* ===
   SESSION SETUP 
==*/
$session_lifetime = 1800;

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
include "db.php";
/** @var PDO $pdo */

/* ===
   AUTH + SESSION EXPIRY CHECK
=== */
function force_login_redirect($pdo = null) {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: index.php?expired=1");
    exit;
}

if (!isset($_SESSION['user_id'])) {
    force_login_redirect($pdo ?? null);
}

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $session_lifetime) {
    force_login_redirect($pdo ?? null);
}
$_SESSION['last_activity'] = time();
if (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
} elseif (time() - $_SESSION['created'] > 900) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
}

$user_id = (int)$_SESSION['user_id'];

/* ===
   GET TEACHER INFO
=== */
$stmt = $pdo->prepare("
    SELECT t.*, u.full_name, u.email
    FROM teachers t
    LEFT JOIN users u ON u.id = t.user_id
    WHERE t.user_id = ?
    LIMIT 1
");
$stmt->execute([$user_id]);
$teacherInfo = $stmt->fetch();

if (!$teacherInfo) {
    force_login_redirect($pdo);
}
$teacher_id = $user_id;

/* ===
   GENERATE CSRF TOKENS
=== */
function ensure_token($key) {
    if (empty($_SESSION[$key])) {
        $_SESSION[$key] = bin2hex(random_bytes(32));
    }
    return $_SESSION[$key];
}
ensure_token('note_token');
ensure_token('quiz_token');
ensure_token('course_token');
ensure_token('video_token');
ensure_token('student_token');
ensure_token('enroll_token');
ensure_token('announce_token');
ensure_token('profile_token');
ensure_token('approval_token');
ensure_token('assignment_token');
ensure_token('attendance_token');
ensure_token('grading_token');
ensure_token('message_token');
ensure_token('mentorship_token');
ensure_token('supervision_token');
ensure_token('cpd_token');
ensure_token('competency_token');
ensure_token('certificate_token');
ensure_token('session_token_csrf');
ensure_token('availability_token');
ensure_token('consultation_token');
ensure_token('notification_token');
ensure_token('forum_token');

/* ===
   CSRF VALIDATION 
=== */
function require_csrf($postKey, $sessionKey) {
    if (!isset($_POST[$postKey]) || !isset($_SESSION[$sessionKey]) || !hash_equals($_SESSION[$sessionKey], $_POST[$postKey])) {
        force_login_redirect();
    }
}

/* ===
   ROLE CHECK HELPER
=== */
function require_teacher_role() {
    if (($_SESSION['user_role'] ?? '') !== 'teacher') {
        force_login_redirect();
    }
}

/* ===
   AUDIT LOG HELPER
=== */
function log_audit(PDO $pdo, int $userId, string $actionType, string $description, ?string $entityType = null, ?int $entityId = null): void {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO audit_logs (user_id, action_type, description, ip_address, entity_type, entity_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $userId,
            $actionType,
            $description,
            $_SERVER['REMOTE_ADDR'] ?? null,
            $entityType,
            $entityId
        ]);
    } catch (Throwable $e) {
    }
}

/* ===
   NOTIFICATION HELPER
=== */
function notify_user(PDO $pdo, int $userId, string $message): void {
    try {
        $stmt = $pdo->prepare("INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, NOW())");
        $stmt->execute([$userId, $message]);
    } catch (Throwable $e) {
        // Non-fatal.
    }
}

function submit_change_request(PDO $pdo, string $entityType, ?int $entityId, array $oldData, array $newData, int $requestedBy, string $message = ''): int {
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("
            INSERT INTO change_requests
                (entity_type, entity_id, requested_by, old_data, new_data, status, review_comments)
            VALUES (?, ?, ?, ?, ?, 'pending', ?)
        ");
        $stmt->execute([
            $entityType,
            $entityId,
            $requestedBy,
            json_encode($oldData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            json_encode($newData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            $message
        ]);
        $requestId = (int)$pdo->lastInsertId();
        $pdo->commit();
        return $requestId;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}

function create_content_version(PDO $pdo, string $contentType, int $contentId, array $snapshot, int $editedBy, int $requestId): void {
    $stmt = $pdo->prepare("SELECT COALESCE(MAX(version_number),0)+1 AS next_version FROM content_versions WHERE content_type=? AND content_id=?");
    $stmt->execute([$contentType, $contentId]);
    $version = (int)($stmt->fetch()['next_version'] ?? 1);

    $stmt = $pdo->prepare("
        INSERT INTO content_versions
            (content_type, content_id, version_number, data_snapshot, edited_by, change_request_id, status)
        VALUES (?, ?, ?, ?, ?, ?, 'pending_approval')
    ");
    $stmt->execute([
        $contentType,
        $contentId,
        $version,
        json_encode($snapshot, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        $editedBy,
        $requestId
    ]);
}

function queue_trainer_change(PDO $pdo, string $entityType, ?int $entityId, array $oldData, array $newData, int $teacherId, string $message = '', ?string $versionType = null, ?int $versionContentId = null): int {
    $requestId = submit_change_request($pdo, $entityType, $entityId, $oldData, $newData, $teacherId, $message);
    if ($versionType !== null) {
        create_content_version($pdo, $versionType, $versionContentId ?? (int)($entityId ?? 0), $newData, $teacherId, $requestId);
    }
    return $requestId;
}

/* ===
   DELETE COURSE  
=== */
if (isset($_GET['delete_course'])) {
    $token = $_GET['course_token'] ?? '';
    if (!hash_equals($_SESSION['course_token'], $token)) {
        force_login_redirect();
    }
    $course_id = (int)$_GET['delete_course'];

    $check = $pdo->prepare("SELECT title FROM courses WHERE id=? LIMIT 1");
    $check->execute([$course_id]);
    $courseRow = $check->fetch();

    queue_trainer_change(
        $pdo,
        'course',
        $course_id,
        ['title' => $courseRow['title'] ?? ''],
        ['action' => 'archive_request', 'course_id' => $course_id],
        $teacher_id,
        'Trainer requested removal/archiving of this course. Super Administrator approval required.'
    );

    $_SESSION['course_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Archive request submitted for Super Administrator approval.";
    log_audit($pdo, $teacher_id, 'course_archive_request', "Requested archive of course #$course_id", 'course', $course_id);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT COURSE
=== */
if (isset($_POST['edit_course'])) {
    require_csrf('course_token', 'course_token');

    $course_id   = (int)$_POST['course_id'];
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($course_id <= 0 || $title === '') die("Invalid course input");

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) die("Unauthorized course access");

    $stmt = $pdo->prepare("SELECT title, description, price FROM courses WHERE id=? LIMIT 1");
    $stmt->execute([$course_id]);
    $oldCourse = $stmt->fetch() ?: [];

    queue_trainer_change(
        $pdo,
        'course',
        $course_id,
        [
            'title' => $oldCourse['title'] ?? '',
            'description' => $oldCourse['description'] ?? ''
        ],
        [
            'action' => 'update',
            'course_id' => $course_id,
            'title' => $title,
            'description' => $description
        ],
        $teacher_id,
        'Trainer submitted a course content edit for Super Administrator approval. (Price/payment/certificate/status/branding fields are locked to trainers.)',
        'course',
        $course_id
    );

    $_SESSION['course_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Course changes submitted for Super Administrator approval.";
    log_audit($pdo, $teacher_id, 'course_edit_request', "Submitted edit request for course #$course_id", 'course', $course_id);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   UPLOAD DIRECTORIES
=== */
$video_dir = "uploads/videos/";
$note_dir  = "uploads/notes/";
$submission_dir = "uploads/submissions/";
if (!file_exists($video_dir)) mkdir($video_dir, 0755, true);
if (!file_exists($note_dir))  mkdir($note_dir,  0755, true);
if (!file_exists($submission_dir)) mkdir($submission_dir, 0755, true);

/* ===
   UPLOAD VIDEO
=== */
if (isset($_POST['upload_video'])) {
    require_csrf('video_token', 'video_token');

    $course_id = (int)$_POST['course_id'];
    $title     = trim($_POST['title']);
    $access    = $_POST['access_type'];
    $file_path = "";

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("Unauthorized course access");
    }

    if (!empty($_FILES['video']['name']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
        $allowedVideoExt  = ['mp4', 'mov', 'webm', 'mkv'];
        $allowedVideoMime = ['video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska'];
        $maxVideoSize     = 500 * 1024 * 1024;

        $originalName = basename($_FILES['video']['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedVideoExt, true)) {
            die("X Video file type not allowed.");
        }
        if ($_FILES['video']['size'] > $maxVideoSize) {
            die("X Video is too large. Max size is 500MB.");
        }

        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($_FILES['video']['tmp_name']);
        if (!in_array($mimeType, $allowedVideoMime, true)) {
            die("X Video content does not match an allowed type.");
        }

        $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
        $target   = $video_dir . $safeName;

        if (move_uploaded_file($_FILES['video']['tmp_name'], $target)) {
            $file_path = $target;
        } else {
            die("X Failed to save uploaded video.");
        }
    }

    try {
        queue_trainer_change(
            $pdo,
            'course_content',
            null,
            [],
            [
                'action' => 'create',
                'content_type' => 'video',
                'course_id' => $course_id,
                'title' => $title,
                'video_path' => $file_path,
                'access_type' => $access,
                'uploaded_by' => $teacher_id
            ],
            $teacher_id,
            'Trainer uploaded a video. Super Administrator approval is required before publication.',
            'course_content',
            0
        );
    } catch (Throwable $e) {
        if (!empty($file_path) && file_exists($file_path)) @unlink($file_path);
        $_SESSION['error_message'] = "Could not submit the video for approval.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    $_SESSION['video_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Video submitted for Super Administrator approval.";
    log_audit($pdo, $teacher_id, 'video_upload_request', "Uploaded video '$title' for course #$course_id pending approval", 'course_content', $course_id);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT VIDEO 
=== */
if (isset($_POST['edit_video'])) {
    require_csrf('video_token', 'video_token');

    $video_id = (int)$_POST['video_id'];
    $title    = trim($_POST['title'] ?? '');
    $access   = $_POST['access_type'] ?? 'free';

    $stmt = $pdo->prepare("
        SELECT v.* FROM course_videos v
        JOIN course_teachers ct ON ct.course_id = v.course_id
        WHERE v.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $stmt->execute([$video_id, $teacher_id]);
    $oldVideo = $stmt->fetch();
    if (!$oldVideo) die("Unauthorized video access");

    $new_file_path = $oldVideo['video_path'];
    if (!empty($_FILES['video']['name']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
        $allowedVideoExt  = ['mp4', 'mov', 'webm', 'mkv'];
        $allowedVideoMime = ['video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska'];
        $maxVideoSize     = 500 * 1024 * 1024;

        $originalName = basename($_FILES['video']['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedVideoExt, true)) die("X Video file type not allowed.");
        if ($_FILES['video']['size'] > $maxVideoSize) die("X Video is too large. Max size is 500MB.");

        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($_FILES['video']['tmp_name']);
        if (!in_array($mimeType, $allowedVideoMime, true)) die("X Video content does not match an allowed type.");

        $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
        $target   = $video_dir . $safeName;
        if (move_uploaded_file($_FILES['video']['tmp_name'], $target)) {
            $new_file_path = $target;
        } else {
            die("X Failed to save uploaded video.");
        }
    }

    queue_trainer_change(
        $pdo,
        'course_content',
        $video_id,
        [
            'title' => $oldVideo['title'],
            'access_type' => $oldVideo['access_type'],
            'video_path' => $oldVideo['video_path']
        ],
        [
            'action' => 'update',
            'content_type' => 'video',
            'video_id' => $video_id,
            'course_id' => $oldVideo['course_id'],
            'title' => $title,
            'video_path' => $new_file_path,
            'access_type' => $access,
            'uploaded_by' => $teacher_id
        ],
        $teacher_id,
        'Trainer submitted a video edit for Super Administrator approval.',
        'course_content',
        $video_id
    );

    $_SESSION['video_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Video changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   DELETE VIDEO
=== */
if (isset($_GET['delete_video'])) {
    $token = $_GET['video_token'] ?? '';
    if (!hash_equals($_SESSION['video_token'], $token)) {
        force_login_redirect();
    }
    $id = (int)$_GET['delete_video'];

    $stmt = $pdo->prepare("
        SELECT v.video_path FROM course_videos v
        JOIN course_teachers ct ON ct.course_id = v.course_id
        WHERE v.id = ? AND ct.teacher_id = ?
    ");
    $stmt->execute([$id, $teacher_id]);
    $old = $stmt->fetch();

    if ($old) {
        if (!empty($old['video_path']) && file_exists($old['video_path'])) {
            unlink($old['video_path']);
        }
        $stmt = $pdo->prepare("
            DELETE v FROM course_videos v
            JOIN course_teachers ct ON ct.course_id = v.course_id
            WHERE v.id = ? AND ct.teacher_id = ?
        ");
        $stmt->execute([$id, $teacher_id]);
        $_SESSION['success_message'] = "Video deleted.";
        log_audit($pdo, $teacher_id, 'video_delete', "Deleted video #$id", 'course_video', $id);
    }
    $_SESSION['video_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   VIEW VIDEO
=== */
if (isset($_GET['view_video'])) {
    $id = (int)$_GET['view_video'];
    $stmt = $pdo->prepare("
        SELECT v.*, c.title AS course_title
        FROM course_videos v
        INNER JOIN courses c ON c.id = v.course_id
        INNER JOIN course_teachers ct ON ct.course_id = c.id
        WHERE v.id = ? AND ct.teacher_id = ?
    ");
    $stmt->execute([$id, $teacher_id]);
    $video = $stmt->fetch();

    if (!$video) {
        die("Video not found or access denied");
    }

    $stmt = $pdo->prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? LIMIT 1");
    $stmt->execute([$user_id, $video['course_id']]);
    $isEnrolled = $stmt->rowCount() > 0;

    if ($video['access_type'] == 'paid' && !$isEnrolled) {
        die("<h2>Access Denied X</h2><p>You must enroll to watch this video.</p>");
    }
    ?>
    <!DOCTYPE html><html><head><title><?= htmlspecialchars($video['title']) ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body style="background:#000;color:#fff;padding:20px;margin:0;">
        <h2><?= htmlspecialchars($video['title']) ?></h2>
        <video width="100%" controls controlsList="nodownload" oncontextmenu="return false">
            <source src="<?= htmlspecialchars($video['video_path']) ?>" type="video/mp4">
        </video>
        <script>document.addEventListener("contextmenu", e => e.preventDefault());</script>
    </body></html>
    <?php exit;
}

/* ===
   ADD NOTE
=== */
if (isset($_POST['add_note'])) {
    require_csrf('note_token', 'note_token');
    require_teacher_role();

    $teacher_id = (int)$_SESSION['user_id'];
    $course_id = (int)$_POST['course_id'];

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("X Unauthorized course access");
    }

    $title   = trim($_POST['title'] ?? '');
    $content  = trim($_POST['content'] ?? '');
    $access_type = $_POST['access_type'] ?? 'free';
    $file_path   = "";
    if (isset($_FILES['file']) && !empty($_FILES['file']['name']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $allowedExt = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'txt', 'jpg', 'jpeg', 'png'];
        $allowedMime = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
            'image/jpeg',
            'image/png',
        ];
        $maxFileSize = 10 * 1024 * 1024;

        $originalName = basename($_FILES['file']['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedExt, true)) {
            die("X File type not allowed. Allowed types: " . implode(', ', $allowedExt));
        }
        if ($_FILES['file']['size'] > $maxFileSize) {
            die("X File is too large. Max size is 10MB.");
        }

        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($_FILES['file']['tmp_name']);

        if (!in_array($mimeType, $allowedMime, true)) {
            die("X File content does not match an allowed type.");
        }

        $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
        $target   = rtrim($note_dir, '/') . '/' . $safeName;

        if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            $file_path = $target;
        } else {
            die("X Failed to save uploaded file.");
        }
    }
    try {
        queue_trainer_change(
            $pdo,
            'note',
            null,
            [],
            [
                'action' => 'create',
                'course_id' => $course_id,
                'title' => $title,
                'content' => $content,
                'access_type' => $access_type,
                'created_by' => $teacher_id,
                'file_path' => $file_path
            ],
            $teacher_id,
            'Trainer submitted a learning material/note for approval.',
            'note',
            0
        );
        $_SESSION['note_token']      = bin2hex(random_bytes(32));
        $_SESSION['success_message'] = "Learning material submitted for Super Administrator approval.";
    } catch (Throwable $e) {
        if (!empty($file_path) && file_exists($file_path)) @unlink($file_path);
        $_SESSION['error_message'] = "Failed to submit learning material for approval.";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT NOTE (APPROVAL REQUIRED)
=== */
if (isset($_POST['edit_note'])) {
    require_csrf('note_token', 'note_token');
    require_teacher_role();

    $note_id = (int)$_POST['note_id'];
    $stmt = $pdo->prepare("
        SELECT n.* FROM notes n
        JOIN course_teachers ct ON ct.course_id = n.course_id
        WHERE n.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $stmt->execute([$note_id, $teacher_id]);
    $oldNote = $stmt->fetch();
    if (!$oldNote) die("X Unauthorized note access");

    $title       = trim($_POST['title'] ?? '');
    $content     = trim($_POST['content'] ?? '');
    $access_type = $_POST['access_type'] ?? 'free';
    $file_path   = $oldNote['file_path'];

    if (isset($_FILES['file']) && !empty($_FILES['file']['name']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
        $allowedExt = ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'txt', 'jpg', 'jpeg', 'png'];
        $allowedMime = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
            'image/jpeg',
            'image/png',
        ];
        $maxFileSize = 10 * 1024 * 1024;

        $originalName = basename($_FILES['file']['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedExt, true)) die("X File type not allowed.");
        if ($_FILES['file']['size'] > $maxFileSize) die("X File is too large. Max size is 10MB.");

        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($_FILES['file']['tmp_name']);
        if (!in_array($mimeType, $allowedMime, true)) die("X File content does not match an allowed type.");

        $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
        $target   = rtrim($note_dir, '/') . '/' . $safeName;
        if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            $file_path = $target;
        } else {
            die("X Failed to save uploaded file.");
        }
    }

    queue_trainer_change(
        $pdo,
        'note',
        $note_id,
        [
            'title' => $oldNote['title'],
            'content' => $oldNote['content'],
            'access_type' => $oldNote['access_type'],
            'file_path' => $oldNote['file_path']
        ],
        [
            'action' => 'update',
            'note_id' => $note_id,
            'course_id' => $oldNote['course_id'],
            'title' => $title,
            'content' => $content,
            'access_type' => $access_type,
            'created_by' => $teacher_id,
            'file_path' => $file_path
        ],
        $teacher_id,
        'Trainer submitted a learning material edit for Super Administrator approval.',
        'note',
        $note_id
    );

    $_SESSION['note_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Learning material changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   DELETE NOTE
=== */
if (isset($_POST['delete_note'])) {
    require_csrf('note_token', 'note_token');

    $id = (int)$_POST['delete_note'];
    $stmt = $pdo->prepare("
        DELETE n FROM notes n
        JOIN course_teachers ct ON ct.course_id = n.course_id
        WHERE n.id = ? AND ct.teacher_id = ?
    ");
    $stmt->execute([$id, $teacher_id]);
    $_SESSION['note_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Note deleted successfully.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   VIEW NOTE
=== */
if (isset($_GET['view_note'])) {
    $note_id = (int)$_GET['view_note'];
    $stmt = $pdo->prepare("
        SELECT n.*, c.title AS course_title
        FROM notes n
        JOIN courses c ON c.id = n.course_id
        JOIN course_teachers ct ON ct.course_id = c.id
        WHERE n.id = ? AND ct.teacher_id = ?
    ");
    $stmt->execute([$note_id, $teacher_id]);
    $note = $stmt->fetch();
    if (!$note) die("Note not found");
    $stmt = $pdo->prepare("SELECT 1 FROM enrollments WHERE user_id=? AND course_id=? LIMIT 1");
    $stmt->execute([$user_id, $note['course_id']]);
    $isEnrolled = $stmt->rowCount() > 0;

    if ($note['access_type'] == 'paid' && !$isEnrolled) {
        die("Access Denied X");
    }
}

/* ===
   CREATE QUIZ
=== */
if (isset($_POST['create_quiz'])) {
    require_csrf('quiz_token', 'quiz_token');
    $course_id = (int)$_POST['course_id'];
    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("X Unauthorized course access");
    }
    $passing_marks = (int)$_POST['passing_marks'];
    $duration = (int)$_POST['duration'];
    $title = trim($_POST['title']);
    $description = trim($_POST['description']);

    queue_trainer_change(
        $pdo,
        'quiz',
        null,
        [],
        [
            'action' => 'create',
            'course_id' => $course_id,
            'title' => $title,
            'description' => $description,
            'passing_score' => $passing_marks,
            'duration' => $duration
        ],
        $teacher_id,
        'Trainer created a quiz. Super Administrator approval is required before publication.',
        'quiz',
        0
    );
    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Quiz submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT QUIZ (APPROVAL REQUIRED)
=== */
if (isset($_POST['edit_quiz'])) {
    require_csrf('quiz_token', 'quiz_token');

    $quiz_id = (int)$_POST['quiz_id'];
    $check = $pdo->prepare("
        SELECT q.* FROM quizzes q
        JOIN course_teachers ct ON ct.course_id = q.course_id
        WHERE q.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$quiz_id, $teacher_id]);
    $oldQuiz = $check->fetch();
    if (!$oldQuiz) die("X Unauthorized quiz access");

    $title         = trim($_POST['title'] ?? '');
    $description   = trim($_POST['description'] ?? '');
    $passing_marks = (int)($_POST['passing_marks'] ?? 0);
    $duration      = (int)($_POST['duration'] ?? 0);

    queue_trainer_change(
        $pdo,
        'quiz',
        $quiz_id,
        [
            'title' => $oldQuiz['title'],
            'description' => $oldQuiz['description'] ?? '',
            'passing_score' => $oldQuiz['passing_score'] ?? 0,
            'duration' => $oldQuiz['duration'] ?? 0
        ],
        [
            'action' => 'update',
            'quiz_id' => $quiz_id,
            'course_id' => $oldQuiz['course_id'],
            'title' => $title,
            'description' => $description,
            'passing_score' => $passing_marks,
            'duration' => $duration
        ],
        $teacher_id,
        'Trainer submitted a quiz edit for Super Administrator approval.',
        'quiz',
        $quiz_id
    );

    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Quiz changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   DELETE QUIZ
=== */
if (isset($_GET['delete_quiz'])) {
    $token = $_GET['quiz_token'] ?? '';
    if (!hash_equals($_SESSION['quiz_token'], $token)) {
        force_login_redirect();
    }
    $quiz_id = (int)$_GET['delete_quiz'];
    $check = $pdo->prepare("
        SELECT 1 FROM quizzes q
        JOIN course_teachers ct ON ct.course_id = q.course_id
        WHERE q.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$quiz_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("X Unauthorized quiz access");
    }
    $stmt = $pdo->prepare("DELETE FROM quiz_results WHERE quiz_id = ?");
    $stmt->execute([$quiz_id]);
    $stmt = $pdo->prepare("DELETE FROM quiz_questions WHERE quiz_id = ?");
    $stmt->execute([$quiz_id]);
    $stmt = $pdo->prepare("DELETE FROM quizzes WHERE id = ?");
    $stmt->execute([$quiz_id]);

    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Quiz deleted successfully.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   ADD QUESTION  
=== */
if (isset($_POST['add_question'])) {
    require_csrf('quiz_token', 'quiz_token');

    $quiz_id = (int)$_POST['quiz_id'];
    $check = $pdo->prepare("
        SELECT 1 FROM quizzes q
        JOIN course_teachers ct ON ct.course_id = q.course_id
        WHERE q.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$quiz_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("X Unauthorized quiz access");
    }
    $marks = (int)$_POST['marks'];
    $questionData = [
        'action' => 'create',
        'quiz_id' => $quiz_id,
        'question' => trim($_POST['question'] ?? ''),
        'question_type' => $_POST['question_type'] ?? 'mcq',
        'option_a' => trim($_POST['option_a'] ?? ''),
        'option_b' => trim($_POST['option_b'] ?? ''),
        'option_c' => trim($_POST['option_c'] ?? ''),
        'option_d' => trim($_POST['option_d'] ?? ''),
        'correct_answer' => strtoupper(trim($_POST['correct_answer'] ?? '')),
        'marks' => $marks,
        'difficulty' => $_POST['difficulty'] ?? 'medium',
        'topic' => trim($_POST['topic'] ?? ''),
        'explanation' => trim($_POST['explanation'] ?? '')
    ];
    queue_trainer_change(
        $pdo,
        'quiz_question',
        null,
        [],
        $questionData,
        $teacher_id,
        'Trainer submitted an assessment question for approval.',
        'quiz_question',
        0
    );
    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Assessment question submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT QUESTION (APPROVAL REQUIRED)
=== */
if (isset($_POST['edit_question'])) {
    require_csrf('quiz_token', 'quiz_token');

    $question_id = (int)$_POST['question_id'];
    $check = $pdo->prepare("
        SELECT qq.* FROM quiz_questions qq
        JOIN quizzes q ON q.id = qq.quiz_id
        JOIN course_teachers ct ON ct.course_id = q.course_id
        WHERE qq.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$question_id, $teacher_id]);
    $oldQuestion = $check->fetch();
    if (!$oldQuestion) die("X Unauthorized question access");

    $marks = (int)($_POST['marks'] ?? 1);
    $newQuestionData = [
        'action' => 'update',
        'question_id' => $question_id,
        'quiz_id' => $oldQuestion['quiz_id'],
        'question' => trim($_POST['question'] ?? ''),
        'question_type' => $_POST['question_type'] ?? 'mcq',
        'option_a' => trim($_POST['option_a'] ?? ''),
        'option_b' => trim($_POST['option_b'] ?? ''),
        'option_c' => trim($_POST['option_c'] ?? ''),
        'option_d' => trim($_POST['option_d'] ?? ''),
        'correct_answer' => strtoupper(trim($_POST['correct_answer'] ?? '')),
        'marks' => $marks,
        'difficulty' => $_POST['difficulty'] ?? 'medium',
        'topic' => trim($_POST['topic'] ?? ''),
        'explanation' => trim($_POST['explanation'] ?? '')
    ];

    queue_trainer_change(
        $pdo,
        'quiz_question',
        $question_id,
        [
            'question' => $oldQuestion['question'],
            'option_a' => $oldQuestion['option_a'],
            'option_b' => $oldQuestion['option_b'],
            'option_c' => $oldQuestion['option_c'],
            'option_d' => $oldQuestion['option_d'],
            'correct_answer' => $oldQuestion['correct_answer'],
            'marks' => $oldQuestion['marks']
        ],
        $newQuestionData,
        $teacher_id,
        'Trainer submitted an assessment question edit for approval.',
        'quiz_question',
        $question_id
    );

    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Question changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   BULK IMPORT QUESTIONS
=== */

function parseBulkQuestionText(string $content): array {
    $content = str_replace(["\r\n", "\r"], "\n", $content);
    $content = str_replace("\xC2\xA0", " ", $content);
    $lines = explode("\n", $content);
    $lines = array_filter($lines, function ($line) {
        return !preg_match('/^\s*HINT\s*[:\-]/i', $line);
    });
    $content = implode("\n", $lines);
    $blocks = preg_split('/\n\s*\n/', trim($content));
    $rows   = [];

    foreach ($blocks as $block) {
        $block = trim($block);
        if ($block === '') continue;
        if (strpos($block, '|') !== false) {
            $pipeLines = array_values(array_filter(array_map('trim', explode("\n", $block)), fn($l) => $l !== ''));
            $allPipeLines = true;
            foreach ($pipeLines as $pl) {
                if (substr_count($pl, '|') < 5) { $allPipeLines = false; break; }
            }
            if ($allPipeLines && count($pipeLines) > 0) {
                foreach ($pipeLines as $pl) {
                    $parts = array_map('trim', explode('|', $pl));
                    if (count($parts) >= 6) {
                        $rows[] = [
                            'question' => $parts[0],
                            'option_a' => $parts[1],
                            'option_b' => $parts[2],
                            'option_c' => $parts[3],
                            'option_d' => $parts[4],
                            'answer'   => strtoupper(substr(trim($parts[5]), 0, 1)),
                        ];
                    }
                }
                continue;
            }
        }
        $rawLines = array_values(array_filter(
            array_map('trim', explode("\n", $block)),
            fn ($l) => $l !== ''
        ));
        if (count($rawLines) < 5) continue;

        $optionPattern = '/^[A-Da-d][\.\)]\s*/';
        $optionIndices = [];
        foreach ($rawLines as $i => $line) {
            if (preg_match($optionPattern, $line)) {
                $optionIndices[] = $i;
            }
        }
        if (count($optionIndices) < 4) continue;
        $numQuestions = intdiv(count($optionIndices), 4);
        $answerLinePattern = '/(?:Answer|Ans|Correct)\s*[:\-]?\s*([A-Da-d])\b/i';
        $loneLetterPattern  = '/^\s*([A-Da-d])\s*$/';

        for ($q = 0; $q < $numQuestions; $q++) {
            $a = $optionIndices[$q * 4 + 0];
            $b = $optionIndices[$q * 4 + 1];
            $c = $optionIndices[$q * 4 + 2];
            $d = $optionIndices[$q * 4 + 3];
            $prevD   = ($q > 0) ? $optionIndices[$q * 4 - 1] : -1;
            $between = array_slice($rawLines, $prevD + 1, $a - $prevD - 1);
            $questionParts = array_values(array_filter($between, function ($l) use ($answerLinePattern, $loneLetterPattern) {
                return !preg_match($answerLinePattern, $l) && !preg_match($loneLetterPattern, $l);
            }));
            $question = implode(' ', $questionParts);
            $question = preg_replace('/^\d+[\.\)]\s*/', '', trim($question));
            $optA = preg_replace($optionPattern, '', $rawLines[$a]);
            $optB = preg_replace($optionPattern, '', $rawLines[$b]);
            $optC = preg_replace($optionPattern, '', $rawLines[$c]);
            $optD = preg_replace($optionPattern, '', $rawLines[$d]);
            $nextA = ($q + 1 < $numQuestions) ? $optionIndices[($q + 1) * 4 + 0] : count($rawLines);
            $afterOptions = array_slice($rawLines, $d + 1, $nextA - $d - 1);

            $answer = '';
            foreach ($afterOptions as $l) {
                if (preg_match($answerLinePattern, $l, $m)) {
                    $answer = strtoupper($m[1]);
                    break;
                }
                if (preg_match($loneLetterPattern, $l, $m)) {
                    $answer = strtoupper($m[1]);
                    break;
                }
            }

            if ($question === '' || $optA === '' || $optB === '' || $optC === '' || $optD === '') {
                continue;
            }

            $rows[] = [
                'question' => $question,
                'option_a' => $optA,
                'option_b' => $optB,
                'option_c' => $optC,
                'option_d' => $optD,
                'answer'   => $answer,
            ];
        }
    }

    return $rows;
}

function extractTextFromDocx(string $path): ?string {
    if (!class_exists('ZipArchive')) return null;
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) return null;
    $xml = $zip->getFromName('word/document.xml');
    $zip->close();
    if ($xml === false) return null;
    $xml = preg_replace('/<\/w:p>/', "\n\n", $xml);
    $xml = preg_replace('/<w:br[^>]*\/>/', "\n", $xml);
    $xml = preg_replace('/<w:tab\/>/', ' ', $xml);
    $text = strip_tags($xml);
    $text = html_entity_decode($text, ENT_QUOTES | ENT_XML1);
    $text = preg_replace('/\n{3,}/', "\n\n", $text);
    return $text;
}

function extractTextFromPdf(string $path): ?string {
    if (!function_exists('shell_exec')) return null;
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (in_array('shell_exec', $disabled, true)) return null;

    $which = @shell_exec('command -v pdftotext 2>/dev/null');
    if (empty(trim((string) $which))) return null;

    $out = $path . '_extracted.txt';
    @shell_exec(
        'pdftotext -layout -nopgbrk '
        . escapeshellarg($path) . ' '
        . escapeshellarg($out)
        . ' 2>/dev/null'
    );

    if (!file_exists($out)) return null;

    $text = file_get_contents($out);
    @unlink($out);
    if ($text === false) return null;

    $text = preg_replace('/\n{3,}/', "\n\n", $text);
    return $text;
}

function parseCsvQuestionFile(string $path): array {
    $rows = [];
    if (($handle = fopen($path, 'r')) === false) return $rows;

    $first = true;
    while (($line = fgetcsv($handle)) !== false) {
        if ($first) {
            $first = false;
            $joined = strtolower(implode(',', $line));
            if (strpos($joined, 'question') !== false && strpos($joined, 'answer') !== false) {
                continue;
            }
        }
        if (count($line) < 6) continue;
        $rows[] = [
            'question' => trim($line[0]),
            'option_a' => trim($line[1]),
            'option_b' => trim($line[2]),
            'option_c' => trim($line[3]),
            'option_d' => trim($line[4]),
            'answer'   => strtoupper(substr(trim($line[5]), 0, 1)),
        ];
    }
    fclose($handle);
    return $rows;
}

if (isset($_POST['bulk_import_questions'])) {
    require_csrf('quiz_token', 'quiz_token');

    $quiz_id = (int)($_POST['quiz_id'] ?? 0);

    $check = $pdo->prepare("
        SELECT 1 FROM quizzes q
        JOIN course_teachers ct ON ct.course_id = q.course_id
        WHERE q.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$quiz_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("X Unauthorized quiz access");
    }

    $rows       = [];
    $sourceInfo = '';
    $rawText    = trim($_POST['bulk_text'] ?? '');
    $tempFile   = null;

    if (isset($_FILES['bulk_file']) && !empty($_FILES['bulk_file']['name']) && $_FILES['bulk_file']['error'] === UPLOAD_ERR_OK) {

        $allowedExt = ['txt', 'csv', 'docx', 'xlsx', 'pdf'];
        $maxSize    = 8 * 1024 * 1024;

        $originalName = basename($_FILES['bulk_file']['name']);
        $ext          = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

        if (!in_array($ext, $allowedExt, true)) {
            die("X Unsupported file type. Allowed: " . implode(', ', $allowedExt));
        }
        if ($_FILES['bulk_file']['size'] > $maxSize) {
            die("X File too large. Max size is 8MB.");
        }

        $allowedMimeMap = [
            'txt'  => ['text/plain'],
            'csv'  => ['text/plain', 'text/csv', 'application/csv', 'application/vnd.ms-excel'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
            'pdf'  => ['application/pdf'],
        ];
        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($_FILES['bulk_file']['tmp_name']);
        if (!in_array($mimeType, $allowedMimeMap[$ext], true)) {
            die("X File content does not match the expected type for ." . $ext);
        }

        $tmp_dir = "uploads/tmp_imports/";
        if (!file_exists($tmp_dir)) mkdir($tmp_dir, 0700, true);
        $safeName = bin2hex(random_bytes(16)) . '.' . $ext;
        $tempFile = rtrim($tmp_dir, '/') . '/' . $safeName;

        if (!move_uploaded_file($_FILES['bulk_file']['tmp_name'], $tempFile)) {
            die("X Failed to process the uploaded file.");
        }

        switch ($ext) {
            case 'txt':
                $rawText = file_get_contents($tempFile);
                $sourceInfo = "from text file";
                break;

            case 'csv':
                $rows = parseCsvQuestionFile($tempFile);
                $sourceInfo = "from CSV file";
                break;

            case 'docx':
                $extracted = extractTextFromDocx($tempFile);
                if ($extracted === null) {
                    @unlink($tempFile);
                    die("X Could not read the Word document. Try saving it as .txt and re-uploading.");
                }
                $rawText = $extracted;
                $sourceInfo = "from Word document";
                break;

            case 'xlsx':
                if (class_exists('\PhpOffice\PhpSpreadsheet\IOFactory')) {
                    try {
                        $spreadsheet = \PhpOffice\PhpSpreadsheet\IOFactory::load($tempFile);
                        $sheet = $spreadsheet->getActiveSheet();
                        foreach ($sheet->getRowIterator() as $i => $row) {
                            $cells = [];
                            foreach ($row->getCellIterator() as $cell) {
                                $cells[] = trim((string)$cell->getValue());
                            }
                            if ($i === 1 && stripos(implode(',', $cells), 'question') !== false) continue;
                            if (count($cells) >= 6 && trim($cells[0]) !== '') {
                                $rows[] = [
                                    'question' => $cells[0],
                                    'option_a' => $cells[1],
                                    'option_b' => $cells[2],
                                    'option_c' => $cells[3],
                                    'option_d' => $cells[4],
                                    'answer'   => strtoupper(substr(trim($cells[5]), 0, 1)),
                                ];
                            }
                        }
                        $sourceInfo = "from Excel file";
                    } catch (\Throwable $e) {
                        @unlink($tempFile);
                        die("X Could not read the Excel file. Make sure it's a valid .xlsx.");
                    }
                } else {
                    @unlink($tempFile);
                    die("X Excel (.xlsx) import requires the PhpSpreadsheet library on the server (composer require phpoffice/phpspreadsheet). Please use CSV, TXT, or paste instead.");
                }
                break;

            case 'pdf':
                $extracted = extractTextFromPdf($tempFile);
                if ($extracted === null) {
                    @unlink($tempFile);
                    die("X PDF import requires the 'pdftotext' tool on the server. Please use TXT, CSV, or paste instead.");
                }
                $rawText = $extracted;
                $sourceInfo = "from PDF file";
                break;
        }

        @unlink($tempFile);
    }

    if (empty($rows) && $rawText !== '') {
        $rows = parseBulkQuestionText($rawText);
        if ($sourceInfo === '') $sourceInfo = "from pasted text";
    }

    if (empty($rows)) {
        die("X No valid questions were found. Please check the format and try again.");
    }

    $maxQuestions = 500;
    if (count($rows) > $maxQuestions) {
        $rows = array_slice($rows, 0, $maxQuestions);
    }

    $imported = 0;
    $skipped  = 0;
    $errors   = [];

    $insert = $pdo->prepare("
        INSERT INTO quiz_questions
        (quiz_id, question, question_type, option_a, option_b, option_c, option_d, correct_answer, marks)
        VALUES (?, ?, 'mcq', ?, ?, ?, ?, ?, 1)
    ");

    foreach ($rows as $idx => $r) {
        $question = mb_substr(trim($r['question'] ?? ''), 0, 2000);
        $a        = mb_substr(trim($r['option_a'] ?? ''), 0, 255);
        $b        = mb_substr(trim($r['option_b'] ?? ''), 0, 255);
        $c        = mb_substr(trim($r['option_c'] ?? ''), 0, 255);
        $d        = mb_substr(trim($r['option_d'] ?? ''), 0, 255);
        $answer   = strtoupper(trim($r['answer'] ?? ''));

        if ($question === '' || $a === '' || $b === '' || $c === '' || $d === '' || !in_array($answer, ['A','B','C','D'], true)) {
            $skipped++;
            $errors[] = "Row " . ($idx + 1) . ": " . ($question !== '' ? $question : '(empty question)');
            continue;
        }

        try {
            $insert->execute([$quiz_id, $question, $a, $b, $c, $d, $answer]);
            $imported++;
        } catch (\PDOException $e) {
            $skipped++;
            $errors[] = "Row " . ($idx + 1) . ": database error";
        }
    }

    $_SESSION['quiz_token'] = bin2hex(random_bytes(32));

    $msg = "Imported {$imported} question(s) {$sourceInfo}.";
    if ($skipped > 0) {
        $msg .= " {$skipped} row(s) were skipped due to missing/invalid data.";
    }
    $_SESSION['success_message'] = $msg;
    if (!empty($errors)) {
        $_SESSION['error_message'] = "Skipped details: " . htmlspecialchars(implode(' | ', array_slice($errors, 0, 10)));
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   STUDENT ACTIONS
=== */
if (isset($_POST['student_action'])) {
    require_csrf('student_token', 'student_token');
    $student_id = (int)$_POST['student_id'];
    $action     = $_POST['action'];
    $ownCheck = $pdo->prepare("
        SELECT 1 FROM students s
        JOIN enrollments e ON e.user_id = s.user_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE s.id = ? AND ct.teacher_id = ?
        LIMIT 1
    ");
    $ownCheck->execute([$student_id, $teacher_id]);
    if ($ownCheck->rowCount() == 0) {
        die("X Unauthorized student access");
    }

    $stmt = $pdo->prepare("SELECT user_id FROM students WHERE id=?");
    $stmt->execute([$student_id]);
    $student = $stmt->fetch();

    if (!$student) die("Student not found");
    $userId = $student['user_id'];

    if ($action == "activate") {
        $s = $pdo->prepare("UPDATE students SET status='active' WHERE id=?");
        $s->execute([$student_id]);
        $s = $pdo->prepare("UPDATE users SET status='active' WHERE id=?");
        $s->execute([$userId]);
    } elseif ($action == "suspend") {
        $s = $pdo->prepare("UPDATE students SET status='suspended' WHERE id=?");
        $s->execute([$student_id]);
        $s = $pdo->prepare("UPDATE users SET status='suspended' WHERE id=?");
        $s->execute([$userId]);
    } elseif ($action == "reset_password") {
        $newPass = password_hash(bin2hex(random_bytes(6)), PASSWORD_DEFAULT);
        $s = $pdo->prepare("UPDATE users SET password=? WHERE id=?");
        $s->execute([$newPass, $userId]);
    } elseif ($action == "delete") {
        $s = $pdo->prepare("DELETE FROM enrollments WHERE user_id=?");
        $s->execute([$userId]);
        $s = $pdo->prepare("DELETE FROM students WHERE id=?");
        $s->execute([$student_id]);
        $s = $pdo->prepare("DELETE FROM users WHERE id=?");
        $s->execute([$userId]);
    }

    $_SESSION['student_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Student action applied.";
    log_audit($pdo, $teacher_id, 'student_action', "Applied '$action' to student #$student_id", 'student', $student_id);
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   ENROLLMENT ACTIONS
=== */
if (isset($_POST['enroll_action'])) {
    require_csrf('enroll_token', 'enroll_token');

    $enroll_id = (int)$_POST['enroll_id'];
    $action    = $_POST['action'];

    $check = $pdo->prepare("
        SELECT e.id FROM enrollments e
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE e.id=? AND ct.teacher_id=?
    ");
    $check->execute([$enroll_id, $teacher_id]);
    if ($check->rowCount() == 0) {
        die("Unauthorized enrollment action");
    }

    if ($action == "approve") {
        $s = $pdo->prepare("UPDATE enrollments SET status='approved' WHERE id=?");
        $s->execute([$enroll_id]);
    } elseif ($action == "reject") {
        $s = $pdo->prepare("UPDATE enrollments SET status='rejected' WHERE id=?");
        $s->execute([$enroll_id]);
    } elseif ($action == "delete") {
        $s = $pdo->prepare("DELETE FROM enrollments WHERE id=?");
        $s->execute([$enroll_id]);
    }

    $_SESSION['enroll_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Enrollment updated.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   CREATE ASSIGNMENT (APPROVAL REQUIRED)
=== */
if (isset($_POST['create_assignment'])) {
    require_csrf('assignment_token', 'assignment_token');
    require_teacher_role();

    $course_id = (int)($_POST['course_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $due_date = trim($_POST['due_date'] ?? '');

    if ($course_id <= 0 || $title === '') die("Invalid assignment input");

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() === 0) die("Unauthorized course access");

    queue_trainer_change(
        $pdo,
        'assignment',
        null,
        [],
        [
            'action' => 'create',
            'course_id' => $course_id,
            'teacher_id' => $teacher_id,
            'title' => $title,
            'description' => $description,
            'due_date' => ($due_date !== '' ? $due_date : null)
        ],
        $teacher_id,
        'Trainer submitted an assignment for Super Administrator approval.',
        'assignment',
        0
    );

    $_SESSION['assignment_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Assignment submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT ASSIGNMENT (APPROVAL REQUIRED)
=== */
if (isset($_POST['edit_assignment'])) {
    require_csrf('assignment_token', 'assignment_token');
    require_teacher_role();

    $assignment_id = (int)($_POST['assignment_id'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $due_date = trim($_POST['due_date'] ?? '');

    if ($assignment_id <= 0 || $title === '') die("Invalid assignment input");

    $check = $pdo->prepare("SELECT * FROM assignments WHERE id=? AND teacher_id=? LIMIT 1");
    $check->execute([$assignment_id, $teacher_id]);
    $oldAssignment = $check->fetch();
    if (!$oldAssignment) die("Unauthorized assignment access");

    queue_trainer_change(
        $pdo,
        'assignment',
        $assignment_id,
        [
            'title' => $oldAssignment['title'],
            'description' => $oldAssignment['description'] ?? '',
            'due_date' => $oldAssignment['due_date'] ?? null
        ],
        [
            'action' => 'update',
            'assignment_id' => $assignment_id,
            'course_id' => $oldAssignment['course_id'],
            'teacher_id' => $teacher_id,
            'title' => $title,
            'description' => $description,
            'due_date' => ($due_date !== '' ? $due_date : null)
        ],
        $teacher_id,
        'Trainer submitted an assignment edit for Super Administrator approval.',
        'assignment',
        $assignment_id
    );

    $_SESSION['assignment_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Assignment changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   GRADE SUBMISSION  
=== */
if (isset($_POST['grade_submission'])) {
    require_csrf('grading_token', 'grading_token');

    $submission_id = (int)($_POST['submission_id'] ?? 0);
    $marks         = $_POST['marks'] !== '' ? (int)$_POST['marks'] : null;
    $feedback      = trim($_POST['feedback'] ?? '');
    $grade_action  = $_POST['grade_action'] ?? 'grade'; // grade | return_for_correction | mark_late

    $check = $pdo->prepare("
        SELECT s.*, a.teacher_id, a.title AS assignment_title
        FROM submissions s
        JOIN assignments a ON a.id = s.assignment_id
        WHERE s.id = ? AND a.teacher_id = ?
        LIMIT 1
    ");
    $check->execute([$submission_id, $teacher_id]);
    $submission = $check->fetch();
    if (!$submission) die("X Unauthorized submission access");

    if ($grade_action === 'return_for_correction') {
        $newStatus = 'resubmission_requested';
    } elseif ($grade_action === 'mark_late') {
        $newStatus = 'late';
    } else {
        $newStatus = 'graded';
    }

    $stmt = $pdo->prepare("
        UPDATE submissions
        SET marks = ?, feedback = ?, status = ?, graded_at = NOW()
        WHERE id = ?
    ");
    $stmt->execute([$marks, $feedback, $newStatus, $submission_id]);

    $stmtStudent = $pdo->prepare("SELECT user_id FROM students WHERE id=?");
    $stmtStudent->execute([$submission['student_id']]);
    $studentUser = $stmtStudent->fetch();
    if ($studentUser) {
        notify_user($pdo, (int)$studentUser['user_id'], "Your submission for \"{$submission['assignment_title']}\" was " . ($newStatus === 'graded' ? "graded." : "updated: $newStatus."));
    }

    log_audit($pdo, $teacher_id, 'submission_graded', "Graded submission #$submission_id ($newStatus)", 'submission', $submission_id);

    $_SESSION['grading_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Submission updated.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   ADD ANNOUNCEMENT
=== */
if (isset($_POST['add_announcement'])) {
    require_csrf('announce_token', 'announce_token');
    require_teacher_role();

    $session_user_id = (int)$_SESSION['user_id'];

    $course_id = (int)$_POST['course_id'];
    $title     = trim($_POST['title']);
    $message   = trim($_POST['message']);

    if ($course_id <= 0 || empty($title) || empty($message)) die("Invalid input");

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $session_user_id]);
    if ($check->rowCount() == 0) die("Unauthorized course access");

    $teacherLookup = $pdo->prepare("SELECT id FROM teachers WHERE user_id=? LIMIT 1");
    $teacherLookup->execute([$session_user_id]);
    $teacherRow = $teacherLookup->fetch();

    if (!$teacherRow) {
        die("Teacher profile not found.");
    }

    $teacher_profile_id = (int)$teacherRow['id'];

    queue_trainer_change(
        $pdo,
        'other',
        null,
        [],
        [
            'action' => 'create',
            'content_type' => 'announcement',
            'course_id' => $course_id,
            'teacher_id' => $teacher_profile_id,
            'title' => $title,
            'message' => $message
        ],
        $teacher_id,
        'Trainer submitted an announcement for approval.',
        null,
        null
    );
    $_SESSION['announce_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Announcement submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   EDIT ANNOUNCEMENT (APPROVAL REQUIRED)
=== */
if (isset($_POST['edit_announcement'])) {
    require_csrf('announce_token', 'announce_token');
    require_teacher_role();

    $announcement_id = (int)($_POST['announcement_id'] ?? 0);
    $title   = trim($_POST['title'] ?? '');
    $message = trim($_POST['message'] ?? '');

    if ($announcement_id <= 0 || $title === '' || $message === '') die("Invalid input");

    $check = $pdo->prepare("
        SELECT a.* FROM announcements a
        JOIN course_teachers ct ON ct.course_id = a.course_id
        WHERE a.id=? AND ct.teacher_id=?
        LIMIT 1
    ");
    $check->execute([$announcement_id, $teacher_id]);
    $oldAnnouncement = $check->fetch();
    if (!$oldAnnouncement) die("Unauthorized announcement access");

    $teacherLookup = $pdo->prepare("SELECT id FROM teachers WHERE user_id=? LIMIT 1");
    $teacherLookup->execute([$teacher_id]);
    $teacherRow = $teacherLookup->fetch();
    $teacher_profile_id = $teacherRow ? (int)$teacherRow['id'] : 0;

    queue_trainer_change(
        $pdo,
        'other',
        $announcement_id,
        [
            'title' => $oldAnnouncement['title'],
            'message' => $oldAnnouncement['message']
        ],
        [
            'action' => 'update',
            'content_type' => 'announcement',
            'announcement_id' => $announcement_id,
            'course_id' => $oldAnnouncement['course_id'],
            'teacher_id' => $teacher_profile_id,
            'title' => $title,
            'message' => $message
        ],
        $teacher_id,
        'Trainer submitted an announcement edit for approval.',
        null,
        null
    );

    $_SESSION['announce_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Announcement changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   DELETE ANNOUNCEMENT
=== */
if (isset($_GET['delete_announcement'])) {
    $token = $_GET['announce_token'] ?? '';
    if (!hash_equals($_SESSION['announce_token'], $token)) {
        force_login_redirect();
    }
    $id = (int)$_GET['delete_announcement'];
    $stmt = $pdo->prepare("
        DELETE a FROM announcements a
        INNER JOIN course_teachers ct ON ct.course_id = a.course_id
        WHERE a.id=? AND ct.teacher_id=?
    ");
    $stmt->execute([$id, $teacher_id]);
    $_SESSION['announce_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Announcement deleted.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   UPDATE PROFILE
=== */
if (isset($_POST['update_profile'])) {
    require_csrf('profile_token', 'profile_token');

    $specialization    = trim($_POST['specialization'] ?? '');
    $qualification     = trim($_POST['qualification'] ?? '');
    $qualificationLevel = trim($_POST['qualification_level'] ?? '');
    $licenseNumber     = trim($_POST['license_number'] ?? '');
    $phone             = trim($_POST['phone'] ?? '');
    $experience_years  = (int)($_POST['experience_years'] ?? 0);

    if ($experience_years < 0 || $experience_years > 60) die("Invalid experience value");

    $oldProfile = [
        'specialization' => $teacherInfo['specialization'] ?? '',
        'qualification' => $teacherInfo['qualification'] ?? '',
        'qualification_level' => $teacherInfo['qualification_level'] ?? '',
        'license_number' => $teacherInfo['license_number'] ?? '',
        'phone' => $teacherInfo['phone'] ?? ''
    ];
    $newProfile = [
        'action' => 'update',
        'user_id' => $user_id,
        'specialization' => $specialization,
        'qualification' => $qualification,
        'qualification_level' => $qualificationLevel,
        'license_number' => $licenseNumber,
        'phone' => $phone,
        'experience_years' => $experience_years
    ];

    queue_trainer_change(
        $pdo,
        'profile',
        $user_id,
        $oldProfile,
        $newProfile,
        $teacher_id,
        'Trainer profile change submitted for Super Administrator verification.',
        null,
        null
    );
    $_SESSION['profile_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Profile changes submitted for Super Administrator approval.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

/* ===
   SAFE COUNT FUNCTION
=== */
function getCount($pdo, $sql, $teacher_id) {
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$teacher_id]);
    $row = $stmt->fetch();
    return $row['total'] ?? 0;
}


/* ===
   CBT-KENYA / STP BRANDING
=== */
$branding = [
    'brand_name' => 'CBT-Kenya STP',
    'brand_tagline' => 'Skills Transfer Program',
    'primary_color' => '#0b3d33',
    'secondary_color' => '#0f6b56',
    'accent_color' => '#14b8a6',
    'font_family' => "'Poppins', 'Segoe UI', Arial, sans-serif",
    'logo_path' => 'https://www.cbtkenya.org/wp-content/uploads/2018/11/cbt-ke.png',
];
try {
    $stmtBrand = $pdo->query("SELECT * FROM branding_settings WHERE is_active=1 ORDER BY id DESC LIMIT 1");
    $dbBrand = $stmtBrand ? $stmtBrand->fetch() : false;
    if ($dbBrand) $branding = array_merge($branding, array_filter($dbBrand, fn($v) => $v !== null && $v !== ''));
} catch (Throwable $e) {
    // Branding migration may not yet be installed; use safe defaults.
}

/* ===
   PROMOTIONS / ADVERTISING SPACE
=== */
$promotions = [];
try {
    $stmtPromo = $pdo->prepare("
        SELECT * FROM promotions
        WHERE is_active = 1
          AND (starts_at IS NULL OR starts_at <= NOW())
          AND (ends_at IS NULL OR ends_at >= NOW())
        ORDER BY sort_order ASC, id DESC
        LIMIT 6
    ");
    $stmtPromo->execute();
    $promotions = $stmtPromo->fetchAll();
} catch (Throwable $e) {
}
if (empty($promotions)) {
    $promotions = [
        [
            'title' => 'CBT-Kenya Skills Transfer Program',
            'body'  => 'Explore the full STP pathway from foundational training to supervised, transition-to-practice mentorship.',
            'link_url' => 'https://www.cbtkenya.org/skills-transfer-program/',
            'link_label' => 'View the STP Journey',
            'image_url' => '',
        ],
        [
            'title' => 'Employee Assistance Program',
            'body'  => 'CBT-Kenya partners with organisations to provide professional counselling for their teams.',
            'link_url' => 'https://www.cbtkenya.org/employee-assistance-program/',
            'link_label' => 'Learn More',
            'image_url' => '',
        ],
        [
            'title' => 'Counselling Outreach Programs',
            'body'  => 'Bringing psychological support closer to communities that need it most across Kenya.',
            'link_url' => 'https://www.cbtkenya.org/counselling-outreach-programs/',
            'link_label' => 'See Outreach Work',
            'image_url' => '',
        ],
    ];
}

/* ===
   STATS
=== */
$courses_count  = getCount($pdo, "SELECT COUNT(DISTINCT ct.course_id) AS total FROM course_teachers ct INNER JOIN courses c ON c.id = ct.course_id WHERE ct.teacher_id=? AND ct.status='active'", $teacher_id);
$students_count = getCount($pdo, "SELECT COUNT(DISTINCT e.user_id) AS total FROM enrollments e INNER JOIN course_teachers ct ON ct.course_id=e.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=? AND ct.status='active'", $teacher_id);
$notes_count    = getCount($pdo, "SELECT COUNT(*) AS total FROM notes n INNER JOIN course_teachers ct ON ct.course_id=n.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=? AND ct.status='active'", $teacher_id);
$videos_count   = getCount($pdo, "SELECT COUNT(*) AS total FROM course_videos cv INNER JOIN course_teachers ct ON ct.course_id = cv.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id = ? AND ct.status = 'active'", $teacher_id);
$quiz_count     = getCount($pdo, "SELECT COUNT(*) AS total FROM quizzes q INNER JOIN course_teachers ct ON ct.course_id=q.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=? AND ct.status='active'", $teacher_id);

$total_courses  = getCount($pdo, "SELECT COUNT(*) AS total FROM course_teachers ct INNER JOIN courses c ON c.id = ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_students = getCount($pdo, "SELECT COUNT(DISTINCT e.user_id) AS total FROM enrollments e JOIN course_teachers ct ON ct.course_id=e.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_content  = getCount($pdo, "SELECT COUNT(*) AS total FROM course_contents cc JOIN course_teachers ct ON ct.course_id=cc.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_videos   = getCount($pdo, "SELECT COUNT(*) AS total FROM course_videos v JOIN course_teachers ct ON ct.course_id=v.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_notes    = getCount($pdo, "SELECT COUNT(*) AS total FROM notes n JOIN course_teachers ct ON ct.course_id=n.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_quizzes  = getCount($pdo, "SELECT COUNT(*) AS total FROM quizzes q JOIN course_teachers ct ON ct.course_id=q.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);
$total_questions= getCount($pdo, "SELECT COUNT(*) AS total FROM quiz_questions qq JOIN quizzes q ON q.id=qq.quiz_id JOIN course_teachers ct ON ct.course_id=q.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=?", $teacher_id);

$total_attempts = getCount($pdo, "
    SELECT COUNT(*) AS total
    FROM quiz_results qr
    JOIN quizzes q ON q.id = qr.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    INNER JOIN courses c ON c.id = ct.course_id
    WHERE ct.teacher_id = ?
", $teacher_id);

$passed = getCount($pdo, "
    SELECT COUNT(*) AS total
    FROM quiz_results qr
    JOIN quizzes q ON q.id = qr.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    INNER JOIN courses c ON c.id = ct.course_id
    WHERE ct.teacher_id = ? AND LOWER(qr.status) = 'passed'
", $teacher_id);

$failed = getCount($pdo, "
    SELECT COUNT(*) AS total
    FROM quiz_results qr
    JOIN quizzes q ON q.id = qr.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    INNER JOIN courses c ON c.id = ct.course_id
    WHERE ct.teacher_id = ? AND LOWER(qr.status) = 'failed'
", $teacher_id);
$stmt = $pdo->prepare("
    SELECT AVG(qr.score) AS avg_score
    FROM quiz_results qr
    JOIN quizzes q ON q.id = qr.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    INNER JOIN courses c ON c.id = ct.course_id
    WHERE ct.teacher_id = ?
");
$stmt->execute([$teacher_id]);
$average_score = $stmt->fetch()['avg_score'] ?? 0;

$stmt = $pdo->prepare("SELECT COALESCE(SUM(p.amount),0) AS total_revenue FROM payments p JOIN enrollments e ON e.user_id=p.user_id JOIN course_teachers ct ON ct.course_id=e.course_id INNER JOIN courses c ON c.id=ct.course_id WHERE ct.teacher_id=? AND p.status='success'");
$stmt->execute([$teacher_id]);
$revenue = $stmt->fetch()['total_revenue'] ?? 0;

/* ===
   FETCH DATA SETS
=== */
$stmtAllCourses = $pdo->prepare("
    SELECT c.id, c.title, c.description, COALESCE(c.price,0) AS price, c.created_at,
        (SELECT COUNT(DISTINCT e.user_id) FROM enrollments e WHERE e.course_id=c.id) AS students,
        (SELECT COUNT(*) FROM course_contents cc WHERE cc.course_id=c.id) AS contents
    FROM courses c
    INNER JOIN course_teachers ct ON ct.course_id=c.id
    WHERE ct.teacher_id=? AND ct.status='active'
    ORDER BY c.created_at DESC
");
$stmtAllCourses->execute([$teacher_id]);
$allCourses = $stmtAllCourses->fetchAll();

$stmtTeacherCourses = $pdo->prepare("
    SELECT c.id, c.title, c.price, c.status
    FROM courses c
    JOIN course_teachers ct ON ct.course_id=c.id
    WHERE ct.teacher_id=?
    ORDER BY c.created_at DESC
");
$stmtTeacherCourses->execute([$teacher_id]);
$teacherCourses = $stmtTeacherCourses->fetchAll();

$stmtCoursesDrop = $pdo->prepare("SELECT c.id, c.title FROM courses c JOIN course_teachers ct ON ct.course_id=c.id WHERE ct.teacher_id=? ORDER BY c.title");
$stmtCoursesDrop->execute([$teacher_id]);
$coursesDropData = $stmtCoursesDrop->fetchAll();
$stmtActivities = $pdo->prepare("
    (
        SELECT
            CONCAT(u.full_name, ' enrolled in ', c.title) AS message,
            e.enrolled_at AS created_at
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        JOIN courses c ON c.id = e.course_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE ct.teacher_id = ?
    )
    UNION ALL
    (
        SELECT
            CONCAT(u.full_name, ' completed ', c.title) AS message,
            e.enrolled_at AS created_at
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        JOIN courses c ON c.id = e.course_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE ct.teacher_id = ? AND e.status = 'completed'
    )
    UNION ALL
    (
        SELECT
            CONCAT(u.full_name, ' attempted quiz \"', COALESCE(qr.quiz_title, q.title), '\" (', qr.status, ')') AS message,
            qr.completed_at AS created_at
        FROM quiz_results qr
        JOIN quizzes q ON q.id = qr.quiz_id
        JOIN course_teachers ct ON ct.course_id = q.course_id
        LEFT JOIN users u ON u.id = qr.user_id
        WHERE ct.teacher_id = ?
    )
    ORDER BY created_at DESC
    LIMIT 5
");
$stmtActivities->execute([$teacher_id, $teacher_id, $teacher_id]);
$activities = $stmtActivities->fetchAll();

$stmtVideos = $pdo->prepare("
    SELECT v.*, c.title AS course_title FROM course_videos v
    JOIN courses c ON c.id=v.course_id
    JOIN course_teachers ct ON ct.course_id=c.id
    WHERE ct.teacher_id=?
    ORDER BY v.id DESC
");
$stmtVideos->execute([$teacher_id]);
$videos = $stmtVideos->fetchAll();

$stmtNotes = $pdo->prepare("
    SELECT n.*, c.title AS course_title FROM notes n
    JOIN courses c ON c.id=n.course_id
    JOIN course_teachers ct ON ct.course_id=c.id
    WHERE ct.teacher_id=?
    ORDER BY n.id DESC
");
$stmtNotes->execute([$teacher_id]);
$notes = $stmtNotes->fetchAll();

$stmtStudents = $pdo->prepare("
    SELECT DISTINCT s.* FROM students s
    JOIN users u ON u.id = s.user_id
    JOIN enrollments e ON e.user_id=s.user_id
    JOIN course_teachers ct ON ct.course_id=e.course_id
    WHERE ct.teacher_id=?
      AND ct.status='active'
      AND u.role='student'
    ORDER BY s.id DESC
");
$stmtStudents->execute([$teacher_id]);
$students = $stmtStudents->fetchAll();

$stmtEnrollments = $pdo->prepare("
    SELECT e.*, u.full_name, c.title FROM enrollments e
    JOIN users u ON u.id=e.user_id
    JOIN courses c ON c.id=e.course_id
    JOIN course_teachers ct ON ct.course_id=c.id
    WHERE ct.teacher_id=?
      AND u.role='student'
    ORDER BY e.id DESC
");
$stmtEnrollments->execute([$teacher_id]);
$enrollments = $stmtEnrollments->fetchAll();

$stmtTop = $pdo->prepare("
    SELECT c.title, COUNT(e.id) AS students FROM courses c
    JOIN course_teachers ct ON ct.course_id=c.id
    LEFT JOIN enrollments e ON e.course_id=c.id
    WHERE ct.teacher_id=?
    GROUP BY c.id, c.title
    ORDER BY students DESC LIMIT 5
");
$stmtTop->execute([$teacher_id]);
$top_courses = $stmtTop->fetchAll();

$stmtQuizList = $pdo->prepare("
    SELECT q.*, c.title AS course_name FROM quizzes q
    LEFT JOIN courses c ON c.id=q.course_id
    JOIN course_teachers ct ON ct.course_id=q.course_id
    WHERE ct.teacher_id=?
    ORDER BY q.id DESC
");
$stmtQuizList->execute([$teacher_id]);
$quizzes = $stmtQuizList->fetchAll();

$stmtQuizDrop = $pdo->prepare("
    SELECT q.id, q.title FROM quizzes q
    JOIN course_teachers ct ON ct.course_id=q.course_id
    WHERE ct.teacher_id=?
    ORDER BY q.id DESC
");
$stmtQuizDrop->execute([$teacher_id]);
$quizDropData = $stmtQuizDrop->fetchAll();

$stmtQuestionsList = $pdo->prepare("
    SELECT qq.*, q.title AS quiz_title FROM quiz_questions qq
    JOIN quizzes q ON q.id = qq.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    WHERE ct.teacher_id=?
    ORDER BY qq.id DESC
    LIMIT 200
");
$stmtQuestionsList->execute([$teacher_id]);
$questionsList = $stmtQuestionsList->fetchAll();

$stmtAttempts = $pdo->prepare("
    SELECT
        qr.id,
        qr.quiz_id,
        qr.score,
        qr.status,
        qr.completed_at,
        COALESCE(qr.quiz_title, q.title) AS quiz_title,
        COALESCE(u_direct.full_name, u_viastudent.full_name) AS full_name
    FROM quiz_results qr
    LEFT JOIN quizzes q ON q.id = qr.quiz_id
    JOIN course_teachers ct ON ct.course_id = q.course_id
    LEFT JOIN users u_direct ON u_direct.id = qr.user_id
    LEFT JOIN students s_via ON s_via.id = qr.student_id
    LEFT JOIN users u_viastudent ON u_viastudent.id = s_via.user_id
    WHERE ct.teacher_id = ?
    ORDER BY qr.id DESC
");
$stmtAttempts->execute([$teacher_id]);
$attempts = $stmtAttempts->fetchAll();

$stmtAnnouncements = $pdo->prepare("
    SELECT a.id, a.title, a.message, a.created_at, c.title AS course
    FROM announcements a
    INNER JOIN course_teachers ct ON ct.course_id=a.course_id
    INNER JOIN courses c ON c.id=a.course_id
    WHERE ct.teacher_id=?
    ORDER BY a.created_at DESC
");
$stmtAnnouncements->execute([$teacher_id]);
$announcements = $stmtAnnouncements->fetchAll();

try {
    $stmtAssignmentsAll = $pdo->prepare("
        SELECT a.*, c.title AS course_title
        FROM assignments a
        JOIN courses c ON c.id=a.course_id
        WHERE a.teacher_id=?
        ORDER BY a.created_at DESC
    ");
    $stmtAssignmentsAll->execute([$teacher_id]);
    $teacherAssignments = $stmtAssignmentsAll->fetchAll();
} catch (Throwable $e) {
    $teacherAssignments = [];
}

/* ===
   INSTRUCTORS 
=== */
$stmtInstructors = $pdo->prepare("
    SELECT
        u2.id              AS teacher_user_id,
        u2.full_name,
        u2.email,
        t2.employee_no,
        t2.specialization,
        t2.qualification,
        t2.experience_years,
        t2.status          AS teacher_status,
        GROUP_CONCAT(DISTINCT c.title ORDER BY c.title SEPARATOR ', ') AS shared_courses,
        COUNT(DISTINCT c.id) AS shared_course_count
    FROM course_teachers ct_mine
    INNER JOIN course_teachers ct2
        ON ct2.course_id = ct_mine.course_id
        AND ct2.teacher_id != ct_mine.teacher_id
    INNER JOIN courses c ON c.id = ct_mine.course_id
    INNER JOIN users u2 ON u2.id = ct2.teacher_id
    LEFT JOIN teachers t2 ON t2.user_id = u2.id
    WHERE ct_mine.teacher_id = ?
      AND ct_mine.status = 'active'
      AND ct2.status = 'active'
    GROUP BY u2.id, u2.full_name, u2.email, t2.employee_no, t2.specialization, t2.qualification, t2.experience_years, t2.status
    ORDER BY u2.full_name
");
$stmtInstructors->execute([$teacher_id]);
$instructors = $stmtInstructors->fetchAll();

$instructors_count = count($instructors);

/* ===
   TRAINER APPROVAL QUEUE / VERSION HISTORY
=== */
$pending_changes = [];
$version_history = [];
try {
    $stmtPending = $pdo->prepare("
        SELECT cr.*, u.full_name AS requester_name
        FROM change_requests cr
        LEFT JOIN users u ON u.id = cr.requested_by
        WHERE cr.requested_by = ?
        ORDER BY cr.created_at DESC
        LIMIT 50
    ");
    $stmtPending->execute([$teacher_id]);
    $pending_changes = $stmtPending->fetchAll();

    $stmtVersions = $pdo->prepare("
        SELECT cv.*, cr.status AS approval_status
        FROM content_versions cv
        LEFT JOIN change_requests cr ON cr.id = cv.change_request_id
        WHERE cv.edited_by = ?
        ORDER BY cv.created_at DESC
        LIMIT 50
    ");
    $stmtVersions->execute([$teacher_id]);
    $version_history = $stmtVersions->fetchAll();
} catch (Throwable $e) {
}
/* ===
   ATTENDANCE: TAKE / SAVE A SESSION
=== */
if (isset($_POST['take_attendance'])) {
    require_csrf('attendance_token', 'attendance_token');

    $course_id = (int)($_POST['course_id'] ?? 0);
    $att_date  = trim($_POST['attendance_date'] ?? date('Y-m-d'));
    $statuses  = $_POST['status'] ?? []; // [user_id => present|absent|late]

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) die("X Unauthorized course access");

    $upsert = $pdo->prepare("
        INSERT INTO attendance (user_id, course_id, attendance_date, status, signed_at)
        VALUES (?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE status = VALUES(status), signed_at = NOW()
    ");
    $saved = 0;
    foreach ($statuses as $studentUserId => $status) {
        $studentUserId = (int)$studentUserId;
        if ($studentUserId <= 0) continue;
        if (!in_array($status, ['present','absent','late','excused'], true)) continue;
        try {
            $upsert->execute([$studentUserId, $course_id, $att_date, $status]);
            $saved++;
        } catch (Throwable $e) {
            try {
                $ins = $pdo->prepare("INSERT INTO attendance (user_id, course_id, attendance_date, status, signed_at) VALUES (?, ?, ?, ?, NOW())");
                $ins->execute([$studentUserId, $course_id, $att_date, $status]);
                $saved++;
            } catch (Throwable $e2) {}
        }
    }

    log_audit($pdo, $teacher_id, 'attendance_taken', "Recorded attendance for course #$course_id on $att_date ($saved students)", 'course', $course_id);
    $_SESSION['attendance_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Attendance saved for $saved student(s).";
    header("Location: " . $_SERVER['PHP_SELF'] . "#attendance");
    exit;
}

/* ===
   NOTIFICATIONS: MARK READ / MARK ALL READ
=== */
if (isset($_POST['mark_notification_read'])) {
    require_csrf('notification_token', 'notification_token');
    $nid = (int)($_POST['notification_id'] ?? 0);
    try {
        $stmt = $pdo->prepare("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?");
        $stmt->execute([$nid, $teacher_id]);
    } catch (Throwable $e) {}
    $_SESSION['notification_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#notifications");
    exit;
}
if (isset($_POST['mark_all_notifications_read'])) {
    require_csrf('notification_token', 'notification_token');
    try {
        $stmt = $pdo->prepare("UPDATE notifications SET is_read=1 WHERE user_id=?");
        $stmt->execute([$teacher_id]);
    } catch (Throwable $e) {}
    $_SESSION['notification_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "All notifications marked as read.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#notifications");
    exit;
}

/* ===
   COMMUNICATION: SEND MESSAGE 
=== */
if (isset($_POST['send_message'])) {
    require_csrf('message_token', 'message_token');

    $target_type = $_POST['target_type'] ?? 'student'; // student | course
    $subject     = trim($_POST['subject'] ?? '');
    $body        = trim($_POST['message'] ?? '');
    if ($body === '') die("X Message cannot be empty");

    $recipients = [];
    if ($target_type === 'course') {
        $course_id = (int)($_POST['course_id'] ?? 0);
        $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
        $check->execute([$course_id, $teacher_id]);
        if ($check->rowCount() == 0) die("X Unauthorized course access");
        $stmt = $pdo->prepare("SELECT DISTINCT user_id FROM enrollments WHERE course_id=?");
        $stmt->execute([$course_id]);
        $recipients = array_column($stmt->fetchAll(), 'user_id');
    } else {
        $student_user_id = (int)($_POST['student_user_id'] ?? 0);
        $ownCheck = $pdo->prepare("
            SELECT 1 FROM enrollments e
            JOIN course_teachers ct ON ct.course_id = e.course_id
            WHERE e.user_id = ? AND ct.teacher_id = ? LIMIT 1
        ");
        $ownCheck->execute([$student_user_id, $teacher_id]);
        if ($ownCheck->rowCount() == 0) die("X Unauthorized recipient");
        $recipients = [$student_user_id];
    }

    $ins = $pdo->prepare("INSERT INTO messages (sender_id, receiver_id, subject, message, is_read, sent_at) VALUES (?, ?, ?, ?, 'No', NOW())");
    $sent = 0;
    foreach (array_unique($recipients) as $rid) {
        try { $ins->execute([$teacher_id, (int)$rid, $subject, $body]); $sent++; } catch (Throwable $e) {}
    }
    log_audit($pdo, $teacher_id, 'message_sent', "Sent message to $sent recipient(s)", 'message', null);
    $_SESSION['message_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Message sent to $sent recipient(s).";
    header("Location: " . $_SERVER['PHP_SELF'] . "#communication");
    exit;
}

/* ===
   FORUM: REPLY TO A TOPIC / LOCK-PIN (moderation)
=== */
if (isset($_POST['forum_reply'])) {
    require_csrf('forum_token', 'forum_token');
    $topic_id = (int)($_POST['topic_id'] ?? 0);
    $reply    = trim($_POST['reply'] ?? '');
    if ($reply === '' || $topic_id <= 0) die("X Invalid reply");

    $check = $pdo->prepare("
        SELECT ft.id FROM forum_topics ft
        JOIN course_teachers ct ON ct.course_id = ft.course_id
        WHERE ft.id=? AND ct.teacher_id=? LIMIT 1
    ");
    $check->execute([$topic_id, $teacher_id]);
    if ($check->rowCount() == 0) die("X Unauthorized topic access");

    $ins = $pdo->prepare("INSERT INTO forum_replies (topic_id, user_id, message, created_at) VALUES (?, ?, ?, NOW())");
    $ins->execute([$topic_id, $teacher_id, $reply]);
    $_SESSION['forum_token'] = bin2hex(random_bytes(32));
    $_SESSION['success_message'] = "Reply posted.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#communication");
    exit;
}
if (isset($_GET['forum_toggle_status'])) {
    $topic_id = (int)$_GET['forum_toggle_status'];
    $check = $pdo->prepare("
        SELECT ft.id, ft.status FROM forum_topics ft
        JOIN course_teachers ct ON ct.course_id = ft.course_id
        WHERE ft.id=? AND ct.teacher_id=? LIMIT 1
    ");
    $check->execute([$topic_id, $teacher_id]);
    $topic = $check->fetch();
    if ($topic) {
        $newStatus = ($topic['status'] === 'open') ? 'closed' : 'open';
        $upd = $pdo->prepare("UPDATE forum_topics SET status=? WHERE id=?");
        $upd->execute([$newStatus, $topic_id]);
        $_SESSION['success_message'] = "Discussion marked as $newStatus.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#communication");
    exit;
}

/* ===
   MENTORSHIP
=== */
if (isset($_POST['add_mentee'])) {
    require_csrf('mentorship_token', 'mentorship_token');
    $mentee_user_id = (int)($_POST['mentee_user_id'] ?? 0);
    $focus_area     = trim($_POST['focus_area'] ?? '');
    if ($mentee_user_id <= 0) die("X Invalid mentee");

    try {
        $ins = $pdo->prepare("
            INSERT INTO mentorship_matches (mentor_id, mentee_id, focus_area, status, matched_at)
            VALUES (?, ?, ?, 'active', NOW())
        ");
        $ins->execute([$teacher_id, $mentee_user_id, $focus_area]);
        $_SESSION['success_message'] = "Mentee added.";
        notify_user($pdo, $mentee_user_id, "You have been added as a mentee under a Skills Transfer Program mentorship track.");
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not add mentee. The mentorship module may not be installed yet.";
    }
    $_SESSION['mentorship_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#mentorship");
    exit;
}
if (isset($_POST['log_mentorship_session'])) {
    require_csrf('mentorship_token', 'mentorship_token');
    $match_id = (int)($_POST['match_id'] ?? 0);
    $notes    = trim($_POST['notes'] ?? '');
    $next_date = trim($_POST['next_session_date'] ?? '');

    $check = $pdo->prepare("SELECT id FROM mentorship_matches WHERE id=? AND mentor_id=? LIMIT 1");
    $check->execute([$match_id, $teacher_id]);
    if ($check->rowCount() == 0) die("X Unauthorized mentorship match");

    try {
        $ins = $pdo->prepare("
            INSERT INTO mentorship_sessions (match_id, session_date, notes, next_session_date, created_at)
            VALUES (?, CURDATE(), ?, ?, NOW())
        ");
        $ins->execute([$match_id, $notes, ($next_date !== '' ? $next_date : null)]);
        $_SESSION['success_message'] = "Mentorship session logged.";
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not log session.";
    }
    $_SESSION['mentorship_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#mentorship");
    exit;
}

/* ===
   SUPERVISION
=== */
if (isset($_POST['supervision_signoff'])) {
    require_csrf('supervision_token', 'supervision_token');
    $log_id = (int)($_POST['log_id'] ?? 0);
    $action = $_POST['signoff_action'] ?? 'approve';

    try {
        if ($action === 'approve') {
            $stmt = $pdo->prepare("UPDATE supervision_logbooks SET supervisor_signoff=1, signoff_at=NOW() WHERE id=? AND supervisor_id=?");
        } else {
            $stmt = $pdo->prepare("UPDATE supervision_logbooks SET supervisor_signoff=0, signoff_at=NULL WHERE id=? AND supervisor_id=?");
        }
        $stmt->execute([$log_id, $teacher_id]);
        $_SESSION['success_message'] = "Logbook entry updated.";
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not update logbook entry.";
    }
    $_SESSION['supervision_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#supervision");
    exit;
}

/* ===
   CPD / CME —
=== */
if (isset($_POST['add_cpd_activity'])) {
    require_csrf('cpd_token', 'cpd_token');
    $activity_title = trim($_POST['activity_title'] ?? '');
    $activity_type  = $_POST['activity_type'] ?? 'course';
    $points         = (float)($_POST['points'] ?? 0);
    $date_earned    = trim($_POST['date_earned'] ?? date('Y-m-d'));

    if ($activity_title === '') die("X Activity title required");

    try {
        $ins = $pdo->prepare("
            INSERT INTO cpd_points (user_id, activity_title, activity_type, points, date_earned, verification_status, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', NOW())
        ");
        $ins->execute([$teacher_id, $activity_title, $activity_type, $points, $date_earned]);
        $_SESSION['success_message'] = "CPD activity submitted for Super Administrator verification.";
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not submit CPD activity.";
    }
    $_SESSION['cpd_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#cpd");
    exit;
}

/* ===
   COMPETENCIES 
=== */
if (isset($_POST['rate_competency'])) {
    require_csrf('competency_token', 'competency_token');
    $student_user_id = (int)($_POST['student_user_id'] ?? 0);
    $competency_id   = (int)($_POST['competency_id'] ?? 0);
    $level           = $_POST['proficiency_level'] ?? 'novice';

    $ownCheck = $pdo->prepare("
        SELECT 1 FROM enrollments e
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE e.user_id = ? AND ct.teacher_id = ? LIMIT 1
    ");
    $ownCheck->execute([$student_user_id, $teacher_id]);
    if ($ownCheck->rowCount() == 0) die("X Unauthorized student access");

    try {
        $ins = $pdo->prepare("
            INSERT INTO user_competencies (user_id, competency_id, proficiency_level, assessed_by, assessed_at)
            VALUES (?, ?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE proficiency_level=VALUES(proficiency_level), assessed_by=VALUES(assessed_by), assessed_at=NOW()
        ");
        $ins->execute([$student_user_id, $competency_id, $level, $teacher_id]);
        $_SESSION['success_message'] = "Competency rating saved.";
    } catch (Throwable $e) {
        try {
            $ins = $pdo->prepare("INSERT INTO user_competencies (user_id, competency_id, proficiency_level, assessed_by, assessed_at) VALUES (?, ?, ?, ?, NOW())");
            $ins->execute([$student_user_id, $competency_id, $level, $teacher_id]);
            $_SESSION['success_message'] = "Competency rating saved.";
        } catch (Throwable $e2) {
            $_SESSION['error_message'] = "Could not save competency rating.";
        }
    }
    $_SESSION['competency_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#competencies");
    exit;
}

/* ===
   CERTIFICATES
=== */
if (isset($_POST['confirm_certificate_eligibility'])) {
    require_csrf('certificate_token', 'certificate_token');
    $student_user_id = (int)($_POST['student_user_id'] ?? 0);
    $course_id       = (int)($_POST['course_id'] ?? 0);

    $ownCheck = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $ownCheck->execute([$course_id, $teacher_id]);
    if ($ownCheck->rowCount() == 0) die("X Unauthorized course access");

    try {
        $ins = $pdo->prepare("INSERT INTO certificate_requests (user_id, course_id, status, requested_at) VALUES (?, ?, 'pending', NOW())");
        $ins->execute([$student_user_id, $course_id]);
        $_SESSION['success_message'] = "Completion confirmed. Certificate request sent to Super Administrator for issuance.";
        log_audit($pdo, $teacher_id, 'certificate_eligibility_confirmed', "Confirmed completion for user #$student_user_id in course #$course_id", 'certificate_request', null);
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not submit certificate request.";
    }
    $_SESSION['certificate_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#certificates");
    exit;
}

/* ===
   TRAINER AVAILABILITY
=== */
if (isset($_POST['save_availability'])) {
    require_csrf('availability_token', 'availability_token');
    $days   = $_POST['day_of_week'] ?? [];
    $starts = $_POST['start_time'] ?? [];
    $ends   = $_POST['end_time'] ?? [];

    try {
        $del = $pdo->prepare("DELETE FROM trainer_availability WHERE teacher_id=?");
        $del->execute([$teacher_id]);
        $ins = $pdo->prepare("INSERT INTO trainer_availability (teacher_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?)");
        foreach ($days as $i => $day) {
            if (empty($starts[$i]) || empty($ends[$i])) continue;
            $ins->execute([$teacher_id, $day, $starts[$i], $ends[$i]]);
        }
        $_SESSION['success_message'] = "Availability updated.";
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not save availability. The availability module may not be installed yet.";
    }
    $_SESSION['availability_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#availability");
    exit;
}

/* ===
   CONSULTATION BOOKING RESPONSES
=== */
if (isset($_POST['consultation_action'])) {
    require_csrf('consultation_token', 'consultation_token');
    $consultation_id = (int)($_POST['consultation_id'] ?? 0);
    $action = $_POST['action'] ?? '';

    $check = $pdo->prepare("SELECT * FROM consultations WHERE id=? AND teacher_id=? LIMIT 1");
    $check->execute([$consultation_id, $teacher_id]);
    $consult = $check->fetch();
    if (!$consult) die("X Unauthorized consultation access");

    $map = ['accept' => 'accepted', 'reject' => 'rejected', 'complete' => 'completed', 'reschedule' => 'rescheduled'];
    $newStatus = $map[$action] ?? null;
    if ($newStatus) {
        $stmt = $pdo->prepare("UPDATE consultations SET status=? WHERE id=?");
        $stmt->execute([$newStatus, $consultation_id]);
        notify_user($pdo, (int)$consult['student_id'], "Your consultation request was $newStatus.");
        $_SESSION['success_message'] = "Consultation $newStatus.";
    }
    $_SESSION['consultation_token'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#availability");
    exit;
}

/* ===
   LIVE / TRAINING SESSIONS (Calendar)
=== */
if (isset($_POST['create_session'])) {
    require_csrf('session_token_csrf', 'session_token_csrf');
    $course_id   = (int)($_POST['course_id'] ?? 0);
    $title       = trim($_POST['title'] ?? '');
    $topic       = trim($_POST['topic'] ?? '');
    $sched_date  = trim($_POST['schedule_date'] ?? '');
    $sched_time  = trim($_POST['schedule_time'] ?? '');
    $end_time    = trim($_POST['end_time'] ?? '');
    $mode        = $_POST['session_mode'] ?? 'online';
    $link        = trim($_POST['meeting_link'] ?? '');
    $description = trim($_POST['description'] ?? '');

    if ($title === '' || $sched_date === '' || $sched_time === '') die("X Invalid session details");

    $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=? LIMIT 1");
    $check->execute([$course_id, $teacher_id]);
    if ($check->rowCount() == 0) die("X Unauthorized course access");

    $scheduleDateTime = $sched_date . ' ' . $sched_time . ':00';
    try {
        $ins = $pdo->prepare("
            INSERT INTO live_classes (title, schedule_time, course_id, teacher_id, topic, description, session_mode, meeting_link, end_time, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'upcoming', NOW())
        ");
        $ins->execute([$title, $scheduleDateTime, $course_id, $teacher_id, $topic, $description, $mode, $link, ($end_time !== '' ? $sched_date . ' ' . $end_time . ':00' : null)]);
        $_SESSION['success_message'] = "Session scheduled.";
    } catch (Throwable $e) {
        $_SESSION['error_message'] = "Could not schedule session. The sessions module may not be fully installed yet.";
    }
    $_SESSION['session_token_csrf'] = bin2hex(random_bytes(32));
    header("Location: " . $_SERVER['PHP_SELF'] . "#calendar");
    exit;
}
if (isset($_GET['cancel_session'])) {
    $sid = (int)$_GET['cancel_session'];
    try {
        $stmt = $pdo->prepare("UPDATE live_classes SET status='cancelled' WHERE id=? AND teacher_id=?");
        $stmt->execute([$sid, $teacher_id]);
        $_SESSION['success_message'] = "Session cancelled.";
    } catch (Throwable $e) {}
    header("Location: " . $_SERVER['PHP_SELF'] . "#calendar");
    exit;
}
$studentProgressRows = [];
$atRiskStudents = [];
try {
    $stmtProg = $pdo->prepare("
        SELECT
            u.id AS user_id,
            u.full_name,
            u.email,
            e.course_id,
            c.title AS course_title,
            e.progress,
            e.status AS enrollment_status,
            (SELECT AVG(qr.score) FROM quiz_results qr
                JOIN quizzes q ON q.id = qr.quiz_id
                WHERE q.course_id = e.course_id AND qr.user_id = u.id) AS quiz_avg,
            (SELECT COUNT(*) FROM assignments a WHERE a.course_id = e.course_id) AS total_assignments,
            (SELECT COUNT(*) FROM submissions sub
                JOIN assignments a2 ON a2.id = sub.assignment_id
                JOIN students st ON st.id = sub.student_id
                WHERE a2.course_id = e.course_id AND st.user_id = u.id) AS submitted_assignments,
            (SELECT ROUND(
                    100 * SUM(CASE WHEN att.status='present' THEN 1 ELSE 0 END) / NULLIF(COUNT(*),0)
                ) FROM attendance att WHERE att.user_id = u.id AND att.course_id = e.course_id) AS attendance_pct,
            (SELECT MAX(login_time) FROM login_history lh WHERE lh.user_id = u.id) AS last_login
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        JOIN courses c ON c.id = e.course_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE ct.teacher_id = ? AND u.role = 'student'
        ORDER BY u.full_name
    ");
    $stmtProg->execute([$teacher_id]);
    $studentProgressRows = $stmtProg->fetchAll();

    foreach ($studentProgressRows as $row) {
        $risk = 0;
        if ((int)($row['progress'] ?? 0) < 40) $risk++;
        if ($row['quiz_avg'] !== null && (float)$row['quiz_avg'] < 50) $risk++;
        if ($row['attendance_pct'] !== null && (float)$row['attendance_pct'] < 60) $risk++;
        if ((int)($row['total_assignments'] ?? 0) > 0 && (int)($row['submitted_assignments'] ?? 0) < (int)($row['total_assignments'] ?? 0)) $risk++;
        if (!$row['last_login'] || strtotime($row['last_login']) < strtotime('-14 days')) $risk++;
        if ($risk >= 2) {
            $row['risk_score'] = $risk;
            $atRiskStudents[] = $row;
        }
    }
} catch (Throwable $e) {
}

/* --- Assignment submissions / grading centre (item #4) --- */
$submissionsList = [];
try {
    $stmtSub = $pdo->prepare("
        SELECT sub.*, a.title AS assignment_title, a.due_date, c.title AS course_title,
               u.full_name AS student_name
        FROM submissions sub
        JOIN assignments a ON a.id = sub.assignment_id
        JOIN courses c ON c.id = a.course_id
        JOIN students st ON st.id = sub.student_id
        JOIN users u ON u.id = st.user_id
        WHERE a.teacher_id = ?
        ORDER BY sub.submitted_at DESC
        LIMIT 200
    ");
    $stmtSub->execute([$teacher_id]);
    $submissionsList = $stmtSub->fetchAll();
} catch (Throwable $e) {
}
$pendingGradingCount = 0;
foreach ($submissionsList as $s) {
    if (($s['status'] ?? '') === 'submitted') $pendingGradingCount++;
}

/* --- Attendance history (item #7) --- */
$attendanceHistory = [];
try {
    $stmtAtt = $pdo->prepare("
        SELECT att.*, u.full_name, c.title AS course_title
        FROM attendance att
        JOIN users u ON u.id = att.user_id
        JOIN courses c ON c.id = att.course_id
        JOIN course_teachers ct ON ct.course_id = att.course_id
        WHERE ct.teacher_id = ?
        ORDER BY att.attendance_date DESC, att.id DESC
        LIMIT 200
    ");
    $stmtAtt->execute([$teacher_id]);
    $attendanceHistory = $stmtAtt->fetchAll();
} catch (Throwable $e) {}

$myNotifications = [];
$unreadNotifications = 0;
try {
    $stmtNotif = $pdo->prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30");
    $stmtNotif->execute([$teacher_id]);
    $myNotifications = $stmtNotif->fetchAll();
    foreach ($myNotifications as $n) {
        if (empty($n['is_read'])) $unreadNotifications++;
    }
} catch (Throwable $e) {}

/* --- Messages (item #10) --- */
$myMessages = [];
try {
    $stmtMsg = $pdo->prepare("
        SELECT m.*, u.full_name AS other_party
        FROM messages m
        JOIN users u ON u.id = (CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END)
        WHERE m.sender_id = ? OR m.receiver_id = ?
        ORDER BY m.sent_at DESC
        LIMIT 100
    ");
    $stmtMsg->execute([$teacher_id, $teacher_id, $teacher_id]);
    $myMessages = $stmtMsg->fetchAll();
} catch (Throwable $e) {}

/* --- Forum topics for my courses (item #11) --- */
$forumTopics = [];
try {
    $stmtForum = $pdo->prepare("
        SELECT ft.*, u.full_name AS author, c.title AS course_title,
               (SELECT COUNT(*) FROM forum_replies fr WHERE fr.topic_id = ft.id) AS reply_count
        FROM forum_topics ft
        JOIN courses c ON c.id = ft.course_id
        JOIN course_teachers ct ON ct.course_id = ft.course_id
        LEFT JOIN users u ON u.id = ft.user_id
        WHERE ct.teacher_id = ?
        ORDER BY ft.created_at DESC
        LIMIT 100
    ");
    $stmtForum->execute([$teacher_id]);
    $forumTopics = $stmtForum->fetchAll();
} catch (Throwable $e) {}

/* --- Mentorship (item #12) --- */
$myMentees = [];
try {
    $stmtMent = $pdo->prepare("
        SELECT mm.*, u.full_name AS mentee_name, u.email AS mentee_email
        FROM mentorship_matches mm
        JOIN users u ON u.id = mm.mentee_id
        WHERE mm.mentor_id = ?
        ORDER BY mm.matched_at DESC
    ");
    $stmtMent->execute([$teacher_id]);
    $myMentees = $stmtMent->fetchAll();
} catch (Throwable $e) {}

/* --- Supervision logbooks (item #13) --- */
$supervisionLogs = [];
try {
    $stmtSup = $pdo->prepare("
        SELECT sl.*, u.full_name AS student_name
        FROM supervision_logbooks sl
        JOIN students st ON st.id = sl.student_id
        JOIN users u ON u.id = st.user_id
        WHERE sl.supervisor_id = ?
        ORDER BY sl.session_date DESC
        LIMIT 100
    ");
    $stmtSup->execute([$teacher_id]);
    $supervisionLogs = $stmtSup->fetchAll();
} catch (Throwable $e) {}

/* --- CPD points (item #16) --- */
$myCpdActivities = [];
$myCpdTotalPoints = 0;
try {
    $stmtCpd = $pdo->prepare("SELECT * FROM cpd_points WHERE user_id=? ORDER BY date_earned DESC");
    $stmtCpd->execute([$teacher_id]);
    $myCpdActivities = $stmtCpd->fetchAll();
    foreach ($myCpdActivities as $c) {
        if (($c['verification_status'] ?? '') === 'verified') $myCpdTotalPoints += (float)$c['points'];
    }
} catch (Throwable $e) {}

/* --- Competencies (item #15) --- */
$competencyList = [];
$studentCompetencies = [];
try {
    $competencyList = $pdo->query("SELECT * FROM competencies ORDER BY category, name")->fetchAll();
    $stmtUC = $pdo->prepare("
        SELECT uc.*, u.full_name AS student_name, comp.name AS competency_name, comp.category
        FROM user_competencies uc
        JOIN users u ON u.id = uc.user_id
        JOIN competencies comp ON comp.id = uc.competency_id
        JOIN enrollments e ON e.user_id = uc.user_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE ct.teacher_id = ?
        GROUP BY uc.id
        ORDER BY u.full_name
    ");
    $stmtUC->execute([$teacher_id]);
    $studentCompetencies = $stmtUC->fetchAll();
} catch (Throwable $e) {}

/* --- Certificate eligibility (item #17) --- */
$eligibleForCertificate = [];
try {
    $stmtElig = $pdo->prepare("
        SELECT u.id AS user_id, u.full_name, e.course_id, c.title AS course_title, e.progress, e.status,
            (SELECT status FROM certificate_requests cr WHERE cr.user_id=u.id AND cr.course_id=e.course_id ORDER BY cr.id DESC LIMIT 1) AS request_status
        FROM enrollments e
        JOIN users u ON u.id = e.user_id
        JOIN courses c ON c.id = e.course_id
        JOIN course_teachers ct ON ct.course_id = e.course_id
        WHERE ct.teacher_id = ? AND (e.status = 'completed' OR e.progress >= 100)
        ORDER BY u.full_name
    ");
    $stmtElig->execute([$teacher_id]);
    $eligibleForCertificate = $stmtElig->fetchAll();
} catch (Throwable $e) {}

/* --- Trainer availability + consultation bookings (items #34, #35) --- */
$myAvailability = [];
$myConsultations = [];
try {
    $stmtAvail = $pdo->prepare("SELECT * FROM trainer_availability WHERE teacher_id=? ORDER BY FIELD(day_of_week,'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')");
    $stmtAvail->execute([$teacher_id]);
    $myAvailability = $stmtAvail->fetchAll();
} catch (Throwable $e) {}
try {
    $stmtConsult = $pdo->prepare("
        SELECT co.*, u.full_name AS student_name
        FROM consultations co
        JOIN users u ON u.id = co.student_id
        WHERE co.teacher_id = ?
        ORDER BY co.requested_date DESC, co.id DESC
    ");
    $stmtConsult->execute([$teacher_id]);
    $myConsultations = $stmtConsult->fetchAll();
} catch (Throwable $e) {}

/* --- Live/training sessions calendar (items #8, #9) --- */
$mySessions = [];
try {
    $stmtSess = $pdo->prepare("
        SELECT lc.*, c.title AS course_title
        FROM live_classes lc
        LEFT JOIN courses c ON c.id = lc.course_id
        WHERE lc.teacher_id = ?
        ORDER BY lc.schedule_time DESC
    ");
    $stmtSess->execute([$teacher_id]);
    $mySessions = $stmtSess->fetchAll();
} catch (Throwable $e) {}

/* --- Course/trainer feedback (item #25) --- */
$courseFeedback = [];
$avgCourseRating = 0;
try {
    $stmtFb = $pdo->prepare("
        SELECT cr.*, c.title AS course_title,
               CASE WHEN cr.is_anonymous=1 THEN 'Anonymous' ELSE u.full_name END AS reviewer_name
        FROM course_reviews cr
        JOIN courses c ON c.id = cr.course_id
        JOIN course_teachers ct ON ct.course_id = cr.course_id
        LEFT JOIN users u ON u.id = cr.user_id
        WHERE ct.teacher_id = ? AND cr.status='approved'
        ORDER BY cr.created_at DESC
        LIMIT 100
    ");
    $stmtFb->execute([$teacher_id]);
    $courseFeedback = $stmtFb->fetchAll();
    if (count($courseFeedback) > 0) {
        $avgCourseRating = array_sum(array_column($courseFeedback, 'rating')) / count($courseFeedback);
    }
} catch (Throwable $e) {}

/* --- Media library: unified view of notes + videos (item #27) --- */
$mediaLibrary = [];
foreach ($notes as $n) {
    if (!empty($n['file_path'])) {
        $mediaLibrary[] = ['type' => 'Document', 'title' => $n['title'], 'course' => $n['course_title'], 'path' => $n['file_path'], 'created_at' => $n['created_at']];
    }
}
foreach ($videos as $v) {
    $mediaLibrary[] = ['type' => 'Video', 'title' => $v['title'], 'course' => $v['course_title'], 'path' => $v['video_path'], 'created_at' => $v['created_at'] ?? null];
}

/* --- Recent audit trail for this trainer (item #33) --- */
$myAuditTrail = [];
try {
    $stmtAudit = $pdo->prepare("SELECT * FROM audit_logs WHERE user_id=? ORDER BY created_at DESC LIMIT 50");
    $stmtAudit->execute([$teacher_id]);
    $myAuditTrail = $stmtAudit->fetchAll();
} catch (Throwable $e) {}

/* --- Trainer workload summary (item #22) --- */
$upcomingSessionsCount = 0;
foreach ($mySessions as $s) {
    if (($s['status'] ?? 'upcoming') === 'upcoming' && strtotime($s['schedule_time']) >= time()) $upcomingSessionsCount++;
}
$workload = [
    'courses' => $total_courses,
    'students' => $total_students,
    'to_grade' => $pendingGradingCount,
    'upcoming_sessions' => $upcomingSessionsCount,
    'mentees' => count($myMentees),
    'supervisees' => count(array_unique(array_column($supervisionLogs, 'student_name'))),
];

/* --- Question bank filter options (item #5) --- */
$questionTopics = array_values(array_unique(array_filter(array_column($questionsList, 'topic'))));

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($branding['brand_name']) ?> — Trainer Dashboard</title>
<meta name="description" content="<?= htmlspecialchars($branding['brand_name']) ?> Trainer Dashboard — manage courses, learning materials, assessments, attendance, mentorship, supervision and the Skills Transfer Program.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
/* == RESET & BASE == */
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Poppins','Segoe UI',Arial,sans-serif;background:#f0f4f3;display:flex;min-height:100vh;color:#1e293b;}

/* == TOPBAR (mobile only) == */
.topbar{
    display:none;
    position:fixed;top:0;left:0;width:100%;height:56px;
    background:var(--brand-primary);color:#fff;align-items:center;
    padding:0 16px;z-index:1100;box-shadow:0 2px 8px rgba(0,0,0,.2);
}
.topbar .menu-btn{
    background:none;border:none;color:#fff;font-size:22px;cursor:pointer;
    padding:8px;margin-right:10px;
}
.topbar .topbar-title{font-size:16px;font-weight:700;}
.topbar .notif-btn{margin-left:auto;position:relative;color:#fff;font-size:18px;background:none;border:none;cursor:pointer;padding:8px;}

/* == SIDEBAR == */
.sidebar{
    width:265px;height:100vh;background:linear-gradient(180deg,#86AC13 0%,#86AC13 100%);
    color:#fff;position:fixed;top:0;left:0;overflow-y:auto;z-index:1050;
    box-shadow:4px 0 15px rgba(0,0,0,.2);
    transition:transform .3s ease;
    display:flex;flex-direction:column;
}
.logo{
    padding:6px;font-size:17px;font-weight:800;
    border-bottom:1px solid rgba(255,255,255,.15);
    display:flex;flex-direction:column;align-items:center;gap:3px;
    background:rgba(0,0,0,.18);letter-spacing:.2px;
}
.logo img{max-width:13rem;heigth:5rem;padding:2px;}
.logo i{font-size:22px;color:#5eead4;}
.logo .brand-tagline{display:block;font-size:13.5px;font-weight:500;opacity:.75;letter-spacing:.4px;text-transform:uppercase;margin-top:2px;}
.sidebar ul{list-style:none;padding:10px 0;flex:1;}
.sidebar .nav-group-label{
    padding:14px 22px 6px;font-size:10.5px;letter-spacing:.6px;text-transform:uppercase;
    color:rgba(255,255,255,.5);font-weight:700;
}
.sidebar ul li a{
    display:flex;align-items:center;gap:12px;
    color:rgba(255,255,255,.82);text-decoration:none;
    padding:11px 22px;font-size:13.3px;font-weight:500;
    transition:all .2s;border-left:3px solid transparent;position:relative;
}
.sidebar ul li a:hover,
.sidebar ul li a.active{
    background:rgba(255,255,255,.12);color:#fff;
    border-left-color:#5eead4;
}
.sidebar ul li a i{width:18px;text-align:center;font-size:15px;}
.nav-badge{
    margin-left:auto;background:#f87171;color:#fff;font-size:10px;font-weight:700;
    border-radius:20px;padding:1px 7px;min-width:18px;text-align:center;
}
.sidebar-footer{
    padding:14px 20px;font-size:11px;color:rgba(255,255,255,.65);
    border-top:1px solid rgba(255,255,255,.15);line-height:1.6;
}
.sidebar-footer a{color:#5eead4;text-decoration:none;}

/* == SIDEBAR OVERLAY  == */
.sidebar-overlay{
    display:none;position:fixed;top:0;left:0;width:100%;height:100%;
    background:rgba(0,0,0,.5);z-index:1040;
}
.sidebar-overlay.open{display:block;}

/* == MAIN == */
.main{margin-left:265px;flex:1;padding:28px;min-height:100vh;max-width:100%;overflow-x:hidden;}

/* == HEADER == */
.header{
    background:#fff;padding:20px 28px;border-radius:14px;
    display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);margin-bottom:24px;
    
}
.header h2{font-size:22px;color:#1e293b;margin-bottom:4px;}
.header p{color:#64748b;font-size:14px;}
.header-right{
    background:#e6f7f4;border-radius:10px;padding:12px 18px;
    text-align:right;font-size:13px;color:var(--brand-primary);
    display:flex;align-items:center;gap:14px;
}
.header-right strong{display:block;font-size:15px;color:#1e293b;}
.notif-bell{position:relative;cursor:pointer;font-size:19px;color:var(--brand-primary);}
.notif-bell .nav-badge{position:absolute;top:-8px;right:-10px;}

/* == ALERT == */
.alert{
    padding:12px 18px;border-radius:10px;margin-bottom:18px;
    font-size:14px;font-weight:500;
}
.alert-success{background:#dcfce7;color:#166534;border:1px solid #bbf7d0;}
.alert-danger {background:#fee2e2;color:#991b1b;border:1px solid #fecaca;}
.alert-warning{background:#fef3c7;color:#92400e;border:1px solid #fde68a;}

/* == STAT CARDS == */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px;}
.card{
    background:#fff;padding:20px 18px;border-radius:14px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);display:flex;flex-direction:column;gap:6px;
}
.card .icon{
    width:44px;height:44px;border-radius:10px;
    display:flex;align-items:center;justify-content:center;font-size:20px;
}
.card .icon.blue{background:#dbeafe;color:#2563eb;}
.card .icon.green{background:#dcfce7;color:#16a34a;}
.card .icon.yellow{background:#fef9c3;color:#ca8a04;}
.card .icon.red{background:#fee2e2;color:#dc2626;}
.card .icon.purple{background:#ede9fe;color:#7c3aed;}
.card .icon.orange{background:#ffedd5;color:#ea580c;}
.card .icon.teal{background:#ccfbf1;color:#0d9488;}
.card .icon.pink{background:#fce7f3;color:#db2777;}
.card h2{font-size:26px;font-weight:700;color:#1e293b;}
.card p{font-size:13px;color:#64748b;}

/* == SECTION BOX == */
.section{
    background:#fff;padding:24px;border-radius:14px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);margin-bottom:24px;
    overflow-x:auto;
}
.section h3{font-size:16px;color:#1e293b;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;}
.section h3 span.sub{font-size:11px;font-weight:500;color:#94a3b8;text-transform:none;border:none;padding:0;}

/* == TABLE == */
table{width:100%;border-collapse:collapse;min-width:560px;}
th,td{padding:12px 14px;text-align:left;font-size:13px;}
th{background:#86AC13;color:#fff;font-weight:600;}
tr:nth-child(even){background:#f8fafc;}
tr:hover{background:#e6f7f4;}
td{border-bottom:1px solid #e2e8f0;color:#374151;}
tr.edit-row{background:#f0fdfa !important;}
tr.edit-row td{padding:18px 14px;border-bottom:2px solid var(--brand-accent);}
tr.edit-row .form-group{margin-bottom:10px;}
tr.risk-row{background:#fff1f2 !important;}

/* == FORM ELEMENTS == */
.form-group{margin-bottom:14px;}
.form-group label{display:block;font-size:13px;font-weight:600;color:#374151;margin-bottom:6px;}
.form-group input,
.form-group select,
.form-group textarea{
    width:100%;padding:10px 13px;border:1px solid #cbd5e1;
    border-radius:8px;font-size:14px;color:#1e293b;
    outline:none;transition:.2s;background:#fff;
}
.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus{border-color:var(--brand-accent);box-shadow:0 0 0 3px rgba(20,184,166,.15);}

/* == BUTTONS == */
.btn{
    padding:9px 16px;border:none;border-radius:8px;
    font-size:13px;font-weight:600;cursor:pointer;
    display:inline-flex;align-items:center;gap:6px;
    text-decoration:none;transition:.2s;
}
.btn:hover{opacity:.88;transform:translateY(-1px);}
.btn-primary{background:#FFB129;;color:#fff;}
.btn-success{background:#16a34a;color:#fff;}
.btn-warning{background:#f59e0b;color:#fff;}
.btn-danger {background:#dc2626;color:#fff;}
.btn-info   {background:#0891b2;color:#fff;}
.btn-edit   {background:#eab308;color:#1e293b;}
.btn-outline{background:transparent;border:1px solid var(--brand-secondary);color:var(--brand-secondary);}
.btn-sm{padding:6px 11px;font-size:12px;}

/* == BADGE == */
.badge{
    display:inline-block;padding:4px 10px;border-radius:20px;
    font-size:11px;font-weight:700;letter-spacing:.3px;
}
.badge-active   {background:#dcfce7;color:#166534;}
.badge-suspended{background:#fee2e2;color:#991b1b;}
.badge-inactive {background:#e5e7eb;color:#374151;}
.badge-pending  {background:#fef3c7;color:#92400e;}
.badge-approved {background:#dcfce7;color:#166534;}
.badge-rejected {background:#fee2e2;color:#991b1b;}
.badge-free     {background:#dbeafe;color:#1e40af;}
.badge-paid     {background:#fce7f3;color:#9d174d;}
.badge-pass     {background:#dcfce7;color:#166534;}
.badge-fail     {background:#fee2e2;color:#991b1b;}
.badge-present  {background:#dcfce7;color:#166534;}
.badge-absent   {background:#fee2e2;color:#991b1b;}
.badge-late     {background:#fef3c7;color:#92400e;}
.badge-excused  {background:#dbeafe;color:#1e40af;}
.badge-graded   {background:#dcfce7;color:#166534;}
.badge-submitted{background:#fef3c7;color:#92400e;}
.badge-resubmission_requested{background:#fee2e2;color:#991b1b;}
.badge-upcoming {background:#dbeafe;color:#1e40af;}
.badge-completed{background:#dcfce7;color:#166534;}
.badge-cancelled{background:#e5e7eb;color:#374151;}
.badge-risk     {background:#fee2e2;color:#991b1b;}
.badge-ontrack  {background:#dcfce7;color:#166534;}

/* == PROGRESS BAR == */
.progress-track{background:#e2e8f0;border-radius:20px;height:8px;width:100%;overflow:hidden;}
.progress-fill{height:100%;border-radius:20px;background:linear-gradient(90deg,var(--brand-secondary),var(--brand-accent));}

/* == GRID == */
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;}
.grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;}
.grid-4{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;}

/* == COURSE CARD == */
.course-card{
    background:#fff;border-radius:14px;padding:20px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);border-top:3px solid var(--brand-accent);
}
.course-card h3{font-size:16px;color:#1e293b;margin-bottom:10px;}
.course-card p{font-size:13px;color:#64748b;margin-bottom:6px;}
.course-card .meta{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0;}
.course-card .meta span{font-size:12px;color:#64748b;display:flex;align-items:center;gap:4px;}
.course-card .actions{display:flex;gap:8px;flex-wrap:wrap;padding-top:12px;border-top:1px solid #e2e8f0;}
.course-card .inline-edit{display:none;margin-top:14px;padding-top:14px;border-top:1px dashed #cbd5e1;}

/* == ACTIVITY == */
.activity-item{
    display:flex;justify-content:space-between;align-items:center;
    padding:12px 0;border-bottom:1px solid #f1f5f9;font-size:13px;flex-wrap:wrap;gap:6px;
}
.activity-item:last-child{border-bottom:none;}
.activity-item .msg{color:#374151;}
.activity-item .time{color:#94a3b8;font-size:12px;white-space:nowrap;margin-left:10px;}

/* == STAT HIGHLIGHT == */
.stat-highlight{
    background:linear-gradient(135deg,var(--brand-secondary),var(--brand-accent));
    color:#fff;border-radius:14px;padding:20px;text-align:center;
}
.stat-highlight h2{font-size:28px;font-weight:700;}
.stat-highlight p{font-size:13px;opacity:.85;margin-top:4px;}

/* == IMPORT TABS / GENERIC TABS == */
.import-tabs{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap;border-bottom:1px solid #e2e8f0;padding-bottom:10px;}
.tab-btn{
    background:#f1f5f9;border:none;padding:9px 16px;border-radius:8px 8px 0 0;
    font-size:13px;font-weight:600;color:#64748b;cursor:pointer;
    display:inline-flex;align-items:center;gap:6px;transition:.2s;
}
.tab-btn:hover{background:#e2e8f0;}
.tab-btn.active{background:var(--brand-secondary);color:#fff;}
.qtab-panel textarea[name="bulk_text"]{font-family:monospace;font-size:12.5px;}

/* == FORMAT HINT BOX == */
.format-hint{
    background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;
    padding:12px 14px;margin-bottom:14px;font-size:12px;color:#0369a1;
    line-height:1.7;
}
.format-hint strong{display:block;margin-bottom:4px;font-size:13px;color:#0c4a6e;}
.format-hint code{
    background:#e0f2fe;border-radius:4px;padding:1px 4px;
    font-family:monospace;font-size:12px;color:#075985;
}

/* == PAGE TITLE == */
.page-title{font-size:20px;font-weight:700;color:#1e293b;margin-bottom:20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.page-title i{color:var(--brand-secondary);}
.page-title .sub-count{font-size:12px;font-weight:500;color:#64748b;background:#f1f5f9;padding:4px 10px;border-radius:20px;}

/* == PROMO / ADVERTISING SPACE == */
.promo-strip{margin-bottom:24px;}
.promo-strip-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.promo-strip-head h4{font-size:13px;text-transform:uppercase;letter-spacing:.6px;color:#64748b;font-weight:700;}
.promo-strip-head span{font-size:11px;color:#94a3b8;}
.promo-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;}
.promo-card{
    position:relative;overflow:hidden;border-radius:14px;padding:18px 20px;color:#fff;
    background:linear-gradient(135deg,var(--brand-primary),var(--brand-secondary));
    box-shadow:0 4px 16px rgba(11,61,51,.18);
    display:flex;flex-direction:column;gap:8px;min-height:120px;
}
.promo-card::after{
    content:"";position:absolute;right:-30px;top:-30px;width:110px;height:110px;
    border-radius:50%;background:rgba(255,255,255,.08);
}
.promo-card .promo-badge{
    position:absolute;top:12px;right:14px;font-size:9.5px;font-weight:700;
    letter-spacing:.5px;text-transform:uppercase;background:rgba(255,255,255,.18);
    padding:3px 9px;border-radius:20px;
}
.promo-card h5{font-size:15px;font-weight:700;padding-right:60px;}
.promo-card p{font-size:12.5px;line-height:1.5;opacity:.92;}
.promo-card a{
    margin-top:auto;align-self:flex-start;font-size:12px;font-weight:700;color:#fff;
    text-decoration:none;border-bottom:2px solid rgba(255,255,255,.6);padding-bottom:2px;
}
.promo-card a:hover{border-color:#fff;}
.promo-card:nth-child(2){background:linear-gradient(135deg,#0d9488,#5eead4);color:#053b32;}
.promo-card:nth-child(2) a{color:#053b32;border-color:rgba(5,59,50,.5);}
.promo-card:nth-child(3n){background:linear-gradient(135deg,#134e4a,#0f766e);}

/* == BRAND FOOTER == */
.brand-footer{
    background:#fff;border-radius:14px;padding:18px 24px;margin-top:6px;
    display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);font-size:12px;color:#64748b;
}
.brand-footer strong{color:var(--brand-primary);}
.brand-footer .contact-line{display:flex;gap:16px;flex-wrap:wrap;}
.brand-footer .contact-line span{display:flex;align-items:center;gap:6px;}
.brand-footer i{color:var(--brand-accent);}

/* == NOTIFICATION LIST / MESSAGE LIST == */
.notif-list{list-style:none;}
.notif-list li{
    display:flex;gap:10px;align-items:flex-start;padding:12px 0;border-bottom:1px solid #f1f5f9;font-size:13px;
}
.notif-list li.unread{background:#f0fdfa;border-radius:8px;padding:12px 10px;}
.notif-list li i{color:var(--brand-accent);margin-top:2px;}
.msg-bubble{background:#f8fafc;border-radius:10px;padding:12px 14px;margin-bottom:10px;border-left:3px solid var(--brand-accent);}
.msg-bubble .meta{font-size:11px;color:#94a3b8;margin-top:6px;}

/* == KANBAN / WORKLOAD MINI == */
.workload-strip{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px;}
.workload-chip{
    background:#fff;border-radius:12px;padding:12px 18px;box-shadow:0 2px 10px rgba(0,0,0,.05);
    display:flex;flex-direction:column;gap:2px;min-width:120px;flex:1;
}
.workload-chip span.num{font-size:20px;font-weight:700;color:var(--brand-primary);}
.workload-chip span.lbl{font-size:11.5px;color:#64748b;}

/* == DIFF VIEW (version comparison) == */
.diff-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.diff-col{background:#f8fafc;border-radius:8px;padding:12px;font-size:12px;font-family:monospace;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;}
.diff-col.old{border-left:3px solid #f87171;}
.diff-col.new{border-left:3px solid #4ade80;}

/* == AVAILABILITY GRID == */
.avail-row{display:grid;grid-template-columns:120px 1fr 1fr;gap:10px;align-items:center;margin-bottom:8px;}
.avail-row label{font-size:12.5px;font-weight:600;color:#374151;}

/* ========
   RESPONSIVE BREAKPOINTS
======== */
@media (max-width:1024px){
    .sidebar{width:225px;}
    .main{margin-left:225px;padding:20px;}
    .cards{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));}
}
@media (max-width:900px){
    .topbar{display:flex;}
    .sidebar{transform:translateX(-100%);top:0;z-index:1150;}
    .sidebar.open{transform:translateX(0);}
    .main{margin-left:0;padding:16px;padding-top:72px;}
    .header{padding:16px 18px;}
    .header-right{text-align:left;}
    .diff-grid{grid-template-columns:1fr;}
    .avail-row{grid-template-columns:1fr;}
}
@media (max-width:600px){
    .cards{grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;}
    .card{padding:16px 14px;}
    .card h2{font-size:21px;}
    .section{padding:16px;}
    .grid-2,.grid-3,.grid-4{grid-template-columns:1fr;}
    .header h2{font-size:18px;}
    .page-title{font-size:17px;}
    table{min-width:480px;}
    .brand-footer{flex-direction:column;align-items:flex-start;}
}
@media (max-width:380px){
    .main{padding:12px;padding-top:68px;}
    .cards{grid-template-columns:1fr 1fr;}
    .card{padding:12px;}
    .topbar .topbar-title{font-size:14px;}
}
</style>
</head>
<body style="--brand-primary: <?= htmlspecialchars($branding['primary_color']) ?>; --brand-secondary: <?= htmlspecialchars($branding['secondary_color']) ?>; --brand-accent: <?= htmlspecialchars($branding['accent_color']) ?>; font-family: <?= htmlspecialchars($branding['font_family']) ?>;">

<!-- == TOPBAR  == -->
<div class="topbar">
    <button class="menu-btn" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
    <div class="topbar-title"><i class="fas fa-graduation-cap"></i> <?= htmlspecialchars($branding['brand_name']) ?> Trainer</div>
    <button class="notif-btn" onclick="showSection('notifications',null)"><i class="fas fa-bell"></i><?php if ($unreadNotifications > 0): ?><span class="nav-badge"><?= $unreadNotifications ?></span><?php endif; ?></button>
</div>

<!-- == SIDEBAR OVERLAY == -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<!-- == SIDEBAR == -->
<div class="sidebar" id="sidebar">
    <div class="logo">
        <?php if (!empty($branding['logo_path'])): ?>
            <img src="<?= htmlspecialchars($branding['logo_path']) ?>" alt="<?= htmlspecialchars($branding['brand_name']) ?> Logo">
        <?php else: ?>
            <i class="fas fa-graduation-cap"></i>
        <?php endif; ?>
        <div>
            <span class="brand-tagline"><?= htmlspecialchars($branding['brand_tagline'] ?? 'Skills Transfer Program') ?></span>
        </div>
    </div>
    <ul>
        <li><a href="#" onclick="showSection('dashboard',this)"><i class="fas fa-home"></i> Dashboard</a></li>
        <li><a href="#" onclick="showSection('profile',this)"><i class="fas fa-user"></i> My Profile</a></li>

        <li class="nav-group-label">My Courses</li>
        <li><a href="#" onclick="showSection('courses',this)"><i class="fas fa-book"></i> Assigned Courses</a></li>
        <li><a href="#" onclick="showSection('notes',this)"><i class="fas fa-file-pdf"></i> Learning Materials</a></li>
        <li><a href="#" onclick="showSection('videos',this)"><i class="fas fa-video"></i> Videos</a></li>
        <li><a href="#" onclick="showSection('media',this)"><i class="fas fa-photo-film"></i> Media Library</a></li>

        <li class="nav-group-label">Students</li>
        <li><a href="#" onclick="showSection('students',this)"><i class="fas fa-users"></i> All Students</a></li>
        <li><a href="#" onclick="showSection('progress',this)"><i class="fas fa-chart-line"></i> Student Progress</a></li>
        <li><a href="#" onclick="showSection('atrisk',this)"><i class="fas fa-triangle-exclamation"></i> At-Risk Students <?php if (count($atRiskStudents) > 0): ?><span class="nav-badge"><?= count($atRiskStudents) ?></span><?php endif; ?></a></li>

        <li class="nav-group-label">Assessments</li>
        <li><a href="#" onclick="showSection('quiz',this)"><i class="fas fa-question-circle"></i> Quizzes &amp; Question Bank</a></li>
        <li><a href="#" onclick="showSection('assignments',this)"><i class="fas fa-tasks"></i> Assignments</a></li>
        <li><a href="#" onclick="showSection('grading',this)"><i class="fas fa-marker"></i> Grading Centre <?php if ($pendingGradingCount > 0): ?><span class="nav-badge"><?= $pendingGradingCount ?></span><?php endif; ?></a></li>

        <li class="nav-group-label">Engagement</li>
        <li><a href="#" onclick="showSection('attendance',this)"><i class="fas fa-clipboard-check"></i> Attendance</a></li>
        <li><a href="#" onclick="showSection('calendar',this)"><i class="fas fa-calendar-days"></i> Calendar &amp; Live Sessions</a></li>
        <li><a href="#" onclick="showSection('communication',this)"><i class="fas fa-comments"></i> Communication</a></li>
        <li><a href="#" onclick="showSection('announcements',this)"><i class="fas fa-bullhorn"></i> Announcements</a></li>
        <li><a href="#" onclick="showSection('availability',this)"><i class="fas fa-calendar-check"></i> Availability &amp; Bookings</a></li>

        <!-- TO BE USED FOR VERSION 2
        <li class="nav-group-label">Professional Practice</li>
        <li><a href="#" onclick="showSection('mentorship',this)"><i class="fas fa-people-arrows"></i> Mentorship</a></li>
        <li><a href="#" onclick="showSection('supervision',this)"><i class="fas fa-user-doctor"></i> Supervision</a></li>
        <li><a href="#" onclick="showSection('competencies',this)"><i class="fas fa-star-half-stroke"></i> Competencies</a></li>
        <li><a href="#" onclick="showSection('cpd',this)"><i class="fas fa-award"></i> CPD / CME</a></li>
        <li><a href="#" onclick="showSection('certificates',this)"><i class="fas fa-certificate"></i> Certificates</a></li>
        -->
        
        <li class="nav-group-label">Insights</li>
        <li><a href="#" onclick="showSection('reports',this)"><i class="fas fa-chart-pie"></i> Reports</a></li>
        <li><a href="#" onclick="showSection('feedback',this)"><i class="fas fa-comment-dots"></i> Student Feedback</a></li>
        <li><a href="#" onclick="showSection('instructors',this)"><i class="fas fa-chalkboard-teacher"></i> Co-Trainers</a></li>

        <li class="nav-group-label">Governance</li>
        <li><a href="#" onclick="showSection('approvals',this)"><i class="fas fa-user-shield"></i> Approval Requests</a></li>
        <li><a href="#" onclick="showSection('notifications',this)"><i class="fas fa-bell"></i> Notifications <?php if ($unreadNotifications > 0): ?><span class="nav-badge"><?= $unreadNotifications ?></span><?php endif; ?></a></li>
        <li><a href="index.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
    </ul>
    <div class="sidebar-footer">
        <?= htmlspecialchars($branding['brand_name']) ?> Trainer Portal<br>
        <a href="https://www.cbtkenya.org/" target="_blank" rel="noopener">cbtkenya.org</a>
    </div>
</div>

<!-- == MAIN == -->
<div class="main">

<?php
if (isset($_SESSION['success_message'])) {
    echo '<div class="alert alert-success"><i class="fas fa-check-circle"></i> ' . htmlspecialchars($_SESSION['success_message']) . '</div>';
    unset($_SESSION['success_message']);
}
if (isset($_SESSION['error_message'])) {
    echo '<div class="alert alert-danger"><i class="fas fa-exclamation-circle"></i> ' . htmlspecialchars($_SESSION['error_message']) . '</div>';
    unset($_SESSION['error_message']);
}
?>

<!-- ==== DASHBOARD ==== -->
<div id="sec-dashboard" class="section-page" style="display:none;">
    <div class="header">
        <div>
            <h2>Welcome back, <?= htmlspecialchars($teacherInfo['full_name'] ?? 'Teacher') ?> </h2>
            <p>Here's what's happening across your <?= htmlspecialchars($branding['brand_tagline'] ?? 'Skills Transfer Program') ?> courses today.</p>
        </div>
        <div class="header-right">
            <div class="notif-bell" onclick="showSection('notifications',null)">
                <i class="fas fa-bell"></i>
                <?php if ($unreadNotifications > 0): ?><span class="nav-badge"><?= $unreadNotifications ?></span><?php endif; ?>
            </div>
            <div>
                <strong><?= htmlspecialchars($teacherInfo['email'] ?? '') ?></strong>
                Trainer Account
            </div>
        </div>
    </div>

    <!-- Workload snapshot (item #22) -->
    <div class="workload-strip">
        <div class="workload-chip"><span class="num"><?= $workload['courses'] ?></span><span class="lbl">Courses</span></div>
        <div class="workload-chip"><span class="num"><?= $workload['students'] ?></span><span class="lbl">Students</span></div>
        <div class="workload-chip"><span class="num"><?= $workload['to_grade'] ?></span><span class="lbl">To Grade</span></div>
        <div class="workload-chip"><span class="num"><?= $workload['upcoming_sessions'] ?></span><span class="lbl">Upcoming Sessions</span></div>
        <div class="workload-chip"><span class="num"><?= $workload['mentees'] ?></span><span class="lbl">Mentees</span></div>
        <div class="workload-chip"><span class="num"><?= $workload['supervisees'] ?></span><span class="lbl">Supervisees</span></div>
        <div class="workload-chip"><span class="num"><?= count($atRiskStudents) ?></span><span class="lbl">At-Risk Students</span></div>
    </div>

    <?php if (!empty($promotions)): ?>
    <div class="promo-strip">
        <div class="promo-strip-head">
            <h4><i class="fas fa-bullhorn"></i> CBT-Kenya Programmes &amp; Announcements</h4>
            <span>Sponsored space managed by Super Administration</span>
        </div>
        <div class="promo-cards">
            <?php foreach ($promotions as $p): ?>
            <div class="promo-card">
                <span class="promo-badge">Featured</span>
                <h5><?= htmlspecialchars($p['title'] ?? '') ?></h5>
                <p><?= htmlspecialchars($p['body'] ?? '') ?></p>
                <?php if (!empty($p['link_url'])): ?>
                    <a href="<?= htmlspecialchars($p['link_url']) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($p['link_label'] ?? 'Learn More') ?> <i class="fas fa-arrow-right"></i></a>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="cards">
        <div class="card"><div class="icon blue"><i class="fas fa-book"></i></div><h2><?= $courses_count ?></h2><p>My Courses</p></div>
        <div class="card"><div class="icon green"><i class="fas fa-users"></i></div><h2><?= $students_count ?></h2><p>Students</p></div>
        <div class="card"><div class="icon yellow"><i class="fas fa-file-pdf"></i></div><h2><?= $notes_count ?></h2><p>Notes</p></div>
        <div class="card"><div class="icon red"><i class="fas fa-video"></i></div><h2><?= $videos_count ?></h2><p>Videos</p></div>
        <div class="card"><div class="icon purple"><i class="fas fa-question-circle"></i></div><h2><?= $quiz_count ?></h2><p>Quizzes</p></div>
        <div class="card"><div class="icon teal"><i class="fas fa-chalkboard-teacher"></i></div><h2><?= $instructors_count ?></h2><p>Co-Instructors</p></div>
        <div class="card"><div class="icon pink"><i class="fas fa-people-arrows"></i></div><h2><?= count($myMentees) ?></h2><p>Mentees</p></div>
        <div class="card"><div class="icon orange"><i class="fas fa-triangle-exclamation"></i></div><h2><?= count($atRiskStudents) ?></h2><p>At-Risk Students</p></div>
    </div>

    <div class="grid-2">
        <div class="section">
            <h3><i class="fas fa-book"></i> My Courses Overview</h3>
            <table>
                <tr><th>Course</th><th>Price (KES)</th><th>Students</th><th>Status</th></tr>
                <?php
                $stmtE = $pdo->prepare("SELECT COUNT(*) AS total FROM enrollments WHERE course_id=?");
                foreach ($teacherCourses as $row):
                    $cid = $row['id'];
                    $stmtE->execute([$cid]);
                    $enrolled = $stmtE->fetch()['total'];
                ?>
                <tr>
                    <td><?= htmlspecialchars($row['title']) ?></td>
                    <td><?= number_format($row['price'] ?? 0) ?></td>
                    <td><strong><?= $enrolled ?></strong></td>
                    <td><span class="badge badge-<?= strtolower($row['status'] ?? 'inactive') ?>"><?= htmlspecialchars($row['status'] ?? 'Inactive') ?></span></td>
                </tr>
                <?php endforeach; ?>
            </table>
        </div>

        <div class="section">
            <h3><i class="fas fa-triangle-exclamation"></i> At-Risk Students <span class="sub">auto-flagged</span></h3>
            <?php if (count($atRiskStudents) > 0): ?>
                <?php foreach (array_slice($atRiskStudents, 0, 5) as $r): ?>
                <div class="activity-item">
                    <span class="msg"><i class="fas fa-circle" style="font-size:8px;color:#dc2626;margin-right:8px;"></i><?= htmlspecialchars($r['full_name']) ?> — <?= htmlspecialchars($r['course_title']) ?></span>
                    <span class="badge badge-risk">Risk x<?= (int)$r['risk_score'] ?></span>
                </div>
                <?php endforeach; ?>
                <div style="margin-top:12px;"><a href="#" onclick="showSection('atrisk', document.querySelector('.sidebar a[onclick*=atrisk]'))" class="btn btn-outline btn-sm">View all at-risk students</a></div>
            <?php else: ?>
                <p style="color:#64748b;">No students currently flagged as at-risk. </p>
            <?php endif; ?>
        </div>
    </div>

    <div class="section">
        <h3><i class="fas fa-clock"></i> Recent Activities</h3>
        <?php if (count($activities) > 0): ?>
            <?php foreach ($activities as $a): ?>
            <div class="activity-item">
                <span class="msg"><i class="fas fa-circle" style="font-size:8px;color:var(--brand-accent);margin-right:8px;"></i><?= htmlspecialchars($a['message']) ?></span>
                <span class="time"><?= htmlspecialchars($a['created_at']) ?></span>
            </div>
            <?php endforeach; ?>
        <?php else: ?>
            <p style="color:#64748b;">No recent activity for your courses yet.</p>
        <?php endif; ?>
    </div>
</div>

<!-- ==== MY COURSES ==== -->
<div id="sec-courses" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-book"></i> My Courses <span class="sub-count"><?= count($allCourses) ?> course(s)</span></p>
    <div class="format-hint"><strong>Editing scope (item #20)</strong>Trainers may propose changes to title/description only. Price, payment, certificate configuration, ownership, status and branding are locked to Super Administrator control.</div>
    <div class="grid-2">
    <?php if (count($allCourses) > 0): ?>
        <?php foreach ($allCourses as $row):
            $id = (int)$row['id'];
            $title = htmlspecialchars($row['title'] ?? '');
            $desc  = htmlspecialchars($row['description'] ?? '');
            $price = (float)($row['price'] ?? 0);
        ?>
        <div class="course-card">
            <h3><?= $title ?></h3>
            <?php if (!empty($desc)): ?><p><?= $desc ?></p><?php endif; ?>
            <div class="meta">
                <span><i class="fas fa-users"></i> <?= (int)($row['students'] ?? 0) ?> students</span>
                <span><i class="fas fa-folder"></i> <?= (int)($row['contents'] ?? 0) ?> items</span>
                <span><i class="fas fa-tag"></i> KES <?= number_format($price,2) ?> (locked)</span>
            </div>
            <div class="actions">
                <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('course-edit-<?= $id ?>')"><i class="fas fa-pen"></i> Edit</button>
                <a class="btn btn-danger btn-sm" href="?delete_course=<?= $id ?>&course_token=<?= urlencode($_SESSION['course_token']) ?>" onclick="return confirm('Request archiving/removal of this course? A Super Administrator must approve.')">
                    <i class="fas fa-box-archive"></i> Request Archive
                </a>
            </div>
            <div class="inline-edit" id="course-edit-<?= $id ?>">
                <form method="POST">
                    <input type="hidden" name="course_token" value="<?= htmlspecialchars($_SESSION['course_token']) ?>">
                    <input type="hidden" name="course_id" value="<?= $id ?>">
                    <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= $title ?>" required></div>
                    <div class="form-group"><label>Description</label><textarea name="description" rows="3"><?= $desc ?></textarea></div>
                    <div class="format-hint"><strong>Approval required</strong>Course edits are staged for Super Administrator review before they go live.</div>
                    <button type="submit" name="edit_course" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                </form>
            </div>
        </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="section"><p style="color:#64748b;">No courses assigned to you yet.</p></div>
    <?php endif; ?>
    </div>
</div>

<!-- ==== VIDEOS ==== -->
<div id="sec-videos" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-video"></i> Video Management</p>

    <div class="section">
        <h3>Upload New Video</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="video_token" value="<?= htmlspecialchars($_SESSION['video_token']) ?>">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach($coursesDropData as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Video Title</label><input name="title" placeholder="Enter title" required></div>
            <div class="form-group"><label>Video File</label><input type="file" name="video" accept="video/*" required></div>
            <div class="form-group">
                <label>Access Type</label>
                <select name="access_type">
                    <option value="free">Free</option>
                    <option value="paid">Paid</option>
                </select>
            </div>
            <button type="submit" name="upload_video" class="btn btn-primary"><i class="fas fa-upload"></i> Upload Video</button>
        </form>
    </div>

    <div class="section">
        <h3>Uploaded Videos</h3>
        <table>
            <tr><th>Course</th><th>Title</th><th>Access</th><th>Actions</th></tr>
            <?php foreach ($videos as $v): $vid = (int)$v['id']; ?>
            <tr>
                <td><?= htmlspecialchars($v['course_title']) ?></td>
                <td><?= htmlspecialchars($v['title']) ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($v['access_type']) ?>"><?= ucfirst(htmlspecialchars($v['access_type'])) ?></span></td>
                <td>
                    <a class="btn btn-success btn-sm" href="?view_video=<?= $vid ?>" target="_blank"><i class="fas fa-play"></i> Watch</a>
                    <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('video-edit-<?= $vid ?>')"><i class="fas fa-pen"></i> Edit</button>
                    <a class="btn btn-danger btn-sm" href="?delete_video=<?= $vid ?>&video_token=<?= urlencode($_SESSION['video_token']) ?>" onclick="return confirm('Delete this video?')"><i class="fas fa-trash"></i> Delete</a>
                </td>
            </tr>
            <tr class="edit-row" id="video-edit-<?= $vid ?>" style="display:none;">
                <td colspan="4">
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="video_token" value="<?= htmlspecialchars($_SESSION['video_token']) ?>">
                        <input type="hidden" name="video_id" value="<?= $vid ?>">
                        <div class="grid-3">
                            <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= htmlspecialchars($v['title']) ?>" required></div>
                            <div class="form-group">
                                <label>Access Type</label>
                                <select name="access_type">
                                    <option value="free" <?= $v['access_type']=='free'?'selected':'' ?>>Free</option>
                                    <option value="paid" <?= $v['access_type']=='paid'?'selected':'' ?>>Paid</option>
                                </select>
                            </div>
                            <div class="form-group"><label>Replace File (optional)</label><input type="file" name="video" accept="video/*"></div>
                        </div>
                        <div class="format-hint"><strong>Approval required</strong>Video edits go through Super Administrator review before publishing.</div>
                        <button type="submit" name="edit_video" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>

<!-- ==== NOTES / LEARNING MATERIALS ==== -->
<div id="sec-notes" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-file-pdf"></i> Notes Management</p>

    <div class="section">
        <h3>Create Note</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="note_token" value="<?= htmlspecialchars($_SESSION['note_token']) ?>">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach($coursesDropData as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input name="title" placeholder="Note title" required></div>
            <div class="form-group"><label>Attachment (optional)</label><input type="file" name="file"></div>
            <div class="form-group">
                <label>Access Type</label>
                <select name="access_type">
                    <option value="free">Free</option>
                    <option value="paid">Paid</option>
                </select>
            </div>
            <button type="submit" name="add_note" class="btn btn-primary"><i class="fas fa-plus"></i> Add Note</button>
        </form>
    </div>

    <div class="section">
        <h3>All Notes</h3>
        <table>
            <tr><th>Course</th><th>Title</th><th>Access</th><th>File</th><th>Action</th></tr>
            <?php foreach ($notes as $n): $nid = (int)$n['id']; ?>
            <tr>
                <td><?= htmlspecialchars($n['course_title']) ?></td>
                <td><?= htmlspecialchars($n['title']) ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($n['access_type']) ?>"><?= ucfirst(htmlspecialchars($n['access_type'])) ?></span></td>
                <td><?= !empty($n['file_path']) ? '<span style="color:#16a34a;"><i class="fas fa-paperclip"></i> Attached</span>' : 'Text only' ?></td>
                <td>
                    <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('note-edit-<?= $nid ?>')"><i class="fas fa-pen"></i> Edit</button>
                    <form method="POST" onsubmit="return confirm('Delete this note?');" style="display:inline;">
                        <input type="hidden" name="note_token" value="<?= htmlspecialchars($_SESSION['note_token']) ?>">
                        <input type="hidden" name="delete_note" value="<?= $nid ?>">
                        <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Delete</button>
                    </form>
                </td>
            </tr>
            <tr class="edit-row" id="note-edit-<?= $nid ?>" style="display:none;">
                <td colspan="5">
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="note_token" value="<?= htmlspecialchars($_SESSION['note_token']) ?>">
                        <input type="hidden" name="note_id" value="<?= $nid ?>">
                        <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= htmlspecialchars($n['title']) ?>" required></div>
                        <div class="form-group"><label>Content</label><textarea name="content" rows="3"><?= htmlspecialchars($n['content'] ?? '') ?></textarea></div>
                        <div class="grid-3">
                            <div class="form-group">
                                <label>Access Type</label>
                                <select name="access_type">
                                    <option value="free" <?= $n['access_type']=='free'?'selected':'' ?>>Free</option>
                                    <option value="paid" <?= $n['access_type']=='paid'?'selected':'' ?>>Paid</option>
                                </select>
                            </div>
                            <div class="form-group"><label>Replace Attachment (optional)</label><input type="file" name="file"></div>
                        </div>
                        <div class="format-hint"><strong>Approval required</strong>Learning material edits go through Super Administrator review.</div>
                        <button type="submit" name="edit_note" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>

<!-- ==== MEDIA LIBRARY (item #27) ==== -->
<div id="sec-media" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-photo-film"></i> Media Library <span class="sub-count"><?= count($mediaLibrary) ?> item(s)</span></p>
    <div class="section">
        <table>
            <tr><th>Type</th><th>Title</th><th>Course</th><th>Added</th><th>Action</th></tr>
            <?php if (count($mediaLibrary) > 0): foreach ($mediaLibrary as $m): ?>
            <tr>
                <td><span class="badge badge-<?= $m['type']==='Video' ? 'paid' : 'free' ?>"><?= htmlspecialchars($m['type']) ?></span></td>
                <td><?= htmlspecialchars($m['title']) ?></td>
                <td><?= htmlspecialchars($m['course']) ?></td>
                <td><?= htmlspecialchars($m['created_at'] ?? '') ?></td>
                <td><a class="btn btn-outline btn-sm" href="<?= htmlspecialchars($m['path']) ?>" target="_blank"><i class="fas fa-eye"></i> Preview</a></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No media uploaded yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== ATTENDANCE (item #7) ==== -->
<div id="sec-attendance" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-clipboard-check"></i> Attendance</p>

    <div class="section">
        <h3>Take Attendance</h3>
        <form method="POST" id="attendanceForm">
            <input type="hidden" name="attendance_token" value="<?= htmlspecialchars($_SESSION['attendance_token']) ?>">
            <div class="grid-2">
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" id="attCourseSelect" required onchange="filterAttendanceStudents()">
                        <option value="">-- Select Course --</option>
                        <?php foreach($coursesDropData as $c): ?>
                            <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Session Date</label><input type="date" name="attendance_date" value="<?= date('Y-m-d') ?>" required></div>
            </div>
            <table>
                <tr><th>Student</th><th>Present</th><th>Late</th><th>Absent</th><th>Excused</th></tr>
                <?php foreach ($students as $s): ?>
                <tr>
                    <td><?= htmlspecialchars($s['full_name'] ?? '') ?></td>
                    <?php foreach (['present'=>'Present','late'=>'Late','absent'=>'Absent','excused'=>'Excused'] as $val=>$label): ?>
                    <td style="text-align:center;"><input type="radio" name="status[<?= (int)$s['user_id'] ?>]" value="<?= $val ?>" <?= $val==='present'?'checked':'' ?>></td>
                    <?php endforeach; ?>
                </tr>
                <?php endforeach; ?>
            </table>
            <div style="margin-top:14px;">
                <button type="submit" name="take_attendance" class="btn btn-primary"><i class="fas fa-save"></i> Save Attendance</button>
            </div>
        </form>
    </div>

    <div class="section">
        <h3>Attendance History</h3>
        <table>
            <tr><th>Date</th><th>Student</th><th>Course</th><th>Status</th></tr>
            <?php if (count($attendanceHistory) > 0): foreach ($attendanceHistory as $a): ?>
            <tr>
                <td><?= htmlspecialchars($a['attendance_date']) ?></td>
                <td><?= htmlspecialchars($a['full_name']) ?></td>
                <td><?= htmlspecialchars($a['course_title']) ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($a['status']) ?>"><?= ucfirst(htmlspecialchars($a['status'])) ?></span></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="4" style="text-align:center;color:#64748b;">No attendance recorded yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== ASSIGNMENTS ==== -->
<div id="sec-assignments" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-tasks"></i> Assignment Management</p>

    <div class="section">
        <h3>Create Assignment</h3>
        <form method="POST">
            <input type="hidden" name="assignment_token" value="<?= htmlspecialchars($_SESSION['assignment_token']) ?>">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach($coursesDropData as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Assignment Title</label><input type="text" name="title" placeholder="Assignment title" required></div>
            <div class="form-group"><label>Description</label><textarea name="description" rows="5" placeholder="Instructions and requirements"></textarea></div>
            <div class="form-group"><label>Due Date</label><input type="date" name="due_date"></div>
            <div class="format-hint"><strong>Approval required</strong>Assignments are staged for Super Administrator review before students can see them.</div>
            <button type="submit" name="create_assignment" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
        </form>
    </div>

    <div class="section">
        <h3>Published Assignments</h3>
        <div style="overflow-x:auto;">
        <table>
            <tr><th>Course</th><th>Title</th><th>Due Date</th><th>Created</th><th>Action</th></tr>
            <?php if ($teacherAssignments): foreach ($teacherAssignments as $assignment): $aid = (int)$assignment['id']; ?>
            <tr>
                <td><?= htmlspecialchars($assignment['course_title'] ?? '') ?></td>
                <td><?= htmlspecialchars($assignment['title'] ?? '') ?></td>
                <td><?= htmlspecialchars($assignment['due_date'] ?? '—') ?></td>
                <td><?= htmlspecialchars($assignment['created_at'] ?? '') ?></td>
                <td><button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('assignment-edit-<?= $aid ?>')"><i class="fas fa-pen"></i> Edit</button></td>
            </tr>
            <tr class="edit-row" id="assignment-edit-<?= $aid ?>" style="display:none;">
                <td colspan="5">
                    <form method="POST">
                        <input type="hidden" name="assignment_token" value="<?= htmlspecialchars($_SESSION['assignment_token']) ?>">
                        <input type="hidden" name="assignment_id" value="<?= $aid ?>">
                        <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= htmlspecialchars($assignment['title'] ?? '') ?>" required></div>
                        <div class="form-group"><label>Description</label><textarea name="description" rows="4"><?= htmlspecialchars($assignment['description'] ?? '') ?></textarea></div>
                        <div class="form-group"><label>Due Date</label><input type="date" name="due_date" value="<?= htmlspecialchars($assignment['due_date'] ?? '') ?>"></div>
                        <div class="format-hint"><strong>Approval required</strong>Assignment edits require Super Administrator review before they update for students.</div>
                        <button type="submit" name="edit_assignment" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No published assignments yet.</td></tr>
            <?php endif; ?>
        </table>
        </div>
    </div>
</div>

<!-- ==== GRADING CENTRE (item #4) ==== -->
<div id="sec-grading" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-marker"></i> Assignment Submission &amp; Grading Centre <span class="sub-count"><?= $pendingGradingCount ?> pending</span></p>
    <div class="section">
        <table>
            <tr><th>Student</th><th>Assignment</th><th>Course</th><th>Submitted</th><th>Status</th><th>Marks</th><th>Action</th></tr>
            <?php if (count($submissionsList) > 0): foreach ($submissionsList as $sub): $subId = (int)$sub['id']; ?>
            <tr>
                <td><?= htmlspecialchars($sub['student_name']) ?></td>
                <td><?= htmlspecialchars($sub['assignment_title']) ?></td>
                <td><?= htmlspecialchars($sub['course_title']) ?></td>
                <td><?= htmlspecialchars($sub['submitted_at']) ?><?php if (!empty($sub['due_date']) && strtotime($sub['submitted_at']) > strtotime($sub['due_date'].' 23:59:59')): ?> <span class="badge badge-late">Late</span><?php endif; ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($sub['status'] ?? 'submitted') ?>"><?= ucfirst(str_replace('_',' ', htmlspecialchars($sub['status'] ?? 'submitted'))) ?></span></td>
                <td><?= $sub['marks'] !== null ? (int)$sub['marks'] : '—' ?></td>
                <td>
                    <?php if (!empty($sub['file_path'])): ?><a class="btn btn-outline btn-sm" href="<?= htmlspecialchars($sub['file_path']) ?>" target="_blank"><i class="fas fa-download"></i></a><?php endif; ?>
                    <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('grade-<?= $subId ?>')"><i class="fas fa-pen"></i> Grade</button>
                </td>
            </tr>
            <tr class="edit-row" id="grade-<?= $subId ?>" style="display:none;">
                <td colspan="7">
                    <form method="POST">
                        <input type="hidden" name="grading_token" value="<?= htmlspecialchars($_SESSION['grading_token']) ?>">
                        <input type="hidden" name="submission_id" value="<?= $subId ?>">
                        <div class="grid-3">
                            <div class="form-group"><label>Marks</label><input type="number" name="marks" value="<?= htmlspecialchars((string)($sub['marks'] ?? '')) ?>"></div>
                            <div class="form-group">
                                <label>Action</label>
                                <select name="grade_action">
                                    <option value="grade">Grade</option>
                                    <option value="return_for_correction">Return for Correction (Request Resubmission)</option>
                                    <option value="mark_late">Mark as Late</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group"><label>Feedback</label><textarea name="feedback" rows="2"><?= htmlspecialchars($sub['feedback'] ?? '') ?></textarea></div>
                        <button type="submit" name="grade_submission" class="btn btn-primary btn-sm"><i class="fas fa-check"></i> Save Grade</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="7" style="text-align:center;color:#64748b;">No submissions yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== QUIZZES + QUESTION BANK ==== -->
<div id="sec-quiz" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-question-circle"></i> Quiz &amp; Question Bank Management</p>

    <div class="cards">
        <div class="card"><div class="icon blue"><i class="fas fa-list"></i></div><h2><?= $total_quizzes ?></h2><p>Total Quizzes</p></div>
        <div class="card"><div class="icon purple"><i class="fas fa-question"></i></div><h2><?= $total_questions ?></h2><p>Questions</p></div>
        <div class="card"><div class="icon yellow"><i class="fas fa-pen"></i></div><h2><?= $total_attempts ?></h2><p>Attempts</p></div>
        <div class="card"><div class="icon green"><i class="fas fa-check"></i></div><h2><?= $passed ?></h2><p>Passed</p></div>
        <div class="card"><div class="icon red"><i class="fas fa-times"></i></div><h2><?= $failed ?></h2><p>Failed</p></div>
        <div class="card"><div class="icon orange"><i class="fas fa-chart-bar"></i></div><h2><?= round($average_score,1) ?>%</h2><p>Avg Score</p></div>
    </div>

    <!-- Assessment analytics (item #6) -->
    <div class="section">
        <h3><i class="fas fa-chart-column"></i> Assessment Analytics</h3>
        <div class="grid-3">
            <div class="stat-highlight"><h2><?= round($average_score,1) ?>%</h2><p>Average Score</p></div>
            <div class="stat-highlight"><h2><?= $total_attempts > 0 ? round(100*$passed/$total_attempts,1) : 0 ?>%</h2><p>Pass Rate</p></div>
            <div class="stat-highlight"><h2><?= $total_attempts > 0 ? round(100*$failed/$total_attempts,1) : 0 ?>%</h2><p>Failure Rate</p></div>
        </div>
    </div>

    <div class="grid-2">
        <div class="section">
            <h3>Create Quiz</h3>
            <form method="POST">
                <input type="hidden" name="quiz_token" value="<?= htmlspecialchars($_SESSION['quiz_token']) ?>">
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">-- Select Course --</option>
                        <?php foreach($coursesDropData as $c): ?>
                            <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Quiz Title</label><input type="text" name="title" placeholder="Quiz title" required></div>
                <div class="form-group"><label>Description</label><textarea name="description" rows="3" placeholder="Description..."></textarea></div>
                <div class="form-group"><label>Passing Marks (%)</label><input type="number" name="passing_marks" placeholder="e.g. 60" required></div>
                <div class="form-group"><label>Duration (minutes)</label><input type="number" name="duration" placeholder="e.g. 30" required></div>
                <button type="submit" name="create_quiz" class="btn btn-primary"><i class="fas fa-plus"></i> Create Quiz</button>
            </form>
        </div>

        <div class="section">
            <h3>Add Questions</h3>

            <div class="import-tabs">
                <button type="button" class="tab-btn active" onclick="showQTab('single', this)"><i class="fas fa-keyboard"></i> Single Question</button>
                <button type="button" class="tab-btn" onclick="showQTab('bulk', this)"><i class="fas fa-file-import"></i> Bulk Import</button>
            </div>

            <!-- SINGLE QUESTION FORM -->
            <div id="qtab-single" class="qtab-panel">
                <form method="POST">
                    <input type="hidden" name="quiz_token" value="<?= htmlspecialchars($_SESSION['quiz_token']) ?>">
                    <div class="form-group">
                        <label>Quiz</label>
                        <select name="quiz_id" required>
                            <option value="">-- Select Quiz --</option>
                            <?php foreach ($quizDropData as $q): ?>
                                <option value="<?= $q['id'] ?>"><?= htmlspecialchars($q['title']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group"><label>Question</label><textarea name="question" rows="3" placeholder="Enter question" required></textarea></div>
                    <div class="grid-3">
                        <div class="form-group">
                            <label>Type</label>
                            <select name="question_type">
                                <option value="mcq">Multiple Choice</option>
                                <option value="short_answer">Short Answer</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Difficulty</label>
                            <select name="difficulty">
                                <option value="easy">Easy</option>
                                <option value="medium" selected>Medium</option>
                                <option value="hard">Hard</option>
                            </select>
                        </div>
                        <div class="form-group"><label>Topic / Module</label><input type="text" name="topic" placeholder="e.g. Risk Assessment"></div>
                    </div>
                    <div class="form-group"><label>Option A</label><input type="text" name="option_a" placeholder="Option A"></div>
                    <div class="form-group"><label>Option B</label><input type="text" name="option_b" placeholder="Option B"></div>
                    <div class="form-group"><label>Option C</label><input type="text" name="option_c" placeholder="Option C"></div>
                    <div class="form-group"><label>Option D</label><input type="text" name="option_d" placeholder="Option D"></div>
                    <div class="form-group"><label>Correct Answer</label><input type="text" name="correct_answer" placeholder="e.g. A or full answer" required></div>
                    <div class="form-group"><label>Explanation (shown after grading)</label><textarea name="explanation" rows="2" placeholder="Why is this the correct answer?"></textarea></div>
                    <div class="form-group"><label>Marks</label><input type="number" name="marks" value="1"></div>
                    <button type="submit" name="add_question" class="btn btn-primary"><i class="fas fa-plus"></i> Add Question</button>
                </form>
            </div>

            <!-- BULK IMPORT FORM -->
            <div id="qtab-bulk" class="qtab-panel" style="display:none;">

                <div class="format-hint">
                    <strong> Required Format (paste, .txt, Word, or PDF)</strong>
                    Separate each question with a <strong>blank line</strong>. Each question needs 4 options (A–D) and an <code>Answer: X</code> line. <br><br>
                    <strong>Multi-line format:</strong><br>
                    <code>1. What is the capital of France?</code><br>
                    <code>A. Berlin</code><br>
                    <code>B. Madrid</code><br>
                    <code>C. Paris</code><br>
                    <code>D. Rome</code><br>
                    <code>Answer: C</code><br><br>
                    <strong>one line per question </strong><br>
                   
                </div>

                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="quiz_token" value="<?= htmlspecialchars($_SESSION['quiz_token']) ?>">
                    <div class="form-group">
                        <label>Quiz</label>
                        <select name="quiz_id" required>
                            <option value="">-- Select Quiz --</option>
                            <?php foreach ($quizDropData as $q): ?>
                                <option value="<?= $q['id'] ?>"><?= htmlspecialchars($q['title']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Paste Questions <span style="font-weight:400;color:#64748b;">(optional if uploading a file)</span></label>
                        <textarea name="bulk_text" rows="10" placeholder="1. What is the capital of France?
                            A. Berlin
                            B. Madrid
                            C. Paris
                            D. Rome
                            Answer: C

                            2. HTML stands for?
                            A. Hyper Text Markup Language
                            B. High Text Machine Language
                            C. Home Tool Markup Language
                            D. Hyperlinks and Text Markup Language
                            Answer: A">
                        </textarea>
                    </div>

                    <div class="form-group">
                        <label>Or Upload File <span style="font-weight:400;color:#64748b;">(.txt, .csv, .docx, .xlsx, .pdf — max 8MB)</span></label>
                        <input type="file" name="bulk_file" accept=".txt,.csv,.docx,.xlsx,.pdf">
                    </div>

                    <button type="submit" name="bulk_import_questions" class="btn btn-primary"><i class="fas fa-file-import"></i> Import Questions</button>
                </form>
            </div>
        </div>
    </div>

    <div class="section">
        <h3>Quiz List</h3>
        <table>
            <tr><th>ID</th><th>Course</th><th>Quiz Title</th><th>Passing %</th><th>Duration</th><th>Status</th><th>Action</th></tr>
            <?php foreach ($quizzes as $row): $qid = (int)$row['id']; ?>
            <tr>
                <td><?= $qid ?></td>
                <td><?= htmlspecialchars($row['course_name'] ?? '') ?></td>
                <td><?= htmlspecialchars($row['title']) ?></td>
                <td><?= $row['passing_score'] ?? 0 ?>%</td>
                <td><?= $row['duration'] ?> mins</td>
                <td><span class="badge badge-<?= strtolower(htmlspecialchars($row['status'] ?? 'inactive')) ?>"><?= ucfirst(htmlspecialchars($row['status'] ?? 'Active')) ?></span></td>
                <td>
                    <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('quiz-edit-<?= $qid ?>')"><i class="fas fa-pen"></i> Edit</button>
                    <a class="btn btn-danger btn-sm"
                       href="?delete_quiz=<?= $qid ?>&quiz_token=<?= urlencode($_SESSION['quiz_token']) ?>"
                       onclick="return confirm('Delete this quiz and all its questions and attempts? This cannot be undone.')">
                        <i class="fas fa-trash"></i> Delete
                    </a>
                </td>
            </tr>
            <tr class="edit-row" id="quiz-edit-<?= $qid ?>" style="display:none;">
                <td colspan="7">
                    <form method="POST">
                        <input type="hidden" name="quiz_token" value="<?= htmlspecialchars($_SESSION['quiz_token']) ?>">
                        <input type="hidden" name="quiz_id" value="<?= $qid ?>">
                        <div class="grid-3">
                            <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= htmlspecialchars($row['title']) ?>" required></div>
                            <div class="form-group"><label>Passing Marks (%)</label><input type="number" name="passing_marks" value="<?= (int)($row['passing_score'] ?? 0) ?>" required></div>
                            <div class="form-group"><label>Duration (minutes)</label><input type="number" name="duration" value="<?= (int)$row['duration'] ?>" required></div>
                        </div>
                        <div class="form-group"><label>Description</label><textarea name="description" rows="3"><?= htmlspecialchars($row['description'] ?? '') ?></textarea></div>
                        <div class="format-hint"><strong>Approval required</strong>Quiz edits go through Super Administrator review.</div>
                        <button type="submit" name="edit_quiz" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <div class="section">
        <h3>Question Bank <span class="sub">filter by topic below</span></h3>
        <?php if (count($questionTopics) > 0): ?>
        <div class="form-group" style="max-width:280px;">
            <label>Filter by Topic</label>
            <select id="topicFilter" onchange="filterQuestionBank()">
                <option value="">All Topics</option>
                <?php foreach ($questionTopics as $t): ?><option value="<?= htmlspecialchars($t) ?>"><?= htmlspecialchars($t) ?></option><?php endforeach; ?>
            </select>
        </div>
        <?php endif; ?>
        <table id="questionBankTable">
            <tr><th>Quiz</th><th>Question</th><th>Topic</th><th>Correct</th><th>Marks</th><th>Action</th></tr>
            <?php if (count($questionsList) > 0): foreach ($questionsList as $ques): $qqid = (int)$ques['id']; ?>
            <tr data-topic="<?= htmlspecialchars($ques['topic'] ?? '') ?>">
                <td><?= htmlspecialchars($ques['quiz_title'] ?? '') ?></td>
                <td><?= htmlspecialchars(mb_strimwidth($ques['question'] ?? '', 0, 80, '…')) ?></td>
                <td><?= htmlspecialchars($ques['topic'] ?? '—') ?></td>
                <td><span class="badge badge-approved"><?= htmlspecialchars($ques['correct_answer'] ?? '') ?></span></td>
                <td><?= (int)($ques['marks'] ?? 1) ?></td>
                <td><button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('question-edit-<?= $qqid ?>')"><i class="fas fa-pen"></i> Edit</button></td>
            </tr>
            <tr class="edit-row" id="question-edit-<?= $qqid ?>" style="display:none;">
                <td colspan="6">
                    <form method="POST">
                        <input type="hidden" name="quiz_token" value="<?= htmlspecialchars($_SESSION['quiz_token']) ?>">
                        <input type="hidden" name="question_id" value="<?= $qqid ?>">
                        <div class="form-group"><label>Question</label><textarea name="question" rows="2" required><?= htmlspecialchars($ques['question'] ?? '') ?></textarea></div>
                        <div class="grid-3">
                            <div class="form-group"><label>Option A</label><input type="text" name="option_a" value="<?= htmlspecialchars($ques['option_a'] ?? '') ?>"></div>
                            <div class="form-group"><label>Option B</label><input type="text" name="option_b" value="<?= htmlspecialchars($ques['option_b'] ?? '') ?>"></div>
                            <div class="form-group"><label>Option C</label><input type="text" name="option_c" value="<?= htmlspecialchars($ques['option_c'] ?? '') ?>"></div>
                        </div>
                        <div class="grid-3">
                            <div class="form-group"><label>Option D</label><input type="text" name="option_d" value="<?= htmlspecialchars($ques['option_d'] ?? '') ?>"></div>
                            <div class="form-group"><label>Correct Answer</label><input type="text" name="correct_answer" value="<?= htmlspecialchars($ques['correct_answer'] ?? '') ?>" required></div>
                            <div class="form-group"><label>Marks</label><input type="number" name="marks" value="<?= (int)($ques['marks'] ?? 1) ?>"></div>
                        </div>
                        <div class="grid-3">
                            <div class="form-group">
                                <label>Difficulty</label>
                                <select name="difficulty">
                                    <?php foreach (['easy','medium','hard'] as $d): ?>
                                    <option value="<?= $d ?>" <?= ($ques['difficulty'] ?? '')===$d?'selected':'' ?>><?= ucfirst($d) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="form-group"><label>Topic</label><input type="text" name="topic" value="<?= htmlspecialchars($ques['topic'] ?? '') ?>"></div>
                            <div class="form-group"><label>Explanation</label><input type="text" name="explanation" value="<?= htmlspecialchars($ques['explanation'] ?? '') ?>"></div>
                        </div>
                        <input type="hidden" name="question_type" value="<?= htmlspecialchars($ques['question_type'] ?? 'mcq') ?>">
                        <div class="format-hint"><strong>Approval required</strong>Question edits go through Super Administrator review before students see them.</div>
                        <button type="submit" name="edit_question" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="6" style="text-align:center;color:#64748b;">No questions added yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>

    <div class="section">
        <h3>Student Quiz Attempts</h3>
        <table>
            <tr><th>Student</th><th>Quiz</th><th>Score</th><th>Percentage</th><th>Result</th><th>Date</th></tr>
            <?php if (count($attempts) > 0): ?>
                <?php foreach ($attempts as $attempt):
                    $status = strtolower($attempt['status'] ?? 'failed');
                    $badgeClass = (strpos($status, 'pass') !== false) ? 'pass' : 'fail';
                ?>
                <tr>
                    <td><?= htmlspecialchars($attempt['full_name'] ?? 'Unknown') ?></td>
                    <td><?= htmlspecialchars($attempt['quiz_title'] ?? 'Unknown') ?></td>
                    <td><?= (int)$attempt['score'] ?></td>
                    <td><?= (int)$attempt['score'] ?>%</td>
                    <td><span class="badge badge-<?= $badgeClass ?>"><?= ucfirst(htmlspecialchars($attempt['status'] ?? 'Failed')) ?></span></td>
                    <td><?= htmlspecialchars($attempt['completed_at'] ?? '') ?></td>
                </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="6" style="text-align:center;color:#64748b;">No quiz attempts yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== STUDENTS ==== -->
<div id="sec-students" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-users"></i> Student Management</p>

    <div class="section">
        <h3>My Students</h3>
        <table>
            <tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Status</th><th>Joined</th><th>Action</th></tr>
            <?php foreach ($students as $s): ?>
            <tr>
                <td><?= $s['id'] ?></td>
                <td><?= htmlspecialchars($s['full_name'] ?? '') ?></td>
                <td><?= htmlspecialchars($s['email'] ?? '') ?></td>
                <td><?= htmlspecialchars($s['phone'] ?? '') ?></td>
                <td><span class="badge badge-<?= strtolower(htmlspecialchars($s['status'] ?? 'inactive')) ?>"><?= ucfirst(htmlspecialchars($s['status'] ?? '')) ?></span></td>
                <td><?= htmlspecialchars($s['created_at']) ?></td>
                <td>
                    <form method="POST" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                        <input type="hidden" name="student_token" value="<?= htmlspecialchars($_SESSION['student_token']) ?>">
                        <input type="hidden" name="student_id" value="<?= $s['id'] ?>">
                        <select name="action" style="padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:12px;">
                            <option value="activate">Activate</option>
                            <option value="suspend">Suspend</option>
                            <option value="reset_password">Reset Password</option>
                            <option value="delete">Delete</option>
                        </select>
                        <button type="submit" name="student_action" class="btn btn-primary btn-sm" onclick="return confirm('Apply this action?')">Apply</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>

    <div class="section">
        <h3>Enrollments</h3>
        <table>
            <tr><th>ID</th><th>Student</th><th>Course</th><th>Status</th><th>Progress</th><th>Enrolled</th><th>Actions</th></tr>
            <?php foreach ($enrollments as $e): ?>
            <tr>
                <td><?= $e['id'] ?></td>
                <td><?= htmlspecialchars($e['full_name']) ?></td>
                <td><?= htmlspecialchars($e['title']) ?></td>
                <td><span class="badge badge-<?= strtolower(htmlspecialchars($e['status'] ?? '')) ?>"><?= ucfirst(htmlspecialchars($e['status'] ?? '')) ?></span></td>
                <td><?= $e['progress'] ?? 0 ?>%</td>
                <td><?= htmlspecialchars($e['enrolled_at']) ?></td>
                <td>
                    <form method="POST" style="display:flex;gap:5px;flex-wrap:wrap;">
                        <input type="hidden" name="enroll_token" value="<?= htmlspecialchars($_SESSION['enroll_token']) ?>">
                        <input type="hidden" name="enroll_id" value="<?= $e['id'] ?>">
                        <input type="hidden" name="enroll_action" value="1">
                        <button type="submit" name="action" value="approve" class="btn btn-success btn-sm">Approve</button>
                        <button type="submit" name="action" value="reject"  class="btn btn-warning btn-sm">Reject</button>
                        <button type="submit" name="action" value="delete"  class="btn btn-danger btn-sm" onclick="return confirm('Delete enrollment?')">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>

<!-- ==== STUDENT PROGRESS (item #2) ==== -->
<div id="sec-progress" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-chart-line"></i> Student Progress</p>
    <div class="section">
        <table>
            <tr><th>Student</th><th>Course</th><th>Progress</th><th>Quiz Avg</th><th>Assignments</th><th>Attendance</th><th>Last Login</th><th>Status</th></tr>
            <?php if (count($studentProgressRows) > 0): foreach ($studentProgressRows as $r):
                $prog = (int)($r['progress'] ?? 0);
                $onTrack = $prog >= 60 && ($r['quiz_avg'] === null || $r['quiz_avg'] >= 50);
            ?>
            <tr>
                <td><?= htmlspecialchars($r['full_name']) ?></td>
                <td><?= htmlspecialchars($r['course_title']) ?></td>
                <td style="min-width:140px;">
                    <div class="progress-track"><div class="progress-fill" style="width:<?= $prog ?>%;"></div></div>
                    <span style="font-size:11px;color:#64748b;"><?= $prog ?>%</span>
                </td>
                <td><?= $r['quiz_avg'] !== null ? round($r['quiz_avg'],1).'%' : '—' ?></td>
                <td><?= (int)($r['submitted_assignments'] ?? 0) ?>/<?= (int)($r['total_assignments'] ?? 0) ?></td>
                <td><?= $r['attendance_pct'] !== null ? $r['attendance_pct'].'%' : '—' ?></td>
                <td><?= $r['last_login'] ? htmlspecialchars($r['last_login']) : 'Never' ?></td>
                <td><span class="badge badge-<?= $onTrack ? 'ontrack' : 'risk' ?>"><?= $onTrack ? 'On Track' : 'Needs Attention' ?></span></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="8" style="text-align:center;color:#64748b;">No student progress data yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== AT-RISK STUDENTS (item #3) ==== -->
<div id="sec-atrisk" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-triangle-exclamation"></i> At-Risk Students <span class="sub-count"><?= count($atRiskStudents) ?> flagged</span></p>
    <div class="format-hint"><strong>How students get flagged</strong>A student is flagged when two or more of the following are true: progress under 40%, quiz average under 50%, attendance under 60%, missing assignment submissions, or no login in the last 14 days.</div>
    <div class="section">
        <table>
            <tr><th>Student</th><th>Course</th><th>Progress</th><th>Quiz Avg</th><th>Attendance</th><th>Last Login</th><th>Risk Score</th><th>Action</th></tr>
            <?php if (count($atRiskStudents) > 0): foreach ($atRiskStudents as $r): ?>
            <tr class="risk-row">
                <td><?= htmlspecialchars($r['full_name']) ?></td>
                <td><?= htmlspecialchars($r['course_title']) ?></td>
                <td><?= (int)($r['progress'] ?? 0) ?>%</td>
                <td><?= $r['quiz_avg'] !== null ? round($r['quiz_avg'],1).'%' : '—' ?></td>
                <td><?= $r['attendance_pct'] !== null ? $r['attendance_pct'].'%' : '—' ?></td>
                <td><?= $r['last_login'] ? htmlspecialchars($r['last_login']) : 'Never' ?></td>
                <td><span class="badge badge-risk">x<?= (int)$r['risk_score'] ?></span></td>
                <td>
                    <button type="button" class="btn btn-outline btn-sm" onclick="prefillMessage(<?= (int)$r['user_id'] ?>, '<?= htmlspecialchars(addslashes($r['full_name']), ENT_QUOTES) ?>')"><i class="fas fa-message"></i> Message</button>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="8" style="text-align:center;color:#64748b;">No students currently flagged as at-risk. </td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== REPORTS ==== -->
<div id="sec-reports" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-chart-pie"></i> Reports Dashboard</p>

    <div class="cards">
        <div class="card"><div class="icon blue"><i class="fas fa-book"></i></div><h2><?= $total_courses ?></h2><p>My Courses</p></div>
        <div class="card"><div class="icon green"><i class="fas fa-users"></i></div><h2><?= $total_students ?></h2><p>Total Students</p></div>
        <div class="card"><div class="icon yellow"><i class="fas fa-folder"></i></div><h2><?= $total_content ?></h2><p>Content Items</p></div>
        <div class="card"><div class="icon red"><i class="fas fa-video"></i></div><h2><?= $total_videos ?></h2><p>Videos</p></div>
        <div class="card"><div class="icon purple"><i class="fas fa-file-pdf"></i></div><h2><?= $total_notes ?></h2><p>Notes</p></div>
        <div class="card"><div class="icon orange"><i class="fas fa-coins"></i></div><h2>KES <?= number_format($revenue) ?></h2><p>Revenue</p></div>
    </div>

    <div class="grid-2">
        <div class="section">
            <h3><i class="fas fa-trophy"></i> Top Performing Courses</h3>
            <table>
                <tr><th>Course</th><th>Enrolled Students</th></tr>
                <?php foreach ($top_courses as $row): ?>
                <tr>
                    <td><?= htmlspecialchars($row['title']) ?></td>
                    <td><strong><?= $row['students'] ?></strong></td>
                </tr>
                <?php endforeach; ?>
            </table>
        </div>

        <div class="section">
            <h3><i class="fas fa-user-clock"></i> Trainer Workload</h3>
            <table>
                <tr><td>Courses</td><td><strong><?= $workload['courses'] ?></strong></td></tr>
                <tr><td>Students</td><td><strong><?= $workload['students'] ?></strong></td></tr>
                <tr><td>Assignments to Grade</td><td><strong><?= $workload['to_grade'] ?></strong></td></tr>
                <tr><td>Upcoming Sessions</td><td><strong><?= $workload['upcoming_sessions'] ?></strong></td></tr>
                <tr><td>Mentees</td><td><strong><?= $workload['mentees'] ?></strong></td></tr>
                <tr><td>Supervisees</td><td><strong><?= $workload['supervisees'] ?></strong></td></tr>
            </table>
        </div>
    </div>

    <div class="section">
        <h3><i class="fas fa-file-export"></i> Export</h3>
        <p style="color:#64748b;font-size:13px;margin-bottom:12px;">Export the tables above for offline reporting. Exports use your browser's print function so no extra libraries are required.</p>
        <button type="button" class="btn btn-outline btn-sm" onclick="window.print()"><i class="fas fa-file-pdf"></i> Export / Print PDF</button>
    </div>
</div>

<!-- ==== STUDENT FEEDBACK (item #25) ==== -->
<div id="sec-feedback" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-comment-dots"></i> Student Feedback <span class="sub-count">Avg rating: <?= round($avgCourseRating,1) ?>/5</span></p>
    <div class="section">
        <table>
            <tr><th>Course</th><th>Reviewer</th><th>Rating</th><th>Review</th><th>Date</th></tr>
            <?php if (count($courseFeedback) > 0): foreach ($courseFeedback as $f): ?>
            <tr>
                <td><?= htmlspecialchars($f['course_title']) ?></td>
                <td><?= htmlspecialchars($f['reviewer_name'] ?? 'Anonymous') ?></td>
                <td><?php for ($i=0;$i<5;$i++): ?><i class="fa<?= $i < (int)$f['rating'] ? 's' : 'r' ?> fa-star" style="color:#f59e0b;font-size:11px;"></i><?php endfor; ?></td>
                <td><?= htmlspecialchars(mb_strimwidth($f['review'] ?? '', 0, 140, '…')) ?></td>
                <td><?= htmlspecialchars($f['created_at']) ?></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No feedback submitted yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== ANNOUNCEMENTS ==== -->
<div id="sec-announcements" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-bullhorn"></i> Announcements</p>

    <div class="section">
        <h3>Post Announcement</h3>
        <form method="POST">
            <input type="hidden" name="announce_token" value="<?= htmlspecialchars($_SESSION['announce_token']) ?>">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach($coursesDropData as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input type="text" name="title" placeholder="Announcement title" required></div>
            <div class="form-group"><label>Message</label><textarea name="message" rows="4" placeholder="Write your message..." required></textarea></div>
            <button type="submit" name="add_announcement" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Post</button>
        </form>
    </div>

    <div class="section">
        <h3>All Announcements</h3>
        <table>
            <tr><th>Course</th><th>Title</th><th>Message</th><th>Date</th><th>Action</th></tr>
            <?php if(count($announcements) > 0): foreach ($announcements as $a): $anid = (int)$a['id']; ?>
            <tr>
                <td><?= htmlspecialchars($a['course']) ?></td>
                <td><?= htmlspecialchars($a['title']) ?></td>
                <td><?= htmlspecialchars($a['message']) ?></td>
                <td><?= htmlspecialchars($a['created_at']) ?></td>
                <td>
                    <button type="button" class="btn btn-edit btn-sm" onclick="toggleInline('announce-edit-<?= $anid ?>')"><i class="fas fa-pen"></i> Edit</button>
                    <a class="btn btn-danger btn-sm" href="?delete_announcement=<?= $anid ?>&announce_token=<?= urlencode($_SESSION['announce_token']) ?>" onclick="return confirm('Delete?')">
                        <i class="fas fa-trash"></i> Delete
                    </a>
                </td>
            </tr>
            <tr class="edit-row" id="announce-edit-<?= $anid ?>" style="display:none;">
                <td colspan="5">
                    <form method="POST">
                        <input type="hidden" name="announce_token" value="<?= htmlspecialchars($_SESSION['announce_token']) ?>">
                        <input type="hidden" name="announcement_id" value="<?= $anid ?>">
                        <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= htmlspecialchars($a['title']) ?>" required></div>
                        <div class="form-group"><label>Message</label><textarea name="message" rows="3" required><?= htmlspecialchars($a['message']) ?></textarea></div>
                        <div class="format-hint"><strong>Approval required</strong>Announcement edits are reviewed by the Super Administrator before publishing.</div>
                        <button type="submit" name="edit_announcement" class="btn btn-primary btn-sm"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No announcements yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== CALENDAR & LIVE SESSIONS (items #8, #9) ==== -->
<div id="sec-calendar" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-calendar-days"></i> Calendar &amp; Live Sessions</p>

    <div class="section">
        <h3>Schedule a Session</h3>
        <form method="POST">
            <input type="hidden" name="session_token_csrf" value="<?= htmlspecialchars($_SESSION['session_token_csrf']) ?>">
            <div class="grid-2">
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">-- Select Course --</option>
                        <?php foreach($coursesDropData as $c): ?>
                            <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Session Title</label><input type="text" name="title" placeholder="e.g. Week 4 Supervision Clinic" required></div>
            </div>
            <div class="form-group"><label>Topic</label><input type="text" name="topic" placeholder="Topic covered"></div>
            <div class="grid-3">
                <div class="form-group"><label>Date</label><input type="date" name="schedule_date" required></div>
                <div class="form-group"><label>Start Time</label><input type="time" name="schedule_time" required></div>
                <div class="form-group"><label>End Time</label><input type="time" name="end_time"></div>
            </div>
            <div class="grid-2">
                <div class="form-group">
                    <label>Mode</label>
                    <select name="session_mode">
                        <option value="online">Online</option>
                        <option value="physical">Physical</option>
                    </select>
                </div>
                <div class="form-group"><label>Meeting Link (if online)</label><input type="url" name="meeting_link" placeholder="https://..."></div>
            </div>
            <div class="form-group"><label>Description / Materials</label><textarea name="description" rows="2"></textarea></div>
            <button type="submit" name="create_session" class="btn btn-primary"><i class="fas fa-calendar-plus"></i> Schedule Session</button>
        </form>
    </div>

    <div class="section">
        <h3>Upcoming &amp; Past Sessions</h3>
        <table>
            <tr><th>Title</th><th>Course</th><th>When</th><th>Mode</th><th>Status</th><th>Action</th></tr>
            <?php if (count($mySessions) > 0): foreach ($mySessions as $sess): ?>
            <tr>
                <td><?= htmlspecialchars($sess['title']) ?></td>
                <td><?= htmlspecialchars($sess['course_title'] ?? '') ?></td>
                <td><?= htmlspecialchars($sess['schedule_time']) ?></td>
                <td><?= htmlspecialchars(ucfirst($sess['session_mode'] ?? 'online')) ?><?php if (!empty($sess['meeting_link'])): ?> <a href="<?= htmlspecialchars($sess['meeting_link']) ?>" target="_blank"><i class="fas fa-link"></i></a><?php endif; ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($sess['status'] ?? 'upcoming') ?>"><?= ucfirst(htmlspecialchars($sess['status'] ?? 'upcoming')) ?></span></td>
                <td><?php if (($sess['status'] ?? 'upcoming') === 'upcoming'): ?><a class="btn btn-danger btn-sm" href="?cancel_session=<?= (int)$sess['id'] ?>" onclick="return confirm('Cancel this session?')"><i class="fas fa-ban"></i> Cancel</a><?php endif; ?></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="6" style="text-align:center;color:#64748b;">No sessions scheduled yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== COMMUNICATION: MESSAGES + FORUMS (items #10, #11) ==== -->
<div id="sec-communication" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-comments"></i> Communication</p>

    <div class="import-tabs">
        <button type="button" class="tab-btn active" onclick="showCommTab('messages', this)"><i class="fas fa-envelope"></i> Messages</button>
        <button type="button" class="tab-btn" onclick="showCommTab('forums', this)"><i class="fas fa-people-group"></i> Discussion Forums</button>
    </div>

    <div id="comm-messages" class="qtab-panel">
        <div class="section">
            <h3>Send a Message</h3>
            <form method="POST" id="messageForm">
                <input type="hidden" name="message_token" value="<?= htmlspecialchars($_SESSION['message_token']) ?>">
                <div class="grid-2">
                    <div class="form-group">
                        <label>Send To</label>
                        <select name="target_type" id="msgTargetType" onchange="toggleMsgTarget()">
                            <option value="student">Individual Student</option>
                            <option value="course">Entire Course (broadcast)</option>
                        </select>
                    </div>
                    <div class="form-group" id="msgStudentWrap">
                        <label>Student</label>
                        <select name="student_user_id" id="msgStudentSelect">
                            <option value="">-- Select Student --</option>
                            <?php foreach ($students as $s): ?>
                                <option value="<?= (int)$s['user_id'] ?>"><?= htmlspecialchars($s['full_name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group" id="msgCourseWrap" style="display:none;">
                        <label>Course</label>
                        <select name="course_id">
                            <option value="">-- Select Course --</option>
                            <?php foreach($coursesDropData as $c): ?>
                                <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="form-group"><label>Subject</label><input type="text" name="subject" placeholder="Subject (optional)"></div>
                <div class="form-group"><label>Message</label><textarea id="msgBody" name="message" rows="4" required></textarea></div>
                <button type="submit" name="send_message" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Send</button>
            </form>
        </div>
        <div class="section">
            <h3>Message History</h3>
            <?php if (count($myMessages) > 0): foreach ($myMessages as $m): ?>
                <div class="msg-bubble">
                    <strong><?= (int)$m['sender_id'] === $teacher_id ? 'To: ' : 'From: ' ?><?= htmlspecialchars($m['other_party'] ?? 'User') ?></strong>
                    <?php if (!empty($m['subject'])): ?><div style="font-weight:600;margin-top:4px;"><?= htmlspecialchars($m['subject']) ?></div><?php endif; ?>
                    <div><?= nl2br(htmlspecialchars($m['message'] ?? '')) ?></div>
                    <div class="meta"><?= htmlspecialchars($m['sent_at']) ?></div>
                </div>
            <?php endforeach; else: ?>
                <p style="color:#64748b;">No messages yet.</p>
            <?php endif; ?>
        </div>
    </div>

    <div id="comm-forums" class="qtab-panel" style="display:none;">
        <div class="section">
            <h3>Course Discussion Boards</h3>
            <?php if (count($forumTopics) > 0): foreach ($forumTopics as $t): ?>
                <div class="msg-bubble">
                    <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                        <strong><?= htmlspecialchars($t['title']) ?></strong>
                        <span>
                            <span class="badge badge-<?= $t['status']==='open' ? 'active' : 'inactive' ?>"><?= ucfirst(htmlspecialchars($t['status'])) ?></span>
                            <a href="?forum_toggle_status=<?= (int)$t['id'] ?>" class="btn btn-outline btn-sm"><i class="fas fa-lock"></i> <?= $t['status']==='open' ? 'Lock' : 'Reopen' ?></a>
                        </span>
                    </div>
                    <div style="font-size:12px;color:#64748b;margin:4px 0;"><?= htmlspecialchars($t['course_title']) ?> · by <?= htmlspecialchars($t['author'] ?? 'Student') ?> · <?= (int)$t['reply_count'] ?> repl(ies)</div>
                    <div><?= nl2br(htmlspecialchars($t['message'])) ?></div>
                    <form method="POST" style="margin-top:10px;display:flex;gap:8px;">
                        <input type="hidden" name="forum_token" value="<?= htmlspecialchars($_SESSION['forum_token']) ?>">
                        <input type="hidden" name="topic_id" value="<?= (int)$t['id'] ?>">
                        <input type="text" name="reply" placeholder="Write a reply..." style="flex:1;padding:8px 10px;border:1px solid #cbd5e1;border-radius:8px;">
                        <button type="submit" name="forum_reply" class="btn btn-primary btn-sm"><i class="fas fa-reply"></i></button>
                    </form>
                </div>
            <?php endforeach; else: ?>
                <p style="color:#64748b;">No discussion topics yet.</p>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- ==== MENTORSHIP (item #12) ==== -->
<div id="sec-mentorship" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-people-arrows"></i> Mentorship <span class="sub-count"><?= count($myMentees) ?> mentee(s)</span></p>

    <div class="section">
        <h3>Add Mentee</h3>
        <form method="POST">
            <input type="hidden" name="mentorship_token" value="<?= htmlspecialchars($_SESSION['mentorship_token']) ?>">
            <div class="grid-2">
                <div class="form-group">
                    <label>Student</label>
                    <select name="mentee_user_id" required>
                        <option value="">-- Select Student --</option>
                        <?php foreach ($students as $s): ?>
                            <option value="<?= (int)$s['user_id'] ?>"><?= htmlspecialchars($s['full_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Focus Area</label><input type="text" name="focus_area" placeholder="e.g. Private Practice Development"></div>
            </div>
            <button type="submit" name="add_mentee" class="btn btn-primary"><i class="fas fa-user-plus"></i> Add Mentee</button>
        </form>
    </div>

    <div class="section">
        <h3>My Mentees</h3>
        <table>
            <tr><th>Mentee</th><th>Focus Area</th><th>Status</th><th>Matched</th><th>Log a Session</th></tr>
            <?php if (count($myMentees) > 0): foreach ($myMentees as $m): ?>
            <tr>
                <td><?= htmlspecialchars($m['mentee_name']) ?></td>
                <td><?= htmlspecialchars($m['focus_area'] ?? '—') ?></td>
                <td><span class="badge badge-<?= $m['status']==='active' ? 'active' : 'inactive' ?>"><?= ucfirst(htmlspecialchars($m['status'])) ?></span></td>
                <td><?= htmlspecialchars($m['matched_at']) ?></td>
                <td>
                    <form method="POST" style="display:flex;gap:6px;flex-wrap:wrap;">
                        <input type="hidden" name="mentorship_token" value="<?= htmlspecialchars($_SESSION['mentorship_token']) ?>">
                        <input type="hidden" name="match_id" value="<?= (int)$m['id'] ?>">
                        <input type="text" name="notes" placeholder="Session notes" style="flex:1;min-width:140px;padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:12px;">
                        <input type="date" name="next_session_date" style="padding:6px 8px;border:1px solid #cbd5e1;border-radius:6px;font-size:12px;">
                        <button type="submit" name="log_mentorship_session" class="btn btn-primary btn-sm">Log</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No mentees yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== SUPERVISION (item #13) ==== -->
<div id="sec-supervision" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-user-doctor"></i> Supervision Logbooks</p>
    <div class="format-hint"><strong>Note</strong>Logbook entries are created by supervisees (students) from their portal; here you review, sign off, or request changes. Client case references must remain anonymised.</div>
    <div class="section">
        <table>
            <tr><th>Student</th><th>Date</th><th>Hours</th><th>Activity</th><th>Competencies</th><th>Sign-off</th><th>Action</th></tr>
            <?php if (count($supervisionLogs) > 0): foreach ($supervisionLogs as $log): ?>
            <tr>
                <td><?= htmlspecialchars($log['student_name']) ?></td>
                <td><?= htmlspecialchars($log['session_date']) ?></td>
                <td><?= htmlspecialchars((string)$log['hours']) ?></td>
                <td><?= htmlspecialchars(mb_strimwidth($log['activity_description'] ?? '', 0, 80, '…')) ?></td>
                <td><?= htmlspecialchars(mb_strimwidth($log['competencies_covered'] ?? '', 0, 60, '…')) ?></td>
                <td><span class="badge badge-<?= !empty($log['supervisor_signoff']) ? 'approved' : 'pending' ?>"><?= !empty($log['supervisor_signoff']) ? 'Signed Off' : 'Pending' ?></span></td>
                <td>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="supervision_token" value="<?= htmlspecialchars($_SESSION['supervision_token']) ?>">
                        <input type="hidden" name="log_id" value="<?= (int)$log['id'] ?>">
                        <input type="hidden" name="signoff_action" value="approve">
                        <button type="submit" name="supervision_signoff" class="btn btn-success btn-sm"><i class="fas fa-check"></i></button>
                    </form>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="supervision_token" value="<?= htmlspecialchars($_SESSION['supervision_token']) ?>">
                        <input type="hidden" name="log_id" value="<?= (int)$log['id'] ?>">
                        <input type="hidden" name="signoff_action" value="revoke">
                        <button type="submit" name="supervision_signoff" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i></button>
                    </form>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="7" style="text-align:center;color:#64748b;">No supervision logbook entries yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== COMPETENCIES (item #15) ==== -->
<div id="sec-competencies" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-star-half-stroke"></i> Competency Tracking</p>

    <div class="section">
        <h3>Rate a Student</h3>
        <form method="POST">
            <input type="hidden" name="competency_token" value="<?= htmlspecialchars($_SESSION['competency_token']) ?>">
            <div class="grid-3">
                <div class="form-group">
                    <label>Student</label>
                    <select name="student_user_id" required>
                        <option value="">-- Select Student --</option>
                        <?php foreach ($students as $s): ?>
                            <option value="<?= (int)$s['user_id'] ?>"><?= htmlspecialchars($s['full_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Competency</label>
                    <select name="competency_id" required>
                        <option value="">-- Select --</option>
                        <?php foreach ($competencyList as $comp): ?>
                            <option value="<?= (int)$comp['id'] ?>"><?= htmlspecialchars($comp['name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Level</label>
                    <select name="proficiency_level">
                        <option value="novice">Novice</option>
                        <option value="developing">Developing</option>
                        <option value="competent">Competent</option>
                        <option value="proficient">Proficient</option>
                        <option value="expert">Expert</option>
                    </select>
                </div>
            </div>
            <?php if (count($competencyList) === 0): ?>
                <div class="format-hint"><strong>No competencies defined yet</strong>Ask your Super Administrator to add competencies (or run stp_trainer_enhancements.sql), then they'll appear here for rating.</div>
            <?php endif; ?>
            <button type="submit" name="rate_competency" class="btn btn-primary"><i class="fas fa-star"></i> Save Rating</button>
        </form>
    </div>

    <div class="section">
        <h3>Student Competency Ratings</h3>
        <table>
            <tr><th>Student</th><th>Competency</th><th>Category</th><th>Level</th><th>Assessed</th></tr>
            <?php if (count($studentCompetencies) > 0): foreach ($studentCompetencies as $sc): ?>
            <tr>
                <td><?= htmlspecialchars($sc['student_name']) ?></td>
                <td><?= htmlspecialchars($sc['competency_name']) ?></td>
                <td><?= htmlspecialchars($sc['category'] ?? '—') ?></td>
                <td><span class="badge badge-approved"><?= ucfirst(htmlspecialchars($sc['proficiency_level'])) ?></span></td>
                <td><?= htmlspecialchars($sc['assessed_at'] ?? '') ?></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No competency ratings yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== CPD / CME (item #16) ==== -->
<div id="sec-cpd" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-award"></i> CPD / CME <span class="sub-count"><?= $myCpdTotalPoints ?> verified points</span></p>

    <div class="section">
        <h3>Submit CPD Activity</h3>
        <form method="POST">
            <input type="hidden" name="cpd_token" value="<?= htmlspecialchars($_SESSION['cpd_token']) ?>">
            <div class="grid-2">
                <div class="form-group"><label>Activity Title</label><input type="text" name="activity_title" required></div>
                <div class="form-group">
                    <label>Type</label>
                    <select name="activity_type">
                        <option value="course">Course</option>
                        <option value="workshop">Workshop</option>
                        <option value="conference">Conference</option>
                        <option value="supervision">Supervision</option>
                        <option value="publication">Publication</option>
                        <option value="other">Other</option>
                    </select>
                </div>
            </div>
            <div class="grid-2">
                <div class="form-group"><label>Points Claimed</label><input type="number" step="0.5" name="points" required></div>
                <div class="form-group"><label>Date</label><input type="date" name="date_earned" value="<?= date('Y-m-d') ?>"></div>
            </div>
            <div class="format-hint"><strong>Note</strong>Official point validation remains controlled by the Super Administrator.</div>
            <button type="submit" name="add_cpd_activity" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Submit</button>
        </form>
    </div>

    <div class="section">
        <h3>My CPD Activities</h3>
        <table>
            <tr><th>Activity</th><th>Type</th><th>Points</th><th>Date</th><th>Status</th></tr>
            <?php if (count($myCpdActivities) > 0): foreach ($myCpdActivities as $c): ?>
            <tr>
                <td><?= htmlspecialchars($c['activity_title']) ?></td>
                <td><?= ucfirst(htmlspecialchars($c['activity_type'])) ?></td>
                <td><?= htmlspecialchars((string)$c['points']) ?></td>
                <td><?= htmlspecialchars($c['date_earned']) ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($c['verification_status']) ?>"><?= ucfirst(htmlspecialchars($c['verification_status'])) ?></span></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No CPD activities submitted yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== CERTIFICATES (item #17) ==== -->
<div id="sec-certificates" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-certificate"></i> Certificate Eligibility</p>
    <div class="format-hint"><strong>Trainer role</strong>You confirm that a student completed the academic/training requirements. The Super Administrator handles official certificate issuance.</div>
    <div class="section">
        <table>
            <tr><th>Student</th><th>Course</th><th>Progress</th><th>Enrollment Status</th><th>Request Status</th><th>Action</th></tr>
            <?php if (count($eligibleForCertificate) > 0): foreach ($eligibleForCertificate as $el): ?>
            <tr>
                <td><?= htmlspecialchars($el['full_name']) ?></td>
                <td><?= htmlspecialchars($el['course_title']) ?></td>
                <td><?= (int)($el['progress'] ?? 0) ?>%</td>
                <td><span class="badge badge-approved"><?= ucfirst(htmlspecialchars($el['status'])) ?></span></td>
                <td><?php if ($el['request_status']): ?><span class="badge badge-<?= htmlspecialchars($el['request_status']) ?>"><?= ucfirst(htmlspecialchars($el['request_status'])) ?></span><?php else: ?><span style="color:#94a3b8;font-size:12px;">Not requested</span><?php endif; ?></td>
                <td>
                    <?php if (!$el['request_status'] || $el['request_status'] === 'rejected'): ?>
                    <form method="POST">
                        <input type="hidden" name="certificate_token" value="<?= htmlspecialchars($_SESSION['certificate_token']) ?>">
                        <input type="hidden" name="student_user_id" value="<?= (int)$el['user_id'] ?>">
                        <input type="hidden" name="course_id" value="<?= (int)$el['course_id'] ?>">
                        <button type="submit" name="confirm_certificate_eligibility" class="btn btn-primary btn-sm"><i class="fas fa-check"></i> Confirm Completion</button>
                    </form>
                    <?php else: ?>
                    <span style="color:#94a3b8;font-size:12px;">Awaiting/Issued</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="6" style="text-align:center;color:#64748b;">No students have reached completion status yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== AVAILABILITY & CONSULTATION BOOKINGS (items #34, #35) ==== -->
<div id="sec-availability" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-calendar-check"></i> Availability &amp; Bookings</p>

    <div class="section">
        <h3>Weekly Availability</h3>
        <form method="POST">
            <input type="hidden" name="availability_token" value="<?= htmlspecialchars($_SESSION['availability_token']) ?>">
            <?php
            $days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
            $existing = [];
            foreach ($myAvailability as $av) { $existing[$av['day_of_week']] = $av; }
            foreach ($days as $day):
                $ex = $existing[$day] ?? null;
            ?>
            <div class="avail-row">
                <label><input type="checkbox" onclick="this.nextElementSibling.nextElementSibling.querySelectorAll('input').forEach(i=>i.disabled=!this.checked)" <?= $ex ? 'checked' : '' ?>> <?= $day ?></label>
                <input type="hidden" name="day_of_week[]" value="<?= $day ?>">
                <div style="display:flex;gap:8px;">
                    <input type="time" name="start_time[]" value="<?= $ex ? htmlspecialchars($ex['start_time']) : '' ?>" <?= $ex ? '' : 'disabled' ?>>
                    <input type="time" name="end_time[]" value="<?= $ex ? htmlspecialchars($ex['end_time']) : '' ?>" <?= $ex ? '' : 'disabled' ?>>
                </div>
            </div>
            <?php endforeach; ?>
            <button type="submit" name="save_availability" class="btn btn-primary" style="margin-top:10px;"><i class="fas fa-save"></i> Save Availability</button>
        </form>
    </div>

    <div class="section">
        <h3>Consultation Requests</h3>
        <table>
            <tr><th>Student</th><th>Date</th><th>Purpose</th><th>Status</th><th>Action</th></tr>
            <?php if (count($myConsultations) > 0): foreach ($myConsultations as $co): ?>
            <tr>
                <td><?= htmlspecialchars($co['student_name']) ?></td>
                <td><?= htmlspecialchars(($co['requested_date'] ?? '') . ' ' . ($co['requested_time'] ?? '')) ?></td>
                <td><?= htmlspecialchars($co['purpose'] ?? '') ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($co['status']) ?>"><?= ucfirst(htmlspecialchars($co['status'])) ?></span></td>
                <td>
                    <?php if ($co['status'] === 'pending'): ?>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="consultation_token" value="<?= htmlspecialchars($_SESSION['consultation_token']) ?>">
                        <input type="hidden" name="consultation_id" value="<?= (int)$co['id'] ?>">
                        <button type="submit" name="consultation_action" value="1" class="btn btn-success btn-sm" onclick="this.form.action.value='accept'">Accept</button>
                        <input type="hidden" name="action" value="accept">
                    </form>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="consultation_token" value="<?= htmlspecialchars($_SESSION['consultation_token']) ?>">
                        <input type="hidden" name="consultation_id" value="<?= (int)$co['id'] ?>">
                        <input type="hidden" name="action" value="reject">
                        <button type="submit" name="consultation_action" value="1" class="btn btn-danger btn-sm">Reject</button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No consultation requests yet.</td></tr>
            <?php endif; ?>
        </table>
    </div>
</div>

<!-- ==== APPROVALS / VERSION CONTROL (items #18, #19) ==== -->
<div id="sec-approvals" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-user-shield"></i> Approval &amp; Version Control</p>

    <div class="section" style="margin-bottom:18px;">
        <div class="format-hint">
            <strong><i class="fas fa-info-circle"></i> Governance workflow</strong>
            Trainer-created or trainer-edited content (courses, notes, videos, quizzes, questions, assignments and
            announcements) is submitted as a change request following this pipeline:
            <strong>Draft → Submitted → Under Review → Approved → Published</strong> (or <strong>Rejected → Changes Requested → Trainer Edits → Resubmitted</strong>).
            A Super Administrator must approve it before it is published or updated live.
        </div>
    </div>

    <div class="section">
        <h3>My Change Requests</h3>
        <div style="overflow-x:auto;">
        <table>
            <tr>
                <th>ID</th><th>Type</th><th>Entity</th><th>Status</th><th>Submitted</th><th>Review Comments</th><th>Compare</th>
            </tr>
            <?php if ($pending_changes): foreach ($pending_changes as $change): ?>
            <tr>
                <td>#<?= (int)$change['id'] ?></td>
                <td><?= htmlspecialchars(ucwords(str_replace('_',' ', $change['entity_type'] ?? 'change'))) ?></td>
                <td><?= (int)($change['entity_id'] ?? 0) ?: 'New item' ?></td>
                <td>
                    <span class="badge badge-<?= htmlspecialchars($change['status'] ?? 'pending') ?>">
                        <?= htmlspecialchars(ucfirst($change['status'] ?? 'pending')) ?>
                    </span>
                </td>
                <td><?= htmlspecialchars($change['created_at'] ?? '') ?></td>
                <td><?= htmlspecialchars($change['review_comments'] ?? 'Awaiting Super Administrator review') ?></td>
                <td><button type="button" class="btn btn-outline btn-sm" onclick="toggleInline('diff-<?= (int)$change['id'] ?>')"><i class="fas fa-code-compare"></i></button></td>
            </tr>
            <tr class="edit-row" id="diff-<?= (int)$change['id'] ?>" style="display:none;">
                <td colspan="7">
                    <div class="diff-grid">
                        <div>
                            <strong style="font-size:12px;color:#991b1b;">Before</strong>
                            <div class="diff-col old"><?= htmlspecialchars(json_encode(json_decode($change['old_data'] ?? '{}'), JSON_PRETTY_PRINT)) ?></div>
                        </div>
                        <div>
                            <strong style="font-size:12px;color:#166534;">Proposed</strong>
                            <div class="diff-col new"><?= htmlspecialchars(json_encode(json_decode($change['new_data'] ?? '{}'), JSON_PRETTY_PRINT)) ?></div>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="7" style="text-align:center;color:#64748b;">No change requests submitted yet.</td></tr>
            <?php endif; ?>
        </table>
        </div>
    </div>

    <div class="section">
        <h3>Content Version History</h3>
        <div style="overflow-x:auto;">
        <table>
            <tr><th>Version</th><th>Content Type</th><th>Content ID</th><th>Status</th><th>Request</th><th>Created</th></tr>
            <?php if ($version_history): foreach ($version_history as $version): ?>
            <tr>
                <td>v<?= (int)$version['version_number'] ?></td>
                <td><?= htmlspecialchars(ucwords(str_replace('_',' ', $version['content_type'] ?? ''))) ?></td>
                <td><?= (int)$version['content_id'] ?></td>
                <td><span class="badge badge-<?= htmlspecialchars($version['status'] ?? 'draft') ?>"><?= htmlspecialchars(ucfirst(str_replace('_',' ', $version['status'] ?? 'draft'))) ?></span></td>
                <td>#<?= (int)($version['change_request_id'] ?? 0) ?></td>
                <td><?= htmlspecialchars($version['created_at'] ?? '') ?></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="6" style="text-align:center;color:#64748b;">No version history yet.</td></tr>
            <?php endif; ?>
        </table>
        </div>
    </div>

    <!-- Trainer audit trail (item #33) -->
    <div class="section">
        <h3>My Audit Trail</h3>
        <div style="overflow-x:auto;">
        <table>
            <tr><th>Action</th><th>Description</th><th>Entity</th><th>IP</th><th>When</th></tr>
            <?php if ($myAuditTrail): foreach ($myAuditTrail as $log): ?>
            <tr>
                <td><?= htmlspecialchars(ucwords(str_replace('_',' ', $log['action_type'] ?? ''))) ?></td>
                <td><?= htmlspecialchars($log['description'] ?? '') ?></td>
                <td><?= htmlspecialchars(($log['entity_type'] ?? '') . ($log['entity_id'] ? ' #'.$log['entity_id'] : '')) ?></td>
                <td><?= htmlspecialchars($log['ip_address'] ?? '') ?></td>
                <td><?= htmlspecialchars($log['created_at'] ?? '') ?></td>
            </tr>
            <?php endforeach; else: ?>
            <tr><td colspan="5" style="text-align:center;color:#64748b;">No audit trail entries yet.</td></tr>
            <?php endif; ?>
        </table>
        </div>
    </div>
</div>

<!-- ==== NOTIFICATIONS (item #26) ==== -->
<div id="sec-notifications" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-bell"></i> Notifications <span class="sub-count"><?= $unreadNotifications ?> unread</span></p>
    <div class="section">
        <?php if (count($myNotifications) > 0): ?>
        <form method="POST" style="margin-bottom:14px;">
            <input type="hidden" name="notification_token" value="<?= htmlspecialchars($_SESSION['notification_token']) ?>">
            <button type="submit" name="mark_all_notifications_read" class="btn btn-outline btn-sm"><i class="fas fa-check-double"></i> Mark all as read</button>
        </form>
        <ul class="notif-list">
            <?php foreach ($myNotifications as $n): ?>
            <li class="<?= empty($n['is_read']) ? 'unread' : '' ?>">
                <i class="fas fa-circle-info"></i>
                <div style="flex:1;">
                    <div><?= htmlspecialchars($n['message']) ?></div>
                    <div style="font-size:11px;color:#94a3b8;margin-top:4px;"><?= htmlspecialchars($n['created_at']) ?></div>
                </div>
                <?php if (empty($n['is_read'])): ?>
                <form method="POST">
                    <input type="hidden" name="notification_token" value="<?= htmlspecialchars($_SESSION['notification_token']) ?>">
                    <input type="hidden" name="notification_id" value="<?= (int)$n['id'] ?>">
                    <button type="submit" name="mark_notification_read" class="btn btn-outline btn-sm">Mark read</button>
                </form>
                <?php endif; ?>
            </li>
            <?php endforeach; ?>
        </ul>
        <?php else: ?>
        <p style="color:#64748b;">No notifications yet.</p>
        <?php endif; ?>
    </div>
</div>

<!-- ==== INSTRUCTORS / CO-TRAINERS ==== -->
<div id="sec-instructors" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-chalkboard-teacher"></i> Co-Trainers</p>
    <div class="section" style="margin-bottom:18px;">
        <p style="color:#64748b;font-size:13px;">Other Trainers assigned alongside you on the courses you teach. Coordinate to avoid duplicate content and align on shared sessions.</p>
    </div>

    <div class="grid-2">
    <?php if ($instructors_count > 0): ?>
        <?php foreach ($instructors as $ins): ?>
        <div class="course-card" style="border-top-color:#7c3aed;">
            <h3><i class="fas fa-chalkboard-teacher" style="color:#7c3aed;margin-right:6px;"></i><?= htmlspecialchars($ins['full_name'] ?? 'Unknown') ?></h3>
            <p><i class="fas fa-envelope" style="width:16px;color:#94a3b8;"></i> <?= htmlspecialchars($ins['email'] ?? '') ?></p>
            <?php if (!empty($ins['employee_no'])): ?>
                <p><i class="fas fa-id-badge" style="width:16px;color:#94a3b8;"></i> <?= htmlspecialchars($ins['employee_no']) ?></p>
            <?php endif; ?>
            <div class="meta">
                <?php if (!empty($ins['specialization'])): ?>
                    <span><i class="fas fa-graduation-cap"></i> <?= htmlspecialchars($ins['specialization']) ?></span>
                <?php endif; ?>
                <?php if (!empty($ins['qualification'])): ?>
                    <span><i class="fas fa-award"></i> <?= htmlspecialchars($ins['qualification']) ?></span>
                <?php endif; ?>
                <span><i class="fas fa-briefcase"></i> <?= (int)($ins['experience_years'] ?? 0) ?> yrs experience</span>
            </div>
            <div class="actions" style="border-top:1px solid #e2e8f0;">
                <span class="badge badge-<?= strtolower(htmlspecialchars($ins['teacher_status'] ?? 'active')) ?>">
                    <?= ucfirst(htmlspecialchars($ins['teacher_status'] ?? 'Active')) ?>
                </span>
                <span style="font-size:12px;color:#64748b;display:flex;align-items:center;gap:5px;">
                    <i class="fas fa-book" style="color:var(--brand-secondary);"></i>
                    Shared: <?= htmlspecialchars($ins['shared_courses'] ?? '') ?>
                    (<?= (int)($ins['shared_course_count'] ?? 0) ?>)
                </span>
                <button type="button" class="btn btn-outline btn-sm" onclick="showSection('communication', document.querySelector('.sidebar a[onclick*=communication]'))"><i class="fas fa-message"></i> Coordinate</button>
            </div>
        </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="section"><p style="color:#64748b;">You're not currently sharing any courses with another instructor.</p></div>
    <?php endif; ?>
    </div>
</div>

<!-- ==== PROFILE ==== -->
<div id="sec-profile" class="section-page" style="display:none;">
    <p class="page-title"><i class="fas fa-user"></i> Trainer Profile</p>

    <div class="grid-2">
        <div class="section">
            <h3>Profile Info</h3>
            <p style="margin-bottom:10px;"><strong>Name:</strong> <?= htmlspecialchars($teacherInfo['full_name']) ?></p>
            <p style="margin-bottom:10px;"><strong>Email:</strong> <?= htmlspecialchars($teacherInfo['email']) ?></p>
            <p style="margin-bottom:10px;"><strong>Phone:</strong> <?= htmlspecialchars($teacherInfo['phone'] ?? 'N/A') ?></p>
            <p style="margin-bottom:10px;"><strong>Employee No:</strong> <?= htmlspecialchars($teacherInfo['employee_no'] ?? 'N/A') ?></p>
            <p style="margin-bottom:10px;"><strong>Licence/Registration No:</strong> <?= htmlspecialchars($teacherInfo['license_number'] ?? 'N/A') ?></p>
            <p style="margin-bottom:10px;"><strong>Qualification:</strong> <?= htmlspecialchars($teacherInfo['qualification'] ?? 'N/A') ?></p>
            <p style="margin-bottom:10px;"><strong>Qualification Level:</strong> <?= htmlspecialchars($teacherInfo['qualification_level'] ?? 'N/A') ?></p>
            <p style="margin-bottom:10px;"><strong>Verification:</strong> <span class="badge badge-<?= htmlspecialchars($teacherInfo['verification_status'] ?? 'unverified') ?>"><?= htmlspecialchars(ucfirst($teacherInfo['verification_status'] ?? 'unverified')) ?></span></p>
            <p style="margin-bottom:10px;"><strong>Experience:</strong> <?= $teacherInfo['experience_years'] ?? 0 ?> years</p>
            <p><strong>KRA PIN:</strong> <?= htmlspecialchars($teacherInfo['kra_pin'] ?? 'N/A') ?></p>
        </div>

        <div class="section">
            <h3>Update Profile</h3>
            <form method="POST">
                <input type="hidden" name="profile_token" value="<?= htmlspecialchars($_SESSION['profile_token']) ?>">
                <div class="form-group"><label>Phone Number</label><input type="text" name="phone" value="<?= htmlspecialchars($teacherInfo['phone'] ?? '') ?>" placeholder="e.g. 07XXXXXXXX"></div>
                <div class="form-group"><label>Professional Licence / Registration No.</label><input type="text" name="license_number" value="<?= htmlspecialchars($teacherInfo['license_number'] ?? '') ?>" placeholder="Where applicable"></div>
                <div class="form-group"><label>Specialization</label><input type="text" name="specialization" value="<?= htmlspecialchars($teacherInfo['specialization'] ?? '') ?>" placeholder="e.g. Clinical Psychology"></div>
                <div class="form-group"><label>Qualification</label><input type="text" name="qualification" value="<?= htmlspecialchars($teacherInfo['qualification'] ?? '') ?>" placeholder="e.g. M.Sc"></div>
                <div class="form-group"><label>Academic Qualification Level</label>
                    <select name="qualification_level">
                        <option value="">-- Select --</option>
                        <?php foreach (['Diploma','Degree','Masters','PhD'] as $level): ?>
                            <option value="<?= $level ?>" <?= (($teacherInfo['qualification_level'] ?? '') === $level) ? 'selected' : '' ?>><?= $level ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Experience (years)</label><input type="number" name="experience_years" value="<?= $teacherInfo['experience_years'] ?? 0 ?>" min="0" max="60"></div>
                <div class="format-hint"><strong>Approval required</strong>Your profile changes are saved as a pending request and only become active after Super Administrator verification.</div>
                <button type="submit" name="update_profile" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Submit for Approval</button>
            </form>
        </div>
    </div>

    <div class="cards" style="margin-top:0;">
        <div class="card"><div class="icon blue"><i class="fas fa-book"></i></div><h2><?= $total_courses ?></h2><p>Courses</p></div>
        <div class="card"><div class="icon green"><i class="fas fa-users"></i></div><h2><?= $total_students ?></h2><p>Students</p></div>
        <div class="card"><div class="icon red"><i class="fas fa-video"></i></div><h2><?= $total_videos ?></h2><p>Videos</p></div>
        <div class="card"><div class="icon yellow"><i class="fas fa-file-pdf"></i></div><h2><?= $total_notes ?></h2><p>Notes</p></div>
        <div class="card"><div class="icon purple"><i class="fas fa-question-circle"></i></div><h2><?= $total_quizzes ?></h2><p>Quizzes</p></div>
        <div class="card"><div class="icon orange"><i class="fas fa-coins"></i></div><h2>KES <?= number_format($revenue) ?></h2><p>Revenue</p></div>
    </div>
</div>

<div class="brand-footer">
    <div><strong><?= htmlspecialchars($branding['brand_name']) ?></strong> Trainer Portal — Cognitive Behavioural Therapy Kenya, <?= date('Y') ?></div>
    <div class="contact-line">
        <span><i class="fas fa-map-marker-alt"></i> Muthangari Road 37, Lavington, Nairobi</span>
        <span><i class="fas fa-phone"></i> +254 739 935 333</span>
        <span><i class="fas fa-envelope"></i> info@cbtkenya.org</span>
        <span><a href="https://www.cbtkenya.org/" target="_blank" rel="noopener" style="color:var(--brand-secondary);text-decoration:none;font-weight:600;">cbtkenya.org <i class="fas fa-external-link-alt" style="font-size:10px;"></i></a></span>
    </div>
</div>

</div>

<script>
function showSection(id, link) {
    document.querySelectorAll('.section-page').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.sidebar ul li a').forEach(el => el.classList.remove('active'));
    var target = document.getElementById('sec-' + id);
    if (target) target.style.display = 'block';
    if (link) link.classList.add('active');
    closeSidebar();
    window.scrollTo(0,0);
    try { history.replaceState(null, '', '#' + id); } catch(e) {}
}

function showQTab(tab, btn) {
    document.getElementById('qtab-single').style.display = (tab === 'single') ? 'block' : 'none';
    document.getElementById('qtab-bulk').style.display   = (tab === 'bulk')   ? 'block' : 'none';
    document.querySelectorAll('#sec-quiz .tab-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
}

function showCommTab(tab, btn) {
    document.getElementById('comm-messages').style.display = (tab === 'messages') ? 'block' : 'none';
    document.getElementById('comm-forums').style.display   = (tab === 'forums')   ? 'block' : 'none';
    document.querySelectorAll('#sec-communication .tab-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
}

function toggleMsgTarget() {
    var isCourse = document.getElementById('msgTargetType').value === 'course';
    document.getElementById('msgStudentWrap').style.display = isCourse ? 'none' : 'block';
    document.getElementById('msgCourseWrap').style.display = isCourse ? 'block' : 'none';
    document.getElementById('msgStudentSelect').required = !isCourse;
}

function prefillMessage(userId, name) {
    showSection('communication', document.querySelector('.sidebar a[onclick*=communication]'));
    setTimeout(function() {
        document.getElementById('msgTargetType').value = 'student';
        toggleMsgTarget();
        document.getElementById('msgStudentSelect').value = userId;
        document.getElementById('msgBody').focus();
    }, 100);
}

function filterQuestionBank() {
    var val = document.getElementById('topicFilter').value;
    document.querySelectorAll('#questionBankTable tr[data-topic]').forEach(function(row) {
        row.style.display = (!val || row.getAttribute('data-topic') === val) ? '' : 'none';
    });
}

function filterAttendanceStudents() {
}

function toggleInline(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var isTableRow = el.tagName === 'TR';
    var visible = el.style.display !== 'none' && el.style.display !== '';
    el.style.display = visible ? 'none' : (isTableRow ? 'table-row' : 'block');
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('open');
}
function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('open');
}

(function () {
    const SESSION_LIFETIME_MS = <?= $session_lifetime * 1000 ?>;
    setTimeout(function () {
        window.location.href = 'index.php?expired=1';
    }, SESSION_LIFETIME_MS);
})();

window.onload = function() {
    var initial = (window.location.hash || '#dashboard').replace('#','');
    var link = document.querySelector('.sidebar a[onclick*="' + initial + '"]') || document.querySelector('.sidebar a');
    showSection(document.getElementById('sec-' + initial) ? initial : 'dashboard', link);
};
</script>

</body>
</html>