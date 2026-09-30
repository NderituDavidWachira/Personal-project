<?php
session_start();
include "db.php";

/* ==========================================================
   CBT-KENYA STP ADMIN PANEL
   Branding note: colours below are a placeholder palette
   (teal/deep-blue, matching a counselling/health brand feel)
   until the official CBT-Kenya brand kit (exact hex codes,
   logo file, typography) is supplied. Super Admins can
   override them live from Settings > Branding without
   touching code (see $branding block + stp_settings table).
   ========================================================== */

/* ======
   CSRF
   ====== */
if (empty($_SESSION['csrf_token'])) { $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); }

function validateCsrf(): void {
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403); die("Invalid CSRF token.");
    }
}

/* ======
   SESSION / ROLE CONTEXT
   Roles: super_admin > admin > teacher > student
   ====== */
$user_id   = $_SESSION['user_id'] ?? 1;
$user_role = strtolower(trim($_SESSION['role'] ?? 'admin'));

$is_super       = ($user_role === 'super_admin');
$is_admin_up    = in_array($user_role, ['admin', 'super_admin'], true);
$is_staff       = in_array($user_role, ['admin', 'super_admin', 'teacher'], true);

function requireSuper(bool $isSuper): void {
    if (!$isSuper) { http_response_code(403); die("This action requires Super Administrator authorization."); }
}

function logActivity(PDO $pdo, int $uid, string $message): void {
    try {
        $pdo->prepare("INSERT INTO activities(user_id,message) VALUES(?,?)")->execute([$uid, $message]);
    } catch (Throwable $e) { /* non-fatal */ }
}

/* ======
   SCHEMA BOOTSTRAP (idempotent) — new tables/columns needed
   for the approval workflow, certification, stp_referrals, CPD,
   practice hub, stp_promotions, stp_attendance, stp_invoices and branding.
   ====== */
function ensureSchema(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_course_versions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        course_id INT NOT NULL,
        version_no INT NOT NULL DEFAULT 1,
        payload TEXT NOT NULL,
        submitted_by INT NOT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        reviewed_by INT NULL,
        review_note VARCHAR(255) NULL,
        reviewed_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_certificates (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        course_id INT NOT NULL,
        cert_number VARCHAR(60) NOT NULL UNIQUE,
        issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_user_course (user_id, course_id)
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_referrals (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        code VARCHAR(40) NOT NULL UNIQUE,
        commission_rate DECIMAL(5,2) NOT NULL DEFAULT 5.00,
        status ENUM('active','disabled') NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_referral_uses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        referral_id INT NOT NULL,
        referred_user_id INT NULL,
        referred_name VARCHAR(150) NULL,
        course_id INT NULL,
        amount DECIMAL(12,2) NOT NULL DEFAULT 0,
        commission DECIMAL(12,2) NOT NULL DEFAULT 0,
        status ENUM('pending','paid') NOT NULL DEFAULT 'pending',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_cpd_points (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        activity VARCHAR(150) NOT NULL,
        points INT NOT NULL DEFAULT 0,
        activity_date DATE NOT NULL,
        created_by INT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_practice_resources (
        id INT AUTO_INCREMENT PRIMARY KEY,
        category VARCHAR(80) NOT NULL,
        title VARCHAR(200) NOT NULL,
        description TEXT NULL,
        link VARCHAR(255) NULL,
        file_path VARCHAR(255) NULL,
        status ENUM('published','draft','archived') NOT NULL DEFAULT 'published',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_promotions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        description TEXT NULL,
        image VARCHAR(255) NULL,
        link VARCHAR(255) NULL,
        placement VARCHAR(40) NOT NULL DEFAULT 'homepage',
        start_date DATE NULL,
        end_date DATE NULL,
        status ENUM('active','scheduled','expired','archived') NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_attendance (
        id INT AUTO_INCREMENT PRIMARY KEY,
        course_id INT NOT NULL,
        user_id INT NOT NULL,
        session_date DATE NOT NULL,
        status ENUM('present','absent','excused') NOT NULL DEFAULT 'present',
        marked_by INT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_invoices (
        id INT AUTO_INCREMENT PRIMARY KEY,
        invoice_no VARCHAR(60) NOT NULL UNIQUE,
        user_id INT NULL,
        course_id INT NULL,
        kra_pin VARCHAR(30) NULL,
        amount DECIMAL(12,2) NOT NULL DEFAULT 0,
        tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
        etims_status ENUM('draft','submitted','failed') NOT NULL DEFAULT 'draft',
        etims_ref VARCHAR(80) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS stp_settings (
        setting_key VARCHAR(60) PRIMARY KEY,
        setting_value TEXT NULL
    ) ENGINE=InnoDB");

    // Best-effort column additions on pre-existing tables (ignore errors if already present).
    $alters = [
        "ALTER TABLE users ADD COLUMN license_no VARCHAR(80) NULL",
        "ALTER TABLE users ADD COLUMN qualification_level VARCHAR(40) NULL",
        "ALTER TABLE users ADD COLUMN kra_pin VARCHAR(30) NULL",
        "ALTER TABLE users ADD COLUMN is_alumni TINYINT(1) NOT NULL DEFAULT 0",
        "ALTER TABLE pending_teachers ADD COLUMN license_no VARCHAR(80) NULL",
        "ALTER TABLE pending_teachers ADD COLUMN kra_pin VARCHAR(30) NULL",

        // Self-heal in case any of these tables already existed (e.g. from a
        // partial earlier run) with a different structure than expected —
        // CREATE TABLE IF NOT EXISTS silently skips those, so patch columns in too.
        "ALTER TABLE stp_certificates ADD COLUMN cert_number VARCHAR(60) NOT NULL",
        "ALTER TABLE stp_certificates ADD COLUMN issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "ALTER TABLE stp_certificates ADD UNIQUE KEY cert_number (cert_number)",
        "ALTER TABLE stp_certificates ADD UNIQUE KEY uniq_user_course (user_id, course_id)",

        "ALTER TABLE stp_course_versions ADD COLUMN payload TEXT NOT NULL",
        "ALTER TABLE stp_course_versions ADD COLUMN submitted_by INT NOT NULL",
        "ALTER TABLE stp_course_versions ADD COLUMN status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending'",
        "ALTER TABLE stp_course_versions ADD COLUMN reviewed_by INT NULL",
        "ALTER TABLE stp_course_versions ADD COLUMN review_note VARCHAR(255) NULL",
        "ALTER TABLE stp_course_versions ADD COLUMN reviewed_at DATETIME NULL",

        "ALTER TABLE stp_referrals ADD COLUMN code VARCHAR(40) NOT NULL",
        "ALTER TABLE stp_referrals ADD COLUMN commission_rate DECIMAL(5,2) NOT NULL DEFAULT 5.00",
        "ALTER TABLE stp_referrals ADD COLUMN status ENUM('active','disabled') NOT NULL DEFAULT 'active'",
        "ALTER TABLE stp_referrals ADD UNIQUE KEY code (code)",

        "ALTER TABLE stp_referral_uses ADD COLUMN referred_name VARCHAR(150) NULL",
        "ALTER TABLE stp_referral_uses ADD COLUMN amount DECIMAL(12,2) NOT NULL DEFAULT 0",
        "ALTER TABLE stp_referral_uses ADD COLUMN commission DECIMAL(12,2) NOT NULL DEFAULT 0",
        "ALTER TABLE stp_referral_uses ADD COLUMN status ENUM('pending','paid') NOT NULL DEFAULT 'pending'",

        "ALTER TABLE stp_cpd_points ADD COLUMN activity VARCHAR(150) NOT NULL",
        "ALTER TABLE stp_cpd_points ADD COLUMN points INT NOT NULL DEFAULT 0",
        "ALTER TABLE stp_cpd_points ADD COLUMN activity_date DATE NOT NULL",
        "ALTER TABLE stp_cpd_points ADD COLUMN created_by INT NULL",

        "ALTER TABLE stp_practice_resources ADD COLUMN category VARCHAR(80) NOT NULL",
        "ALTER TABLE stp_practice_resources ADD COLUMN link VARCHAR(255) NULL",
        "ALTER TABLE stp_practice_resources ADD COLUMN file_path VARCHAR(255) NULL",
        "ALTER TABLE stp_practice_resources ADD COLUMN status ENUM('published','draft','archived') NOT NULL DEFAULT 'published'",

        "ALTER TABLE stp_promotions ADD COLUMN image VARCHAR(255) NULL",
        "ALTER TABLE stp_promotions ADD COLUMN link VARCHAR(255) NULL",
        "ALTER TABLE stp_promotions ADD COLUMN placement VARCHAR(40) NOT NULL DEFAULT 'homepage'",
        "ALTER TABLE stp_promotions ADD COLUMN start_date DATE NULL",
        "ALTER TABLE stp_promotions ADD COLUMN end_date DATE NULL",
        "ALTER TABLE stp_promotions ADD COLUMN status ENUM('active','scheduled','expired','archived') NOT NULL DEFAULT 'active'",

        "ALTER TABLE stp_attendance ADD COLUMN session_date DATE NOT NULL",
        "ALTER TABLE stp_attendance ADD COLUMN status ENUM('present','absent','excused') NOT NULL DEFAULT 'present'",
        "ALTER TABLE stp_attendance ADD COLUMN marked_by INT NULL",

        "ALTER TABLE stp_invoices ADD COLUMN invoice_no VARCHAR(60) NOT NULL",
        "ALTER TABLE stp_invoices ADD COLUMN kra_pin VARCHAR(30) NULL",
        "ALTER TABLE stp_invoices ADD COLUMN tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0",
        "ALTER TABLE stp_invoices ADD COLUMN etims_status ENUM('draft','submitted','failed') NOT NULL DEFAULT 'draft'",
        "ALTER TABLE stp_invoices ADD COLUMN etims_ref VARCHAR(80) NULL",
        "ALTER TABLE stp_invoices ADD UNIQUE KEY invoice_no (invoice_no)",
    ];
    foreach ($alters as $sql) {
        try { $pdo->exec($sql); } catch (Throwable $e) { /* column likely already exists */ }
    }
}
ensureSchema($pdo);

/* ======
   TRAINER / STUDENT GOVERNANCE SCHEMA BOOTSTRAP (idempotent)
   These tables are what teacher.php and student.php actually write to
   (change_requests + content_versions for trainer submissions,
   certificate_requests for trainer-confirmed completions, cpd_points
   for trainer/student-submitted CPD activity, and the verification_status
   column on students for professional-profile verification). This is
   the "trainer submits a change -> admin reviews it -> admin
   approves/rejects before anything touches the live tables" pipeline.
   ====== */
function ensureGovernanceSchema(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS change_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        entity_type VARCHAR(40) NOT NULL,
        entity_id INT NULL,
        requested_by INT NOT NULL,
        old_data TEXT NULL,
        new_data TEXT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        review_comments VARCHAR(500) NULL,
        reviewed_by INT NULL,
        reviewed_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS content_versions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        content_type VARCHAR(40) NOT NULL,
        content_id INT NOT NULL DEFAULT 0,
        version_number INT NOT NULL DEFAULT 1,
        data_snapshot TEXT NULL,
        edited_by INT NOT NULL,
        change_request_id INT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'pending_approval',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS certificate_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        course_id INT NOT NULL,
        status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        reviewed_by INT NULL,
        reviewed_at DATETIME NULL,
        requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $pdo->exec("CREATE TABLE IF NOT EXISTS cpd_points (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        activity_title VARCHAR(255) NOT NULL,
        activity_type VARCHAR(60) NOT NULL DEFAULT 'other',
        points DECIMAL(6,2) NOT NULL DEFAULT 0,
        date_earned DATE NOT NULL,
        evidence_path VARCHAR(255) NULL,
        verification_status ENUM('pending','verified','rejected') NOT NULL DEFAULT 'pending',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");

    $alters = [
        "ALTER TABLE students ADD COLUMN verification_status ENUM('unverified','pending','verified','rejected') NOT NULL DEFAULT 'unverified'",
        "ALTER TABLE students ADD COLUMN license_number VARCHAR(100) NULL",
        "ALTER TABLE students ADD COLUMN qualification_level VARCHAR(40) NULL",
        "ALTER TABLE notifications ADD COLUMN is_read TINYINT(1) NOT NULL DEFAULT 0",
        // Index used by the Trainer Change Requests screen to sort/filter quickly.
        "ALTER TABLE change_requests ADD INDEX idx_cr_status_created (status, created_at)",
        "ALTER TABLE change_requests ADD INDEX idx_cr_requested_by (requested_by)",
    ];
    foreach ($alters as $sql) {
        try { $pdo->exec($sql); } catch (Throwable $e) { /* column/index likely already exists */ }
    }
}
ensureGovernanceSchema($pdo);

/* ======
   NOTIFY HELPER (mirrors teacher.php's notify_user)
   ====== */
function notifyUser(PDO $pdo, int $userId, string $message): void {
    try {
        $pdo->prepare("INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, NOW())")
            ->execute([$userId, $message]);
    } catch (Throwable $e) { /* non-fatal */ }
}

/* ======
   READABLE LABEL FOR A CHANGE REQUEST
   Turns entity_type + new_data into a short human-readable
   summary so reviewers don't have to read raw JSON to know
   what they're approving (e.g. "Video: Intro to CBT" instead
   of just "course_content").
   ====== */
function changeRequestLabel(string $entityType, array $data): string {
    $action = ucfirst($data['action'] ?? 'update');
    switch ($entityType) {
        case 'course':
            return "$action course — " . ($data['title'] ?? 'Untitled');
        case 'course_content':
            $kind = ($data['content_type'] ?? '') === 'video' ? 'Video' : 'Content';
            return "$action $kind — " . ($data['title'] ?? 'Untitled');
        case 'note':
            return "$action note — " . ($data['title'] ?? 'Untitled');
        case 'quiz':
            return "$action quiz — " . ($data['title'] ?? 'Untitled');
        case 'quiz_question':
            return "$action question — " . mb_strimwidth($data['question'] ?? '', 0, 60, '...');
        case 'assignment':
            return "$action assignment — " . ($data['title'] ?? 'Untitled');
        case 'other':
            if (($data['content_type'] ?? '') === 'announcement') {
                return "$action announcement — " . ($data['title'] ?? 'Untitled');
            }
            return "$action item";
        case 'profile':
            return "Trainer profile update";
        default:
            return ucwords(str_replace('_', ' ', $entityType));
    }
}

/* ======
   APPLY A TRAINER CHANGE REQUEST TO THE LIVE TABLES
   teacher.php stages every trainer create/edit as a row in
   change_requests (+ content_versions). This is the missing
   other half: turning an approved request into a real change,
   using the same column names teacher.php itself relies on.
   Video-table writes try both known column layouts, since the
   codebase has two different assumptions about that table.
   Nothing here runs until an admin/super admin explicitly
   approves the request — rejecting it leaves the live tables
   completely untouched.
   ====== */
function applyChangeRequest(PDO $pdo, array $change): array {
    $entityType = $change['entity_type'];
    $entityId   = $change['entity_id'] !== null ? (int)$change['entity_id'] : null;
    $data       = json_decode($change['new_data'] ?? '{}', true) ?: [];
    $action     = $data['action'] ?? 'update';

    try {
        switch ($entityType) {
            case 'course':
                if ($action === 'archive_request') {
                    $pdo->prepare("UPDATE courses SET status='Inactive' WHERE id=?")->execute([$entityId ?? (int)($data['course_id'] ?? 0)]);
                    return ['ok' => true, 'message' => 'Course archived.'];
                }
                $pdo->prepare("UPDATE courses SET title=?, description=? WHERE id=?")
                    ->execute([$data['title'] ?? '', $data['description'] ?? '', $entityId ?? (int)($data['course_id'] ?? 0)]);
                return ['ok' => true, 'message' => 'Course content updated.'];

            case 'course_content':
                if (($data['content_type'] ?? '') === 'video') {
                    if ($action === 'create') {
                        try {
                            $pdo->prepare("INSERT INTO course_videos (course_id, title, video_path, access_type, uploaded_by, description) VALUES (?,?,?,?,?,?)")
                                ->execute([$data['course_id'] ?? 0, $data['title'] ?? '', $data['video_path'] ?? '', $data['access_type'] ?? 'free', $data['uploaded_by'] ?? null, $data['description'] ?? null]);
                        } catch (Throwable $e) {
                            $pdo->prepare("INSERT INTO course_videos (course_id, title, local_path, access_type, uploaded_by, description, upload_status) VALUES (?,?,?,?,?,?,'local')")
                                ->execute([$data['course_id'] ?? 0, $data['title'] ?? '', $data['video_path'] ?? '', $data['access_type'] ?? 'free', $data['uploaded_by'] ?? null, $data['description'] ?? null]);
                        }
                        return ['ok' => true, 'message' => 'Video published.'];
                    }
                    $vid = (int)($data['video_id'] ?? 0);
                    try {
                        $pdo->prepare("UPDATE course_videos SET title=?, video_path=?, access_type=? WHERE id=?")
                            ->execute([$data['title'] ?? '', $data['video_path'] ?? '', $data['access_type'] ?? 'free', $vid]);
                    } catch (Throwable $e) {
                        $pdo->prepare("UPDATE course_videos SET title=?, local_path=?, access_type=? WHERE id=?")
                            ->execute([$data['title'] ?? '', $data['video_path'] ?? '', $data['access_type'] ?? 'free', $vid]);
                    }
                    return ['ok' => true, 'message' => 'Video updated.'];
                }
                return ['ok' => false, 'message' => 'Unrecognized content type.'];

            case 'note':
                if ($action === 'create') {
                    $pdo->prepare("INSERT INTO notes(course_id,title,content,access_type,created_by,file_path) VALUES(?,?,?,?,?,?)")
                        ->execute([$data['course_id'] ?? 0, $data['title'] ?? '', $data['content'] ?? '', $data['access_type'] ?? 'free', $data['created_by'] ?? null, $data['file_path'] ?: null]);
                    return ['ok' => true, 'message' => 'Note published.'];
                }
                $pdo->prepare("UPDATE notes SET title=?, content=?, access_type=?, file_path=? WHERE id=?")
                    ->execute([$data['title'] ?? '', $data['content'] ?? '', $data['access_type'] ?? 'free', $data['file_path'] ?: null, (int)($data['note_id'] ?? 0)]);
                return ['ok' => true, 'message' => 'Note updated.'];

            case 'quiz':
                if ($action === 'create') {
                    $pdo->prepare("INSERT INTO quizzes(course_id,title,description,passing_score,duration) VALUES(?,?,?,?,?)")
                        ->execute([$data['course_id'] ?? 0, $data['title'] ?? '', $data['description'] ?? '', $data['passing_score'] ?? 0, $data['duration'] ?? 0]);
                    return ['ok' => true, 'message' => 'Quiz published.'];
                }
                $pdo->prepare("UPDATE quizzes SET title=?, description=?, passing_score=?, duration=? WHERE id=?")
                    ->execute([$data['title'] ?? '', $data['description'] ?? '', $data['passing_score'] ?? 0, $data['duration'] ?? 0, (int)($data['quiz_id'] ?? 0)]);
                return ['ok' => true, 'message' => 'Quiz updated.'];

            case 'quiz_question':
                if ($action === 'create') {
                    try {
                        $pdo->prepare("INSERT INTO quiz_questions(quiz_id,question,question_type,option_a,option_b,option_c,option_d,correct_answer,marks,difficulty,topic,explanation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
                            ->execute([$data['quiz_id'] ?? 0, $data['question'] ?? '', $data['question_type'] ?? 'mcq', $data['option_a'] ?? '', $data['option_b'] ?? '', $data['option_c'] ?? '', $data['option_d'] ?? '', $data['correct_answer'] ?? '', $data['marks'] ?? 1, $data['difficulty'] ?? 'medium', $data['topic'] ?? '', $data['explanation'] ?? '']);
                    } catch (Throwable $e) {
                        $pdo->prepare("INSERT INTO quiz_questions(quiz_id,question,question_type,option_a,option_b,option_c,option_d,correct_answer,marks) VALUES(?,?,?,?,?,?,?,?,?)")
                            ->execute([$data['quiz_id'] ?? 0, $data['question'] ?? '', $data['question_type'] ?? 'mcq', $data['option_a'] ?? '', $data['option_b'] ?? '', $data['option_c'] ?? '', $data['option_d'] ?? '', $data['correct_answer'] ?? '', $data['marks'] ?? 1]);
                    }
                    return ['ok' => true, 'message' => 'Question published.'];
                }
                $qid = (int)($data['question_id'] ?? 0);
                try {
                    $pdo->prepare("UPDATE quiz_questions SET question=?, option_a=?, option_b=?, option_c=?, option_d=?, correct_answer=?, marks=?, difficulty=?, topic=?, explanation=? WHERE id=?")
                        ->execute([$data['question'] ?? '', $data['option_a'] ?? '', $data['option_b'] ?? '', $data['option_c'] ?? '', $data['option_d'] ?? '', $data['correct_answer'] ?? '', $data['marks'] ?? 1, $data['difficulty'] ?? 'medium', $data['topic'] ?? '', $data['explanation'] ?? '', $qid]);
                } catch (Throwable $e) {
                    $pdo->prepare("UPDATE quiz_questions SET question=?, option_a=?, option_b=?, option_c=?, option_d=?, correct_answer=?, marks=? WHERE id=?")
                        ->execute([$data['question'] ?? '', $data['option_a'] ?? '', $data['option_b'] ?? '', $data['option_c'] ?? '', $data['option_d'] ?? '', $data['correct_answer'] ?? '', $data['marks'] ?? 1, $qid]);
                }
                return ['ok' => true, 'message' => 'Question updated.'];

            case 'assignment':
                if ($action === 'create') {
                    $pdo->prepare("INSERT INTO assignments(course_id,teacher_id,title,description,due_date,created_at) VALUES(?,?,?,?,?,NOW())")
                        ->execute([$data['course_id'] ?? 0, $data['teacher_id'] ?? 0, $data['title'] ?? '', $data['description'] ?? '', $data['due_date'] ?: null]);
                    return ['ok' => true, 'message' => 'Assignment published.'];
                }
                $pdo->prepare("UPDATE assignments SET title=?, description=?, due_date=? WHERE id=?")
                    ->execute([$data['title'] ?? '', $data['description'] ?? '', $data['due_date'] ?: null, (int)($data['assignment_id'] ?? 0)]);
                return ['ok' => true, 'message' => 'Assignment updated.'];

            case 'other':
                if (($data['content_type'] ?? '') === 'announcement') {
                    if ($action === 'create') {
                        $pdo->prepare("INSERT INTO announcements(course_id,teacher_id,title,message) VALUES(?,?,?,?)")
                            ->execute([$data['course_id'] ?? 0, $data['teacher_id'] ?? 0, $data['title'] ?? '', $data['message'] ?? '']);
                        return ['ok' => true, 'message' => 'Announcement published.'];
                    }
                    $pdo->prepare("UPDATE announcements SET title=?, message=? WHERE id=?")
                        ->execute([$data['title'] ?? '', $data['message'] ?? '', (int)($data['announcement_id'] ?? 0)]);
                    return ['ok' => true, 'message' => 'Announcement updated.'];
                }
                return ['ok' => false, 'message' => 'Unrecognized item type.'];

            case 'profile':
                $uid = (int)($data['user_id'] ?? $entityId ?? 0);
                $pdo->prepare("UPDATE teachers SET specialization=?, qualification=?, qualification_level=?, license_number=?, phone=?, experience_years=? WHERE user_id=?")
                    ->execute([$data['specialization'] ?? '', $data['qualification'] ?? '', $data['qualification_level'] ?? '', $data['license_number'] ?? '', $data['phone'] ?? '', $data['experience_years'] ?? 0, $uid]);
                return ['ok' => true, 'message' => 'Trainer profile updated.'];

            default:
                return ['ok' => false, 'message' => 'Unknown submission type: ' . $entityType];
        }
    } catch (Throwable $e) {
        return ['ok' => false, 'message' => 'Could not apply automatically (' . $e->getMessage() . '). Approved but needs a manual data fix.'];
    }
}

/* ======
   BRANDING (Super Admin overridable, stored in `stp_settings`)
   ====== */
function getSetting(PDO $pdo, string $key, string $default): string {
    try {
        $stmt = $pdo->prepare("SELECT setting_value FROM stp_settings WHERE setting_key=?");
        $stmt->execute([$key]);
        $val = $stmt->fetchColumn();
        return $val !== false && $val !== null && $val !== '' ? $val : $default;
    } catch (Throwable $e) { return $default; }
}
function setSetting(PDO $pdo, string $key, string $value): void {
    $stmt = $pdo->prepare("INSERT INTO stp_settings(setting_key,setting_value) VALUES(?,?)
        ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)");
    $stmt->execute([$key, $value]);
}

$branding = [
    'org_name'    => getSetting($pdo, 'org_name', 'CBT-Kenya STP'),
    'color_primary'     => getSetting($pdo, 'color_primary', '#0f766e'),
    'color_primary_dark'=> getSetting($pdo, 'color_primary_dark', '#0b544e'),
    'color_primary_light'=> getSetting($pdo, 'color_primary_light', '#14b8a6'),
    'color_accent' => getSetting($pdo, 'color_accent', '#f59e0b'),
    'logo_url'     => getSetting($pdo, 'logo_url', 'https://www.cbtkenya.org/wp-content/uploads/2018/11/cbt-ke.png'),
];

if (isset($_POST['save_branding'])) {
    validateCsrf();
    requireSuper($is_super);
    setSetting($pdo, 'org_name', trim($_POST['org_name'] ?? 'CBT-Kenya STP'));
    setSetting($pdo, 'color_primary', trim($_POST['color_primary'] ?? '#0f766e'));
    setSetting($pdo, 'color_primary_dark', trim($_POST['color_primary_dark'] ?? '#0b544e'));
    setSetting($pdo, 'color_primary_light', trim($_POST['color_primary_light'] ?? '#14b8a6'));
    setSetting($pdo, 'color_accent', trim($_POST['color_accent'] ?? '#f59e0b'));
    setSetting($pdo, 'logo_url', trim($_POST['logo_url'] ?? ''));
    $_SESSION['success'] = "Branding updated.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#settingsSection"); exit;
}

/* ======
   CERTIFICATE HELPERS
   ====== */
function generateCertificateNumber(PDO $pdo): string {
    $year = date('Y');
    $stmt = $pdo->query("SELECT COUNT(*) FROM stp_certificates WHERE YEAR(issued_at)=" . (int)$year);
    $seq = (int)$stmt->fetchColumn() + 1;
    return sprintf("CBT-STP-%s-%06d", $year, $seq);
}

function issueCertificateIfEligible(PDO $pdo, int $user_id, int $course_id, int $overallProgress): void {
    if ($overallProgress < 90) { return; }
    $check = $pdo->prepare("SELECT id FROM stp_certificates WHERE user_id=? AND course_id=?");
    $check->execute([$user_id, $course_id]);
    if ($check->fetchColumn()) { return; }
    $certNo = generateCertificateNumber($pdo);
    $stmt = $pdo->prepare("INSERT INTO stp_certificates(user_id,course_id,cert_number) VALUES(?,?,?)");
    try {
        $stmt->execute([$user_id, $course_id, $certNo]);
        logActivity($pdo, $user_id, "Certificate $certNo auto-issued");
    } catch (Throwable $e) { /* race condition on unique key, ignore */ }
}

/* ======
   VIDEO HELPERS
   ====== */
function isValidVideo(string $tmpFile): bool {
    $allowed = ['video/mp4', 'video/webm', 'video/ogg'];
    return in_array(mime_content_type($tmpFile), $allowed, true);
}

function convertDriveLink(string $url): string {
    if ($url !== '' && strpos($url, 'drive.google.com') !== false) {
        preg_match('/\/d\/(.*?)\//', $url, $m);
        if (!empty($m[1])) {
            return "https://drive.google.com/file/d/{$m[1]}/preview";
        }
    }
    return $url;
}

/* ======
   PROGRESS
   ====== */
if (!function_exists('recalcEnrollmentProgress')) {
    function recalcEnrollmentProgress(PDO $pdo, int $user_id, int $course_id): int {

        /* VIDEOS */
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM course_videos WHERE course_id=?");
        $stmt->execute([$course_id]);
        $video_count = (int)$stmt->fetchColumn();

        $video_progress = 0;
        if ($video_count > 0) {
            $stmt = $pdo->prepare(
                "SELECT COALESCE(AVG(pct),0) FROM (
                    SELECT cv.id, COALESCE(MAX(vp.watched_percentage),0) AS pct
                    FROM course_videos cv
                    LEFT JOIN video_progress vp
                        ON vp.content_id = cv.id AND vp.user_id = ?
                    WHERE cv.course_id = ?
                    GROUP BY cv.id
                ) t"
            );
            $stmt->execute([$user_id, $course_id]);
            $video_progress = (int)round((float)$stmt->fetchColumn());
        }

        /* NOTES */
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM notes WHERE course_id=?");
        $stmt->execute([$course_id]);
        $note_count = (int)$stmt->fetchColumn();

        $note_progress = 0;
        if ($note_count > 0) {
            $stmt = $pdo->prepare(
                "SELECT COUNT(*) FROM notes n
                 JOIN note_progress np
                    ON np.note_id = n.id AND np.user_id = ? AND np.completed = 1
                 WHERE n.course_id = ?"
            );
            $stmt->execute([$user_id, $course_id]);
            $completed_notes = (int)$stmt->fetchColumn();
            $note_progress = (int)round(($completed_notes / $note_count) * 100);
        }

        /* QUIZZES */
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM quizzes WHERE course_id=?");
        $stmt->execute([$course_id]);
        $quiz_count = (int)$stmt->fetchColumn();

        $quiz_progress = 0;
        if ($quiz_count > 0) {
            $stmt = $pdo->prepare(
                "SELECT COUNT(DISTINCT qr.quiz_id) FROM quiz_results qr
                 JOIN quizzes q ON q.id = qr.quiz_id
                 WHERE qr.user_id = ? AND q.course_id = ? AND qr.status = 'passed'"
            );
            $stmt->execute([$user_id, $course_id]);
            $passed = (int)$stmt->fetchColumn();
            $quiz_progress = (int)round(($passed / $quiz_count) * 100);
        }

        /* WEIGHTED OVERALL */
        $w_video = $video_count > 0 ? 0.60 : 0;
        $w_note  = $note_count  > 0 ? 0.25 : 0;
        $w_quiz  = $quiz_count  > 0 ? 0.15 : 0;
        $w_total = $w_video + $w_note + $w_quiz;

        $overall = $w_total > 0
            ? (int)round(($video_progress * $w_video + $note_progress * $w_note + $quiz_progress * $w_quiz) / $w_total)
            : 0;

        $overall = max(0, min(100, $overall));

        if ($overall >= 90) {
            $stmt = $pdo->prepare(
                "UPDATE enrollments
                 SET progress = ?, status = 'completed'
                 WHERE user_id = ? AND course_id = ? AND status NOT IN ('rejected','deleted')"
            );
        } else {
            $stmt = $pdo->prepare(
                "UPDATE enrollments
                 SET progress = ?
                 WHERE user_id = ? AND course_id = ? AND status NOT IN ('rejected','deleted')"
            );
        }
        $stmt->execute([$overall, $user_id, $course_id]);

        issueCertificateIfEligible($pdo, $user_id, $course_id, $overall);

        return $overall;
    }

    function recalcAllEnrollmentProgress(PDO $pdo): void {
        $rows = $pdo->query(
            "SELECT DISTINCT user_id, course_id FROM enrollments
             WHERE status NOT IN ('rejected','deleted')"
        )->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $r) {
            recalcEnrollmentProgress($pdo, (int)$r['user_id'], (int)$r['course_id']);
        }
    }
}
recalcAllEnrollmentProgress($pdo);

/* ======
   CREATE COURSE
   Teachers can propose a new course, but it is created with
   status = 'Pending Approval' and is not publicly active until
   a Super Administrator approves it via the Approvals screen.
   Admin/Super Admin creations go live immediately.
   ====== */
if (isset($_POST['create_course'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }

    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $category    = trim($_POST['category'] ?? '');
    $custom_cat  = trim($_POST['custom_category'] ?? '');
    if ($custom_cat !== '') { $category = $custom_cat; }

    $course_type = ($_POST['course_type'] ?? 'Free') === 'Paid' ? 'Paid' : 'Free';
    $requested_status = ($_POST['status'] ?? 'Active') === 'Inactive' ? 'Inactive' : 'Active';
    $teacher_id  = intval($_POST['teacher_id'] ?? 0);
    $price       = (float)($_POST['price'] ?? 0);

    $errors = [];
    if ($title === '')       $errors[] = "Title is required.";
    if ($description === '') $errors[] = "Description is required.";
    if ($category === '')    $errors[] = "Category is required.";
    if ($teacher_id <= 0)    $errors[] = "Please assign a teacher.";

    $thumbnail_path = null;
    if (!empty($_FILES['thumbnail']['name'])) {
        $ext = strtolower(pathinfo($_FILES['thumbnail']['name'], PATHINFO_EXTENSION));
        $allowed_img = ['jpg','jpeg','png','gif','webp'];
        if (!in_array($ext, $allowed_img, true)) {
            $errors[] = "Thumbnail must be an image (jpg, png, gif, webp).";
        } elseif ($_FILES['thumbnail']['size'] > 5 * 1024 * 1024) {
            $errors[] = "Thumbnail too large (max 5MB).";
        } else {
            $thumb_dir = "uploads/thumbnails/";
            if (!file_exists($thumb_dir)) { mkdir($thumb_dir, 0777, true); }
            $newName = "thumb_" . time() . "_" . rand(1000, 9999) . "." . $ext;
            if (move_uploaded_file($_FILES['thumbnail']['tmp_name'], $thumb_dir . $newName)) {
                $thumbnail_path = $thumb_dir . $newName;
            } else {
                $errors[] = "Failed to upload thumbnail.";
            }
        }
    }

    if (empty($errors)) {
        $status = ($user_role === 'teacher') ? 'Pending Approval' : $requested_status;

        $stmt = $pdo->prepare(
            "INSERT INTO courses (title, description, category, thumbnail, course_type, status, teacher_id, price)
             VALUES (?,?,?,?,?,?,?,?)"
        );
        $stmt->execute([$title, $description, $category, $thumbnail_path, $course_type, $status, $teacher_id, $price]);
        $new_course_id = (int)$pdo->lastInsertId();

        if ($user_role === 'teacher') {
            $payload = json_encode([
                'title' => $title, 'description' => $description, 'category' => $category,
                'thumbnail' => $thumbnail_path, 'course_type' => $course_type, 'status' => $requested_status,
                'teacher_id' => $teacher_id, 'price' => $price, 'action' => 'create',
            ]);
            $pdo->prepare("INSERT INTO stp_course_versions(course_id,version_no,payload,submitted_by,status) VALUES(?,?,?,?,'pending')")
                ->execute([$new_course_id, 1, $payload, $user_id]);
            logActivity($pdo, $user_id, "Submitted new course \"$title\" for Super Admin approval");
            $_SESSION['success'] = "Course \"$title\" submitted for Super Administrator approval.";
        } else {
            logActivity($pdo, $user_id, "Created course \"$title\"");
            $_SESSION['success'] = "Course \"$title\" created successfully.";
        }
    } else {
        $_SESSION['course_errors'] = $errors;
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ======
   UPDATE COURSE (EDIT)
   Teacher edits are queued as a pending stp_course_versions row
   instead of touching the live course row. Admin/Super Admin
   edits apply immediately (and are logged as an auto-approved
   version for history/audit purposes).
   ====== */
if (isset($_POST['update_course'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }

    $course_id   = intval($_POST['course_id'] ?? 0);
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $category    = trim($_POST['category'] ?? '');
    $custom_cat  = trim($_POST['custom_category'] ?? '');
    if ($custom_cat !== '') { $category = $custom_cat; }

    $course_type = ($_POST['course_type'] ?? 'Free') === 'Paid' ? 'Paid' : 'Free';
    $status      = ($_POST['status'] ?? 'Active') === 'Inactive' ? 'Inactive' : 'Active';
    $teacher_id  = intval($_POST['teacher_id'] ?? 0);
    $price       = (float)($_POST['price'] ?? 0);

    $errors = [];
    if ($course_id <= 0)      $errors[] = "Invalid course selected.";
    if ($title === '')        $errors[] = "Title is required.";
    if ($description === '')  $errors[] = "Description is required.";
    if ($category === '')     $errors[] = "Category is required.";
    if ($teacher_id <= 0)     $errors[] = "Please assign a teacher.";

    $existingCourse = null;
    if ($course_id > 0) {
        $existsStmt = $pdo->prepare("SELECT id, thumbnail FROM courses WHERE id = ?");
        $existsStmt->execute([$course_id]);
        $existingCourse = $existsStmt->fetch(PDO::FETCH_ASSOC);
        if (!$existingCourse) { $errors[] = "Course not found."; }
    }

    $thumbnail_path = $existingCourse['thumbnail'] ?? null;

    if (!empty($_FILES['thumbnail']['name'])) {
        $ext = strtolower(pathinfo($_FILES['thumbnail']['name'], PATHINFO_EXTENSION));
        $allowed_img = ['jpg','jpeg','png','gif','webp'];
        if (!in_array($ext, $allowed_img, true)) {
            $errors[] = "Thumbnail must be an image (jpg, png, gif, webp).";
        } elseif ($_FILES['thumbnail']['size'] > 5 * 1024 * 1024) {
            $errors[] = "Thumbnail too large (max 5MB).";
        } else {
            $thumb_dir = "uploads/thumbnails/";
            if (!file_exists($thumb_dir)) { mkdir($thumb_dir, 0777, true); }
            $newName = "thumb_" . time() . "_" . rand(1000, 9999) . "." . $ext;
            if (move_uploaded_file($_FILES['thumbnail']['tmp_name'], $thumb_dir . $newName)) {
                $thumbnail_path = $thumb_dir . $newName;
            } else {
                $errors[] = "Failed to upload thumbnail.";
            }
        }
    }

    if (empty($errors)) {
        if ($user_role === 'teacher') {
            $verStmt = $pdo->prepare("SELECT COALESCE(MAX(version_no),0)+1 FROM stp_course_versions WHERE course_id=?");
            $verStmt->execute([$course_id]);
            $nextVersion = (int)$verStmt->fetchColumn();

            $payload = json_encode([
                'title' => $title, 'description' => $description, 'category' => $category,
                'thumbnail' => $thumbnail_path, 'course_type' => $course_type, 'status' => $status,
                'teacher_id' => $teacher_id, 'price' => $price, 'action' => 'update',
            ]);
            $pdo->prepare("INSERT INTO stp_course_versions(course_id,version_no,payload,submitted_by,status) VALUES(?,?,?,?,'pending')")
                ->execute([$course_id, $nextVersion, $payload, $user_id]);
            logActivity($pdo, $user_id, "Submitted update (v$nextVersion) for course \"$title\" — awaiting Super Admin approval");
            $_SESSION['success'] = "Update for \"$title\" submitted for Super Administrator approval (v$nextVersion).";
        } else {
            $stmt = $pdo->prepare(
                "UPDATE courses
                 SET title=?, description=?, category=?, thumbnail=?, course_type=?, status=?, teacher_id=?, price=?
                 WHERE id=?"
            );
            $stmt->execute([$title, $description, $category, $thumbnail_path, $course_type, $status, $teacher_id, $price, $course_id]);

            $verStmt = $pdo->prepare("SELECT COALESCE(MAX(version_no),0)+1 FROM stp_course_versions WHERE course_id=?");
            $verStmt->execute([$course_id]);
            $nextVersion = (int)$verStmt->fetchColumn();
            $payload = json_encode([
                'title' => $title, 'description' => $description, 'category' => $category,
                'thumbnail' => $thumbnail_path, 'course_type' => $course_type, 'status' => $status,
                'teacher_id' => $teacher_id, 'price' => $price, 'action' => 'update',
            ]);
            $pdo->prepare("INSERT INTO stp_course_versions(course_id,version_no,payload,submitted_by,status,reviewed_by,reviewed_at) VALUES(?,?,?,?,'approved',?,NOW())")
                ->execute([$course_id, $nextVersion, $payload, $user_id, $user_id]);

            logActivity($pdo, $user_id, "Updated course \"$title\"");
            $_SESSION['success'] = "Course \"$title\" updated successfully.";
        }
    } else {
        $_SESSION['course_errors'] = $errors;
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ======
   COURSE VERSION APPROVAL (Super Admin only)
   ====== */
if (isset($_POST['review_version'])) {
    validateCsrf();
    requireSuper($is_super);

    $version_id = intval($_POST['version_id'] ?? 0);
    $decision   = $_POST['decision'] ?? '';
    $note       = trim($_POST['review_note'] ?? '');

    $vstmt = $pdo->prepare("SELECT * FROM stp_course_versions WHERE id=?");
    $vstmt->execute([$version_id]);
    $version = $vstmt->fetch(PDO::FETCH_ASSOC);

    if ($version && $version['status'] === 'pending' && in_array($decision, ['approved','rejected'], true)) {
        $data = json_decode($version['payload'], true) ?: [];

        if ($decision === 'approved') {
            if (($data['action'] ?? '') === 'create' || ($data['action'] ?? '') === 'update') {
                $upd = $pdo->prepare(
                    "UPDATE courses SET title=?, description=?, category=?, thumbnail=?, course_type=?, status=?, teacher_id=?, price=? WHERE id=?"
                );
                $upd->execute([
                    $data['title'] ?? '', $data['description'] ?? '', $data['category'] ?? '',
                    $data['thumbnail'] ?? null, $data['course_type'] ?? 'Free', $data['status'] ?? 'Active',
                    (int)($data['teacher_id'] ?? 0), (float)($data['price'] ?? 0), (int)$version['course_id'],
                ]);
            }
            $pdo->prepare("UPDATE stp_course_versions SET status='approved', reviewed_by=?, review_note=?, reviewed_at=NOW() WHERE id=?")
                ->execute([$user_id, $note, $version_id]);
            logActivity($pdo, $user_id, "Approved course version #{$version['version_no']} for course #{$version['course_id']}");
            $_SESSION['success'] = "Version approved and published.";
        } else {
            $pdo->prepare("UPDATE stp_course_versions SET status='rejected', reviewed_by=?, review_note=?, reviewed_at=NOW() WHERE id=?")
                ->execute([$user_id, $note, $version_id]);
            if (($data['action'] ?? '') === 'create') {
                $pdo->prepare("UPDATE courses SET status='Inactive' WHERE id=?")->execute([(int)$version['course_id']]);
            }
            logActivity($pdo, $user_id, "Rejected course version #{$version['version_no']} for course #{$version['course_id']}");
            $_SESSION['success'] = "Version rejected.";
        }
    } else {
        $_SESSION['course_errors'] = ["Version not found or already reviewed."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#approvalsSection"); exit;
}

/* ======
   TRAINER CHANGE REQUEST REVIEW (Admin / Super Admin)
   This is the core "trainer submits -> admin reviews -> admin
   approves or rejects -> only THEN does it get saved" pipeline:
   trainer-submitted course edits, video uploads/edits, notes,
   quizzes, questions, assignments, announcements and profile
   updates all land in change_requests with status='pending' and
   are NEVER written to the live tables until this handler runs
   with an explicit 'approved' decision. Rejecting a request
   leaves every live table completely untouched.
   ====== */
if (isset($_POST['review_change_request'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }

    $cr_id    = intval($_POST['change_request_id'] ?? 0);
    $decision = $_POST['cr_decision'] ?? '';
    $note     = trim($_POST['cr_review_note'] ?? '');

    $stmt = $pdo->prepare("SELECT * FROM change_requests WHERE id=?");
    $stmt->execute([$cr_id]);
    $change = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($change && $change['status'] === 'pending' && in_array($decision, ['approved', 'rejected'], true)) {
        if ($decision === 'approved') {
            $result = applyChangeRequest($pdo, $change);
            $note = trim($note . ' ' . ($result['message'] ?? ''));
        }

        $pdo->prepare("UPDATE change_requests SET status=?, review_comments=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?")
            ->execute([$decision, $note, $user_id, $cr_id]);
        try {
            $pdo->prepare("UPDATE content_versions SET status=? WHERE change_request_id=?")
                ->execute([$decision === 'approved' ? 'approved' : 'rejected', $cr_id]);
        } catch (Throwable $e) { /* content_versions row may not exist for this request */ }

        if (!empty($change['requested_by'])) {
            notifyUser($pdo, (int)$change['requested_by'], "Your submitted change request #$cr_id was $decision" . ($note ? ": $note" : "."));
        }
        logActivity($pdo, $user_id, "Reviewed trainer change request #$cr_id ({$change['entity_type']}): $decision");
        $_SESSION['success'] = "Change request #$cr_id $decision.";
    } else {
        $_SESSION['course_errors'] = ["Change request not found or already reviewed."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#changeRequestsSection"); exit;
}

/* ======
   BULK APPROVE / REJECT TRAINER CHANGE REQUESTS
   Lets an admin clear a backlog of routine trainer submissions
   (e.g. a batch of note or announcement edits) without opening
   each one individually — still runs through the same
   applyChangeRequest() path per row, so nothing bypasses review.
   ====== */
if (isset($_POST['bulk_review_change_requests'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }

    $ids      = array_filter(array_map('intval', $_POST['cr_ids'] ?? []));
    $decision = $_POST['bulk_decision'] ?? '';
    $count    = 0;

    if (!empty($ids) && in_array($decision, ['approved', 'rejected'], true)) {
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $pdo->prepare("SELECT * FROM change_requests WHERE status='pending' AND id IN ($placeholders)");
        $stmt->execute($ids);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $change) {
            $note = '';
            if ($decision === 'approved') {
                $result = applyChangeRequest($pdo, $change);
                $note = trim($result['message'] ?? '');
            }
            $pdo->prepare("UPDATE change_requests SET status=?, review_comments=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?")
                ->execute([$decision, $note, $user_id, $change['id']]);
            try {
                $pdo->prepare("UPDATE content_versions SET status=? WHERE change_request_id=?")
                    ->execute([$decision === 'approved' ? 'approved' : 'rejected', $change['id']]);
            } catch (Throwable $e) { /* ignore */ }
            if (!empty($change['requested_by'])) {
                notifyUser($pdo, (int)$change['requested_by'], "Your submitted change request #{$change['id']} was $decision" . ($note ? ": $note" : "."));
            }
            $count++;
        }
        logActivity($pdo, $user_id, "Bulk $decision $count trainer change request(s)");
        $_SESSION['success'] = "$count change request(s) $decision.";
    } else {
        $_SESSION['course_errors'] = ["Select at least one pending request to review."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#changeRequestsSection"); exit;
}

/* ======
   CERTIFICATE REQUEST REVIEW (trainer-confirmed completions)
   teacher.php's "Confirm Completion" button inserts into
   certificate_requests, but nothing previously read that table.
   ====== */
if (isset($_POST['review_certificate_request'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }

    $req_id   = intval($_POST['cert_request_id'] ?? 0);
    $decision = $_POST['cert_decision'] ?? '';

    $stmt = $pdo->prepare("SELECT * FROM certificate_requests WHERE id=?");
    $stmt->execute([$req_id]);
    $req = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($req && $req['status'] === 'pending' && in_array($decision, ['approved', 'rejected'], true)) {
        if ($decision === 'approved') {
            $check = $pdo->prepare("SELECT id FROM stp_certificates WHERE user_id=? AND course_id=?");
            $check->execute([$req['user_id'], $req['course_id']]);
            if (!$check->fetchColumn()) {
                $certNo = generateCertificateNumber($pdo);
                $pdo->prepare("INSERT INTO stp_certificates(user_id,course_id,cert_number) VALUES(?,?,?)")
                    ->execute([$req['user_id'], $req['course_id'], $certNo]);
                logActivity($pdo, $user_id, "Issued certificate $certNo from trainer completion confirmation #$req_id");
            }
        }
        $pdo->prepare("UPDATE certificate_requests SET status=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?")
            ->execute([$decision, $user_id, $req_id]);
        notifyUser($pdo, (int)$req['user_id'], "Your certificate request was $decision.");
        $_SESSION['success'] = "Certificate request $decision.";
    } else {
        $_SESSION['course_errors'] = ["Certificate request not found or already reviewed."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#certificateSection"); exit;
}

/* ======
   CPD VERIFICATION QUEUE (trainer/student submitted cpd_points)
   Both teacher.php and student.php insert into cpd_points with
   verification_status='pending'; admin.php previously only managed
   its own separate stp_cpd_points table, so those submissions were
   never actually reviewable.
   ====== */
if (isset($_POST['review_cpd_point'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }

    $cpd_id   = intval($_POST['cpd_point_id'] ?? 0);
    $decision = $_POST['cpd_decision'] ?? '';

    if (in_array($decision, ['verified', 'rejected'], true)) {
        $stmt = $pdo->prepare("SELECT user_id, activity_title FROM cpd_points WHERE id=? AND verification_status='pending'");
        $stmt->execute([$cpd_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $pdo->prepare("UPDATE cpd_points SET verification_status=? WHERE id=?")->execute([$decision, $cpd_id]);
            notifyUser($pdo, (int)$row['user_id'], "Your CPD activity \"{$row['activity_title']}\" was $decision.");
            logActivity($pdo, $user_id, "CPD point #$cpd_id ({$row['activity_title']}) marked $decision");
            $_SESSION['success'] = "CPD entry $decision.";
        } else {
            $_SESSION['course_errors'] = ["CPD entry not found or already reviewed."];
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#cpdSection"); exit;
}

/* ======
   STUDENT PROFESSIONAL-PROFILE VERIFICATION
   student.php's "Update Professional Details" form sets
   students.verification_status='pending', but admin.php's Students
   screen was reading/writing a completely different set of columns
   (users.license_no instead of students.license_number), so those
   submissions were invisible to admins.
   ====== */
if (isset($_POST['review_student_verification'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }

    $student_row_id = intval($_POST['student_row_id'] ?? 0);
    $decision       = $_POST['sv_decision'] ?? '';

    if ($student_row_id > 0 && in_array($decision, ['verified', 'rejected'], true)) {
        $stmt = $pdo->prepare("SELECT user_id FROM students WHERE id=?");
        $stmt->execute([$student_row_id]);
        $studentUserId = (int)$stmt->fetchColumn();

        $pdo->prepare("UPDATE students SET verification_status=? WHERE id=?")->execute([$decision, $student_row_id]);
        if ($studentUserId) {
            notifyUser($pdo, $studentUserId, "Your professional profile verification was $decision.");
        }
        logActivity($pdo, $user_id, "Student professional profile #$student_row_id marked $decision");
        $_SESSION['success'] = "Student verification $decision.";
    } else {
        $_SESSION['course_errors'] = ["Invalid verification request."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#studentsSection"); exit;
}

/* ======
   DELETE / ARCHIVE COURSE
   ====== */
if (isset($_POST['delete_course'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $del_course_id = intval($_POST['course_id'] ?? 0);
    $del_action    = $_POST['action'] ?? '';
    if ($del_course_id > 0) {
        if ($del_action === 'archive') {
            $pdo->prepare("UPDATE courses SET status='Inactive' WHERE id=?")->execute([$del_course_id]);
            logActivity($pdo, $user_id, "Archived course #$del_course_id");
            $_SESSION['success'] = "Course archived.";
        } elseif ($del_action === 'delete') {
            $pdo->prepare("DELETE FROM courses WHERE id=?")->execute([$del_course_id]);
            logActivity($pdo, $user_id, "Deleted course #$del_course_id");
            $_SESSION['success'] = "Course deleted.";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ==
   DASHBOARD STATISTICS
== */

$total_students = $pdo->query("SELECT COUNT(*) AS total FROM users WHERE role='student'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$active_users = $pdo->query("SELECT COUNT(*) AS total FROM users WHERE status='active'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$total_courses = $pdo->query("SELECT COUNT(*) AS total FROM courses")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$free_courses = $pdo->query("SELECT COUNT(*) AS total FROM courses WHERE course_type='free'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$paid_courses = $pdo->query("SELECT COUNT(*) AS total FROM courses WHERE course_type='paid'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$total_enrollments = $pdo->query("SELECT COUNT(*) AS total FROM enrollments")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$revenue = 0;
$row = $pdo->query("SELECT SUM(amount) AS total FROM payments WHERE status='completed'")->fetch(PDO::FETCH_ASSOC);
if ($row) { $revenue = $row['total'] ?? 0; }

$completion_rate = $pdo->query("SELECT AVG(progress) AS avg_progress FROM enrollments WHERE status NOT IN ('rejected','deleted')")
    ->fetch(PDO::FETCH_ASSOC)['avg_progress'] ?? 0;

$pending_payments = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='pending'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$successful_payments = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='completed'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$failed_payments = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='failed'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$pending_approvals_count = $pdo->query("SELECT COUNT(*) AS total FROM stp_course_versions WHERE status='pending'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$certificates_issued_count = $pdo->query("SELECT COUNT(*) AS total FROM stp_certificates")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$active_referrals_count = $pdo->query("SELECT COUNT(*) AS total FROM stp_referrals WHERE status='active'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$pending_commission_total = $pdo->query("SELECT COALESCE(SUM(commission),0) AS total FROM stp_referral_uses WHERE status='pending'")
    ->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

/* ==
   TRAINER GOVERNANCE QUEUES (change requests, certificate requests,
   CPD verification, student verification) — feed the sidebar badges
   and the new sections rendered further down.
== */
$pending_change_requests_count = (int) ($pdo->query("SELECT COUNT(*) FROM change_requests WHERE status='pending'")->fetchColumn() ?: 0);
$pending_change_requests = $pdo->query(
    "SELECT cr.*, u.full_name AS requester_name
     FROM change_requests cr
     LEFT JOIN users u ON u.id = cr.requested_by
     WHERE cr.status='pending'
     ORDER BY cr.created_at DESC"
);
$change_request_history = $pdo->query(
    "SELECT cr.*, u.full_name AS requester_name, r.full_name AS reviewer_name
     FROM change_requests cr
     LEFT JOIN users u ON u.id = cr.requested_by
     LEFT JOIN users r ON r.id = cr.reviewed_by
     WHERE cr.status <> 'pending'
     ORDER BY cr.id DESC LIMIT 50"
);

$pending_certificate_requests_count = (int) ($pdo->query("SELECT COUNT(*) FROM certificate_requests WHERE status='pending'")->fetchColumn() ?: 0);
$pending_certificate_requests = $pdo->query(
    "SELECT cr.*, u.full_name, c.title AS course_title
     FROM certificate_requests cr
     JOIN users u ON u.id=cr.user_id
     JOIN courses c ON c.id=cr.course_id
     WHERE cr.status='pending'
     ORDER BY cr.requested_at DESC"
);

$pending_cpd_points_count = (int) ($pdo->query("SELECT COUNT(*) FROM cpd_points WHERE verification_status='pending'")->fetchColumn() ?: 0);
$pending_cpd_points = $pdo->query(
    "SELECT cp.*, u.full_name, u.role
     FROM cpd_points cp
     JOIN users u ON u.id=cp.user_id
     WHERE cp.verification_status='pending'
     ORDER BY cp.created_at DESC"
);
$cpd_points_history = $pdo->query(
    "SELECT cp.*, u.full_name
     FROM cpd_points cp
     JOIN users u ON u.id=cp.user_id
     WHERE cp.verification_status<>'pending'
     ORDER BY cp.id DESC LIMIT 50"
);

$pending_student_verifications_count = (int) ($pdo->query("SELECT COUNT(*) FROM students WHERE verification_status='pending'")->fetchColumn() ?: 0);
$pending_student_verifications = $pdo->query(
    "SELECT s.*, u.full_name, u.email, u.kra_pin
     FROM students s
     JOIN users u ON u.id = s.user_id
     WHERE s.verification_status='pending'
     ORDER BY s.id DESC"
);

/* ==
   MOST POPULAR COURSES
== */
$popular_courses = $pdo->query(
    "SELECT courses.id, courses.title,
        COUNT(enrollments.id) AS users,
        COALESCE(SUM(payments.amount),0) AS revenue,
        COALESCE(AVG(enrollments.progress),0) AS completion_rate
    FROM courses
    LEFT JOIN enrollments ON courses.id = enrollments.course_id AND enrollments.status NOT IN ('rejected','deleted')
    LEFT JOIN payments ON enrollments.user_id = payments.user_id AND payments.status='completed'
    GROUP BY courses.id, courses.title
    ORDER BY users DESC LIMIT 5"
);

/* ==
   RECENT STUDENTS
== */
$recent_students = $pdo->query(
    "SELECT users.id, users.full_name, users.email,
        COALESCE(enrollments.status,'Not Enrolled') AS status,
        courses.title AS course_name
    FROM users
    LEFT JOIN enrollments ON users.id = enrollments.user_id
    LEFT JOIN courses ON enrollments.course_id = courses.id
    ORDER BY users.id DESC LIMIT 10"
);

/* ==
   RECENT ACTIVITIES (AUDIT LOG FEED)
== */
$activities = $pdo->query("SELECT * FROM activities ORDER BY id DESC LIMIT 10");
$audit_log  = $pdo->query("SELECT * FROM activities ORDER BY id DESC LIMIT 100");

/* ==
   ALLOWED FILE TYPES
== */
$allowed_images = ['jpg','jpeg','png','gif','webp'];
$allowed_docs   = ['pdf','doc','docx'];
$material_dir = "uploads/materials/";
if (!file_exists($material_dir)) { mkdir($material_dir, 0777, true); }

/* ==
   HANDLE UPLOAD MATERIAL
== */
if (isset($_POST['upload_material'])) {
    validateCsrf();
    $title     = trim($_POST['title'] ?? '');
    $course_id = intval($_POST['course_id'] ?? 0);
    if ($title === "" || $course_id === 0) { die("Invalid input"); }

    $courseCheck = $pdo->prepare("SELECT id FROM courses WHERE id=?");
    $courseCheck->execute([$course_id]);
    if (!$courseCheck->fetch()) { die("Selected course does not exist."); }

    if (!empty($_FILES['file']['name'])) {
        $fileName = $_FILES['file']['name'];
        $fileTmp  = $_FILES['file']['tmp_name'];
        $fileSize = $_FILES['file']['size'];
        $ext      = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if (!in_array($ext, array_merge($allowed_images, $allowed_docs), true)) { die("Only PDF, DOC, DOCX, and Images allowed"); }
        if ($fileSize > 10 * 1024 * 1024) { die("File too large (max 10MB)"); }

        $newFile = time() . '_' . rand(1000, 9999) . '.' . $ext;
        if (!move_uploaded_file($fileTmp, $material_dir . $newFile)) { die("Upload failed."); }
        $type = in_array($ext, $allowed_docs, true) ? strtoupper($ext) : "IMAGE";

        $stmt = $pdo->prepare("INSERT INTO course_contents(course_id,content_title,content_type,content_file) VALUES(?,?,?,?)");
        $stmt->execute([$course_id, $title, $type, $material_dir . $newFile]);

        logActivity($pdo, $user_id, "Uploaded material: $title");
        $_SESSION['success'] = "Material \"$title\" uploaded.";
    } else {
        $_SESSION['course_errors'] = ["No file selected."];
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ==
   VIDEO MANAGEMENT
== */
$video_dir = "uploads/videos/";
if (!file_exists($video_dir)) { mkdir($video_dir, 0777, true); }

$editVideo = null;
if (isset($_GET['edit'])) {
    $vid_edit_id = (int)$_GET['edit'];
    $stmt = $pdo->prepare("SELECT * FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $vid_edit_id, PDO::PARAM_INT);
    $stmt->execute();
    $editVideo = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

if (isset($_POST['upload_video'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }

    $course_id   = (int)($_POST['course_id'] ?? 0);
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $access_type = ($_POST['access_type'] ?? 'free') === 'paid' ? 'paid' : 'free';
    $cloud_url   = trim($_POST['cloud_url'] ?? '');

    $local_path    = null;
    $file_size     = 0;
    $mime_type     = null;
    $upload_status = 'cloud';

    if (!empty($_FILES['video']['name'])) {
        if (!isValidVideo($_FILES['video']['tmp_name'])) { die("Only MP4, WEBM, OGG allowed"); }
        $filename   = time() . "_" . basename($_FILES['video']['name']);
        $local_path = $video_dir . $filename;
        if (move_uploaded_file($_FILES['video']['tmp_name'], $local_path)) {
            $file_size     = $_FILES['video']['size'];
            $mime_type     = mime_content_type($local_path);
            $upload_status = 'local';
        } else {
            $local_path = null;
        }
    }

    $stmt = $pdo->prepare(
        "INSERT INTO course_videos
            (course_id, title, local_path, cloud_url, upload_status, file_size, mime_type, access_type, uploaded_by, description)
         VALUES (:course_id, :title, :local_path, :cloud_url, :upload_status, :file_size, :mime_type, :access_type, :uploaded_by, :description)"
    );
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

    logActivity($pdo, $user_id, "Uploaded video \"$title\"");
    $_SESSION['success'] = "Video \"$title\" uploaded.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#videoSection"); exit;
}

if (isset($_POST['update_video'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }

    $vid_id      = (int)($_POST['video_id'] ?? 0);
    $course_id   = (int)($_POST['course_id'] ?? 0);
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $cloud_url   = trim($_POST['cloud_url'] ?? '');
    $access_type = ($_POST['access_type'] ?? 'free') === 'paid' ? 'paid' : 'free';

    if (!empty($_FILES['video']['name'])) {
        $stmt = $pdo->prepare("SELECT local_path FROM course_videos WHERE id=:id");
        $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
        $stmt->execute();
        $old = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!empty($old['local_path']) && file_exists($old['local_path'])) { unlink($old['local_path']); }

        if (!isValidVideo($_FILES['video']['tmp_name'])) { die("Invalid video file"); }
        $filename   = time() . "_" . basename($_FILES['video']['name']);
        $local_path = $video_dir . $filename;
        if (move_uploaded_file($_FILES['video']['tmp_name'], $local_path)) {
            $stmt = $pdo->prepare("UPDATE course_videos SET local_path=:local_path, upload_status='local' WHERE id=:id");
            $stmt->bindParam(':local_path', $local_path, PDO::PARAM_STR);
            $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
            $stmt->execute();
        }
    }

    $stmt = $pdo->prepare(
        "UPDATE course_videos
         SET course_id=:course_id, title=:title, description=:description, cloud_url=:cloud_url, access_type=:access_type
         WHERE id=:id"
    );
    $stmt->bindParam(':course_id', $course_id, PDO::PARAM_INT);
    $stmt->bindParam(':title', $title, PDO::PARAM_STR);
    $stmt->bindParam(':description', $description, PDO::PARAM_STR);
    $stmt->bindParam(':cloud_url', $cloud_url, PDO::PARAM_STR);
    $stmt->bindParam(':access_type', $access_type, PDO::PARAM_STR);
    $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
    $stmt->execute();

    logActivity($pdo, $user_id, "Updated video #$vid_id");
    $_SESSION['success'] = "Video updated.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#videoSection"); exit;
}

if (isset($_POST['delete_video'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }

    $vid_id = (int)($_POST['video_id'] ?? 0);
    $stmt = $pdo->prepare("SELECT local_path FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
    $stmt->execute();
    $video = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!empty($video['local_path']) && file_exists($video['local_path'])) { unlink($video['local_path']); }

    $stmt = $pdo->prepare("DELETE FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
    $stmt->execute();

    logActivity($pdo, $user_id, "Deleted video #$vid_id");
    $_SESSION['success'] = "Video deleted.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#videoSection"); exit;
}

if (isset($_GET['view_video'])) {
    $vid_id = (int)$_GET['view_video'];
    $stmt = $pdo->prepare("SELECT * FROM course_videos WHERE id=:id");
    $stmt->bindParam(':id', $vid_id, PDO::PARAM_INT);
    $stmt->execute();
    $video = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$video) { die("Video not found"); }

    if ($video['access_type'] == 'paid') {
        $check = $pdo->prepare(
            "SELECT 1 FROM enrollments WHERE user_id=:user_id AND course_id=:course_id AND status IN ('ongoing','completed','approved')"
        );
        $check->bindParam(':user_id', $user_id, PDO::PARAM_INT);
        $check->bindParam(':course_id', $video['course_id'], PDO::PARAM_INT);
        $check->execute();
        if ($check->rowCount() == 0 && !$is_staff) {
            die("<h2>Access Denied</h2><p>You must enroll in this course to watch this video.</p>");
        }
    }

    $isLocal  = !empty($video['local_path']);
    $videoSrc = $isLocal ? $video['local_path'] : convertDriveLink($video['cloud_url'] ?? '');
    ?>
    <div style="padding:20px;font-family:Arial;">
        <h2><?= htmlspecialchars($video['title']) ?></h2>
        <?php if ($isLocal): ?>
            <video width="100%" height="480" controls src="<?= htmlspecialchars($videoSrc) ?>"></video>
        <?php elseif (!empty($videoSrc)): ?>
            <iframe src="<?= htmlspecialchars($videoSrc) ?>" width="100%" height="480" allow="autoplay" frameborder="0"></iframe>
        <?php endif; ?>
        <p style="white-space:pre-line;margin-top:14px;"><?= nl2br(htmlspecialchars($video['description'] ?? '')) ?></p>
    </div>
    <?php
    exit;
}

/* ==
   ENROLLMENT ACTIONS
== */
if (isset($_POST['enroll_action'])) {
    validateCsrf();
    $enroll_id = intval($_POST['enroll_id']);
    $action    = $_POST['action'];
    if ($action == "approve") { $pdo->prepare("UPDATE enrollments SET status='approved' WHERE id=?")->execute([$enroll_id]); }
    if ($action == "reject")  { $pdo->prepare("DELETE FROM enrollments WHERE id=?")->execute([$enroll_id]); }
    if ($action == "delete")  { $pdo->prepare("UPDATE enrollments SET status='deleted'  WHERE id=?")->execute([$enroll_id]); }
    logActivity($pdo, $user_id, "Enrollment #$enroll_id action: $action");
}

/* ==
   STUDENT ACTIONS
== */
if (isset($_POST['student_action'])) {
    validateCsrf();
    $sid    = intval($_POST['student_id'] ?? 0);
    $saction = $_POST['action'] ?? '';
    if ($sid > 0) {
        if ($saction === 'activate') { $pdo->prepare("UPDATE users SET status='active' WHERE id=?")->execute([$sid]); logActivity($pdo,$user_id,"Activated student #$sid"); $_SESSION['success'] = "Student activated."; }
        if ($saction === 'suspend')  { $pdo->prepare("UPDATE users SET status='suspended' WHERE id=?")->execute([$sid]); logActivity($pdo,$user_id,"Suspended student #$sid"); $_SESSION['success'] = "Student suspended."; }
        if ($saction === 'mark_alumni') { $pdo->prepare("UPDATE users SET is_alumni=1 WHERE id=?")->execute([$sid]); logActivity($pdo,$user_id,"Marked student #$sid as alumni"); $_SESSION['success'] = "Student marked as alumni."; }
        if ($saction === 'delete') {
            if (isset($_SESSION['user_id']) && (int)$_SESSION['user_id'] === $sid) {
                $_SESSION['course_errors'] = ["You cannot delete your own account."];
            } else {
                $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$sid]);
                logActivity($pdo,$user_id,"Deleted student #$sid");
                $_SESSION['success'] = "Student deleted.";
            }
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

if (isset($_POST['reset_student_password'])) {
    validateCsrf();
    $sid      = intval($_POST['student_id'] ?? 0);
    $new_pass = $_POST['new_password'] ?? '';
    if ($sid > 0 && strlen($new_pass) >= 6) {
        $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hashed, $sid]);
        logActivity($pdo,$user_id,"Reset password for user #$sid");
        $_SESSION['success'] = "Password reset.";
    } else {
        $_SESSION['course_errors'] = ["Password must be at least 6 characters."];
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ======
   UPDATE STUDENT PROFESSIONAL PROFILE
   (licence/registration no., qualification level, KRA PIN)
   ====== */
if (isset($_POST['update_profile_fields'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $pid = intval($_POST['profile_user_id'] ?? 0);
    $license = trim($_POST['license_no'] ?? '');
    $qual    = trim($_POST['qualification_level'] ?? '');
    $kra     = trim($_POST['kra_pin'] ?? '');
    if ($pid > 0) {
        $pdo->prepare("UPDATE users SET license_no=?, qualification_level=?, kra_pin=? WHERE id=?")
            ->execute([$license, $qual, $kra, $pid]);
        logActivity($pdo, $user_id, "Updated professional profile fields for user #$pid");
        $_SESSION['success'] = "Profile updated.";
    }
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

/* ==
   FETCH DATA
== */
$students = $pdo->query(
    "SELECT u.*, s.student_no, s.id AS student_row_id, s.verification_status AS student_verification_status,
            s.license_number AS student_license_number, s.qualification_level AS student_qualification_level
     FROM users u
     LEFT JOIN students s ON s.user_id = u.id
     WHERE u.role='student'
     ORDER BY u.id DESC"
);

$enrollments_result = $pdo->query(
    "SELECT e.*, u.full_name, s.student_no, c.title
     FROM enrollments e
     JOIN users u ON e.user_id = u.id
     LEFT JOIN students s ON s.user_id = e.user_id
     JOIN courses c ON e.course_id = c.id
     ORDER BY e.id DESC"
);
$enrollments_data = $enrollments_result->fetchAll(PDO::FETCH_ASSOC);

/* ==
   TEACHERS
== */
$teachers = $pdo->query(
    "SELECT t.id, u.full_name FROM teachers t JOIN users u ON t.user_id = u.id ORDER BY u.full_name ASC"
);

$courses = $pdo->query(
    "SELECT c.*, u.full_name FROM courses c
     LEFT JOIN teachers t ON c.teacher_id = t.id
     LEFT JOIN users u ON t.user_id = u.id
     ORDER BY c.id DESC"
);

/* ==
   NOTES
== */
$teacher_id = 1; // TODO: replace with the actual logged-in teacher's id if notes need to be scoped per teacher

$notes_dir = "uploads/notes/";
if (!file_exists($notes_dir)) { mkdir($notes_dir, 0777, true); }

if (isset($_POST['add_note'])) {
    validateCsrf();
    $course_id   = intval($_POST['course_id']);
    $title       = trim($_POST['title']);
    $content     = trim($_POST['content']);
    $access_type = $_POST['access_type'];
    $file_path   = "";
    if (!empty($_FILES['file']['name'])) {
        $file_name = time() . "_" . basename($_FILES['file']['name']);
        $target    = $notes_dir . $file_name;
        move_uploaded_file($_FILES['file']['tmp_name'], $target);
        $file_path = $target;
    }
    $stmt = $pdo->prepare("INSERT INTO notes(course_id,title,content,access_type,created_by,file_path) VALUES(?,?,?,?,?,?)");
    $stmt->execute([$course_id, $title, $content, $access_type, $teacher_id, $file_path]);
}

if (isset($_GET['delete_note'])) {
    $id = intval($_GET['delete_note']);
    $stmt = $pdo->prepare("SELECT file_path FROM notes WHERE id=?");
    $stmt->execute([$id]);
    $old = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!empty($old['file_path']) && file_exists($old['file_path'])) { unlink($old['file_path']); }
    $pdo->prepare("DELETE FROM notes WHERE id=?")->execute([$id]);
    header("Location: " . $_SERVER['PHP_SELF']); exit;
}

if (isset($_GET['view_note'])) {
    $note_id = intval($_GET['view_note']);
    $stmt = $pdo->prepare("SELECT n.*, c.course_type FROM notes n JOIN courses c ON c.id=n.course_id WHERE n.id=?");
    $stmt->execute([$note_id]);
    $note = $stmt->fetch(PDO::FETCH_ASSOC);

    $check = $pdo->prepare("SELECT * FROM enrollments WHERE user_id=? AND course_id=? AND status IN ('ongoing','completed','approved')");
    $check->execute([$user_id, $note['course_id']]);
    $isEnrolled = $check->rowCount() > 0;

    if ($note['access_type'] == 'paid' && !$isEnrolled) { die("<h2>Access Denied</h2><p>You must enroll to access this note.</p>"); }
    ?>
    <div style="padding:20px;font-family:Arial;user-select:none;">
        <h2><?= htmlspecialchars($note['title']); ?></h2>
        <?php if ($note['file_path']) { ?>
            <iframe src="<?= htmlspecialchars($note['file_path']); ?>" width="100%" height="500px"></iframe>
        <?php } ?>
        <p style="white-space:pre-line;"><?= htmlspecialchars($note['content']); ?></p>
    </div>
    <script>
        document.addEventListener("contextmenu", e => e.preventDefault());
        document.addEventListener("copy",  e => e.preventDefault());
        document.addEventListener("cut",   e => e.preventDefault());
        document.addEventListener("paste", e => e.preventDefault());
    </script>
    <?php exit;
}

$notes_stmt = $pdo->prepare(
    "SELECT n.*, c.title AS course_title FROM notes n
     JOIN courses c ON c.id = n.course_id
     JOIN course_teachers ct ON ct.course_id = c.id
     WHERE ct.teacher_id = ?"
);
$notes_stmt->execute([$teacher_id]);
$notes = $notes_stmt;

/* ==
   QUIZ
== */
if (isset($_POST['create_quiz'])) {
    validateCsrf();
    $course_id     = intval($_POST['course_id']);
    $title         = trim($_POST['title']);
    $description   = trim($_POST['description']);
    $passing_marks = intval($_POST['passing_marks']);
    $duration      = intval($_POST['duration']);
    $stmt = $pdo->prepare("INSERT INTO quizzes(course_id,title,description,passing_score,duration) VALUES (?,?,?,?,?)");
    $stmt->execute([$course_id, $title, $description, $passing_marks, $duration]);
}

if (isset($_POST['add_question'])) {
    validateCsrf();
    $quiz_id        = intval($_POST['quiz_id']);
    $question       = trim($_POST['question']);
    $question_type  = $_POST['question_type'];
    $option_a       = $_POST['option_a'] ?? null;
    $option_b       = $_POST['option_b'] ?? null;
    $option_c       = $_POST['option_c'] ?? null;
    $option_d       = $_POST['option_d'] ?? null;
    $correct_answer = trim($_POST['correct_answer']);
    $marks          = intval($_POST['marks']);

    $check = $pdo->prepare("SELECT id FROM quizzes WHERE id=?");
    $check->execute([$quiz_id]);
    if ($check->rowCount() == 0) { die("Error: Selected quiz does not exist."); }

    $stmt = $pdo->prepare("INSERT INTO quiz_questions(quiz_id,question,question_type,option_a,option_b,option_c,option_d,correct_answer,marks) VALUES (?,?,?,?,?,?,?,?,?)");
    $ok = $stmt->execute([$quiz_id, $question, $question_type, $option_a, $option_b, $option_c, $option_d, $correct_answer, $marks]);
    $ok ? print("Question added") : print("Error inserting question");
}

/* ==
   QUIZ STATS
== */
$total_quizzes   = $pdo->query("SELECT COUNT(*) total FROM quizzes")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$total_questions = $pdo->query("SELECT COUNT(*) total FROM quiz_questions")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$total_attempts  = $pdo->query("SELECT COUNT(*) total FROM quiz_results")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$passed          = $pdo->query("SELECT COUNT(*) total FROM quiz_results WHERE status='passed'")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$failed_quiz     = $pdo->query("SELECT COUNT(*) total FROM quiz_results WHERE status='failed'")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$average_score   = $pdo->query("SELECT AVG(score) avg_score FROM quiz_results")->fetch(PDO::FETCH_ASSOC)['avg_score'] ?? 0;

/* ==
   ENROLLMENT BULK ACTIONS
== */
if (isset($_GET['approve'])) {
    $id = intval($_GET['approve']);
    $pdo->prepare("UPDATE enrollments SET status='approved' WHERE id=?")->execute([$id]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#enrollmentSection"); exit;
}
if (isset($_GET['reject'])) {
    $id = intval($_GET['reject']);
    $pdo->prepare("DELETE FROM enrollments WHERE id=?")->execute([$id]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#enrollmentSection"); exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['approve_all'])) { validateCsrf(); $pdo->exec("UPDATE enrollments SET status='approved' WHERE status IN ('pending','ongoing')"); }
    if (isset($_POST['reject_all']))  { validateCsrf(); $pdo->exec("DELETE FROM enrollments WHERE status IN ('pending','ongoing')"); }
    if (isset($_POST['clear_all']))   { validateCsrf(); $pdo->exec("DELETE FROM enrollments"); }
}

/* ==
   PAYMENT
== */
if (isset($_GET['action']) && isset($_GET['id'])) {
    $id     = intval($_GET['id']);
    $action = $_GET['action'];
    if (in_array($action, ['completed', 'failed', 'pending'], true)) {

        $pstmt = $pdo->prepare("SELECT * FROM payments WHERE id=?");
        $pstmt->execute([$id]);
        $payRow = $pstmt->fetch(PDO::FETCH_ASSOC);

        if ($payRow) {
            $verification = $action === 'completed' ? 'verified' : ($action === 'failed' ? 'rejected' : 'pending');
            $admin_id     = $_SESSION['user_id'] ?? null;

            $stmt = $pdo->prepare(
                "UPDATE payments
                 SET status = ?, verification_status = ?, verified_by = ?, verified_at = NOW()
                 WHERE id = ?"
            );
            $stmt->execute([$action, $verification, $admin_id, $id]);

            if ($action === 'completed') {
                $check = $pdo->prepare("SELECT id, status FROM enrollments WHERE user_id=? AND course_id=?");
                $check->execute([$payRow['user_id'], $payRow['course_id']]);
                $enr = $check->fetch(PDO::FETCH_ASSOC);

                if ($enr) {
                    if (!in_array($enr['status'], ['approved', 'ongoing', 'completed'], true)) {
                        $pdo->prepare("UPDATE enrollments SET status='approved' WHERE id=?")->execute([$enr['id']]);
                    }
                } else {
                    $pdo->prepare(
                        "INSERT INTO enrollments (user_id, course_id, status, progress, enrolled_at)
                         VALUES (?, ?, 'approved', 0, NOW())"
                    )->execute([$payRow['user_id'], $payRow['course_id']]);
                }

                logActivity($pdo, $admin_id ?: 1, "Verified " . strtoupper($payRow['payment_method']) . " payment #$id and enrolled user #{$payRow['user_id']} in course #{$payRow['course_id']}");

                // Referral commission settlement, if this payment was tied to a referral use.
                $ru = $pdo->prepare("SELECT * FROM stp_referral_uses WHERE referred_user_id=? AND course_id=? AND status='pending' LIMIT 1");
                $ru->execute([$payRow['user_id'], $payRow['course_id']]);
                $refUse = $ru->fetch(PDO::FETCH_ASSOC);
                if ($refUse) {
                    $pdo->prepare("UPDATE stp_referral_uses SET amount=?, commission=? WHERE id=?")
                        ->execute([$payRow['amount'], round($payRow['amount'] * 0.05, 2), $refUse['id']]);
                }

            } elseif ($action === 'failed') {
                $pdo->prepare("DELETE FROM enrollments WHERE user_id=? AND course_id=? AND status='pending'")
                    ->execute([$payRow['user_id'], $payRow['course_id']]);
            }
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#paymentSection"); exit;
}

$successful = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='completed'")->fetch(PDO::FETCH_ASSOC)['total'];
$failed     = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='failed'")->fetch(PDO::FETCH_ASSOC)['total'];
$pending    = $pdo->query("SELECT COUNT(*) AS total FROM payments WHERE status='pending'")->fetch(PDO::FETCH_ASSOC)['total'];

$daily   = $pdo->query("SELECT SUM(amount) AS total FROM payments WHERE status='completed' AND DATE(created_at)=CURDATE()")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$monthly = $pdo->query("SELECT SUM(amount) AS total FROM payments WHERE status='completed' AND MONTH(created_at)=MONTH(CURDATE()) AND YEAR(created_at)=YEAR(CURDATE())")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;
$yearly  = $pdo->query("SELECT SUM(amount) AS total FROM payments WHERE status='completed' AND YEAR(created_at)=YEAR(CURDATE())")->fetch(PDO::FETCH_ASSOC)['total'] ?? 0;

$methods       = $pdo->query("SELECT payment_method, COUNT(*) AS total, SUM(amount) AS revenue FROM payments WHERE status='completed' GROUP BY payment_method");
$courseRevenue = $pdo->query("SELECT c.title, SUM(p.amount) AS total FROM payments p JOIN courses c ON p.course_id=c.id WHERE p.status='completed' GROUP BY p.course_id, c.title ORDER BY total DESC");
$payments = $pdo->query(
    "SELECT p.*, c.title AS course_title
     FROM payments p
     LEFT JOIN courses c ON c.id = p.course_id
     ORDER BY p.created_at DESC LIMIT 20"
);

/* ==
   INVOICES / eTIMS (KRA compliance capture — draft/queued state;
   final submission depends on the organisation's live KRA eTIMS
   API credentials, which are outside this file's scope)
== */
if (isset($_POST['create_invoice'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $inv_user_id   = intval($_POST['user_id'] ?? 0);
    $inv_course_id = intval($_POST['course_id'] ?? 0);
    $inv_amount    = (float)($_POST['amount'] ?? 0);
    $inv_kra       = trim($_POST['kra_pin'] ?? '');
    $tax_amount    = round($inv_amount * 0.16 / 1.16, 2); // VAT component assuming amount is tax-inclusive

    $year = date('Y');
    $seqStmt = $pdo->query("SELECT COUNT(*) FROM stp_invoices WHERE YEAR(created_at)=" . (int)$year);
    $seq = (int)$seqStmt->fetchColumn() + 1;
    $invoiceNo = sprintf("INV-%s-%05d", $year, $seq);

    $stmt = $pdo->prepare("INSERT INTO stp_invoices(invoice_no,user_id,course_id,kra_pin,amount,tax_amount,etims_status) VALUES(?,?,?,?,?,?,'draft')");
    $stmt->execute([$invoiceNo, $inv_user_id ?: null, $inv_course_id ?: null, $inv_kra ?: null, $inv_amount, $tax_amount]);
    logActivity($pdo, $user_id, "Created invoice $invoiceNo");
    $_SESSION['success'] = "Invoice $invoiceNo created (draft — pending eTIMS submission).";
    header("Location: " . $_SERVER['PHP_SELF'] . "#invoiceSection"); exit;
}

$stp_invoices = $pdo->query(
    "SELECT i.*, u.full_name, c.title AS course_title
     FROM stp_invoices i
     LEFT JOIN users u ON u.id=i.user_id
     LEFT JOIN courses c ON c.id=i.course_id
     ORDER BY i.id DESC LIMIT 50"
);

/* ==
   ANNOUNCEMENTS
== */
if (isset($_POST['add'])) {
    validateCsrf();
    $course_id = intval($_POST['course_id']);
    $ann_title = trim($_POST['title']);
    $ann_msg   = trim($_POST['message']);
    if ($course_id > 0 && $ann_title !== '' && $ann_msg !== '') {
        $check = $pdo->prepare("SELECT 1 FROM course_teachers WHERE course_id=? AND teacher_id=?");
        $check->execute([$course_id, $teacher_id]);
        if ($check->rowCount() > 0) {
            $stmt = $pdo->prepare("INSERT INTO announcements(course_id,teacher_id,title,message) VALUES(?,?,?,?)");
            $stmt->execute([$course_id, $teacher_id, $ann_title, $ann_msg]);
        }
    }
}

if (isset($_GET['delete_ann'])) {
    $id = intval($_GET['delete_ann']);
    $stmt = $pdo->prepare("DELETE FROM announcements WHERE id=? AND teacher_id=?");
    $stmt->execute([$id, $teacher_id]);
}

$ann_courses_stmt = $pdo->prepare("SELECT c.id,c.title FROM courses c INNER JOIN course_teachers ct ON ct.course_id=c.id WHERE ct.teacher_id=?");
$ann_courses_stmt->execute([$teacher_id]);
$ann_courses = $ann_courses_stmt;

$announcements_stmt = $pdo->prepare("SELECT a.*, c.title AS course FROM announcements a INNER JOIN courses c ON c.id=a.course_id WHERE a.teacher_id=? ORDER BY a.created_at DESC");
$announcements_stmt->execute([$teacher_id]);
$announcements = $announcements_stmt;

/* ==
   ADD TEACHER (extended: licence/registration no. + KRA PIN)
== */
date_default_timezone_set("Africa/Nairobi");
include "sendmail1.php";

$message     = "";
$messageType = "";

if (isset($_POST['add_teacher'])) {
    validateCsrf();
    $full_name        = trim($_POST['full_name']);
    $email            = strtolower(trim($_POST['email']));
    $phone            = trim($_POST['phone'] ?? '');
    $password         = $_POST['password'];
    $employee_no      = trim($_POST['employee_no'] ?? '');
    $license_no       = trim($_POST['license_no'] ?? '');
    $specialization   = trim($_POST['specialization'] ?? '');
    $qualification    = trim($_POST['qualification'] ?? '');
    $experience_years = (int)($_POST['experience_years'] ?? 0);
    $kra_pin          = trim($_POST['kra_pin'] ?? '');

    if (empty($full_name) || empty($email) || empty($password)) {
        $message = "Full name, email and password are required!"; $messageType = "error";
    } else {
        $check = $pdo->prepare("SELECT id FROM pending_teachers WHERE email=?");
        $check->execute([$email]);
        if ($check->rowCount() > 0) {
            $message = "Email already exists!"; $messageType = "error";
        } else {
            $role_stmt = $pdo->prepare("SELECT id FROM roles WHERE role_name='teacher'");
            $role_stmt->execute();
            $role_data = $role_stmt->fetch(PDO::FETCH_ASSOC);
            if (!$role_data) {
                $message = "Role 'teacher' not found!"; $messageType = "error";
            } else {
                $role_id        = $role_data['id'];
                $otp            = rand(100000, 999999);
                $expiry         = date("Y-m-d H:i:s", strtotime("+10 minutes"));
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO pending_teachers(full_name,email,phone,password,role_id,employee_no,license_no,specialization,qualification,experience_years,kra_pin,otp,otp_expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
                try {
                    $stmt->execute([$full_name, $email, $phone, $hashedPassword, $role_id, $employee_no, $license_no, $specialization, $qualification, $experience_years, $kra_pin, $otp, $expiry]);
                    sendOTP($email, $full_name, $otp);
                    header("Location: verify2.php?email=" . urlencode($email)); exit;
                } catch (PDOException $e) {
                    $message = "Database error: " . $e->getMessage(); $messageType = "error";
                }
            }
        }
    }
}

/* ==
   PAYMENT STATUS COUNTS
== */
$successful_payments = 0; $pending_payments = 0; $failed_payments = 0;
$result = $pdo->query("SELECT status, COUNT(*) AS total FROM payments GROUP BY status");
foreach ($result as $row) {
    if ($row['status'] == 'completed') { $successful_payments = $row['total']; }
    if ($row['status'] == 'pending')   { $pending_payments    = $row['total']; }
    if ($row['status'] == 'failed')    { $failed_payments     = $row['total']; }
}

/* ==
   CHART DATA
== */
$revenue_labels = []; $revenue_values = [];
$rq = $pdo->query("SELECT DATE_FORMAT(MIN(payment_date),'%b %Y') AS month_name, SUM(amount) AS total FROM payments WHERE status='completed' AND payment_date IS NOT NULL GROUP BY YEAR(payment_date), MONTH(payment_date) ORDER BY YEAR(payment_date), MONTH(payment_date)");
if ($rq) { foreach ($rq as $row) { $revenue_labels[] = $row['month_name']; $revenue_values[] = (float)$row['total']; } }

$student_labels = []; $student_values = []; $running_total = 0;
$sq = $pdo->query("SELECT DATE_FORMAT(MIN(created_at),'%b %Y') AS month_name, COUNT(*) AS total FROM users WHERE role='student' GROUP BY YEAR(created_at), MONTH(created_at) ORDER BY YEAR(created_at), MONTH(created_at)");
if ($sq) { foreach ($sq as $row) { $running_total += $row['total']; $student_labels[] = $row['month_name']; $student_values[] = $running_total; } }

$enrollment_labels = []; $enrollment_values = [];
$eq = $pdo->query("SELECT DATE_FORMAT(MIN(enrolled_at),'%b %Y') AS month_name, COUNT(*) AS total FROM enrollments GROUP BY YEAR(enrolled_at), MONTH(enrolled_at) ORDER BY YEAR(enrolled_at), MONTH(enrolled_at)");
if ($eq) { foreach ($eq as $row) { $enrollment_labels[] = $row['month_name']; $enrollment_values[] = (int)$row['total']; } }

if (empty($revenue_labels))    { $revenue_labels    = ['No Data']; $revenue_values    = [0]; }
if (empty($student_labels))    { $student_labels    = ['No Data']; $student_values    = [0]; }
if (empty($enrollment_labels)) { $enrollment_labels = ['No Data']; $enrollment_values = [0]; }

/* ==
   STUDENT PAYMENT MONITORING
== */
$student_payments = $pdo->query(
    "SELECT p.id,
        COALESCE(u.full_name, p.payer_name)  AS student_name,
        COALESCE(u.email, p.payer_email)     AS email,
        s.student_no,
        c.title AS course,
        p.amount, p.payment_method, p.status, p.verification_status,
        p.transaction_code, p.mpesa_receipt, p.payer_name, p.payer_phone, p.payer_email,
        p.notes, p.payment_date, p.created_at
     FROM payments p
     LEFT JOIN users u ON u.email = p.payer_email
     LEFT JOIN students s ON s.user_id = u.id
     LEFT JOIN courses c ON p.course_id = c.id
     ORDER BY p.created_at DESC"
);

/* ==
   CERTIFICATES
== */
if (isset($_POST['issue_certificate'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $cu = intval($_POST['user_id'] ?? 0);
    $cc = intval($_POST['course_id'] ?? 0);
    if ($cu > 0 && $cc > 0) {
        $check = $pdo->prepare("SELECT id FROM stp_certificates WHERE user_id=? AND course_id=?");
        $check->execute([$cu, $cc]);
        if ($check->fetchColumn()) {
            $_SESSION['course_errors'] = ["Certificate already issued for this student/course."];
        } else {
            $certNo = generateCertificateNumber($pdo);
            $pdo->prepare("INSERT INTO stp_certificates(user_id,course_id,cert_number) VALUES(?,?,?)")->execute([$cu, $cc, $certNo]);
            logActivity($pdo, $user_id, "Manually issued certificate $certNo");
            $_SESSION['success'] = "Certificate $certNo issued.";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#certificateSection"); exit;
}

if (isset($_GET['view_cert'])) {
    $cid = intval($_GET['view_cert']);
    $cstmt = $pdo->prepare(
        "SELECT cert.*, u.full_name, c.title AS course_title
         FROM stp_certificates cert
         JOIN users u ON u.id=cert.user_id
         JOIN courses c ON c.id=cert.course_id
         WHERE cert.id=?"
    );
    $cstmt->execute([$cid]);
    $cert = $cstmt->fetch(PDO::FETCH_ASSOC);
    if (!$cert) { die("Certificate not found."); }
    $verifyUrl = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . '/verify_certificate.php?cert=' . urlencode($cert['cert_number']);
    $qrImg = "https://api.qrserver.com/v1/create-qr-code/?size=140x140&data=" . urlencode($verifyUrl);
    ?>
    <div style="font-family:Arial;padding:40px;border:10px solid #0f766e;max-width:800px;margin:30px auto;text-align:center;">
        <h3 style="letter-spacing:2px;color:#0f766e;">CBT-KENYA SKILLS TRANSFER PROGRAMME</h3>
        <h1 style="margin:18px 0 6px;">Certificate of Completion</h1>
        <p style="color:#64748b;">This is to certify that</p>
        <h2 style="margin:10px 0;"><?= htmlspecialchars($cert['full_name']) ?></h2>
        <p style="color:#64748b;">has successfully completed the course</p>
        <h3 style="margin:8px 0 20px;"><?= htmlspecialchars($cert['course_title']) ?></h3>
        <p>Issued on <?= date('d M Y', strtotime($cert['issued_at'])) ?></p>
        <p style="font-size:12px;color:#94a3b8;margin-top:20px;">Certificate No: <?= htmlspecialchars($cert['cert_number']) ?></p>
        <img src="<?= htmlspecialchars($qrImg) ?>" alt="Verification QR" style="margin-top:14px;">
        <p style="font-size:11px;color:#94a3b8;">Scan to verify authenticity</p>
    </div>
    <?php exit;
}

$certificates_list = $pdo->query(
    "SELECT cert.*, u.full_name, c.title AS course_title
     FROM stp_certificates cert
     JOIN users u ON u.id=cert.user_id
     JOIN courses c ON c.id=cert.course_id
     ORDER BY cert.id DESC LIMIT 100"
);

/* ==
   REFERRALS
== */
if (isset($_POST['generate_referral_code'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $ref_user = intval($_POST['referral_user_id'] ?? 0);
    $ref_rate = (float)($_POST['commission_rate'] ?? 5);
    if ($ref_user > 0) {
        $u = $pdo->prepare("SELECT full_name FROM users WHERE id=?");
        $u->execute([$ref_user]);
        $uname = $u->fetchColumn() ?: 'USER';
        $slug = strtoupper(preg_replace('/[^A-Z0-9]/i', '', explode(' ', $uname)[0] ?: 'REF'));
        $code = "STP-" . substr($slug, 0, 8) . "-" . date('Y') . "-" . rand(100, 999);
        $pdo->prepare("INSERT INTO stp_referrals (user_id,code,commission_rate) VALUES(?,?,?)")->execute([$ref_user, $code, $ref_rate]);
        logActivity($pdo, $user_id, "Generated referral code $code");
        $_SESSION['success'] = "Referral code $code generated.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#referralSection"); exit;
}

if (isset($_POST['mark_commission_paid'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $ru_id = intval($_POST['referral_use_id'] ?? 0);
    $pdo->prepare("UPDATE stp_referral_uses SET status='paid' WHERE id=?")->execute([$ru_id]);
    logActivity($pdo, $user_id, "Marked referral commission #$ru_id as paid");
    $_SESSION['success'] = "Commission marked as paid.";
    header("Location: " . $_SERVER['PHP_SELF'] . "#referralSection"); exit;
}

$referral_codes = $pdo->query(
    "SELECT r.*, u.full_name,
        (SELECT COUNT(*) FROM stp_referral_uses ru WHERE ru.referral_id=r.id) AS uses,
        (SELECT COALESCE(SUM(commission),0) FROM stp_referral_uses ru WHERE ru.referral_id=r.id AND ru.status='paid') AS paid_total,
        (SELECT COALESCE(SUM(commission),0) FROM stp_referral_uses ru WHERE ru.referral_id=r.id AND ru.status='pending') AS pending_total
     FROM stp_referrals r JOIN users u ON u.id=r.user_id
     ORDER BY r.id DESC"
);
$referral_uses_list = $pdo->query(
    "SELECT ru.*, r.code, ref_u.full_name AS referrer_name, c.title AS course_title
     FROM stp_referral_uses ru
     JOIN stp_referrals r ON r.id=ru.referral_id
     JOIN users ref_u ON ref_u.id=r.user_id
     LEFT JOIN courses c ON c.id=ru.course_id
     ORDER BY ru.id DESC LIMIT 100"
);

/* ==
   CPD / CME POINTS (admin-logged, legacy stp_cpd_points table)
== */
$cpd_annual_target = 40;
if (isset($_POST['add_cpd_points'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $cpd_user   = intval($_POST['cpd_user_id'] ?? 0);
    $cpd_activity = trim($_POST['activity'] ?? '');
    $cpd_points_val = intval($_POST['points'] ?? 0);
    $cpd_date   = $_POST['activity_date'] ?? date('Y-m-d');
    if ($cpd_user > 0 && $cpd_activity !== '' && $cpd_points_val > 0) {
        $pdo->prepare("INSERT INTO stp_cpd_points(user_id,activity,points,activity_date,created_by) VALUES(?,?,?,?,?)")
            ->execute([$cpd_user, $cpd_activity, $cpd_points_val, $cpd_date, $user_id]);
        logActivity($pdo, $user_id, "Logged $cpd_points_val CPD points ($cpd_activity) for user #$cpd_user");
        $_SESSION['success'] = "CPD points logged.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#cpdSection"); exit;
}

$cpd_summary = $pdo->query(
    "SELECT u.id, u.full_name, COALESCE(SUM(cp.points),0) AS total_points
     FROM users u
     LEFT JOIN stp_cpd_points cp ON cp.user_id=u.id AND YEAR(cp.activity_date)=YEAR(CURDATE())
     WHERE u.role IN ('student','teacher')
     GROUP BY u.id, u.full_name
     HAVING total_points > 0
     ORDER BY total_points DESC"
);
$cpd_recent = $pdo->query(
    "SELECT cp.*, u.full_name FROM stp_cpd_points cp JOIN users u ON u.id=cp.user_id ORDER BY cp.id DESC LIMIT 30"
);

/* ==
   PRACTICE SUPPORT HUB
== */
if (isset($_POST['add_resource'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }
    $res_cat   = trim($_POST['category'] ?? '');
    $res_title = trim($_POST['res_title'] ?? '');
    $res_desc  = trim($_POST['res_description'] ?? '');
    $res_link  = trim($_POST['res_link'] ?? '');
    $res_status = ($_POST['res_status'] ?? 'published') === 'draft' ? 'draft' : 'published';

    $res_file = null;
    if (!empty($_FILES['res_file']['name'])) {
        $res_dir = "uploads/practice_hub/";
        if (!file_exists($res_dir)) { mkdir($res_dir, 0777, true); }
        $ext = strtolower(pathinfo($_FILES['res_file']['name'], PATHINFO_EXTENSION));
        $newName = "res_" . time() . "_" . rand(1000,9999) . "." . $ext;
        if (move_uploaded_file($_FILES['res_file']['tmp_name'], $res_dir . $newName)) {
            $res_file = $res_dir . $newName;
        }
    }

    if ($res_cat !== '' && $res_title !== '') {
        $pdo->prepare("INSERT INTO stp_practice_resources(category,title,description,link,file_path,status) VALUES(?,?,?,?,?,?)")
            ->execute([$res_cat, $res_title, $res_desc, $res_link, $res_file, $res_status]);
        logActivity($pdo, $user_id, "Added Practice Hub resource: $res_title");
        $_SESSION['success'] = "Resource added to Practice Support Hub.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#practiceHubSection"); exit;
}

if (isset($_GET['delete_resource'])) {
    if (!$is_staff) { die("Unauthorized"); }
    $rid = intval($_GET['delete_resource']);
    $pdo->prepare("DELETE FROM stp_practice_resources WHERE id=?")->execute([$rid]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#practiceHubSection"); exit;
}

$stp_practice_resources = $pdo->query("SELECT * FROM stp_practice_resources ORDER BY id DESC");

/* ==
   PROMOTIONS / ADVERTISEMENTS
== */
if (isset($_POST['add_promotion'])) {
    validateCsrf();
    if (!$is_admin_up) { die("Unauthorized"); }
    $p_title = trim($_POST['promo_title'] ?? '');
    $p_desc  = trim($_POST['promo_description'] ?? '');
    $p_link  = trim($_POST['promo_link'] ?? '');
    $p_place = trim($_POST['placement'] ?? 'homepage');
    $p_start = $_POST['start_date'] ?? null;
    $p_end   = $_POST['end_date'] ?? null;

    $p_image = null;
    if (!empty($_FILES['promo_image']['name'])) {
        $promo_dir = "uploads/stp_promotions/";
        if (!file_exists($promo_dir)) { mkdir($promo_dir, 0777, true); }
        $ext = strtolower(pathinfo($_FILES['promo_image']['name'], PATHINFO_EXTENSION));
        $newName = "promo_" . time() . "_" . rand(1000,9999) . "." . $ext;
        if (move_uploaded_file($_FILES['promo_image']['tmp_name'], $promo_dir . $newName)) {
            $p_image = $promo_dir . $newName;
        }
    }

    if ($p_title !== '') {
        $pdo->prepare("INSERT INTO stp_promotions(title,description,image,link,placement,start_date,end_date,status) VALUES(?,?,?,?,?,?,?,'active')")
            ->execute([$p_title, $p_desc, $p_image, $p_link, $p_place, $p_start ?: null, $p_end ?: null]);
        logActivity($pdo, $user_id, "Created promotion: $p_title");
        $_SESSION['success'] = "Promotion created.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#promotionSection"); exit;
}

if (isset($_GET['archive_promotion'])) {
    if (!$is_admin_up) { die("Unauthorized"); }
    $pid = intval($_GET['archive_promotion']);
    $pdo->prepare("UPDATE stp_promotions SET status='archived' WHERE id=?")->execute([$pid]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#promotionSection"); exit;
}

$promotions_list = $pdo->query("SELECT * FROM stp_promotions ORDER BY id DESC");

/* ==
   ATTENDANCE
== */
if (isset($_POST['mark_attendance'])) {
    validateCsrf();
    if (!$is_staff) { die("Unauthorized"); }
    $att_course = intval($_POST['att_course_id'] ?? 0);
    $att_user   = intval($_POST['att_user_id'] ?? 0);
    $att_date   = $_POST['session_date'] ?? date('Y-m-d');
    $att_status = in_array($_POST['att_status'] ?? '', ['present','absent','excused'], true) ? $_POST['att_status'] : 'present';
    if ($att_course > 0 && $att_user > 0) {
        $pdo->prepare("INSERT INTO stp_attendance(course_id,user_id,session_date,status,marked_by) VALUES(?,?,?,?,?)")
            ->execute([$att_course, $att_user, $att_date, $att_status, $user_id]);
        $_SESSION['success'] = "Attendance recorded.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#attendanceSection"); exit;
}

$attendance_list = $pdo->query(
    "SELECT a.*, u.full_name, c.title AS course_title
     FROM stp_attendance a
     JOIN users u ON u.id=a.user_id
     JOIN courses c ON c.id=a.course_id
     ORDER BY a.id DESC LIMIT 100"
);

/* ==
   PENDING COURSE VERSIONS (for Approvals screen)
== */
$pending_versions = $pdo->query(
    "SELECT cv.*, c.title AS course_title, u.full_name AS submitted_by_name
     FROM stp_course_versions cv
     JOIN courses c ON c.id=cv.course_id
     JOIN users u ON u.id=cv.submitted_by
     WHERE cv.status='pending'
     ORDER BY cv.id DESC"
);
$version_history = $pdo->query(
    "SELECT cv.*, c.title AS course_title, u.full_name AS submitted_by_name, r.full_name AS reviewed_by_name
     FROM stp_course_versions cv
     JOIN courses c ON c.id=cv.course_id
     JOIN users u ON u.id=cv.submitted_by
     LEFT JOIN users r ON r.id=cv.reviewed_by
     WHERE cv.status <> 'pending'
     ORDER BY cv.id DESC LIMIT 50"
);

$flash_success = $_SESSION['success'] ?? ''; unset($_SESSION['success']);
$flash_errors  = $_SESSION['course_errors'] ?? []; unset($_SESSION['course_errors']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($branding['org_name']) ?> — Admin Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

<style>
:root {
    --primary:      <?= htmlspecialchars($branding['color_primary']) ?>;
    --primary-light:<?= htmlspecialchars($branding['color_primary_light']) ?>;
    --primary-dark: <?= htmlspecialchars($branding['color_primary_dark']) ?>;
    --success:      #10b981;
    --warning:      #f59e0b;
    --danger:       #ef4444;
    --info:         #0ea5e9;
    --accent:       <?= htmlspecialchars($branding['color_accent']) ?>;
    --bg:           #f1f5f9;
    --sidebar-bg:   #0b2321;
    --card-bg:      #ffffff;
    --text:         #0f172a;
    --muted:        #64748b;
    --border:       #e2e8f0;
    --radius:       14px;
    --shadow:       0 4px 20px rgba(0,0,0,0.06);
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
    font-family: 'Inter', Arial, sans-serif;
    background: var(--bg);
    display: flex;
    min-height: 100vh;
    overflow-x: hidden;
    color: var(--text);
}

.sidebar {
    width: 260px;
    background: var(--sidebar-bg);
    position: fixed;
    top: 0; left: 0; bottom: 0;
    overflow-y: auto;
    z-index: 1000;
    transition: width .3s;
}

.sidebar::-webkit-scrollbar { width: 4px; }
.sidebar::-webkit-scrollbar-thumb { background: #134e4a; border-radius: 4px; }

.logo {
    padding: 24px 20px 18px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo-icon {
    width: 38px; height: 38px;
    background: var(--primary);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; color: #fff; flex-shrink: 0;
    overflow: hidden;
}
.logo-icon img { width: 100%; height: 100%; object-fit: cover; }

.logo h2 { font-size: 17px; font-weight: 700; color: #fff; letter-spacing: -.3px; }
.logo span { font-size: 11px; color: #94a3b8; font-weight: 400; }

.menu { padding: 12px 0; }

.menu-label {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1px;
    color: #5eead4;
    padding: 14px 22px 6px;
    text-transform: uppercase;
}

.menu ul { list-style: none; }

.menu ul li a {
    text-decoration: none;
    color: #94a3b8;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 11px 22px;
    border-radius: 0;
    transition: all .2s;
    font-size: 14px;
    font-weight: 500;
    border-left: 3px solid transparent;
    margin: 1px 0;
}

.menu ul li a:hover,
.menu ul li a.active {
    background: rgba(255,255,255,.08);
    color: #fff;
    border-left-color: var(--primary-light);
}

.menu ul li a i { width: 18px; text-align: center; font-size: 15px; }
.nav-badge {
    margin-left: auto;
    background: #f87171;
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    border-radius: 20px;
    padding: 1px 7px;
    min-width: 18px;
    text-align: center;
}

.sidebar-footer {
    padding: 14px 20px;
    font-size: 11px;
    color: rgba(255,255,255,.65);
    border-top: 1px solid rgba(255,255,255,.15);
    line-height: 1.6;
}
.sidebar-footer a { color: #5eead4; text-decoration: none; }

.main {
    margin-left: 260px;
    flex: 1;
    padding: 24px;
    min-height: 100vh;
}

.topbar {
    background: var(--card-bg);
    padding: 16px 24px;
    border-radius: var(--radius);
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: var(--shadow);
    margin-bottom: 24px;
    border: 1px solid var(--border);
}

.topbar h1 { font-size: 22px; font-weight: 700; color: var(--text); }
.topbar-left { display: flex; align-items: center; gap: 14px; }
.topbar-right { display: flex; align-items: center; gap: 16px; }

.topbar-icon {
    width: 38px; height: 38px;
    border-radius: 10px;
    background: var(--bg);
    display: flex; align-items: center; justify-content: center;
    color: var(--muted);
    cursor: pointer;
    border: 1px solid var(--border);
    transition: .2s;
}
.topbar-icon:hover { background: var(--primary); color: #fff; border-color: var(--primary); }

.menu-toggle {
    display: none;
    width: 38px; height: 38px;
    border-radius: 10px;
    background: var(--bg);
    align-items: center; justify-content: center;
    color: var(--text);
    cursor: pointer;
    border: 1px solid var(--border);
    flex-shrink: 0;
    font-size: 16px;
}

.sidebar-overlay { display: none; position: fixed; inset: 0; background: rgba(15,23,42,.5); z-index: 999; }
.sidebar-overlay.show { display: block; }

.admin-profile {
    display: flex; align-items: center; gap: 5px;
    padding: 8px 10px 1px 15px; border-radius: 30px;
    border: 1px solid var(--border); cursor: pointer; transition: .2s;
    background: linear-gradient(135deg, var(--accent), #fbbf24);
}
.admin-profile .info h4 { font-size: 13px; font-weight: 600; color: var(--text); }
.admin-profile .info p  { font-size: 11px; color: var(--muted); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 18px; margin-bottom: 24px; }

.card {
    background: var(--card-bg); padding: 20px; border-radius: var(--radius);
    box-shadow: var(--shadow); border: 1px solid var(--border);
    transition: transform .25s, box-shadow .25s;
    display: flex; flex-direction: column; gap: 12px; min-width: 0;
}
.card:hover { transform: translateY(-4px); box-shadow: 0 8px 30px rgba(0,0,0,.1); }
.card-top { display: flex; align-items: center; justify-content: space-between; }

.card-icon { width: 46px; height: 46px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 20px; color: #fff; flex-shrink: 0; }
.c-blue   { background: linear-gradient(135deg,var(--primary),var(--primary-light)); }
.c-green  { background: linear-gradient(135deg,#10b981,#34d399); }
.c-orange { background: linear-gradient(135deg,#f59e0b,#fbbf24); }
.c-red    { background: linear-gradient(135deg,#ef4444,#f87171); }
.c-cyan   { background: linear-gradient(135deg,#0ea5e9,#38bdf8); }
.c-purple { background: linear-gradient(135deg,#8b5cf6,#a78bfa); }
.c-teal   { background: linear-gradient(135deg,var(--primary-dark),var(--primary)); }

.card-trend { font-size: 11px; padding: 3px 8px; border-radius: 20px; font-weight: 600; white-space: nowrap; }
.trend-up   { background: #dcfce7; color: #166534; }
.trend-down { background: #fee2e2; color: #991b1b; }

.card h3 { font-size: 26px; font-weight: 700; color: var(--text); line-height: 1; word-break: break-word; }
.card p  { font-size: 13px; color: var(--muted); font-weight: 500; margin: 0; }

.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 28px; }
.chart-box { background: var(--card-bg); border-radius: var(--radius); padding: 22px; box-shadow: var(--shadow); border: 1px solid var(--border); min-width: 0; }
.chart-box h2 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 18px; display: flex; align-items: center; gap: 8px; }
.chart-box h2 i { color: var(--primary); }
.chart-box canvas { width: 100% !important; height: 260px !important; }

.payment-summary { display: grid; grid-template-columns: repeat(3,1fr); gap: 10px; margin-bottom: 16px; }
.pay-stat { text-align: center; padding: 12px; border-radius: 10px; background: var(--bg); }
.pay-stat span { font-size: 11px; color: var(--muted); font-weight: 500; display: block; margin-bottom: 4px; }
.pay-stat strong { font-size: 22px; font-weight: 700; color: var(--text); }
.pay-stat.s-success strong { color: var(--success); }
.pay-stat.s-pending strong { color: var(--warning); }
.pay-stat.s-failed  strong { color: var(--danger);  }

.table-section { background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 22px; overflow: hidden; }
.table-header { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 10px; }
.table-header h2 { font-size: 15px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 8px; }
.table-header h2 i { color: var(--primary); }
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

.table-wrap.scrollable { max-height: 460px; overflow-y: auto; }
.table-wrap.scrollable thead th {
    position: sticky;
    top: 0;
    z-index: 2;
    background: #f8fafc;
    box-shadow: 0 1px 0 var(--border);
}
.table-wrap.scrollable::-webkit-scrollbar { width: 8px; }
.table-wrap.scrollable::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 8px; }
.table-wrap.scrollable::-webkit-scrollbar-track { background: transparent; }

table { width: 100%; border-collapse: collapse; }
table thead { background: #f8fafc; }
table th { padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); white-space: nowrap; }
table td { padding: 13px 16px; font-size: 13.5px; color: var(--text); border-bottom: 1px solid #f1f5f9; }
table tbody tr:last-child td { border-bottom: none; }
table tbody tr:hover { background: #fafbff; }

.badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; display: inline-block; white-space: nowrap; }
.badge-success, .badge-active, .badge-approved, .badge-completed, .badge-verified, .badge-published, .badge-paid, .badge-present { background: #dcfce7; color: #166534; }
.badge-warning, .badge-pending, .badge-ongoing, .badge-draft, .badge-scheduled { background: #fef3c7; color: #92400e; }
.badge-danger,  .badge-failed,  .badge-rejected, .badge-suspended, .badge-deleted, .badge-absent, .badge-expired  { background: #fee2e2; color: #991b1b; }
.badge-info,    .badge-open, .badge-excused                     { background: #e0f2fe; color: #0369a1; }
.badge-secondary, .badge-not-enrolled, .badge-archived           { background: #f1f5f9; color: #475569; }
.badge-in-progress                              { background: #ede9fe; color: #5b21b6; }
.badge-pending-approval { background: #fef3c7; color: #92400e; }
.badge-unverified { background: #f1f5f9; color: #475569; }

.actions { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 18px; margin-top: 24px; margin-bottom: 10px; }
.action-box { background: var(--card-bg); padding: 22px; border-radius: var(--radius); text-align: center; box-shadow: var(--shadow); border: 1px solid var(--border); cursor: pointer; transition: .25s; }
.action-box:hover { transform: translateY(-4px); border-color: var(--primary-light); box-shadow: 0 8px 30px rgba(15,118,110,.12); }
.action-box .abox-icon { width: 52px; height: 52px; border-radius: 14px; background: linear-gradient(135deg,#ccfbf1,#99f6e4); display: flex; align-items: center; justify-content: center; margin: 0 auto 14px; font-size: 22px; color: var(--primary); transition: .25s; }
.action-box:hover .abox-icon { background: var(--primary); color: #fff; }
.action-box h4 { font-size: 14px; font-weight: 600; color: var(--text); margin-bottom: 6px; }
.action-box p  { font-size: 12px; color: var(--muted); }

.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15,23,42,.55); backdrop-filter: blur(4px); justify-content: center; align-items: center; z-index: 9999; padding: 16px; }
.modal-content { background: var(--card-bg); width: 480px; max-width: 95vw; max-height: 90vh; overflow-y: auto; padding: 28px; border-radius: 18px; position: relative; box-shadow: 0 20px 60px rgba(0,0,0,.2); animation: modalIn .25s ease; }
@keyframes modalIn { from { transform: translateY(-16px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.modal-content h3 { font-size: 18px; font-weight: 700; margin-bottom: 20px; color: var(--text); padding-right: 30px; }
.close-modal { position: absolute; right: 18px; top: 18px; width: 32px; height: 32px; border-radius: 8px; background: var(--bg); border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 18px; color: var(--muted); transition: .2s; }
.close-modal:hover { background: #fee2e2; color: var(--danger); }

.form-group { margin-bottom: 14px; }
.form-group label { font-size: 12px; font-weight: 600; color: var(--muted); display: block; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .4px; }

input[type=text], input[type=email], input[type=password], input[type=number], input[type=file], input[type=date], input[type=color], textarea, select {
    width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; font-size: 14px;
    background: var(--bg); color: var(--text); outline: none; transition: .2s; font-family: inherit;
}
input:focus, textarea:focus, select:focus { border-color: var(--primary); background: #fff; box-shadow: 0 0 0 3px rgba(15,118,110,.12); }
textarea { resize: vertical; min-height: 90px; }

.btn { padding: 9px 18px; border: none; border-radius: 9px; cursor: pointer; font-size: 13px; font-weight: 600; font-family: inherit; transition: .2s; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
.btn-primary  { background: var(--primary);  color: #fff; }
.btn-primary:hover { background: var(--primary-dark); color: #fff; }
.btn-success  { background: var(--success); color: #fff; }
.btn-success:hover { background: #059669; }
.btn-warning  { background: var(--warning); color: #fff; }
.btn-warning:hover { background: #d97706; }
.btn-danger   { background: var(--danger);  color: #fff; }
.btn-danger:hover  { background: #dc2626; }
.btn-outline  { background: transparent; border: 1.5px solid var(--border); color: var(--text); }
.btn-outline:hover { border-color: var(--primary); color: var(--primary); background: rgba(15,118,110,.06); }
.btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 7px; }
.btn-full { width: 100%; justify-content: center; padding: 12px; font-size: 14px; }

.form-card { background: var(--card-bg); border-radius: var(--radius); padding: 24px; box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 22px; min-width: 0; }
.form-card h3 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 18px; padding-bottom: 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
.form-card h3 i { color: var(--primary); }

.alert { padding: 12px 16px; border-radius: 10px; font-size: 13px; font-weight: 500; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.alert-error   { background: #fee2e2; color: #991b1b; border-left: 4px solid var(--danger); }
.alert-success { background: #dcfce7; color: #166534; border-left: 4px solid var(--success); }
.alert-note    { background: #ecfeff; color: #155e75; border-left: 4px solid var(--info); }

.mini-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 14px; margin-bottom: 22px; }
.mini-stat { background: var(--card-bg); border-radius: 12px; padding: 16px; text-align: center; border: 1px solid var(--border); box-shadow: var(--shadow); min-width: 0; }
.mini-stat h2 { font-size: 26px; font-weight: 700; color: var(--primary); }
.mini-stat p  { font-size: 12px; color: var(--muted); margin-top: 4px; }

.bulk-actions { display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; align-items: center; }

.detail-row { display: flex; justify-content: space-between; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f1f5f9; font-size: 13.5px; }
.detail-row:last-child { border-bottom: none; }
.detail-row span.label { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .4px; }
.detail-row span.value { color: var(--text); text-align: right; word-break: break-word; max-width: 60%; }

.roadmap-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap: 14px; }
.roadmap-item { background: var(--bg); border: 1px dashed var(--border); border-radius: 12px; padding: 16px; }
.roadmap-item h4 { font-size: 13.5px; margin-bottom: 6px; display:flex; align-items:center; gap:8px; }
.roadmap-item p { font-size: 12px; color: var(--muted); }

.progress-mini { display:flex; align-items:center; gap:8px; }
.progress-mini .track { flex:1; height:6px; background:#e2e8f0; border-radius:3px; overflow:hidden; }
.progress-mini .fill { height:100%; background:var(--success); border-radius:3px; }
.progress-mini span { font-size:12px; color:var(--muted); }

.diff-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.diff-col{background:#f8fafc;border-radius:8px;padding:12px;font-size:12px;font-family:monospace;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;}
.diff-col.old{border-left:3px solid #f87171;}
.diff-col.new{border-left:3px solid #4ade80;}

@media(max-width: 1024px){ .charts { grid-template-columns: 1fr; } .main { padding: 20px; } }
@media(max-width: 860px){
    .sidebar { width: 260px; left: -260px; box-shadow: 4px 0 24px rgba(0,0,0,.25); }
    .sidebar.open { left: 0; }
    .main { margin-left: 0; width: 100%; padding: 16px; }
    .menu-toggle { display: flex; }
    .cards { grid-template-columns: repeat(2, 1fr); }
}
@media(max-width: 600px){
    .main { padding: 12px; }
    .topbar { flex-wrap: wrap; gap: 10px; padding: 14px 16px; }
    .topbar h1 { font-size: 18px; }
    .admin-profile .info { display: none; }
    .cards { grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .card { padding: 14px; gap: 8px; }
    .card h3 { font-size: 20px; }
    .charts { grid-template-columns: 1fr; gap: 14px; }
    .mini-stats { grid-template-columns: repeat(2, 1fr); gap: 10px; }
    .actions { grid-template-columns: repeat(2, 1fr); gap: 12px; }
    table th, table td { padding: 10px 12px; font-size: 12.5px; }
    .modal-content { padding: 20px; width: 100%; }
    .diff-grid{grid-template-columns:1fr;}
}
@media(max-width: 380px){ .cards { grid-template-columns: 1fr; } .actions { grid-template-columns: 1fr; } .mini-stats { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>

<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<div class="sidebar" id="sidebar">
    <div class="logo">
        <div class="logo-icon">
            <?php if (!empty($branding['logo_url'])): ?>
                <img src="<?= htmlspecialchars($branding['logo_url']) ?>" alt="Logo">
            <?php else: ?>
                <i class="fas fa-graduation-cap"></i>
            <?php endif; ?>
        </div>
        <div><h2><?= htmlspecialchars($branding['org_name']) ?></h2><span>STP Management Panel</span></div>
    </div>

    <div class="menu">
        <div class="menu-label">Main</div>
        <ul>
            <li><a href="#" onclick="showSection('dashboardSection',this)" class="active"><i class="fas fa-chart-line"></i><span>Dashboard</span></a></li>
            <li><a href="#" onclick="showSection('reportsSection',this)"><i class="fas fa-chart-bar"></i><span>Reports</span></a></li>
            <?php if ($is_super): ?>
            <li><a href="#" onclick="showSection('approvalsSection',this)"><i class="fas fa-stamp"></i><span>Course Approvals <?php if ($pending_approvals_count>0): ?><span class="badge badge-warning" style="margin-left:4px;"><?= $pending_approvals_count ?></span><?php endif; ?></span></a></li>
            <?php endif; ?>
            <li><a href="#" onclick="showSection('changeRequestsSection',this)"><i class="fas fa-code-compare"></i><span>Trainer Change Requests</span><?php if ($pending_change_requests_count>0): ?><span class="nav-badge"><?= $pending_change_requests_count ?></span><?php endif; ?></a></li>
            <li><a href="#" onclick="showSection('auditSection',this)"><i class="fas fa-list-check"></i><span>Audit Log</span></a></li>
        </ul>

        <div class="menu-label">Management</div>
        <ul>
            <li><a href="#" onclick="showSection('studentsSection',this)"><i class="fas fa-user-graduate"></i><span>Students</span><?php if ($pending_student_verifications_count>0): ?><span class="nav-badge"><?= $pending_student_verifications_count ?></span><?php endif; ?></a></li>
            <li><a href="#" onclick="showSection('coursesSection',this)"><i class="fas fa-book"></i><span>Courses</span></a></li>
            <li><a href="#" onclick="showSection('roleSection',this)"><i class="fas fa-user-shield"></i><span>Add Trainer</span></a></li>
            <li><a href="#" onclick="showSection('videoSection',this)"><i class="fas fa-video"></i><span>Videos</span></a></li>
            <li><a href="#" onclick="showSection('noteSection',this)"><i class="fas fa-file-alt"></i><span>Notes</span></a></li>
            <li><a href="#" onclick="showSection('quizeSection',this)"><i class="fas fa-question-circle"></i><span>Quizzes</span></a></li>
            <li><a href="#" onclick="showSection('attendanceSection',this)"><i class="fas fa-calendar-check"></i><span>Attendance</span></a></li>
        </ul>

        <div class="menu-label">Operations</div>
        <ul>
            <li><a href="#" onclick="showSection('enrollmentSection',this)"><i class="fas fa-user-check"></i><span>Enrollments</span></a></li>
            <li><a href="cpassword.php"><i class="fas fa-key"></i><span>Assign</span></a></li>
            <li><a href="#" onclick="showSection('paymentSection',this)"><i class="fas fa-credit-card"></i><span>Payments</span></a></li>
            <li><a href="#" onclick="showSection('invoiceSection',this)"><i class="fas fa-file-invoice-dollar"></i><span>Invoices / eTIMS</span></a></li>
            <li><a href="#" onclick="showSection('certificateSection',this)"><i class="fas fa-certificate"></i><span>Certificates</span><?php if ($pending_certificate_requests_count>0): ?><span class="nav-badge"><?= $pending_certificate_requests_count ?></span><?php endif; ?></a></li>
            <li><a href="#" onclick="showSection('announcementSection',this)"><i class="fas fa-bell"></i><span>Announcements</span></a></li>
            <li><a href="#" onclick="showSection('ticketSection',this)"><i class="fas fa-headset"></i><span>Tickets</span></a></li>
        </ul>

        <div class="menu-label">Professional Ecosystem</div>
        <ul>
            <li><a href="#" onclick="showSection('practiceHubSection',this)"><i class="fas fa-briefcase-medical"></i><span>Practice Support Hub</span></a></li>
            <li><a href="#" onclick="showSection('cpdSection',this)"><i class="fas fa-award"></i><span>CPD / CME Points</span><?php if ($pending_cpd_points_count>0): ?><span class="nav-badge"><?= $pending_cpd_points_count ?></span><?php endif; ?></a></li>
            <li><a href="#" onclick="showSection('referralSection',this)"><i class="fas fa-share-nodes"></i><span>Referrals</span></a></li>
            <li><a href="#" onclick="showSection('promotionSection',this)"><i class="fas fa-bullhorn"></i><span>Promotions / Ads</span></a></li>
            <li><a href="#" onclick="showSection('roadmapSection',this)"><i class="fas fa-map"></i><span>Roadmap (Phase 2)</span></a></li>
        </ul>

        <div class="menu-label">Account</div>
        <ul>
            <?php if ($is_super): ?>
            <li><a href="#" onclick="showSection('settingsSection',this)"><i class="fas fa-gear"></i><span>Settings / Branding</span></a></li>
            <?php endif; ?>
            <li><a href="index.php"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a></li>
        </ul>
    </div>
</div>

<div class="main">

<?php if ($flash_success): ?>
    <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?= htmlspecialchars($flash_success) ?></div>
<?php endif; ?>
<?php if (!empty($flash_errors)): ?>
    <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?= implode('<br>', array_map('htmlspecialchars', $flash_errors)) ?></div>
<?php endif; ?>

<div id="dashboardSection">

    <div class="topbar">
        <div class="topbar-left">
            <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
            <h1>Admin Dashboard</h1>
        </div>
        <div class="topbar-right">
            <div class="topbar-icon"><i class="fas fa-search"></i></div>
            <div class="topbar-icon"><i class="fas fa-bell"></i></div>
            <div class="admin-profile"><div class="info"><h4>System</h4><p><?= htmlspecialchars(ucwords(str_replace('_',' ',$user_role))) ?></p></div></div>
        </div>
    </div>

    <div class="cards">
        <div class="card">
            <div class="card-top"><div class="card-icon c-blue"><i class="fas fa-user-graduate"></i></div><span class="card-trend trend-up">+12%</span></div>
            <h3><?= $total_students ?></h3><p>Total Students</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-green"><i class="fas fa-user-check"></i></div><span class="card-trend trend-up">Active</span></div>
            <h3><?= $active_users ?></h3><p>Active Users</p>
        </div>
        <div class="card"><div class="card-top"><div class="card-icon c-purple"><i class="fas fa-book"></i></div></div><h3><?= $total_courses ?></h3><p>Total Courses</p></div>
        <div class="card"><div class="card-top"><div class="card-icon c-cyan"><i class="fas fa-unlock"></i></div></div><h3><?= $free_courses ?></h3><p>Free Courses</p></div>
        <div class="card"><div class="card-top"><div class="card-icon c-orange"><i class="fas fa-lock"></i></div></div><h3><?= $paid_courses ?></h3><p>Paid Courses</p></div>
        <div class="card"><div class="card-top"><div class="card-icon c-blue"><i class="fas fa-user-plus"></i></div></div><h3><?= $total_enrollments ?></h3><p>Total Enrollments</p></div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-red"><i class="fas fa-coins"></i></div><span class="card-trend trend-up">KES</span></div>
            <h3><?= number_format($revenue) ?></h3><p>Revenue Generated</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-green"><i class="fas fa-chart-line"></i></div></div>
            <h3><?= round($completion_rate) ?>%</h3><p>Completion Rate</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-orange"><i class="fas fa-clock"></i></div><span class="card-trend trend-down">Pending</span></div>
            <h3><?= $pending_payments ?></h3><p>Pending Payments</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-teal"><i class="fas fa-stamp"></i></div></div>
            <h3><?= $pending_approvals_count ?></h3><p>Pending Course Approvals</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-teal"><i class="fas fa-code-compare"></i></div></div>
            <h3><?= $pending_change_requests_count ?></h3><p>Pending Trainer Change Requests</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-purple"><i class="fas fa-certificate"></i></div></div>
            <h3><?= $certificates_issued_count ?></h3><p>Certificates Issued</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-cyan"><i class="fas fa-share-nodes"></i></div></div>
            <h3><?= $active_referrals_count ?></h3><p>Active Referral Codes</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-orange"><i class="fas fa-award"></i></div></div>
            <h3><?= $pending_cpd_points_count ?></h3><p>CPD Entries Awaiting Verification</p>
        </div>
        <div class="card">
            <div class="card-top"><div class="card-icon c-red"><i class="fas fa-id-card"></i></div></div>
            <h3><?= $pending_student_verifications_count ?></h3><p>Student Profiles Awaiting Verification</p>
        </div>
    </div>

    <div class="charts">
        <div class="chart-box"><h2><i class="fas fa-chart-area"></i> Revenue Graph</h2><canvas id="revenueChart"></canvas></div>
        <div class="chart-box"><h2><i class="fas fa-chart-line"></i> Student Growth</h2><canvas id="studentChart"></canvas></div>
        <div class="chart-box"><h2><i class="fas fa-chart-bar"></i> Enrollment Trends</h2><canvas id="enrollmentChart"></canvas></div>
        <div class="chart-box">
            <h2><i class="fas fa-money-bill-wave"></i> Payment Status</h2>
            <div class="payment-summary">
                <div class="pay-stat s-success"><span>Success</span><strong><?= $successful_payments ?></strong></div>
                <div class="pay-stat s-pending"><span>Pending</span><strong><?= $pending_payments ?></strong></div>
                <div class="pay-stat s-failed"><span>Failed</span><strong><?= $failed_payments ?></strong></div>
            </div>
            <canvas id="paymentChart"></canvas>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-fire"></i> Most Popular Courses</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Students</th><th>Revenue</th><th>Completion</th></tr></thead>
                <tbody>
                <?php foreach ($popular_courses as $course): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($course['title']) ?></strong></td>
                        <td><?= $course['users'] ?></td>
                        <td>KES <?= number_format($course['revenue']) ?></td>
                        <td>
                            <div class="progress-mini">
                                <div class="track"><div class="fill" style="width:<?= round($course['completion_rate']) ?>%;"></div></div>
                                <span><?= round($course['completion_rate']) ?>%</span>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-users"></i> Recent Registrations</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Course</th><th>Status</th></tr></thead>
                <tbody>
                <?php foreach ($recent_students as $student): ?>
                    <tr>
                        <td><?= $student['id'] ?></td>
                        <td>
                            <div style="display:flex;align-items:center;gap:10px;">
                                <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--primary-light));display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:700;flex-shrink:0;">
                                    <?= strtoupper(substr($student['full_name'],0,1)) ?>
                                </div>
                                <?= htmlspecialchars($student['full_name']) ?>
                            </div>
                        </td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($student['email']) ?></td>
                        <td><?= htmlspecialchars($student['course_name'] ?? 'No Course') ?></td>
                        <td>
                            <?php $st = strtolower($student['status'] ?? 'pending'); ?>
                            <span class="badge badge-<?= $st == 'not enrolled' ? 'secondary' : $st ?>"><?= ucfirst($student['status'] ?? 'Pending') ?></span>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-history"></i> Recent Activities</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Activity</th><th>User</th><th>Date</th><th>Status</th></tr></thead>
                <tbody>
                <?php foreach ($activities as $activity): ?>
                    <tr>
                        <td><?= htmlspecialchars($activity['activity_name'] ?? $activity['message'] ?? '') ?></td>
                        <td><?= htmlspecialchars($activity['user_name'] ?? 'System') ?></td>
                        <td style="color:var(--muted);"><?= !empty($activity['created_at']) ? date("d M Y", strtotime($activity['created_at'])) : '' ?></td>
                        <td><span class="badge badge-success"><?= ucfirst($activity['status'] ?? 'Completed') ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="actions">
        <div class="action-box" onclick="showSection('coursesSection')">
            <div class="abox-icon"><i class="fas fa-plus-circle"></i></div>
            <h4>Create Course</h4>
            <p>Add and publish new courses for students.</p>
        </div>
        <div class="action-box" onclick="openModal('uploadModal')">
            <div class="abox-icon"><i class="fas fa-upload"></i></div>
            <h4>Upload Materials</h4>
            <p>Upload notes, PDFs and videos securely.</p>
        </div>
        <div class="action-box" onclick="showSection('paymentSection')">
            <div class="abox-icon"><i class="fas fa-money-check-alt"></i></div>
            <h4>Monitor Payments</h4>
            <p>Track paid courses and student payments.</p>
        </div>
        <div class="action-box" onclick="showSection('changeRequestsSection')">
            <div class="abox-icon"><i class="fas fa-code-compare"></i></div>
            <h4>Review Trainer Changes</h4>
            <p>Approve or reject pending trainer submissions.</p>
        </div>
    </div>

    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <button class="close-modal" onclick="closeModal('uploadModal')"><i class="fas fa-times"></i></button>
            <h3><i class="fas fa-upload" style="color:var(--primary);margin-right:8px;"></i>Upload Materials</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Material Title</label><input type="text" name="title" placeholder="Material title" required></div>
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">Select Course</option>
                        <?php
                        $c_list_stmt = $pdo->query("SELECT id,title FROM courses");
                        foreach ($c_list_stmt as $c):
                        ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>File (PDF, DOC, Image — max 10MB)</label><input type="file" name="file" required accept=".pdf,.doc,.docx,image/*"></div>
                <button type="submit" name="upload_material" class="btn btn-primary btn-full">Upload</button>
            </form>
        </div>
    </div>
</div>

<div id="reportsSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left">
            <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
            <h1>Reports</h1>
        </div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="mini-stats">
        <div class="mini-stat"><h2><?= $total_students ?></h2><p>Total Students</p></div>
        <div class="mini-stat"><h2><?= $total_courses ?></h2><p>Total Courses</p></div>
        <div class="mini-stat"><h2><?= $total_enrollments ?></h2><p>Total Enrollments</p></div>
        <div class="mini-stat"><h2 style="color:var(--success);"><?= round($completion_rate) ?>%</h2><p>Avg Completion</p></div>
        <div class="mini-stat"><h2>KES <?= number_format($revenue) ?></h2><p>Total Revenue</p></div>
        <div class="mini-stat"><h2><?= $total_quizzes ?></h2><p>Total Quizzes</p></div>
        <div class="mini-stat"><h2><?= $certificates_issued_count ?></h2><p>Certificates Issued</p></div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-fire"></i> Course Performance</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Students</th><th>Revenue</th><th>Completion</th></tr></thead>
                <tbody>
                <?php foreach ($popular_courses as $course): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($course['title']) ?></strong></td>
                        <td><?= $course['users'] ?></td>
                        <td>KES <?= number_format($course['revenue']) ?></td>
                        <td><?= round($course['completion_rate']) ?>%</td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clipboard-list"></i> Student Progress (all enrollments)</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Student No</th><th>Course</th><th>Status</th><th>Progress</th></tr></thead>
                <tbody>
                <?php foreach ($enrollments_data as $e): $prog = max(0, min(100, (int)$e['progress'])); ?>
                    <tr>
                        <td><?= htmlspecialchars($e['full_name']) ?></td>
                        <td><?= htmlspecialchars($e['student_no'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($e['title']) ?></td>
                        <td><span class="badge badge-<?= strtolower($e['status']) ?>"><?= htmlspecialchars($e['status']) ?></span></td>
                        <td>
                            <div class="progress-mini">
                                <div class="track"><div class="fill" style="width:<?= $prog ?>%;"></div></div>
                                <span><?= $prog ?>%</span>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="approvalsSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Course Approvals</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>Super Admin</h4><p>Governance</p></div></div></div>
    </div>

    <div class="alert alert-note"><i class="fas fa-circle-info"></i> Trainer-submitted courses/updates stay hidden from students until approved here. Approving publishes the change immediately; rejecting keeps the previous published version live. Trainer edits to notes, videos, quizzes, questions, assignments and announcements are reviewed separately under <strong>Trainer Change Requests</strong>.</div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-hourglass-half"></i> Pending Trainer Submissions</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Version</th><th>Submitted By</th><th>Action</th><th>Date</th><th>Review</th></tr></thead>
                <tbody>
                <?php foreach ($pending_versions as $pv): $pdata = json_decode($pv['payload'], true) ?: []; ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($pv['course_title']) ?></strong></td>
                        <td>v<?= (int)$pv['version_no'] ?></td>
                        <td><?= htmlspecialchars($pv['submitted_by_name']) ?></td>
                        <td><span class="badge badge-info"><?= htmlspecialchars(ucfirst($pdata['action'] ?? 'update')) ?></span></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($pv['created_at']) ?></td>
                        <td>
                            <button type="button" class="btn btn-outline btn-sm" onclick='openVersionModal(<?= json_encode(["id"=>(int)$pv["id"],"course"=>$pv["course_title"],"data"=>$pdata], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP) ?>)'><i class="fas fa-eye"></i> Review</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($pending_versions->rowCount() === 0): ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:30px;">No pending submissions</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clock-rotate-left"></i> Review History</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Version</th><th>Submitted By</th><th>Status</th><th>Reviewed By</th><th>Reviewed At</th></tr></thead>
                <tbody>
                <?php foreach ($version_history as $vh): ?>
                    <tr>
                        <td><?= htmlspecialchars($vh['course_title']) ?></td>
                        <td>v<?= (int)$vh['version_no'] ?></td>
                        <td><?= htmlspecialchars($vh['submitted_by_name']) ?></td>
                        <td><span class="badge badge-<?= $vh['status']==='approved'?'approved':'rejected' ?>"><?= ucfirst($vh['status']) ?></span></td>
                        <td><?= htmlspecialchars($vh['reviewed_by_name'] ?? '-') ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($vh['reviewed_at'] ?? '-') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div id="versionModal" class="modal">
        <div class="modal-content" style="width:560px;">
            <button class="close-modal" onclick="closeModal('versionModal')"><i class="fas fa-times"></i></button>
            <h3><i class="fas fa-stamp" style="color:var(--primary);margin-right:8px;"></i>Review Submission</h3>
            <div id="vm_body" style="margin-bottom:16px;"></div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="version_id" id="vm_version_id">
                <div class="form-group"><label>Review Note (optional)</label><textarea name="review_note" placeholder="Reason / comments"></textarea></div>
                <div style="display:flex;gap:8px;">
                    <button type="submit" name="review_version" value="1" class="btn btn-success btn-full" onclick="document.getElementById('vm_decision').value='approved';">Approve & Publish</button>
                    <button type="submit" name="review_version" value="1" class="btn btn-danger btn-full" onclick="document.getElementById('vm_decision').value='rejected';">Reject</button>
                </div>
                <input type="hidden" name="decision" id="vm_decision" value="approved">
            </form>
        </div>
    </div>
</div>

<div id="changeRequestsSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Trainer Change Requests</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4><?= htmlspecialchars(ucwords(str_replace('_',' ',$user_role))) ?></h4><p>Governance</p></div></div></div>
    </div>
    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-hourglass-half"></i> Pending Trainer Requests (<?= $pending_change_requests_count ?>)</h2></div>
        <form method="POST" id="bulkCrForm">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="bulk-actions" style="padding:0 22px;">
                <button type="submit" name="bulk_review_change_requests" value="1" onclick="document.getElementById('bulk_cr_decision').value='approved'; return confirm('Approve ALL selected trainer requests and publish them?');" class="btn btn-success btn-sm"><i class="fas fa-check-double"></i> Approve Selected</button>
                <button type="submit" name="bulk_review_change_requests" value="1" onclick="document.getElementById('bulk_cr_decision').value='rejected'; return confirm('Reject ALL selected trainer requests?');" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject Selected</button>
                <input type="hidden" name="bulk_decision" id="bulk_cr_decision" value="approved">
                <span style="font-size:12px;color:var(--muted);">Select rows below, then choose an action.</span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th style="width:34px;"><input type="checkbox" onclick="document.querySelectorAll('.cr-checkbox').forEach(cb=>cb.checked=this.checked)"></th><th>#</th><th>Type</th><th>Summary</th><th>Submitted By</th><th>Submitted</th><th>Compare</th><th>Review</th></tr></thead>
                    <tbody>
                    <?php if ($pending_change_requests && $pending_change_requests->rowCount() > 0): foreach ($pending_change_requests as $cr):
                        $crNewData = json_decode($cr['new_data'] ?? '{}', true) ?: [];
                        $crLabel   = changeRequestLabel($cr['entity_type'], $crNewData);
                    ?>
                        <tr>
                            <td><input type="checkbox" class="cr-checkbox" name="cr_ids[]" value="<?= (int)$cr['id'] ?>" form="bulkCrForm"></td>
                            <td>#<?= (int)$cr['id'] ?></td>
                            <td><?= htmlspecialchars(ucwords(str_replace('_',' ', $cr['entity_type']))) ?></td>
                            <td style="max-width:260px;"><?= htmlspecialchars($crLabel) ?></td>
                            <td><?= htmlspecialchars($cr['requester_name'] ?? 'Trainer #'.$cr['requested_by']) ?></td>
                            <td style="color:var(--muted);"><?= htmlspecialchars($cr['created_at']) ?></td>
                            <td><button type="button" class="btn btn-outline btn-sm" onclick="toggleInline('crdiff-<?= (int)$cr['id'] ?>')"><i class="fas fa-code-compare"></i></button></td>
                            <td>
                                <form method="POST" style="display:inline-flex;gap:6px;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="change_request_id" value="<?= (int)$cr['id'] ?>">
                                    <input type="hidden" name="cr_decision" value="approved">
                                    <button type="submit" name="review_change_request" class="btn btn-success btn-sm" onclick="return confirm('Approve and publish this change?')"><i class="fas fa-check"></i></button>
                                </form>
                                <form method="POST" style="display:inline-flex;gap:6px;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="change_request_id" value="<?= (int)$cr['id'] ?>">
                                    <input type="hidden" name="cr_decision" value="rejected">
                                    <button type="submit" name="review_change_request" class="btn btn-danger btn-sm" onclick="return confirm('Reject this change request?')"><i class="fas fa-xmark"></i></button>
                                </form>
                            </td>
                        </tr>
                        <tr class="crdiff-row" id="crdiff-<?= (int)$cr['id'] ?>" style="display:none;">
                            <td colspan="8">
                                <div class="diff-grid">
                                    <div>
                                        <strong style="font-size:12px;color:#991b1b;">Before</strong>
                                        <div class="diff-col old"><?= htmlspecialchars(json_encode(json_decode($cr['old_data'] ?? '{}'), JSON_PRETTY_PRINT)) ?></div>
                                    </div>
                                    <div>
                                        <strong style="font-size:12px;color:#166534;">Proposed</strong>
                                        <div class="diff-col new"><?= htmlspecialchars(json_encode(json_decode($cr['new_data'] ?? '{}'), JSON_PRETTY_PRINT)) ?></div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; else: ?>
                        <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px;">No pending trainer change requests</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clock-rotate-left"></i> Review History</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>#</th><th>Type</th><th>Submitted By</th><th>Status</th><th>Reviewed By</th><th>Comments</th></tr></thead>
                <tbody>
                <?php if ($change_request_history && $change_request_history->rowCount() > 0): foreach ($change_request_history as $ch): ?>
                    <tr>
                        <td>#<?= (int)$ch['id'] ?></td>
                        <td><?= htmlspecialchars(ucwords(str_replace('_',' ', $ch['entity_type']))) ?></td>
                        <td><?= htmlspecialchars($ch['requester_name'] ?? '-') ?></td>
                        <td><span class="badge badge-<?= $ch['status']==='approved'?'approved':'rejected' ?>"><?= ucfirst($ch['status']) ?></span></td>
                        <td><?= htmlspecialchars($ch['reviewer_name'] ?? '-') ?></td>
                        <td style="color:var(--muted);max-width:260px;"><?= htmlspecialchars($ch['review_comments'] ?? '') ?></td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:30px;">No reviewed requests yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="auditSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Audit Log</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System</h4><p>Accountability trail</p></div></div></div>
    </div>
    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list-check"></i> System Activity (latest 100)</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>#</th><th>Message</th><th>Date</th></tr></thead>
                <tbody>
                <?php foreach ($audit_log as $al): ?>
                    <tr>
                        <td>#<?= (int)$al['id'] ?></td>
                        <td><?= htmlspecialchars($al['message'] ?? ($al['activity_name'] ?? '')) ?></td>
                        <td style="color:var(--muted);"><?= !empty($al['created_at']) ? htmlspecialchars($al['created_at']) : '' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="roleSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Add Trainer</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <?php if (!empty($message)): ?>
        <div class="alert alert-<?= $messageType ?>"><i class="fas fa-<?= $messageType=='error'?'exclamation-circle':'check-circle' ?>"></i> <?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-user-plus"></i> New Trainer Account</h3>
        <form method="POST" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" required maxlength="100" pattern="[A-Za-z\s]+" title="Only letters allowed"></div>
            <div class="form-group"><label>Email *</label><input type="email" name="email" required maxlength="150"></div>
            <div class="form-group"><label>Password *</label><input type="password" name="password" required minlength="6"></div>
            <div class="form-group"><label>Employee Number</label><input type="text" name="employee_no" maxlength="50"></div>
            <div class="form-group"><label>Professional Licence / Registration No.</label><input type="text" name="license_no" maxlength="80" placeholder="e.g. professional body registration number"></div>
            <div class="form-group"><label>Phone Number</label><input type="text" name="phone" maxlength="20" pattern="[0-9+]+"></div>
            <div class="form-group"><label>Specialization</label><input type="text" name="specialization" maxlength="100"></div>
            <div class="form-group">
                <label>Academic Qualification Level</label>
                <select name="qualification">
                    <option value="">Select level</option>
                    <option>Diploma</option><option>Degree</option><option>Master's</option><option>PhD</option>
                </select>
            </div>
            <div class="form-group"><label>Experience (Years)</label><input type="number" name="experience_years" min="0" max="60"></div>
            <div class="form-group"><label>KRA PIN</label><input type="text" name="kra_pin" maxlength="30" placeholder="For invoicing/eTIMS"></div>
            <button type="submit" name="add_teacher" class="btn btn-primary btn-full">Add Trainer</button>
        </form>
    </div>
</div>

<div id="coursesSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Course Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <?php if ($user_role === 'teacher'): ?>
    <div class="alert alert-note"><i class="fas fa-circle-info"></i> As a Trainer, new courses and edits you submit here are queued for Super Administrator approval before they go live.</div>
    <?php endif; ?>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px;">
        <div class="form-card">
            <h3><i class="fas fa-plus-circle"></i> Create Course</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Title</label><input type="text" name="title" placeholder="Course Title" required maxlength="150"></div>
                <div class="form-group"><label>Description</label><textarea name="description" placeholder="Course Description" required maxlength="2000"></textarea></div>
                <div class="form-group">
                    <label>Category</label>
                    <select name="category" required>
                        <option value="">Select Category</option>
                        <option value="Course 1">Course 1</option>
                        <option value="Course 2">Course 2</option>
                        <option value="data_science">Data Science</option>
                        <option value="ui_ux">UI/UX Design</option>
                        <option value="cyber_security">Cyber Security</option>
                        <option value="ai_ml">AI / ML</option>
                    </select>
                </div>
                <div class="form-group"><label>Custom Category</label><input type="text" name="custom_category" placeholder="Optional - overrides selection above" maxlength="100"></div>
                <div class="form-group"><label>Thumbnail</label><input type="file" name="thumbnail" accept="image/*"></div>
                <div class="form-group">
                    <label>Type</label>
                    <select name="course_type"><option value="Free">Free</option><option value="Paid">Paid</option></select>
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select name="status" required><option value="Active">Active</option><option value="Inactive">Inactive</option></select>
                </div>
                <div class="form-group">
                   <label for="teacher_id">Assign Trainer</label>
                   <select name="teacher_id" id="teacher_id" required>
                       <option value="">Select Trainer</option>
                       <?php
                       $teachers_assign_stmt = $pdo->query("SELECT id, full_name FROM users WHERE role='teacher'");
                       $teachers_assign = $teachers_assign_stmt->fetchAll(PDO::FETCH_ASSOC);
                       if (count($teachers_assign) > 0):
                           foreach ($teachers_assign as $t):
                       ?>
                       <option value="<?= (int)$t['id']; ?>"><?= htmlspecialchars($t['full_name']); ?></option>
                       <?php
                           endforeach;
                       else:
                       ?>
                       <option value="">No trainers found</option>
                       <?php endif; ?>
                    </select>
                </div>
                <div class="form-group"><label>Price</label><input type="number" name="price" placeholder="0.00" step="0.01" min="0"></div>
                <button class="btn btn-primary btn-full" name="create_course"><?= $user_role==='teacher' ? 'Submit for Approval' : 'Create Course' ?></button>
            </form>
        </div>

        <div class="form-card">
            <h3><i class="fas fa-archive"></i> Delete / Archive Course</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group">
                    <label>Select Course</label>
                    <select name="course_id" required>
                        <option value="">Select Course</option>
                        <?php $cl_stmt = $pdo->query("SELECT id,title FROM courses ORDER BY id DESC");
                        foreach ($cl_stmt as $c): ?>
                            <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Action</label>
                    <select name="action" required><option value="archive">Archive</option><option value="delete">Delete</option></select>
                </div>
                <button class="btn btn-danger btn-full" name="delete_course">Apply</button>
            </form>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Course List</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Thumbnail</th><th>Price</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                <?php $courses2_stmt = $pdo->query("SELECT * FROM courses ORDER BY id DESC");
                foreach ($courses2_stmt as $row): ?>
                    <tr>
                        <td>#<?= (int)$row['id'] ?></td>
                        <td><strong><?= htmlspecialchars($row['title']) ?></strong></td>
                        <td><?= htmlspecialchars($row['category']) ?></td>
                        <td><?php if (!empty($row['thumbnail'])): ?><img src="<?= htmlspecialchars($row['thumbnail']) ?>" style="width:60px;height:40px;object-fit:cover;border-radius:6px;" alt=""><?php endif; ?></td>
                        <td>kes <?= htmlspecialchars($row['price']) ?></td>
                        <td>
                            <?php $st = strtolower($row['status']); ?>
                            <span class="badge badge-<?= $st==='active' ? 'success' : ($st==='pending approval' ? 'pending-approval' : 'danger') ?>"><?= htmlspecialchars($row['status']) ?></span>
                        </td>
                        <td>
                            <button type="button" class="btn btn-outline btn-sm"
                                onclick='openEditCourseModal(<?= json_encode([
                                    "id"          => (int)$row["id"],
                                    "title"       => $row["title"],
                                    "description" => $row["description"],
                                    "category"    => $row["category"],
                                    "course_type" => $row["course_type"],
                                    "status"      => $row["status"],
                                    "teacher_id"  => $row["teacher_id"],
                                    "price"       => $row["price"],
                                    "thumbnail"   => $row["thumbnail"],
                                ], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP) ?>)'>
                                <i class="fas fa-edit"></i> Edit
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div id="editCourseModal" class="modal">
        <div class="modal-content" style="width:560px;">
            <button class="close-modal" onclick="closeModal('editCourseModal')"><i class="fas fa-times"></i></button>
            <h3><i class="fas fa-edit" style="color:var(--primary);margin-right:8px;"></i>Edit Course</h3>
            <img id="edit_thumbnail_preview" src="" alt="Current thumbnail" style="display:none;width:140px;height:90px;object-fit:cover;border-radius:8px;margin-bottom:12px;">
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="course_id" id="edit_course_id">
                <div class="form-group"><label>Title</label><input type="text" name="title" id="edit_title" required maxlength="150"></div>
                <div class="form-group"><label>Description</label><textarea name="description" id="edit_description" required maxlength="2000"></textarea></div>
                <div class="form-group">
                    <label>Category</label>
                    <select name="category" id="edit_category">
                        <option value="">Select Category</option>
                        <option value="Course 1">Course 1</option>
                        <option value="Course 2">Course 2</option>
                        <option value="data_science">Data Science</option>
                        <option value="ui_ux">UI/UX Design</option>
                        <option value="cyber_security">Cyber Security</option>
                        <option value="ai_ml">AI / ML</option>
                    </select>
                </div>
                <div class="form-group"><label>Custom Category</label><input type="text" name="custom_category" id="edit_custom_category" placeholder="Optional — overrides selection above" maxlength="100"></div>
                <div class="form-group"><label>Replace Thumbnail (optional)</label><input type="file" name="thumbnail" accept="image/*"></div>
                <div class="form-group">
                    <label>Type</label>
                    <select name="course_type" id="edit_course_type"><option value="Free">Free</option><option value="Paid">Paid</option></select>
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select name="status" id="edit_status" required><option value="Active">Active</option><option value="Inactive">Inactive</option></select>
                </div>
                <div class="form-group">
                    <label for="edit_teacher_id">Assign Teacher</label>
                    <select name="teacher_id" id="edit_teacher_id" required>
                        <option value="">Select Teacher</option>
                        <?php
                        $teachers_edit_stmt = $pdo->query("SELECT id, full_name FROM users WHERE role='teacher'");
                        foreach ($teachers_edit_stmt->fetchAll(PDO::FETCH_ASSOC) as $t): ?>
                        <option value="<?= (int)$t['id']; ?>"><?= htmlspecialchars($t['full_name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Price</label><input type="number" name="price" id="edit_price" step="0.01" min="0"></div>
                <button type="submit" name="update_course" class="btn btn-primary btn-full"><?= $user_role==='teacher' ? 'Submit Update for Approval' : 'Save Changes' ?></button>
            </form>
        </div>
    </div>
</div>

<div id="videoSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Video Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card">
        <h3><i class="fas fa-video"></i> <?= isset($editVideo) && $editVideo ? "Edit Video" : "Upload Video" ?></h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="video_id" value="<?= isset($editVideo) ? $editVideo['id'] : '' ?>">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">Select Course</option>
                        <?php $vc_stmt = $pdo->query("SELECT id,title FROM courses ORDER BY title ASC");
                        foreach ($vc_stmt as $c):
                            $sel = (isset($editVideo) && $editVideo && $editVideo['course_id']==$c['id']) ? "selected" : "";
                        ?>
                        <option value="<?= $c['id'] ?>" <?= $sel ?>><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Title</label><input type="text" name="title" value="<?= isset($editVideo) ? htmlspecialchars($editVideo['title'] ?? '') : '' ?>" required></div>
                <div class="form-group"><label>Video File</label><input type="file" name="video" accept="video/*"></div>
                <div class="form-group"><label>Cloud Link (Drive/YouTube)</label><input type="text" name="cloud_url" value="<?= isset($editVideo) ? htmlspecialchars($editVideo['cloud_url'] ?? '') : '' ?>"></div>
                <div class="form-group">
                    <label>Access Type</label>
                    <select name="access_type">
                        <option value="free" <?= (isset($editVideo) && ($editVideo['access_type']??'')=='free')?'selected':'' ?>>Free</option>
                        <option value="paid" <?= (isset($editVideo) && ($editVideo['access_type']??'')=='paid')?'selected':'' ?>>Paid</option>
                    </select>
                </div>
            </div>
            <div class="form-group"><label>Description</label><textarea name="description"><?= isset($editVideo) ? htmlspecialchars($editVideo['description'] ?? '') : '' ?></textarea></div>
            <?php if (isset($editVideo) && $editVideo): ?>
                <button type="submit" name="update_video" class="btn btn-warning">Update Video</button>
            <?php else: ?>
                <button type="submit" name="upload_video" class="btn btn-primary">Upload Video</button>
            <?php endif; ?>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-play-circle"></i> Video Library</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Title</th><th>Access</th><th>Description</th><th>Actions</th></tr></thead>
                <tbody>
                <?php
                $vr_stmt = $pdo->query("SELECT v.*, c.title AS course FROM course_videos v JOIN courses c ON c.id=v.course_id ORDER BY v.id DESC");
                foreach ($vr_stmt as $v): ?>
                    <tr>
                        <td><?= htmlspecialchars($v['course']) ?></td>
                        <td><strong><?= htmlspecialchars($v['title']) ?></strong></td>
                        <td><span class="badge badge-<?= $v['access_type']=='free'?'success':'warning' ?>"><?= ucfirst($v['access_type']) ?></span></td>
                        <td style="color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?= htmlspecialchars($v['description'] ?? 'No description available') ?></td>
                        <td>
                            <a href="?view_video=<?= $v['id'] ?>" class="btn btn-primary btn-sm"><i class="fas fa-play"></i> Watch</a>
                            <?php if ($is_staff): ?>
                            <a href="?edit=<?= $v['id'] ?>" class="btn btn-outline btn-sm"><i class="fas fa-edit"></i></a>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="video_id" value="<?= $v['id'] ?>">
                                <button type="submit" name="delete_video" class="btn btn-danger btn-sm" onclick="return confirm('Delete this video?')"><i class="fas fa-trash"></i></button>
                            </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="quizeSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Quiz Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="mini-stats">
        <div class="mini-stat"><h2><?= $total_quizzes ?></h2><p>Total Quizzes</p></div>
        <div class="mini-stat"><h2><?= $total_questions ?></h2><p>Questions</p></div>
        <div class="mini-stat"><h2><?= $total_attempts ?></h2><p>Attempts</p></div>
        <div class="mini-stat"><h2 style="color:var(--success);"><?= $passed ?></h2><p>Passed</p></div>
        <div class="mini-stat"><h2 style="color:var(--danger);"><?= $failed_quiz ?></h2><p>Failed</p></div>
        <div class="mini-stat"><h2><?= round($average_score,1) ?></h2><p>Avg Score</p></div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px;">
        <div class="form-card">
            <h3><i class="fas fa-plus"></i> Create Quiz</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Course</label>
                    <select name="course_id" required>
                        <option value="">Select Course</option>
                        <?php $qc_stmt = $pdo->query("SELECT * FROM courses"); foreach ($qc_stmt as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Quiz Title</label><input type="text" name="title" placeholder="Quiz Title" required></div>
                <div class="form-group"><label>Description</label><textarea name="description" placeholder="Description"></textarea></div>
                <div class="form-group"><label>Passing Marks (%)</label><input type="number" name="passing_marks" placeholder="e.g. 70" required></div>
                <div class="form-group"><label>Duration (minutes)</label><input type="number" name="duration" placeholder="e.g. 30" required></div>
                <button type="submit" name="create_quiz" class="btn btn-primary btn-full">Create Quiz</button>
            </form>
        </div>

        <div class="form-card">
            <h3><i class="fas fa-question"></i> Add Question</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Quiz</label>
                    <select name="quiz_id" required>
                        <option value="">Select Quiz</option>
                        <?php $ql_stmt = $pdo->query("SELECT * FROM quizzes ORDER BY id DESC"); foreach ($ql_stmt as $q): ?>
                        <option value="<?= $q['id'] ?>"><?= htmlspecialchars($q['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Question</label><textarea name="question" placeholder="Enter question..." required></textarea></div>
                <div class="form-group"><label>Type</label>
                    <select name="question_type"><option value="mcq">Multiple Choice</option><option value="short_answer">Short Answer</option></select>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <div class="form-group"><label>Option A</label><input type="text" name="option_a"></div>
                    <div class="form-group"><label>Option B</label><input type="text" name="option_b"></div>
                    <div class="form-group"><label>Option C</label><input type="text" name="option_c"></div>
                    <div class="form-group"><label>Option D</label><input type="text" name="option_d"></div>
                </div>
                <div class="form-group"><label>Correct Answer</label><input type="text" name="correct_answer" required></div>
                <div class="form-group"><label>Marks</label><input type="number" name="marks" value="1"></div>
                <button type="submit" name="add_question" class="btn btn-success btn-full">Add Question</button>
            </form>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Quiz List</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Course</th><th>Quiz</th><th>Passing</th><th>Duration</th><th>Status</th></tr></thead>
                <tbody>
                <?php $qlist_stmt = $pdo->query("SELECT q.*, c.title AS course_name FROM quizzes q LEFT JOIN courses c ON c.id=q.course_id ORDER BY q.id DESC");
                foreach ($qlist_stmt as $row): ?>
                    <tr>
                        <td>#<?= $row['id'] ?></td>
                        <td><?= htmlspecialchars($row['course_name']) ?></td>
                        <td><strong><?= htmlspecialchars($row['title']) ?></strong></td>
                        <td><?= $row['passing_marks'] ?? $row['passing_score'] ?>%</td>
                        <td><?= $row['duration'] ?> mins</td>
                        <td><span class="badge badge-<?= strtolower($row['status'] ?? 'active')=='active' ? 'success' : 'secondary' ?>"><?= ucfirst($row['status'] ?? 'Active') ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-users"></i> Student Attempts</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Quiz</th><th>Score</th><th>%</th><th>Result</th><th>Date</th></tr></thead>
                <tbody>
                <?php
                $atts_stmt = $pdo->query(
                    "SELECT qr.*, u.full_name
                     FROM quiz_results qr
                     LEFT JOIN users u ON u.id = qr.user_id
                     ORDER BY qr.id DESC"
                );
                foreach ($atts_stmt as $att): ?>
                    <tr>
                        <td><?= htmlspecialchars($att['full_name'] ?? 'Unknown') ?></td>
                        <td><?= htmlspecialchars($att['quiz_title']) ?></td>
                        <td><?= (int)$att['score'] ?></td>
                        <td><?= (int)$att['score'] ?>%</td>
                        <td><span class="badge badge-<?= strtolower($att['status'])=='passed'?'success':'danger' ?>"><?= ucfirst(htmlspecialchars($att['status'])) ?></span></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($att['completed_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="noteSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Notes Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:600px;">
        <h3><i class="fas fa-file-alt"></i> Create Note</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Course</label>
                <select name="course_id" required>
                    <option value="">Select Course</option>
                    <?php $nc_stmt = $pdo->query("SELECT * FROM courses"); foreach ($nc_stmt as $c): ?>
                    <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input name="title" placeholder="Note Title" required></div>
            <div class="form-group"><label>Content</label><textarea name="content" placeholder="Write notes here..." rows="4"></textarea></div>
            <div class="form-group"><label>Attach File (PDF, Doc, Image)</label><input type="file" name="file"></div>
            <div class="form-group"><label>Access Type</label>
                <select name="access_type"><option value="free">Free Course</option><option value="paid">Paid Course</option></select>
            </div>
            <button name="add_note" class="btn btn-primary btn-full">Upload Note</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-book-open"></i> Notes Library</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Title</th><th>Access</th><th>File</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($notes as $n): ?>
                    <tr>
                        <td><?= htmlspecialchars($n['course_title']) ?></td>
                        <td><strong><?= htmlspecialchars($n['title']) ?></strong></td>
                        <td><span class="badge badge-<?= $n['access_type']=='free'?'success':'warning' ?>"><?= ucfirst($n['access_type']) ?></span></td>
                        <td><?= $n['file_path'] ? '<span class="badge badge-info">Uploaded</span>' : '<span class="badge badge-secondary">Text Only</span>' ?></td>
                        <td>
                            <a href="?view_note=<?= $n['id'] ?>" target="_blank" class="btn btn-primary btn-sm"><i class="fas fa-eye"></i> View</a>
                            <a href="?delete_note=<?= $n['id'] ?>" onclick="return confirm('Delete note?')" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="announcementSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Announcements</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:600px;">
        <h3><i class="fas fa-bullhorn"></i> Post Announcement</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Course</label>
                <select name="course_id">
                    <option value="0">-- All Courses --</option>
                    <?php foreach ($ann_courses as $c): ?>
                    <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input type="text" name="title" placeholder="Announcement title" required></div>
            <div class="form-group"><label>Message</label><textarea name="message" placeholder="Write your announcement..." required></textarea></div>
            <button type="submit" name="add" class="btn btn-primary btn-full">Post Announcement</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-bell"></i> Posted Announcements</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Course</th><th>Title</th><th>Message</th><th>Date</th><th>Action</th></tr></thead>
                <tbody>
                <?php
                $announcements_rows = $announcements->fetchAll(PDO::FETCH_ASSOC);
                if (count($announcements_rows) > 0):
                    foreach ($announcements_rows as $a): ?>
                    <tr>
                        <td><?= htmlspecialchars($a['course']) ?></td>
                        <td><strong><?= htmlspecialchars($a['title']) ?></strong></td>
                        <td style="max-width:250px;"><?= nl2br(htmlspecialchars($a['message'])) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($a['created_at']) ?></td>
                        <td><a href="?delete_ann=<?= $a['id'] ?>" onclick="return confirm('Delete?')" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></a></td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;">No announcements yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="enrollmentSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Enrollment Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <?php
    $enroll_list = $pdo->query(
        "SELECT e.id, e.status, e.enrolled_at, u.full_name, u.email, s.student_no, c.title AS course
         FROM enrollments e
         JOIN users u ON u.id=e.user_id
         LEFT JOIN students s ON s.user_id = u.id
         JOIN courses c ON c.id=e.course_id
         WHERE u.role='student'
         ORDER BY e.id DESC"
    );
    ?>

    <form method="POST" class="bulk-actions">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <button type="submit" name="approve_all" class="btn btn-success" onclick="return confirm('Approve ALL pending enrollments?')"><i class="fas fa-check-double"></i> Approve All</button>
        <button type="submit" name="reject_all"  class="btn btn-warning" onclick="return confirm('Reject ALL pending/ongoing enrollments? This will remove them completely.')"><i class="fas fa-times"></i> Reject All</button>
        <button type="submit" name="clear_all"   class="btn btn-danger"  onclick="return confirm('DELETE ALL enrollments permanently?')"><i class="fas fa-trash"></i> Delete All</button>
    </form>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-user-check"></i> All Enrollments</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Student No</th><th>Email</th><th>Course</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($enroll_list as $row): ?>
                    <tr>
                        <td><?= htmlspecialchars($row['full_name']) ?></td>
                        <td><?= htmlspecialchars($row['student_no'] ?? '-') ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($row['email']) ?></td>
                        <td><?= htmlspecialchars($row['course']) ?></td>
                        <td><span class="badge badge-<?= strtolower($row['status']) ?>"><?= strtoupper($row['status']) ?></span></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($row['enrolled_at']) ?></td>
                        <td>
                            <a href="?approve=<?= $row['id'] ?>" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Approve</a>
                            <a href="?reject=<?= $row['id'] ?>" onclick="return confirm('Reject and remove this enrollment completely?')" class="btn btn-danger btn-sm"><i class="fas fa-times"></i> Reject</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="ticketSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Support Tickets</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <?php
    if (isset($_POST['update_status'])) {
        validateCsrf();
        $tid    = (int)($_POST['ticket_id'] ?? 0);
        $tstat  = trim($_POST['status'] ?? '');
        $tallow = ['open','in_progress','resolved','closed'];
        if ($tid > 0 && in_array($tstat, $tallow, true)) {
            $stmt = $pdo->prepare("UPDATE tickets SET status=? WHERE id=?");
            $stmt->execute([$tstat, $tid]);
        }
    }
    ?>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-headset"></i> All Tickets</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Type</th><th>Subject</th><th>Message</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                <?php
                $ts = $pdo->prepare("SELECT t.*, u.full_name FROM tickets t LEFT JOIN users u ON u.id=t.user_id ORDER BY t.id DESC");
                $ts->execute();
                foreach ($ts as $row):
                    $tstat_cls = str_replace('_', '-', strtolower($row['status'] ?? 'open'));
                ?>
                    <tr>
                        <td><?= htmlspecialchars($row['full_name'] ?? '') ?></td>
                        <td><?= htmlspecialchars($row['type'] ?? '') ?></td>
                        <td><strong><?= htmlspecialchars($row['subject'] ?? '') ?></strong></td>
                        <td style="max-width:200px;color:var(--muted);"><?= nl2br(htmlspecialchars($row['message'] ?? '')) ?></td>
                        <td><span class="badge badge-<?= $tstat_cls ?>"><?= strtoupper(htmlspecialchars($row['status'] ?? '')) ?></span></td>
                        <td>
                            <form method="POST" style="display:flex;gap:6px;align-items:center;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="ticket_id"  value="<?= (int)$row['id'] ?>">
                                <select name="status" style="width:130px;padding:6px 10px;font-size:12px;">
                                    <option value="open"        <?= $row['status']==='open'        ?'selected':'' ?>>Open</option>
                                    <option value="in_progress" <?= $row['status']==='in_progress' ?'selected':'' ?>>In Progress</option>
                                    <option value="resolved"    <?= $row['status']==='resolved'    ?'selected':'' ?>>Resolved</option>
                                    <option value="closed"      <?= $row['status']==='closed'      ?'selected':'' ?>>Closed</option>
                                </select>
                                <button type="submit" name="update_status" class="btn btn-primary btn-sm" onclick="return confirm('Update ticket status?')">Update</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="paymentSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Payment Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="cards" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));">
        <div class="card"><div class="card-icon c-green" style="margin-bottom:10px;"><i class="fas fa-check-circle"></i></div><h3><?= $successful ?></h3><p>Successful</p></div>
        <div class="card"><div class="card-icon c-red"   style="margin-bottom:10px;"><i class="fas fa-times-circle"></i></div><h3><?= $failed ?></h3><p>Failed</p></div>
        <div class="card"><div class="card-icon c-orange" style="margin-bottom:10px;"><i class="fas fa-clock"></i></div><h3><?= $pending ?></h3><p>Pending</p></div>
        <div class="card"><div class="card-icon c-blue"  style="margin-bottom:10px;"><i class="fas fa-calendar-day"></i></div><h3>KES <?= number_format($daily,0) ?></h3><p>Today</p></div>
        <div class="card"><div class="card-icon c-purple" style="margin-bottom:10px;"><i class="fas fa-calendar-week"></i></div><h3>KES <?= number_format($monthly,0) ?></h3><p>This Month</p></div>
        <div class="card"><div class="card-icon c-cyan"  style="margin-bottom:10px;"><i class="fas fa-calendar"></i></div><h3>KES <?= number_format($yearly,0) ?></h3><p>This Year</p></div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:22px;">
        <div class="table-section">
            <div class="table-header"><h2><i class="fas fa-credit-card"></i> Payment Methods</h2></div>
            <table>
                <thead><tr><th>Method</th><th>Transactions</th><th>Revenue</th></tr></thead>
                <tbody>
                <?php foreach ($methods as $row): ?>
                    <tr><td><?= strtoupper($row['payment_method']) ?></td><td><?= $row['total'] ?></td><td>KES <?= number_format($row['revenue'],2) ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="table-section">
            <div class="table-header"><h2><i class="fas fa-book"></i> Revenue by Course</h2></div>
            <table>
                <thead><tr><th>Course</th><th>Total Revenue</th></tr></thead>
                <tbody>
                <?php foreach ($courseRevenue as $row): ?>
                    <tr><td><?= htmlspecialchars($row['title']) ?></td><td>KES <?= number_format($row['total'],2) ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Payment Monitoring</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Course</th><th>Amount</th><th>Method</th><th>Status</th><th>Verification</th><th>Date</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($payments as $row): ?>
                    <tr>
                        <td>#<?= $row['id'] ?></td>
                        <td><?= htmlspecialchars($row['course_title'] ?? 'N/A') ?></td>
                        <td>KES <?= number_format($row['amount'],2) ?></td>
                        <td><?= strtoupper($row['payment_method']) ?></td>
                        <td><span class="badge badge-<?= $row['status']=='completed'?'success':($row['status']=='pending'?'warning':'danger') ?>"><?= strtoupper($row['status']) ?></span></td>
                        <td>
                            <?php $vstat = $row['verification_status'] ?? 'pending'; ?>
                            <span class="badge badge-<?= $vstat=='verified'?'success':($vstat=='pending'?'warning':'danger') ?>"><?= strtoupper($vstat) ?></span>
                        </td>
                        <td style="color:var(--muted);"><?= $row['created_at'] ?></td>
                        <td>
                            <button type="button" class="btn btn-outline btn-sm"
                                onclick='openPaymentDetails(<?= json_encode([
                                    "id"             => (int)$row["id"],
                                    "course"         => $row["course_title"] ?? "N/A",
                                    "amount"         => number_format((float)$row["amount"], 2),
                                    "method"         => strtoupper($row["payment_method"]),
                                    "status"         => strtoupper($row["status"]),
                                    "verification"   => strtoupper($row["verification_status"] ?? "pending"),
                                    "payer_name"     => $row["payer_name"] ?? "",
                                    "payer_phone"    => $row["payer_phone"] ?? "",
                                    "payer_email"    => $row["payer_email"] ?? "",
                                    "transaction_code"=> $row["transaction_code"] ?? "",
                                    "mpesa_receipt"  => $row["mpesa_receipt"] ?? "",
                                    "payment_date"   => $row["payment_date"] ?? "",
                                    "notes"          => $row["notes"] ?? "",
                                ], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP) ?>)'>
                                <i class="fas fa-eye"></i> View
                            </button>
                            <a href="?action=completed&id=<?= $row['id'] ?>" onclick="return confirm('Approve and verify this payment? This will enroll the student in the course.')" class="btn btn-success btn-sm">Approve</a>
                            <a href="?action=failed&id=<?= $row['id'] ?>"  onclick="return confirm('Reject this payment?')"  class="btn btn-danger btn-sm">Reject</a>
                            <a href="?action=pending&id=<?= $row['id'] ?>" onclick="return confirm('Mark as pending?')" class="btn btn-warning btn-sm">Pending</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-users"></i> Student Payment Monitoring</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Student</th><th>Student No</th><th>Email</th><th>Course</th><th>Amount</th><th>Method</th><th>Status</th><th>Verification</th><th>Date</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($student_payments as $row): ?>
                    <tr>
                        <td>#<?= $row['id'] ?></td>
                        <td><?= htmlspecialchars($row['student_name'] ?? 'Unknown') ?></td>
                        <td><?= htmlspecialchars($row['student_no'] ?? '-') ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($row['email'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($row['course']) ?></td>
                        <td>KES <?= number_format($row['amount'],2) ?></td>
                        <td><?= strtoupper($row['payment_method']) ?></td>
                        <td><span class="badge badge-<?= $row['status']=='completed'?'success':($row['status']=='pending'?'warning':'danger') ?>"><?= strtoupper($row['status']) ?></span></td>
                        <td>
                            <?php $vstat2 = $row['verification_status'] ?? 'pending'; ?>
                            <span class="badge badge-<?= $vstat2=='verified'?'success':($vstat2=='pending'?'warning':'danger') ?>"><?= strtoupper($vstat2) ?></span>
                        </td>
                        <td style="color:var(--muted);"><?= $row['created_at'] ?></td>
                        <td>
                            <button type="button" class="btn btn-outline btn-sm"
                                onclick='openPaymentDetails(<?= json_encode([
                                    "id"             => (int)$row["id"],
                                    "course"         => $row["course"] ?? "N/A",
                                    "amount"         => number_format((float)$row["amount"], 2),
                                    "method"         => strtoupper($row["payment_method"]),
                                    "status"         => strtoupper($row["status"]),
                                    "verification"   => strtoupper($row["verification_status"] ?? "pending"),
                                    "payer_name"     => $row["payer_name"] ?? ($row["student_name"] ?? ""),
                                    "payer_phone"    => $row["payer_phone"] ?? "",
                                    "payer_email"    => $row["payer_email"] ?? ($row["email"] ?? ""),
                                    "transaction_code"=> $row["transaction_code"] ?? "",
                                    "mpesa_receipt"  => $row["mpesa_receipt"] ?? "",
                                    "payment_date"   => $row["payment_date"] ?? "",
                                    "notes"          => $row["notes"] ?? "",
                                ], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP) ?>)'>
                                <i class="fas fa-eye"></i> View
                            </button>
                            <a href="?action=completed&id=<?= $row['id'] ?>" onclick="return confirm('Approve and verify this payment? This will enroll the student in the course.')" class="btn btn-success btn-sm">Approve</a>
                            <a href="?action=failed&id=<?= $row['id'] ?>"  onclick="return confirm('Reject this payment?')"  class="btn btn-danger btn-sm">Reject</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="invoiceSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Invoices / eTIMS</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Compliance</p></div></div></div>
    </div>

    <div class="alert alert-note"><i class="fas fa-circle-info"></i> Invoices are created here in <strong>draft</strong> status capturing the KRA PIN for compliance. Live submission to the KRA eTIMS API requires the organisation's production credentials, which are configured outside this file's scope.</div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-file-invoice"></i> Create Invoice</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Student</label>
                <select name="user_id" required>
                    <option value="">Select Student</option>
                    <?php $inv_students = $pdo->query("SELECT id, full_name FROM users WHERE role='student' ORDER BY full_name");
                    foreach ($inv_students as $s): ?>
                    <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['full_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Course</label>
                <select name="course_id" required>
                    <option value="">Select Course</option>
                    <?php $inv_courses = $pdo->query("SELECT id, title FROM courses ORDER BY title");
                    foreach ($inv_courses as $c): ?>
                    <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>KRA PIN</label><input type="text" name="kra_pin" maxlength="30" placeholder="e.g. A012345678Z"></div>
            <div class="form-group"><label>Amount (KES, tax-inclusive)</label><input type="number" name="amount" step="0.01" min="0" required></div>
            <button type="submit" name="create_invoice" class="btn btn-primary btn-full">Create Invoice</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Invoices</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Invoice No</th><th>Student</th><th>Course</th><th>KRA PIN</th><th>Amount</th><th>VAT</th><th>eTIMS Status</th><th>Date</th></tr></thead>
                <tbody>
                <?php foreach ($stp_invoices as $inv): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($inv['invoice_no']) ?></strong></td>
                        <td><?= htmlspecialchars($inv['full_name'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($inv['course_title'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($inv['kra_pin'] ?? '-') ?></td>
                        <td>KES <?= number_format($inv['amount'],2) ?></td>
                        <td>KES <?= number_format($inv['tax_amount'],2) ?></td>
                        <td><span class="badge badge-<?= $inv['etims_status']==='submitted'?'success':($inv['etims_status']==='draft'?'draft':'danger') ?>"><?= strtoupper($inv['etims_status']) ?></span></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($inv['created_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="certificateSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Certification Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="alert alert-note"><i class="fas fa-circle-info"></i> Certificates auto-issue once a student's overall course progress reaches 90%. Trainers can also confirm completion from the Trainer Portal (queued below); use the manual form for anything else.</div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-hourglass-half"></i> Trainer-Confirmed Completions Awaiting Issuance</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Course</th><th>Requested</th><th>Action</th></tr></thead>
                <tbody>
                <?php if ($pending_certificate_requests && $pending_certificate_requests->rowCount() > 0): foreach ($pending_certificate_requests as $pcr): ?>
                    <tr>
                        <td><?= htmlspecialchars($pcr['full_name']) ?></td>
                        <td><?= htmlspecialchars($pcr['course_title']) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($pcr['requested_at']) ?></td>
                        <td>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="cert_request_id" value="<?= (int)$pcr['id'] ?>">
                                <input type="hidden" name="cert_decision" value="approved">
                                <button type="submit" name="review_certificate_request" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Approve & Issue</button>
                            </form>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="cert_request_id" value="<?= (int)$pcr['id'] ?>">
                                <input type="hidden" name="cert_decision" value="rejected">
                                <button type="submit" name="review_certificate_request" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px;">No trainer completion confirmations pending</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-certificate"></i> Issue Certificate Manually</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Student</label>
                <select name="user_id" required>
                    <option value="">Select Student</option>
                    <?php $cert_students = $pdo->query("SELECT id, full_name FROM users WHERE role='student' ORDER BY full_name");
                    foreach ($cert_students as $s): ?>
                    <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['full_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Course</label>
                <select name="course_id" required>
                    <option value="">Select Course</option>
                    <?php $cert_courses = $pdo->query("SELECT id, title FROM courses ORDER BY title");
                    foreach ($cert_courses as $c): ?>
                    <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" name="issue_certificate" class="btn btn-primary btn-full">Issue Certificate</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Issued Certificates</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Cert No</th><th>Student</th><th>Course</th><th>Issued</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($certificates_list as $cert): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($cert['cert_number']) ?></strong></td>
                        <td><?= htmlspecialchars($cert['full_name']) ?></td>
                        <td><?= htmlspecialchars($cert['course_title']) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($cert['issued_at']) ?></td>
                        <td><a href="?view_cert=<?= (int)$cert['id'] ?>" target="_blank" class="btn btn-primary btn-sm"><i class="fas fa-eye"></i> View / Print</a></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($certificates_list->rowCount() === 0): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;">No stp_certificates issued yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="referralSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Referral &amp; Affiliate System</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-share-nodes"></i> Generate Referral Code</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Student / Trainer / Alumni</label>
                <select name="referral_user_id" required>
                    <option value="">Select User</option>
                    <?php $ref_users = $pdo->query("SELECT id, full_name, role FROM users WHERE role IN ('student','teacher') ORDER BY full_name");
                    foreach ($ref_users as $ru): ?>
                    <option value="<?= (int)$ru['id'] ?>"><?= htmlspecialchars($ru['full_name']) ?> (<?= htmlspecialchars($ru['role']) ?>)</option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Commission Rate (%)</label><input type="number" name="commission_rate" value="5" step="0.5" min="0" max="100"></div>
            <button type="submit" name="generate_referral_code" class="btn btn-primary btn-full">Generate Code</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Referral Codes</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Code</th><th>Referrer</th><th>Rate</th><th>Uses</th><th>Paid</th><th>Pending</th><th>Status</th></tr></thead>
                <tbody>
                <?php foreach ($referral_codes as $rc): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($rc['code']) ?></strong></td>
                        <td><?= htmlspecialchars($rc['full_name']) ?></td>
                        <td><?= number_format($rc['commission_rate'],2) ?>%</td>
                        <td><?= (int)$rc['uses'] ?></td>
                        <td>KES <?= number_format($rc['paid_total'],2) ?></td>
                        <td>KES <?= number_format($rc['pending_total'],2) ?></td>
                        <td><span class="badge badge-<?= $rc['status']==='active'?'success':'secondary' ?>"><?= ucfirst($rc['status']) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($referral_codes->rowCount() === 0): ?>
                    <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px;">No referral codes yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-hand-holding-dollar"></i> Referral Performance / Commissions</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Referrer</th><th>Code</th><th>Referred</th><th>Course</th><th>Amount</th><th>Commission</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($referral_uses_list as $ru2): ?>
                    <tr>
                        <td><?= htmlspecialchars($ru2['referrer_name']) ?></td>
                        <td><?= htmlspecialchars($ru2['code']) ?></td>
                        <td><?= htmlspecialchars($ru2['referred_name'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($ru2['course_title'] ?? '-') ?></td>
                        <td>KES <?= number_format($ru2['amount'],2) ?></td>
                        <td>KES <?= number_format($ru2['commission'],2) ?></td>
                        <td><span class="badge badge-<?= $ru2['status']==='paid'?'paid':'pending' ?>"><?= ucfirst($ru2['status']) ?></span></td>
                        <td>
                            <?php if ($ru2['status'] === 'pending'): ?>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="referral_use_id" value="<?= (int)$ru2['id'] ?>">
                                <button type="submit" name="mark_commission_paid" class="btn btn-success btn-sm">Mark Paid</button>
                            </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($referral_uses_list->rowCount() === 0): ?>
                    <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px;">No referral activity yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="cpdSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>CPD / CME Points</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Annual target: <?= $cpd_annual_target ?> pts</p></div></div></div>
    </div>

    <div class="alert alert-note"><i class="fas fa-circle-info"></i> Activities submitted by trainers and students through their portals appear in the <strong>Verification Queue</strong> below. The form beneath it is for logging points directly on a user's behalf (automatically verified).</div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-hourglass-half"></i> CPD Verification Queue</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Name</th><th>Role</th><th>Activity</th><th>Type</th><th>Points</th><th>Date</th><th>Evidence</th><th>Action</th></tr></thead>
                <tbody>
                <?php if ($pending_cpd_points && $pending_cpd_points->rowCount() > 0): foreach ($pending_cpd_points as $pcp): ?>
                    <tr>
                        <td><?= htmlspecialchars($pcp['full_name']) ?></td>
                        <td><?= htmlspecialchars(ucfirst($pcp['role'] ?? '')) ?></td>
                        <td><?= htmlspecialchars($pcp['activity_title']) ?></td>
                        <td><?= htmlspecialchars(ucfirst($pcp['activity_type'])) ?></td>
                        <td><?= number_format((float)$pcp['points'], 1) ?></td>
                        <td><?= htmlspecialchars($pcp['date_earned']) ?></td>
                        <td><?php if (!empty($pcp['evidence_path'])): ?><a href="<?= htmlspecialchars($pcp['evidence_path']) ?>" target="_blank">View</a><?php else: ?>—<?php endif; ?></td>
                        <td>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="cpd_point_id" value="<?= (int)$pcp['id'] ?>">
                                <input type="hidden" name="cpd_decision" value="verified">
                                <button type="submit" name="review_cpd_point" class="btn btn-success btn-sm"><i class="fas fa-check"></i></button>
                            </form>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="cpd_point_id" value="<?= (int)$pcp['id'] ?>">
                                <input type="hidden" name="cpd_decision" value="rejected">
                                <button type="submit" name="review_cpd_point" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i></button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px;">No CPD entries awaiting verification</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clock-rotate-left"></i> CPD Verification History</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Name</th><th>Activity</th><th>Points</th><th>Date</th><th>Status</th></tr></thead>
                <tbody>
                <?php if ($cpd_points_history && $cpd_points_history->rowCount() > 0): foreach ($cpd_points_history as $ch2): ?>
                    <tr>
                        <td><?= htmlspecialchars($ch2['full_name']) ?></td>
                        <td><?= htmlspecialchars($ch2['activity_title']) ?></td>
                        <td><?= number_format((float)$ch2['points'], 1) ?></td>
                        <td><?= htmlspecialchars($ch2['date_earned']) ?></td>
                        <td><span class="badge badge-<?= $ch2['verification_status']==='verified'?'verified':'rejected' ?>"><?= ucfirst($ch2['verification_status']) ?></span></td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px;">No verification history yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-award"></i> Log CPD Points Directly (auto-verified)</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Student / Trainer</label>
                <select name="cpd_user_id" required>
                    <option value="">Select User</option>
                    <?php $cpd_users = $pdo->query("SELECT id, full_name FROM users WHERE role IN ('student','teacher') ORDER BY full_name");
                    foreach ($cpd_users as $cu): ?>
                    <option value="<?= (int)$cu['id'] ?>"><?= htmlspecialchars($cu['full_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Activity</label>
                <select name="activity">
                    <option value="Webinar">Webinar (2 pts)</option>
                    <option value="Workshop">Workshop (5 pts)</option>
                    <option value="Training Course">Training Course (10 pts)</option>
                    <option value="Conference">Conference (15 pts)</option>
                    <option value="Professional Assessment">Professional Assessment (5 pts)</option>
                    <option value="Other">Other</option>
                </select>
            </div>
            <div class="form-group"><label>Points</label><input type="number" name="points" min="1" max="50" value="2" required></div>
            <div class="form-group"><label>Activity Date</label><input type="date" name="activity_date" value="<?= date('Y-m-d') ?>"></div>
            <button type="submit" name="add_cpd_points" class="btn btn-primary btn-full">Log Points</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-ranking-star"></i> Annual CPD Progress (admin-logged)</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Name</th><th>Points</th><th>Target</th><th>Progress</th></tr></thead>
                <tbody>
                <?php foreach ($cpd_summary as $cs): $pct = min(100, round(($cs['total_points']/$cpd_annual_target)*100)); ?>
                    <tr>
                        <td><?= htmlspecialchars($cs['full_name']) ?></td>
                        <td><?= (int)$cs['total_points'] ?></td>
                        <td><?= $cpd_annual_target ?></td>
                        <td>
                            <div class="progress-mini">
                                <div class="track"><div class="fill" style="width:<?= $pct ?>%;"></div></div>
                                <span><?= $pct ?>%</span>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($cpd_summary->rowCount() === 0): ?>
                    <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px;">No CPD points logged yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clock-rotate-left"></i> Recent CPD Entries (admin-logged)</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Name</th><th>Activity</th><th>Points</th><th>Date</th></tr></thead>
                <tbody>
                <?php foreach ($cpd_recent as $cr): ?>
                    <tr>
                        <td><?= htmlspecialchars($cr['full_name']) ?></td>
                        <td><?= htmlspecialchars($cr['activity']) ?></td>
                        <td><?= (int)$cr['points'] ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($cr['activity_date']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="practiceHubSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Professional Practice Support Hub</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-briefcase-medical"></i> Add Resource</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Category</label>
                <select name="category" required>
                    <option value="Legal Practice Support">Legal Practice Support</option>
                    <option value="Human Resource Management">Human Resource Management</option>
                    <option value="Finance and Accounting">Finance and Accounting</option>
                    <option value="Tax Compliance">Tax Compliance</option>
                    <option value="Insurance and Professional Indemnity">Insurance and Professional Indemnity</option>
                    <option value="Private Practice Development">Private Practice Development</option>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input type="text" name="res_title" required maxlength="200"></div>
            <div class="form-group"><label>Description</label><textarea name="res_description" maxlength="1000"></textarea></div>
            <div class="form-group"><label>External Link (optional)</label><input type="text" name="res_link" placeholder="https://"></div>
            <div class="form-group"><label>File (optional)</label><input type="file" name="res_file"></div>
            <div class="form-group"><label>Status</label>
                <select name="res_status"><option value="published">Published</option><option value="draft">Draft</option></select>
            </div>
            <button type="submit" name="add_resource" class="btn btn-primary btn-full">Add Resource</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-folder-open"></i> Resource Library</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Category</th><th>Title</th><th>Link/File</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($stp_practice_resources as $pr): ?>
                    <tr>
                        <td><?= htmlspecialchars($pr['category']) ?></td>
                        <td><strong><?= htmlspecialchars($pr['title']) ?></strong></td>
                        <td>
                            <?php if (!empty($pr['link'])): ?><a href="<?= htmlspecialchars($pr['link']) ?>" target="_blank">Open Link</a><?php endif; ?>
                            <?php if (!empty($pr['file_path'])): ?><a href="<?= htmlspecialchars($pr['file_path']) ?>" target="_blank">Download File</a><?php endif; ?>
                            <?php if (empty($pr['link']) && empty($pr['file_path'])): ?><span style="color:var(--muted);">—</span><?php endif; ?>
                        </td>
                        <td><span class="badge badge-<?= $pr['status'] ?>"><?= ucfirst($pr['status']) ?></span></td>
                        <td><a href="?delete_resource=<?= (int)$pr['id'] ?>" onclick="return confirm('Delete resource?')" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i></a></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($stp_practice_resources->rowCount() === 0): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;">No resources yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="promotionSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Promotions &amp; Advertisements</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-bullhorn"></i> Create Promotion</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Title</label><input type="text" name="promo_title" required maxlength="200"></div>
            <div class="form-group"><label>Description</label><textarea name="promo_description" maxlength="1000"></textarea></div>
            <div class="form-group"><label>Link</label><input type="text" name="promo_link" placeholder="https://"></div>
            <div class="form-group"><label>Image</label><input type="file" name="promo_image" accept="image/*"></div>
            <div class="form-group"><label>Placement</label>
                <select name="placement">
                    <option value="homepage">Homepage Banner</option>
                    <option value="login">Login Page</option>
                    <option value="dashboard">Student Dashboard</option>
                </select>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div class="form-group"><label>Start Date</label><input type="date" name="start_date"></div>
                <div class="form-group"><label>End Date</label><input type="date" name="end_date"></div>
            </div>
            <button type="submit" name="add_promotion" class="btn btn-primary btn-full">Create Promotion</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Promotions</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Title</th><th>Placement</th><th>Dates</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                <?php foreach ($promotions_list as $pm): ?>
                    <tr>
                        <td><strong><?= htmlspecialchars($pm['title']) ?></strong></td>
                        <td><?= htmlspecialchars(ucfirst($pm['placement'])) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($pm['start_date'] ?? '-') ?> → <?= htmlspecialchars($pm['end_date'] ?? '-') ?></td>
                        <td><span class="badge badge-<?= $pm['status'] ?>"><?= ucfirst($pm['status']) ?></span></td>
                        <td><?php if ($pm['status']!=='archived'): ?><a href="?archive_promotion=<?= (int)$pm['id'] ?>" class="btn btn-outline btn-sm">Archive</a><?php endif; ?></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($promotions_list->rowCount() === 0): ?>
                    <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px;">No stp_promotions yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="attendanceSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Attendance</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-calendar-check"></i> Mark Attendance</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Course</label>
                <select name="att_course_id" required>
                    <option value="">Select Course</option>
                    <?php $att_courses = $pdo->query("SELECT id, title FROM courses ORDER BY title");
                    foreach ($att_courses as $ac): ?>
                    <option value="<?= (int)$ac['id'] ?>"><?= htmlspecialchars($ac['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Student</label>
                <select name="att_user_id" required>
                    <option value="">Select Student</option>
                    <?php $att_students = $pdo->query("SELECT id, full_name FROM users WHERE role='student' ORDER BY full_name");
                    foreach ($att_students as $as_): ?>
                    <option value="<?= (int)$as_['id'] ?>"><?= htmlspecialchars($as_['full_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Session Date</label><input type="date" name="session_date" value="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Status</label>
                <select name="att_status"><option value="present">Present</option><option value="absent">Absent</option><option value="excused">Excused</option></select>
            </div>
            <button type="submit" name="mark_attendance" class="btn btn-primary btn-full">Record Attendance</button>
        </form>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-list"></i> Attendance Log</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Course</th><th>Date</th><th>Status</th></tr></thead>
                <tbody>
                <?php foreach ($attendance_list as $al2): ?>
                    <tr>
                        <td><?= htmlspecialchars($al2['full_name']) ?></td>
                        <td><?= htmlspecialchars($al2['course_title']) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($al2['session_date']) ?></td>
                        <td><span class="badge badge-<?= $al2['status'] ?>"><?= ucfirst($al2['status']) ?></span></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($attendance_list->rowCount() === 0): ?>
                    <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px;">No stp_attendance recorded yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="studentsSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Student Management</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Administrator</p></div></div></div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-id-card"></i> Professional Profile Verification Queue</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Student</th><th>Email</th><th>Licence No.</th><th>Qualification</th><th>KRA PIN</th><th>Action</th></tr></thead>
                <tbody>
                <?php if ($pending_student_verifications && $pending_student_verifications->rowCount() > 0): foreach ($pending_student_verifications as $psv): ?>
                    <tr>
                        <td><?= htmlspecialchars($psv['full_name']) ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($psv['email']) ?></td>
                        <td><?= htmlspecialchars($psv['license_number'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($psv['qualification_level'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($psv['kra_pin'] ?? '-') ?></td>
                        <td>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="student_row_id" value="<?= (int)$psv['id'] ?>">
                                <input type="hidden" name="sv_decision" value="verified">
                                <button type="submit" name="review_student_verification" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Verify</button>
                            </form>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="student_row_id" value="<?= (int)$psv['id'] ?>">
                                <input type="hidden" name="sv_decision" value="rejected">
                                <button type="submit" name="review_student_verification" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; else: ?>
                    <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px;">No student profiles awaiting verification</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-user-graduate"></i> Records</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Student No</th><th>Full Name</th><th>Email</th><th>Phone</th><th>Licence No.</th><th>Qualification</th><th>Verification</th><th>KRA PIN</th><th>Registered</th><th>Status</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($students as $s): ?>
                    <tr>
                        <td>#<?= (int)$s['id'] ?></td>
                        <td><?= htmlspecialchars($s['student_no'] ?? '-') ?></td>
                        <td>
                            <div style="display:flex;align-items:center;gap:10px;">
                                <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--primary),var(--primary-light));display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:700;flex-shrink:0;">
                                    <?= strtoupper(substr($s['full_name'],0,1)) ?>
                                </div>
                                <?= htmlspecialchars($s['full_name']) ?>
                                <?php if (!empty($s['is_alumni'])): ?><span class="badge badge-info">Alumni</span><?php endif; ?>
                            </div>
                        </td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($s['email']) ?></td>
                        <td><?= htmlspecialchars($s['phone'] ?? '') ?></td>
                        <td><?= htmlspecialchars($s['student_license_number'] ?? $s['license_no'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($s['student_qualification_level'] ?? $s['qualification_level'] ?? '-') ?></td>
                        <td>
                            <?php $svs = $s['student_verification_status'] ?? 'unverified'; ?>
                            <span class="badge badge-<?= $svs ?>"><?= ucfirst($svs) ?></span>
                        </td>
                        <td><?= htmlspecialchars($s['kra_pin'] ?? '-') ?></td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($s['created_at']) ?></td>
                        <td><span class="badge badge-<?= strtolower($s['status'])=='active'?'success':'danger' ?>"><?= htmlspecialchars($s['status']) ?></span></td>
                        <td>
                            <button type="button" class="btn btn-outline btn-sm" onclick='openProfileModal(<?= json_encode(["id"=>(int)$s["id"],"name"=>$s["full_name"],"license_no"=>$s["license_no"]??"","qualification_level"=>$s["qualification_level"]??"","kra_pin"=>$s["kra_pin"]??""], JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP) ?>)'><i class="fas fa-id-card"></i></button>
                            <form method="POST" style="display:inline-flex;gap:6px;align-items:center;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="student_id" value="<?= (int)$s['id'] ?>">
                                <select name="action" onchange="studentAction(this, <?= (int)$s['id'] ?>)" style="padding:6px 10px;font-size:12px;width:140px;">
                                    <option value="">Action</option>
                                    <option value="activate">Activate</option>
                                    <option value="suspend">Suspend</option>
                                    <option value="mark_alumni">Mark Alumni</option>
                                    <option value="reset_password">Reset Password</option>
                                    <option value="delete">Delete</option>
                                </select>
                                <button type="submit" name="student_action" class="btn btn-primary btn-sm" onclick="return confirm('Proceed?')">Go</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="table-section">
        <div class="table-header"><h2><i class="fas fa-clipboard-list"></i> Enrollment Monitoring</h2></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>ID</th><th>Student</th><th>Student No</th><th>Course</th><th>Status</th><th>Progress</th><th>Enrolled At</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($enrollments_data as $e): $prog2 = max(0, min(100, (int)$e['progress'])); ?>
                    <tr>
                        <td> <?= (int)$e['id'] ?></td>
                        <td><?= htmlspecialchars($e['full_name']) ?></td>
                        <td><?= htmlspecialchars($e['student_no'] ?? '-') ?></td>
                        <td><?= htmlspecialchars($e['title']) ?></td>
                        <td><span class="badge badge-<?= strtolower($e['status']) ?>"><?= htmlspecialchars($e['status']) ?></span></td>
                        <td>
                            <div class="progress-mini">
                                <div class="track"><div class="fill" style="width:<?= $prog2 ?>%;"></div></div>
                                <span><?= $prog2 ?>%</span>
                            </div>
                        </td>
                        <td style="color:var(--muted);"><?= htmlspecialchars($e['enrolled_at']) ?></td>
                        <td>
                            <form method="POST" style="display:flex;gap:6px;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                <input type="hidden" name="enroll_id"     value="<?= (int)$e['id'] ?>">
                                <input type="hidden" name="enroll_action" value="1">
                                <button type="submit" name="action" value="approve" class="btn btn-success btn-sm">Approve</button>
                                <button type="submit" name="action" value="reject"  class="btn btn-warning btn-sm" onclick="return confirm('Reject and remove this enrollment completely?')">Reject</button>
                                <button type="submit" name="action" value="delete"  class="btn btn-danger  btn-sm" onclick="return confirm('Delete enrollment?')">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div id="roadmapSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Roadmap — Phase 2 Engagement Features</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>System Admin</h4><p>Planning</p></div></div></div>
    </div>

    <div class="alert alert-note"><i class="fas fa-circle-info"></i> The features below are scoped and designed but not yet wired into this panel. They will be built in the next phase once the current core (approvals, trainer change requests, certification, stp_referrals, CPD, practice hub, stp_promotions, stp_attendance, stp_invoices) is validated in production.</div>

    <div class="form-card">
        <h3><i class="fas fa-map"></i> Planned</h3>
        <div class="roadmap-grid">
            <div class="roadmap-item"><h4><i class="fas fa-comments"></i> Discussion Forum Moderation</h4><p>Course-level peer discussion oversight (trainers already moderate from the Trainer Portal).</p></div>
            <div class="roadmap-item"><h4><i class="fas fa-people-arrows"></i> Mentorship Matching Oversight</h4><p>Admin-level view of mentor/mentee matches created by trainers, alumni and students.</p></div>
            <div class="roadmap-item"><h4><i class="fas fa-notes-medical"></i> Internship / Supervision Logbook Audit</h4><p>Cross-supervisor review of sign-off history.</p></div>
            <div class="roadmap-item"><h4><i class="fas fa-briefcase"></i> Jobs &amp; Placement Board</h4><p>Employer postings, applications and placement tracking.</p></div>
            <div class="roadmap-item"><h4><i class="fas fa-id-badge"></i> Digital Portfolio</h4><p>Aggregated view of stp_certificates, CPD points and competencies per student.</p></div>
            <div class="roadmap-item"><h4><i class="fas fa-mobile-screen"></i> Mobile App / PWA</h4><p>Responsive shell exists; native/PWA packaging is a separate build.</p></div>
        </div>
    </div>
</div>

<?php if ($is_super): ?>
<div id="settingsSection" style="display:none;">
    <div class="topbar">
        <div class="topbar-left"><div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div><h1>Settings / Branding</h1></div>
        <div class="topbar-right"><div class="admin-profile"><div class="info"><h4>Super Admin</h4><p>Governance</p></div></div></div>
    </div>

    <div class="form-card" style="max-width:640px;">
        <h3><i class="fas fa-palette"></i> Branding</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group"><label>Organisation Name</label><input type="text" name="org_name" value="<?= htmlspecialchars($branding['org_name']) ?>" maxlength="100"></div>
            <div class="form-group"><label>Logo URL</label><input type="text" name="logo_url" value="<?= htmlspecialchars($branding['logo_url']) ?>" placeholder="https://.../logo.png"></div>
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;">
                <div class="form-group"><label>Primary</label><input type="color" name="color_primary" value="<?= htmlspecialchars($branding['color_primary']) ?>"></div>
                <div class="form-group"><label>Primary Dark</label><input type="color" name="color_primary_dark" value="<?= htmlspecialchars($branding['color_primary_dark']) ?>"></div>
                <div class="form-group"><label>Primary Light</label><input type="color" name="color_primary_light" value="<?= htmlspecialchars($branding['color_primary_light']) ?>"></div>
                <div class="form-group"><label>Accent</label><input type="color" name="color_accent" value="<?= htmlspecialchars($branding['color_accent']) ?>"></div>
            </div>
            <p style="font-size:11.5px;color:var(--muted);margin-bottom:14px;">Colours default to a placeholder teal palette. Replace with CBT-Kenya's official brand hex codes once supplied.</p>
            <button type="submit" name="save_branding" class="btn btn-primary btn-full">Save Branding</button>
        </form>
    </div>
</div>
<?php endif; ?>

</div>

<div id="resetPasswordModal" class="modal">
    <div class="modal-content" style="max-width:380px;">
        <button class="close-modal" onclick="document.getElementById('resetPasswordModal').style.display='none'"><i class="fas fa-times"></i></button>
        <h3><i class="fas fa-key" style="color:var(--primary);margin-right:8px;"></i>Reset Password</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="student_id" id="modal_student_id">
            <div class="form-group"><label>New Password</label><input type="password" name="new_password" minlength="6" required></div>
            <button type="submit" name="reset_student_password" class="btn btn-success btn-full">Save Password</button>
        </form>
    </div>
</div>

<div id="profileFieldsModal" class="modal">
    <div class="modal-content" style="max-width:420px;">
        <button class="close-modal" onclick="closeModal('profileFieldsModal')"><i class="fas fa-times"></i></button>
        <h3><i class="fas fa-id-card" style="color:var(--primary);margin-right:8px;"></i>Professional Profile</h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="profile_user_id" id="pf_user_id">
            <div class="form-group"><label>Name</label><input type="text" id="pf_name" disabled></div>
            <div class="form-group"><label>Licence / Registration No.</label><input type="text" name="license_no" id="pf_license"></div>
            <div class="form-group">
                <label>Qualification Level</label>
                <select name="qualification_level" id="pf_qualification">
                    <option value="">Select level</option>
                    <option>Diploma</option><option>Degree</option><option>Master's</option><option>PhD</option>
                </select>
            </div>
            <div class="form-group"><label>KRA PIN</label><input type="text" name="kra_pin" id="pf_kra"></div>
            <button type="submit" name="update_profile_fields" class="btn btn-primary btn-full">Save Profile</button>
        </form>
    </div>
</div>

<div id="paymentDetailsModal" class="modal">
    <div class="modal-content" style="max-width:460px;">
        <button class="close-modal" onclick="closeModal('paymentDetailsModal')"><i class="fas fa-times"></i></button>
        <h3><i class="fas fa-receipt" style="color:var(--primary);margin-right:8px;"></i>Transaction Details</h3>
        <div id="pd_body">
            <div class="detail-row"><span class="label">Payment ID</span><span class="value" id="pd_id"></span></div>
            <div class="detail-row"><span class="label">Course</span><span class="value" id="pd_course"></span></div>
            <div class="detail-row"><span class="label">Amount</span><span class="value" id="pd_amount"></span></div>
            <div class="detail-row"><span class="label">Method</span><span class="value" id="pd_method"></span></div>
            <div class="detail-row"><span class="label">Status</span><span class="value" id="pd_status"></span></div>
            <div class="detail-row"><span class="label">Verification</span><span class="value" id="pd_verification"></span></div>
            <div class="detail-row" id="pd_row_payer_name"><span class="label">Payer Name</span><span class="value" id="pd_payer_name"></span></div>
            <div class="detail-row" id="pd_row_payer_phone"><span class="label">Payer Phone</span><span class="value" id="pd_payer_phone"></span></div>
            <div class="detail-row" id="pd_row_payer_email"><span class="label">Payer Email</span><span class="value" id="pd_payer_email"></span></div>
            <div class="detail-row" id="pd_row_txn"><span class="label">Bank Transaction Code</span><span class="value" id="pd_txn"></span></div>
            <div class="detail-row" id="pd_row_receipt"><span class="label">M-Pesa Receipt</span><span class="value" id="pd_receipt"></span></div>
            <div class="detail-row" id="pd_row_date"><span class="label">Deposit Date</span><span class="value" id="pd_date"></span></div>
            <div class="detail-row" id="pd_row_notes"><span class="label">Notes</span><span class="value" id="pd_notes"></span></div>
        </div>
        <div style="margin-top:18px;display:flex;gap:8px;">
            <a id="pd_approve_link" href="#" class="btn btn-success btn-sm" onclick="return confirm('Approve and verify this payment? This will enroll the student in the course.')" style="flex:1;justify-content:center;">Approve</a>
            <a id="pd_reject_link" href="#" class="btn btn-danger btn-sm" onclick="return confirm('Reject this payment?')" style="flex:1;justify-content:center;">Reject</a>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const allSections = [
    'dashboardSection','reportsSection','approvalsSection','changeRequestsSection','auditSection','studentsSection','coursesSection','videoSection',
    'noteSection','enrollmentSection','paymentSection','invoiceSection','certificateSection','announcementSection',
    'ticketSection','quizeSection','roleSection','practiceHubSection','cpdSection','referralSection',
    'promotionSection','attendanceSection','roadmapSection','settingsSection'
];
function showSection(id, link){
    allSections.forEach(s => {
        const el = document.getElementById(s);
        if(el) el.style.display = 'none';
    });
    const target = document.getElementById(id);
    if(target) target.style.display = 'block';
    document.querySelectorAll('.menu ul li a').forEach(a => a.classList.remove('active'));
    if(link) link.classList.add('active');
    else {
        document.querySelectorAll('.menu ul li a').forEach(a => {
            if(a.getAttribute('onclick') && a.getAttribute('onclick').includes(id)){
                a.classList.add('active');
            }
        });
    }
    window.scrollTo({top:0, behavior:'smooth'});
    closeSidebar();
    applyScrollableTables();
}

function openSidebar(){
    document.getElementById('sidebar').classList.add('open');
    document.getElementById('sidebarOverlay').classList.add('show');
}
function closeSidebar(){
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('show');
}

function openModal(id){ document.getElementById(id).style.display = 'flex'; }
function closeModal(id){ document.getElementById(id).style.display = 'none'; }

window.onclick = function(e){
    document.querySelectorAll('.modal').forEach(m => {
        if(e.target === m) m.style.display = 'none';
    });
};

function studentAction(select, studentId){
    if(select.value === 'reset_password'){
        document.getElementById('modal_student_id').value = studentId;
        document.getElementById('resetPasswordModal').style.display = 'flex';
        select.selectedIndex = 0;
    }
}

function openProfileModal(p){
    document.getElementById('pf_user_id').value = p.id;
    document.getElementById('pf_name').value = p.name;
    document.getElementById('pf_license').value = p.license_no || '';
    document.getElementById('pf_qualification').value = p.qualification_level || '';
    document.getElementById('pf_kra').value = p.kra_pin || '';
    openModal('profileFieldsModal');
}

function openVersionModal(v){
    document.getElementById('vm_version_id').value = v.id;
    let rows = '';
    const d = v.data || {};
    const fields = {title:'Title', description:'Description', category:'Category', course_type:'Type', status:'Status', price:'Price'};
    for (const key in fields) {
        if (d[key] !== undefined) {
            rows += '<div class="detail-row"><span class="label">' + fields[key] + '</span><span class="value">' + String(d[key]).replace(/</g,'&lt;') + '</span></div>';
        }
    }
    document.getElementById('vm_body').innerHTML =
        '<div class="detail-row"><span class="label">Course</span><span class="value">' + (v.course || '') + '</span></div>' + rows;
    openModal('versionModal');
}

function toggleInline(id){
    var el = document.getElementById(id);
    if (!el) return;
    var isTableRow = el.tagName === 'TR';
    var visible = el.style.display !== 'none' && el.style.display !== '';
    el.style.display = visible ? 'none' : (isTableRow ? 'table-row' : 'block');
}

/* ==
   PAYMENT
== */
function openPaymentDetails(p){
    document.getElementById('pd_id').textContent = '#' + p.id;
    document.getElementById('pd_course').textContent = p.course || 'N/A';
    document.getElementById('pd_amount').textContent = 'KES ' + p.amount;
    document.getElementById('pd_method').textContent = p.method;
    document.getElementById('pd_status').textContent = p.status;
    document.getElementById('pd_verification').textContent = p.verification;

    const setRow = (rowId, valId, val) => {
        const row = document.getElementById(rowId);
        if(val && String(val).trim() !== ''){
            document.getElementById(valId).textContent = val;
            row.style.display = 'flex';
        } else {
            row.style.display = 'none';
        }
    };

    setRow('pd_row_payer_name',  'pd_payer_name',  p.payer_name);
    setRow('pd_row_payer_phone', 'pd_payer_phone', p.payer_phone);
    setRow('pd_row_payer_email', 'pd_payer_email', p.payer_email);
    setRow('pd_row_txn',         'pd_txn',         p.transaction_code);
    setRow('pd_row_receipt',     'pd_receipt',     p.mpesa_receipt);
    setRow('pd_row_date',        'pd_date',        p.payment_date);
    setRow('pd_row_notes',       'pd_notes',       p.notes);

    document.getElementById('pd_approve_link').href = '?action=completed&id=' + p.id;
    document.getElementById('pd_reject_link').href  = '?action=failed&id=' + p.id;

    openModal('paymentDetailsModal');
}

function applyScrollableTables(){
    document.querySelectorAll('.table-wrap').forEach(wrap => {
        const tbody = wrap.querySelector('table tbody');
        if(!tbody) return;
        if(tbody.querySelectorAll('tr').length > 10){
            wrap.classList.add('scrollable');
        } else {
            wrap.classList.remove('scrollable');
        }
    });
}
document.addEventListener('DOMContentLoaded', applyScrollableTables);

/* ==
   EDIT COURSE MODAL
== */
function openEditCourseModal(course){
    document.getElementById('edit_course_id').value = course.id;
    document.getElementById('edit_title').value = course.title || '';
    document.getElementById('edit_description').value = course.description || '';

    const categorySelect = document.getElementById('edit_category');
    const customCategoryInput = document.getElementById('edit_custom_category');
    let matched = false;
    for (const opt of categorySelect.options) {
        if (opt.value !== '' && opt.value === course.category) { matched = true; break; }
    }
    if (matched) {
        categorySelect.value = course.category;
        customCategoryInput.value = '';
    } else {
        categorySelect.value = '';
        customCategoryInput.value = course.category || '';
    }

    document.getElementById('edit_course_type').value = course.course_type || 'Free';
    document.getElementById('edit_status').value = course.status || 'Active';
    document.getElementById('edit_teacher_id').value = course.teacher_id || '';
    document.getElementById('edit_price').value = course.price || 0;

    const preview = document.getElementById('edit_thumbnail_preview');
    if (course.thumbnail) {
        preview.src = course.thumbnail;
        preview.style.display = 'block';
    } else {
        preview.removeAttribute('src');
        preview.style.display = 'none';
    }

    openModal('editCourseModal');
}

const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { grid: { display: false }, ticks: { font: { size: 11 } } },
        y: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 11 } } }
    }
};

new Chart(document.getElementById('revenueChart'), {
    type: 'line',
    data: {
        labels: <?= json_encode($revenue_labels) ?>,
        datasets: [{
            label: 'Revenue (KES)',
            data: <?= json_encode($revenue_values) ?>,
            borderColor: '<?= htmlspecialchars($branding['color_primary']) ?>',
            backgroundColor: 'rgba(15,118,110,.08)',
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: '<?= htmlspecialchars($branding['color_primary']) ?>',
            pointRadius: 4
        }]
    },
    options: { ...chartDefaults, plugins: { legend: { display: true, position: 'top', labels:{ font:{size:12} } } } }
});

new Chart(document.getElementById('studentChart'), {
    type: 'line',
    data: {
        labels: <?= json_encode($student_labels) ?>,
        datasets: [{
            label: 'Students',
            data: <?= json_encode($student_values) ?>,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16,185,129,.08)',
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: '#10b981',
            pointRadius: 4
        }]
    },
    options: { ...chartDefaults, plugins: { legend: { display: true, position: 'top', labels:{ font:{size:12} } } } }
});

new Chart(document.getElementById('enrollmentChart'), {
    type: 'bar',
    data: {
        labels: <?= json_encode($enrollment_labels) ?>,
        datasets: [{
            label: 'Enrollments',
            data: <?= json_encode($enrollment_values) ?>,
            backgroundColor: 'rgba(15,118,110,.75)',
            borderRadius: 6,
            borderSkipped: false
        }]
    },
    options: { ...chartDefaults, plugins: { legend: { display: false } } }
});

new Chart(document.getElementById('paymentChart'), {
    type: 'doughnut',
    data: {
        labels: ['Successful', 'Pending', 'Failed'],
        datasets: [{
            data: [
                <?= (int)$successful_payments ?>,
                <?= (int)$pending_payments ?>,
                <?= (int)$failed_payments ?>
            ],
            backgroundColor: ['#10b981','#f59e0b','#ef4444'],
            borderWidth: 0,
            hoverOffset: 6
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { position: 'bottom', labels: { font: { size: 12 }, padding: 16 } }
        },
        cutout: '65%'
    }
});
</script>
</body>
</html>