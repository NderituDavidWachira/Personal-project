<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
include "db.php";

/* ======
   CSRF PROTECTION
   ====== */
if (empty($_SESSION['csrf_token'])) { 
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); 
}

function validateCsrf(): void {
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403); 
        die("Invalid CSRF token.");
    }
}

/* ======
   AUTHENTICATION & ROLE NORMALIZATION
   ====== */
$user_id = $_SESSION['user_id'] ?? $_SESSION['id'] ?? $_SESSION['admin_id'] ?? 0;
$user_email = $_SESSION['email'] ?? $_SESSION['user_email'] ?? '';
$raw_role = $_SESSION['role'] ?? $_SESSION['user_role'] ?? $_SESSION['role_name'] ?? '';
$user_role = strtolower(trim((string)$raw_role));

if ($user_role === '1') { $user_role = 'super_admin'; }
if ($user_role === '2') { $user_role = 'admin'; }
if ($user_role === '3') { $user_role = 'teacher'; }

if (empty($user_role) || !in_array($user_role, ['admin', 'super_admin', 'teacher'], true)) {
    if ($user_id > 0) {
        try {
            $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ? LIMIT 1");
            $stmt->execute([(int)$user_id]);
            $dbRole = $stmt->fetchColumn();
            if ($dbRole) {
                $user_role = strtolower(trim((string)$dbRole));
                $_SESSION['role'] = $user_role;
            }
        } catch (Throwable $e) {}
    } elseif (!empty($user_email)) {
        try {
            $stmt = $pdo->prepare("SELECT id, role FROM users WHERE email = ? LIMIT 1");
            $stmt->execute([$user_email]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                $user_id = (int)$row['id'];
                $user_role = strtolower(trim((string)$row['role']));
                $_SESSION['user_id'] = $user_id;
                $_SESSION['role'] = $user_role;
            }
        } catch (Throwable $e) {}
    }
}

if ($user_role === 'super_admin') {
    header("Location: SuperAdmin.php");
    exit;
}

if ($user_id <= 0 || !in_array($user_role, ['admin', 'teacher'], true)) {
    header("Location: index.php?error=" . urlencode("Administrator login required."));
    exit;
}

$is_staff = in_array($user_role, ['admin', 'teacher'], true);

function logActivity(PDO $pdo, int $uid, string $message): void {
    try {
        $pdo->prepare("INSERT INTO activities(user_id,message) VALUES(?,?)")->execute([$uid, $message]);
    } catch (Throwable $e) {}
}

function notifyUser(PDO $pdo, int $userId, string $message): void {
    try {
        $pdo->prepare("INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, NOW())")
            ->execute([$userId, $message]);
    } catch (Throwable $e) {}
}

function getSetting(PDO $pdo, string $key, string $default): string {
    try {
        $stmt = $pdo->prepare("SELECT setting_value FROM stp_settings WHERE setting_key=?");
        $stmt->execute([$key]);
        $val = $stmt->fetchColumn();
        return $val !== false && $val !== null && $val !== '' ? $val : $default;
    } catch (Throwable $e) { return $default; }
}

$branding = [
    'org_name'           => getSetting($pdo, 'org_name', 'CBT-Kenya STP'),
    'color_primary'      => getSetting($pdo, 'color_primary', '#8DC63F'),
    'color_primary_dark' => getSetting($pdo, 'color_primary_dark', '#6C9A2E'),
    'color_primary_light'=> getSetting($pdo, 'color_primary_light', '#AED97A'),
    'color_accent'       => getSetting($pdo, 'color_accent', '#F5A623'),
    'logo_url'           => getSetting($pdo, 'logo_url', 'cbt-ke.png'),
];

/* == COURSE CREATION / EDITING == */
if (isset($_POST['create_course'])) {
    validateCsrf();
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $category    = trim($_POST['category'] ?? '');
    $custom_cat  = trim($_POST['custom_category'] ?? '');
    if ($custom_cat !== '') { $category = $custom_cat; }

    $teacher_id  = intval($_POST['teacher_id'] ?? 0);
    $status      = ($_POST['status'] ?? 'Active') === 'Inactive' ? 'Inactive' : 'Active';
    $course_type = 'Free';
    $price       = 0.00;

    $errors = [];
    if ($title === '')       $errors[] = "Title is required.";
    if ($description === '') $errors[] = "Description is required.";
    if ($category === '')    $errors[] = "Category is required.";
    if ($teacher_id <= 0)    $errors[] = "Please assign a trainer.";

    if (empty($errors)) {
        $stmt = $pdo->prepare(
            "INSERT INTO courses (title, description, category, course_type, status, teacher_id, price)
             VALUES (?,?,?,?,?,?,?)"
        );
        $stmt->execute([$title, $description, $category, $course_type, $status, $teacher_id, $price]);
        logActivity($pdo, $user_id, "Created free course: \"$title\"");
        $_SESSION['success'] = "Free Course \"$title\" created successfully.";
    } else {
        $_SESSION['course_errors'] = $errors;
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#coursesSection");
    exit;
}

if (isset($_POST['delete_course'])) {
    validateCsrf();
    $del_course_id = intval($_POST['course_id'] ?? 0);
    if ($del_course_id > 0) {
        $pdo->prepare("DELETE FROM courses WHERE id=? AND course_type='Free'")->execute([$del_course_id]);
        $_SESSION['success'] = "Course deleted.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#coursesSection");
    exit;
}

/* == ENROLLMENT ACTIONS == */
if (isset($_GET['approve'])) {
    $id = intval($_GET['approve']);
    $pdo->prepare("UPDATE enrollments SET status='approved' WHERE id=?")->execute([$id]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#enrollmentSection");
    exit;
}
if (isset($_GET['reject'])) {
    $id = intval($_GET['reject']);
    $pdo->prepare("DELETE FROM enrollments WHERE id=?")->execute([$id]);
    header("Location: " . $_SERVER['PHP_SELF'] . "#enrollmentSection");
    exit;
}

/* == STUDENT APPROVAL ACTIONS == */
if (isset($_POST['review_student_account'])) {
    validateCsrf();
    $acct_id       = intval($_POST['account_id'] ?? 0);
    $acct_decision = $_POST['account_decision'] ?? '';
    if ($acct_id > 0 && in_array($acct_decision, ['approved', 'rejected'], true)) {
        $newStatus = ($acct_decision === 'approved') ? 'active' : 'rejected';
        $pdo->prepare("UPDATE users SET status=? WHERE id=? AND role='student'")->execute([$newStatus, $acct_id]);
        notifyUser($pdo, $acct_id, "Your account registration has been " . ($acct_decision === 'approved' ? 'approved. You may now log in to your dashboard.' : 'rejected.'));
        logActivity($pdo, $user_id, "Marked student account #$acct_id as $newStatus");
        $_SESSION['success'] = "Student registration marked as $newStatus.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#pendingStudentsSection");
    exit;
}

if (isset($_POST['bulk_approve_students'])) {
    validateCsrf();
    $ids = array_filter(array_map('intval', $_POST['account_ids'] ?? []));
    if (!empty($ids)) {
        $inQuery = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $pdo->prepare("UPDATE users SET status='active' WHERE role='student' AND id IN ($inQuery)");
        $stmt->execute($ids);
        foreach ($ids as $s_uid) {
            notifyUser($pdo, (int)$s_uid, "Your account has been approved. You may now log in to access your dashboard.");
        }
        logActivity($pdo, $user_id, "Bulk approved " . count($ids) . " student accounts.");
        $_SESSION['success'] = count($ids) . " students approved successfully.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#pendingStudentsSection");
    exit;
}

/* == STUDENT PASSWORD RESET == */
if (isset($_POST['reset_student_password'])) {
    validateCsrf();
    $sid      = intval($_POST['student_id'] ?? 0);
    $new_pass = $_POST['new_password'] ?? '';
    if ($sid > 0 && strlen($new_pass) >= 6) {
        $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE users SET password=? WHERE id=? AND role='student'")->execute([$hashed, $sid]);
        logActivity($pdo, $user_id, "Reset password for student #$sid");
        $_SESSION['success'] = "Password reset successfully.";
    } else {
        $_SESSION['course_errors'] = ["Password must be at least 6 characters."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#studentsSection");
    exit;
}

/* == TRAINER CHANGE REQUEST REVIEW == */
if (isset($_POST['review_change_request'])) {
    validateCsrf();
    $cr_id    = intval($_POST['change_request_id'] ?? 0);
    $decision = $_POST['cr_decision'] ?? '';
    $note     = trim($_POST['cr_review_note'] ?? '');

    if ($decision === 'rejected' && $note === '') {
        $_SESSION['course_errors'] = ["A rejection reason is required."];
        header("Location: " . $_SERVER['PHP_SELF'] . "#changeRequestsSection");
        exit;
    }

    if (in_array($decision, ['approved', 'rejected'], true) && $cr_id > 0) {
        $pdo->prepare("UPDATE change_requests SET status=?, review_comments=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?")
            ->execute([$decision, $note, $user_id, $cr_id]);
        $_SESSION['success'] = "Change request #$cr_id has been $decision.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#changeRequestsSection");
    exit;
}

/* == ATTENDANCE == */
if (isset($_POST['mark_attendance'])) {
    validateCsrf();
    $att_course = intval($_POST['att_course_id'] ?? 0);
    $att_date   = $_POST['session_date'] ?? date('Y-m-d');
    $statuses   = $_POST['att_status'] ?? [];

    if ($att_course > 0 && is_array($statuses) && count($statuses) > 0) {
        $ins = $pdo->prepare(
            "INSERT INTO stp_attendance(course_id,user_id,session_date,status,marked_by)
             VALUES (?,?,?,?,?)
             ON DUPLICATE KEY UPDATE status=VALUES(status), marked_by=VALUES(marked_by)"
        );
        foreach ($statuses as $uid => $st) {
            $st = in_array($st, ['present','absent','excused'], true) ? $st : 'present';
            $ins->execute([$att_course, (int)$uid, $att_date, $st, $user_id]);
        }
        $_SESSION['success'] = "Attendance recorded successfully.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#attendanceSection");
    exit;
}

/* == TICKET STATUS == */
if (isset($_POST['update_ticket_status'])) {
    validateCsrf();
    $tid   = intval($_POST['ticket_id'] ?? 0);
    $tstat = trim($_POST['status'] ?? '');
    if ($tid > 0 && in_array($tstat, ['open','in_progress','resolved','closed'], true)) {
        $pdo->prepare("UPDATE tickets SET status=? WHERE id=?")->execute([$tstat, $tid]);
        $_SESSION['success'] = "Ticket status updated.";
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#ticketSection");
    exit;
}

/* == DATA QUERIES == */
$total_students = $pdo->query("SELECT COUNT(*) FROM users u WHERE u.role='student'")->fetchColumn() ?: 0;
$active_users   = $pdo->query("SELECT COUNT(*) FROM users u WHERE u.status='active' AND u.role='student'")->fetchColumn() ?: 0;
$free_courses   = $pdo->query("SELECT COUNT(*) FROM courses c WHERE c.course_type='Free'")->fetchColumn() ?: 0;
$total_enrollments = $pdo->query("SELECT COUNT(*) FROM enrollments e")->fetchColumn() ?: 0;
$pending_change_requests_count = (int)$pdo->query("SELECT COUNT(*) FROM change_requests cr WHERE cr.status='pending'")->fetchColumn();

$pending_student_accounts_count = (int)$pdo->query("
    SELECT COUNT(*) 
    FROM users u 
    WHERE u.role = 'student' 
      AND (u.status IS NULL OR u.status = '' OR LOWER(u.status) IN ('pending', 'inactive', 'unverified'))
")->fetchColumn();

$courses_stmt = $pdo->query("
    SELECT c.id, c.title, c.description, c.category, c.status, u.full_name 
    FROM courses c 
    LEFT JOIN users u ON c.teacher_id = u.id 
    WHERE c.course_type = 'Free' 
    ORDER BY c.id DESC
");

$trainers = $pdo->query("
    SELECT u.id, u.full_name, u.email, u.phone, t.specialization, t.qualification, t.employee_no 
    FROM users u 
    LEFT JOIN teachers t ON t.user_id = u.id 
    WHERE u.role = 'teacher' 
    ORDER BY u.full_name ASC
");

$pending_students = $pdo->query("
    SELECT u.id, u.full_name, u.email, u.phone, u.status, u.created_at, s.student_no
    FROM users u 
    LEFT JOIN students s ON s.user_id = u.id 
    WHERE u.role = 'student' 
      AND (u.status IS NULL OR u.status = '' OR LOWER(u.status) IN ('pending', 'inactive', 'unverified'))
    ORDER BY u.id DESC
");

$active_students = $pdo->query("
    SELECT u.id, u.full_name, u.email, u.phone, u.status, u.created_at, s.student_no
    FROM users u 
    LEFT JOIN students s ON s.user_id = u.id 
    WHERE u.role = 'student' 
      AND LOWER(u.status) = 'active'
    ORDER BY u.id DESC 
    LIMIT 200
");

$enrollments = $pdo->query("
    SELECT e.id, e.status, e.progress, e.enrolled_at, u.full_name, s.student_no, c.title AS course_title 
    FROM enrollments e 
    JOIN users u ON u.id = e.user_id 
    LEFT JOIN students s ON s.user_id = u.id 
    JOIN courses c ON c.id = e.course_id 
    ORDER BY e.id DESC 
    LIMIT 100
");

$pending_change_requests = $pdo->query("
    SELECT cr.id, cr.entity_type, cr.new_data, cr.created_at, u.full_name AS requester_name 
    FROM change_requests cr 
    LEFT JOIN users u ON u.id = cr.requested_by 
    WHERE cr.status = 'pending' 
    ORDER BY cr.created_at DESC
");

$tickets = $pdo->query("
    SELECT t.id, t.subject, t.message, t.status, u.full_name 
    FROM tickets t 
    LEFT JOIN users u ON u.id = t.user_id 
    ORDER BY t.id DESC 
    LIMIT 50
");

/* == CHART METRICS == */
$student_labels = []; $student_values = []; $running_total = 0;
$sq = $pdo->query("SELECT DATE_FORMAT(MIN(created_at),'%b %Y') AS month_name, COUNT(*) AS total FROM users WHERE role='student' GROUP BY YEAR(created_at), MONTH(created_at) ORDER BY YEAR(created_at), MONTH(created_at)");
if ($sq) { 
    foreach ($sq as $row) { 
        $running_total += (int)$row['total']; 
        $student_labels[] = $row['month_name']; 
        $student_values[] = $running_total; 
    } 
}

$enrollment_labels = []; $enrollment_values = [];
$eq = $pdo->query("SELECT DATE_FORMAT(MIN(enrolled_at),'%b %Y') AS month_name, COUNT(*) AS total FROM enrollments GROUP BY YEAR(enrolled_at), MONTH(enrolled_at) ORDER BY YEAR(enrolled_at), MONTH(enrolled_at)");
if ($eq) { 
    foreach ($eq as $row) { 
        $enrollment_labels[] = $row['month_name']; 
        $enrollment_values[] = (int)$row['total']; 
    } 
}

if (empty($student_labels)) { $student_labels = ['Current']; $student_values = [$total_students]; }
if (empty($enrollment_labels)) { $enrollment_labels = ['Current']; $enrollment_values = [$total_enrollments]; }

$flash_success = $_SESSION['success'] ?? ''; unset($_SESSION['success']);
$flash_errors  = $_SESSION['course_errors'] ?? []; unset($_SESSION['course_errors']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($branding['org_name']) ?> - Admin Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="icon" type="image/png" href="/icons/cbt-ke.png">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>

<style>
:root {
    --primary:       <?= htmlspecialchars($branding['color_primary']) ?>;
    --primary-light: <?= htmlspecialchars($branding['color_primary_light']) ?>;
    --primary-dark:  <?= htmlspecialchars($branding['color_primary_dark']) ?>;
    --success:       #6C9A2E;
    --warning:       #F5A623;
    --danger:        #d64545;
    --info:          #4F86C6;
    --accent:        <?= htmlspecialchars($branding['color_accent']) ?>;
    --bg:            #f4f7ef;
    --sidebar-bg:    #23330f;
    --card-bg:       #ffffff;
    --text:          #1f2a12;
    --muted:         #66755a;
    --border:        #e1e8d7;
    --radius:        14px;
    --shadow:        0 4px 20px rgba(35,51,15,0.06);
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
    background: #86AC13;
    color: white;
    position: fixed;
    top: 0; left: 0; bottom: 0;
    overflow-y: auto;
    z-index: 1000;
    transition: transform .3s ease;
}

.sidebar::-webkit-scrollbar { width: 4px; }
.sidebar::-webkit-scrollbar-thumb { background: #3c5518; border-radius: 4px; }

.logo {
    padding: 8px 5px 5px;
    border-bottom: 1px solid rgba(255,255,255,.08);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
}

.logo-icon {
    width: 14rem;
    padding: 3px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; color: #fff; flex-shrink: 0;
    overflow: hidden;
}
.logo-icon img { width: 100%; height: 100%; }

.logo h2 { font-size: 17px; font-weight: 700; color: #fff; letter-spacing: -.3px; }
.logo span { font-size: 11px; color: #b7cf94; font-weight: 400; }

.menu { padding: 12px 0; }

.menu-label {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1px;
    color: #a9d66b;
    padding: 14px 22px 6px;
    text-transform: uppercase;
}

.menu ul { list-style: none; }

.menu ul li a {
    text-decoration: none;
    color: #c7d6b4;
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
    color: #FFFFFF;
    background-color: #FFB129;
}

.menu ul li a i { width: 18px; text-align: center; font-size: 15px; }

.nav-badge {
    margin-left: auto;
    background: #d64545;
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    border-radius: 20px;
    padding: 1px 7px;
    min-width: 18px;
    text-align: center;
}

.sidebar-overlay { 
    display: none; 
    position: fixed; 
    inset: 0; 
    background: rgba(15,23,42,.5); 
    z-index: 999; 
}
.sidebar-overlay.show { display: block; }

.main {
    margin-left: 260px;
    flex: 1;
    padding: 24px;
    min-height: 100vh;
    overflow: auto;
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

.topbar h1 { font-size: 22px; font-weight: 700; color: var(--text); margin: 0; }
.topbar-left { display: flex; align-items: center; gap: 14px; }

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

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 18px; margin-bottom: 24px; }

.card {
    background: var(--card-bg); padding: 20px; border-radius: var(--radius);
    box-shadow: var(--shadow); border: 1px solid var(--border);
    transition: transform .25s, box-shadow .25s;
    display: flex; flex-direction: column; gap: 12px; min-width: 0;
}
.card:hover { transform: translateY(-4px); box-shadow: 0 8px 30px rgba(35,51,15,.12); }
.card h3 { font-size: 26px; font-weight: 700; color: var(--text); line-height: 1; }
.card p  { font-size: 13px; color: var(--muted); font-weight: 500; margin: 0; }

.charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 20px; margin-bottom: 28px; }
.chart-box { background: var(--card-bg); border-radius: var(--radius); padding: 22px; box-shadow: var(--shadow); border: 1px solid var(--border); min-width: 0; }
.chart-box h2 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 18px; display: flex; align-items: center; gap: 8px; }
.chart-box h2 i { color: var(--primary); }
.chart-box canvas { width: 100% !important; height: 260px !important; }

.table-section { background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 22px; overflow: hidden; }
.table-header { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 10px; }
.table-header h2 { font-size: 15px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 8px; margin: 0; }
.table-header h2 i { color: var(--primary); }
.table-header .export-tools { display: flex; gap: 8px; }
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }

table { width: 100%; border-collapse: collapse; }
table thead { background: #f4f7ef; }
table th { padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); white-space: nowrap; }
table td { padding: 13px 16px; font-size: 13.5px; color: var(--text); border-bottom: 1px solid #eef2e6; }
table tbody tr:hover { background: #f8faf4; }

.badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; display: inline-block; white-space: nowrap; }
.badge-success, .badge-active, .badge-approved { background: #e4f3d3; color: #3c5518; }
.badge-warning, .badge-pending { background: #fdecc8; color: #8a5a10; }
.badge-danger, .badge-rejected { background: #fbe3e3; color: #8f2b2b; }

.form-card { background: var(--card-bg); border-radius: var(--radius); padding: 24px; box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 22px; }
.form-card h3 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 18px; padding-bottom: 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
.form-card h3 i { color: var(--primary); }

.form-group { margin-bottom: 14px; }
.form-group label { font-size: 12px; font-weight: 600; color: var(--muted); display: block; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .4px; }

input[type=text], input[type=email], input[type=password], input[type=number], input[type=date], textarea, select {
    width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; font-size: 14px;
    background: var(--bg); color: var(--text); outline: none; transition: .2s; font-family: inherit;
}
input:focus, textarea:focus, select:focus { border-color: var(--primary); background: #fff; box-shadow: 0 0 0 3px rgba(108,154,46,.15); }
textarea { resize: vertical; min-height: 90px; }

.btn { padding: 9px 18px; border: none; border-radius: 9px; cursor: pointer; font-size: 13px; font-weight: 600; font-family: inherit; transition: .2s; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover { background: var(--primary-dark); }
.btn-success { background: var(--success); color: #fff; }
.btn-warning { background: var(--warning); color: #fff; }
.btn-danger  { background: var(--danger); color: #fff; }
.btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--text); }
.btn-outline:hover { border-color: var(--primary); color: var(--primary); }
.btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 7px; }
.btn-full { width: 100%; justify-content: center; padding: 12px; font-size: 14px; }

.alert { padding: 12px 16px; border-radius: 10px; font-size: 13px; font-weight: 500; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.alert-error { background: #fbe3e3; color: #8f2b2b; border: 1px solid var(--danger); }
.alert-success { background: #e4f3d3; color: #3c5518; border: 1px solid var(--success); }

.modal { display: none; position: fixed; inset: 0; background: rgba(31,42,18,.55); backdrop-filter: blur(4px); justify-content: center; align-items: center; z-index: 9999; padding: 16px; }
.modal-content { background: var(--card-bg); width: 440px; max-width: 95vw; padding: 24px; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.2); }

@media(max-width: 860px){
    .sidebar { width: 260px; transform: translateX(-260px); }
    .sidebar.open { transform: translateX(0); }
    .main { margin-left: 0; width: 100%; padding: 16px; }
    .menu-toggle { display: flex; }
    .charts { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<div class="sidebar" id="sidebar">
    <div class="logo">
        <div class="logo-icon"><img src="cbt-ke.png" alt="Logo"></div>
        <div><span>Admin Workstation</span></div>
    </div>

    <div class="menu">
        <div class="menu-label">Main</div>
        <ul>
            <li><a href="#" onclick="showSection('dashboardSection',this)" class="active"><i class="fas fa-chart-line"></i><span>Dashboard</span></a></li>
            <li><a href="#" onclick="showSection('pendingStudentsSection',this)"><i class="fas fa-user-clock"></i><span>Approve Students</span><?php if ($pending_student_accounts_count>0): ?><span class="nav-badge"><?= $pending_student_accounts_count ?></span><?php endif; ?></a></li>
            <li><a href="#" onclick="showSection('changeRequestsSection',this)"><i class="fas fa-code-compare"></i><span>Change Requests</span><?php if ($pending_change_requests_count>0): ?><span class="nav-badge"><?= $pending_change_requests_count ?></span><?php endif; ?></a></li>
        </ul>

        <div class="menu-label">Management</div>
        <ul>
            <li><a href="#" onclick="showSection('studentsSection',this)"><i class="fas fa-user-graduate"></i><span>All Students</span></a></li>
            <li><a href="#" onclick="showSection('trainersSection',this)"><i class="fas fa-chalkboard-teacher"></i><span>Trainers View</span></a></li>
            <li><a href="#" onclick="showSection('coursesSection',this)"><i class="fas fa-book"></i><span>Free Courses</span></a></li>
            <li><a href="#" onclick="showSection('attendanceSection',this)"><i class="fas fa-calendar-check"></i><span>Attendance</span></a></li>
        </ul>

        <div class="menu-label">Operations</div>
        <ul>
            <li><a href="#" onclick="showSection('enrollmentSection',this)"><i class="fas fa-user-check"></i><span>Enrollments</span></a></li>
            <li><a href="#" onclick="showSection('ticketSection',this)"><i class="fas fa-headset"></i><span>Tickets</span></a></li>
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

    <!-- 1. DASHBOARD OVERVIEW -->
    <div id="dashboardSection">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Admin Dashboard</h1>
            </div>
        </div>

        <div class="cards">
            <div class="card"><h3><?= $total_students ?></h3><p>Total Registered Students</p></div>
            <div class="card"><h3><?= $active_users ?></h3><p>Active Verified Students</p></div>
            <div class="card"><h3><?= $pending_student_accounts_count ?></h3><p>Awaiting Approval</p></div>
            <div class="card"><h3><?= $free_courses ?></h3><p>Free Courses Managed</p></div>
            
        </div>

        <!-- GRAPHS SECTION -->
        <div class="charts">
            <div class="chart-box">
                <h2><i class="fas fa-chart-line"></i> Student Registration Growth</h2>
                <canvas id="studentChart"></canvas>
            </div>
            <div class="chart-box">
                <h2><i class="fas fa-chart-bar"></i> Monthly Course Enrollments</h2>
                <canvas id="enrollmentChart"></canvas>
            </div>
        </div>
    </div>

    <!-- 2. APPROVE NEW STUDENTS -->
    <div id="pendingStudentsSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Approve New Student Registrations</h1>
            </div>
        </div>
        <div class="table-section" id="export_pending_students">
            <div class="table-header">
                <h2><i class="fas fa-user-clock"></i> Pending Applications (<?= $pending_student_accounts_count ?>)</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_pending_students', 'Pending_Students_Report.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_pending_students', 'Pending_Students_Report')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div style="padding: 12px 18px 0;">
                    <button type="submit" name="bulk_approve_students" class="btn btn-success btn-sm" onclick="return confirm('Approve all selected student registrations?');"><i class="fas fa-check-double"></i> Bulk Approve Selected</button>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:30px;"><input type="checkbox" onclick="document.querySelectorAll('.app-chk').forEach(c=>c.checked=this.checked)"></th>
                                <th>Student No</th><th>Name</th><th>Email</th><th>Phone</th><th>Status</th><th>Registered Date</th><th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if ($pending_students && $pending_students->rowCount() > 0): foreach ($pending_students as $ps): ?>
                            <tr>
                                <td><input type="checkbox" name="account_ids[]" value="<?= (int)$ps['id'] ?>" class="app-chk"></td>
                                <td><?= htmlspecialchars($ps['student_no'] ?? '-') ?></td>
                                <td><strong><?= htmlspecialchars($ps['full_name']) ?></strong></td>
                                <td><?= htmlspecialchars($ps['email']) ?></td>
                                <td><?= htmlspecialchars($ps['phone'] ?? '-') ?></td>
                                <td><span class="badge badge-warning">Pending Approval</span></td>
                                <td><?= htmlspecialchars($ps['created_at']) ?></td>
                                <td>
                                    <form method="POST" style="display:inline;">
                                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                        <input type="hidden" name="account_id" value="<?= (int)$ps['id'] ?>">
                                        <button type="submit" name="review_student_account" onclick="this.form.account_decision.value='approved'" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Approve</button>
                                        <button type="submit" name="review_student_account" onclick="this.form.account_decision.value='rejected'" class="btn btn-danger btn-sm"><i class="fas fa-times"></i> Reject</button>
                                        <input type="hidden" name="account_decision" value="approved">
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; else: ?>
                            <tr><td colspan="8" style="text-align:center;color:var(--muted);padding:30px;">No new registrations awaiting approval.</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </form>
        </div>
    </div>

    <!-- 3. ALL STUDENTS -->
    <div id="studentsSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Enrolled Student Records</h1>
            </div>
        </div>
        <div class="table-section" id="export_all_students">
            <div class="table-header">
                <h2><i class="fas fa-user-graduate"></i> Active Student Directory (<?= $active_students->rowCount() ?>)</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_all_students', 'Active_Students_Directory.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_all_students', 'Active_Students_Directory')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Student No</th>
                            <th>Full Name</th>
                            <th>Email Address</th>
                            <th>Phone Number</th>
                            <th>Registration Date</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($active_students && $active_students->rowCount() > 0): foreach ($active_students as $s): ?>
                        <tr>
                            <td><?= htmlspecialchars($s['student_no'] ?? '-') ?></td>
                            <td><strong><?= htmlspecialchars($s['full_name']) ?></strong></td>
                            <td><?= htmlspecialchars($s['email']) ?></td>
                            <td><?= htmlspecialchars($s['phone'] ?? '-') ?></td>
                            <td style="color:var(--muted);"><?= htmlspecialchars($s['created_at']) ?></td>
                            <td><span class="badge badge-success">Active</span></td>
                            <td>
                                <button type="button" class="btn btn-warning btn-sm" onclick="openResetModal(<?= (int)$s['id'] ?>, '<?= htmlspecialchars(addslashes($s['full_name'])) ?>')">
                                    <i class="fas fa-key"></i> Reset Password
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; else: ?>
                        <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px;">No active students found. Check "Approve Students" to verify registrations.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 4. COURSES (FREE ONLY) -->
    <div id="coursesSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Free Courses Management</h1>
            </div>
        </div>

        <div class="form-card" style="max-width:640px;">
            <h3><i class="fas fa-plus-circle"></i> Publish Free Course</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="150"></div>
                <div class="form-group"><label>Description</label><textarea name="description" required></textarea></div>
                <div class="form-group"><label>Category</label><input type="text" name="category" required></div>
                <div class="form-group">
                    <label>Assign Trainer</label>
                    <select name="teacher_id" required>
                        <option value="">Select Trainer</option>
                        <?php foreach ($trainers as $t): ?>
                            <option value="<?= (int)$t['id'] ?>"><?= htmlspecialchars($t['full_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select name="status"><option value="Active">Active</option><option value="Inactive">Inactive</option></select>
                </div>
                <button type="submit" name="create_course" class="btn btn-primary btn-full">Create Free Course</button>
            </form>
        </div>

        <div class="table-section" id="export_courses">
            <div class="table-header">
                <h2><i class="fas fa-list"></i> Managed Free Courses</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_courses', 'Free_Courses_Report.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_courses', 'Free_Courses_Report')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>ID</th><th>Title</th><th>Trainer</th><th>Category</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody>
                        <?php foreach ($courses_stmt as $c): ?>
                        <tr>
                            <td>#<?= (int)$c['id'] ?></td>
                            <td><strong><?= htmlspecialchars($c['title']) ?></strong></td>
                            <td><?= htmlspecialchars($c['full_name'] ?? 'Unassigned') ?></td>
                            <td><?= htmlspecialchars($c['category']) ?></td>
                            <td><span class="badge badge-<?= strtolower($c['status']) === 'active' ? 'active' : 'danger' ?>"><?= htmlspecialchars($c['status']) ?></span></td>
                            <td>
                                <form method="POST" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="course_id" value="<?= (int)$c['id'] ?>">
                                    <button type="submit" name="delete_course" value="1" onclick="return confirm('Delete course?');" class="btn btn-danger btn-sm">Delete</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 5. TRAINERS (VIEW ONLY) -->
    <div id="trainersSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Trainers Directory</h1>
            </div>
        </div>
        <div class="table-section" id="export_trainers">
            <div class="table-header">
                <h2><i class="fas fa-chalkboard-teacher"></i> Registered Trainers</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_trainers', 'Trainers_Directory.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_trainers', 'Trainers_Directory')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Specialization</th><th>Qualification</th></tr></thead>
                    <tbody>
                        <?php 
                        $trainers->execute();
                        foreach ($trainers as $tr): 
                        ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($tr['full_name']) ?></strong></td>
                            <td><?= htmlspecialchars($tr['email']) ?></td>
                            <td><?= htmlspecialchars($tr['phone'] ?: '-') ?></td>
                            <td><?= htmlspecialchars($tr['specialization'] ?: 'General') ?></td>
                            <td><?= htmlspecialchars($tr['qualification'] ?: '-') ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 6. CHANGE REQUESTS -->
    <div id="changeRequestsSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Trainer Change Requests</h1>
            </div>
        </div>
        <div class="table-section" id="export_change_requests">
            <div class="table-header">
                <h2><i class="fas fa-code-compare"></i> Pending Submissions</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_change_requests', 'Trainer_Change_Requests.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_change_requests', 'Trainer_Change_Requests')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Type</th><th>Requested By</th><th>Date</th><th>Action</th></tr></thead>
                    <tbody>
                        <?php if ($pending_change_requests && $pending_change_requests->rowCount() > 0): foreach ($pending_change_requests as $cr): ?>
                        <tr>
                            <td><?= htmlspecialchars(ucfirst($cr['entity_type'])) ?></td>
                            <td><?= htmlspecialchars($cr['requester_name']) ?></td>
                            <td><?= htmlspecialchars($cr['created_at']) ?></td>
                            <td>
                                <form method="POST">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="change_request_id" value="<?= (int)$cr['id'] ?>">
                                    <input type="text" name="cr_review_note" placeholder="Reason (if rejecting)" style="padding:4px 8px; font-size:12px; max-width:180px;">
                                    <button type="submit" name="review_change_request" onclick="this.form.cr_decision.value='approved'" class="btn btn-success btn-sm">Approve</button>
                                    <button type="submit" name="review_change_request" onclick="this.form.cr_decision.value='rejected'" class="btn btn-danger btn-sm">Reject</button>
                                    <input type="hidden" name="cr_decision" value="approved">
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px;">No pending change requests</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 7. ENROLLMENTS -->
    <div id="enrollmentSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Enrollment Management</h1>
            </div>
        </div>
        <div class="table-section" id="export_enrollments">
            <div class="table-header">
                <h2><i class="fas fa-user-check"></i> Course Enrollments</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_enrollments', 'Enrollments_Report.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_enrollments', 'Enrollments_Report')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Student</th><th>Course</th><th>Date</th><th>Status</th><th>Action</th></tr></thead>
                    <tbody>
                        <?php foreach ($enrollments as $e): ?>
                        <tr>
                            <td><?= htmlspecialchars($e['full_name']) ?></td>
                            <td><?= htmlspecialchars($e['course_title']) ?></td>
                            <td><?= htmlspecialchars($e['enrolled_at']) ?></td>
                            <td><span class="badge badge-<?= $e['status'] === 'approved' ? 'success' : 'pending' ?>"><?= ucfirst($e['status']) ?></span></td>
                            <td>
                                <?php if ($e['status'] !== 'approved'): ?>
                                <a href="?approve=<?= (int)$e['id'] ?>" class="btn btn-success btn-sm">Approve</a>
                                <a href="?reject=<?= (int)$e['id'] ?>" class="btn btn-danger btn-sm" onclick="return confirm('Reject enrollment?')">Reject</a>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 8. ATTENDANCE -->
    <div id="attendanceSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Attendance</h1>
            </div>
        </div>
        <div class="form-card" style="max-width:640px;">
            <h3><i class="fas fa-calendar-check"></i> Save Attendance Session</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group">
                    <label>Course</label>
                    <select name="att_course_id" required>
                        <option value="">Select Course</option>
                        <?php 
                        $courses_stmt->execute();
                        foreach ($courses_stmt as $cs): 
                        ?>
                            <option value="<?= (int)$cs['id'] ?>"><?= htmlspecialchars($cs['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Session Date</label>
                    <input type="date" name="session_date" value="<?= date('Y-m-d') ?>">
                </div>
                <button type="submit" name="mark_attendance" class="btn btn-primary btn-full">Save Session</button>
            </form>
        </div>
    </div>

    <!-- 9. TICKETS -->
    <div id="ticketSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Support Tickets</h1>
            </div>
        </div>
        <div class="table-section" id="export_tickets">
            <div class="table-header">
                <h2><i class="fas fa-headset"></i> Tickets</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_tickets', 'Tickets_Report.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_tickets', 'Tickets_Report')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Student</th><th>Subject</th><th>Status</th><th>Update</th></tr></thead>
                    <tbody>
                        <?php foreach ($tickets as $tk): ?>
                        <tr>
                            <td><?= htmlspecialchars($tk['full_name'] ?? 'Guest') ?></td>
                            <td><strong><?= htmlspecialchars($tk['subject']) ?></strong></td>
                            <td><span class="badge badge-pending"><?= strtoupper($tk['status']) ?></span></td>
                            <td>
                                <form method="POST" style="display:flex;gap:6px;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="ticket_id" value="<?= (int)$tk['id'] ?>">
                                    <select name="status" style="padding:4px; font-size:12px;">
                                        <option value="open">Open</option>
                                        <option value="in_progress">In Progress</option>
                                        <option value="resolved">Resolved</option>
                                        <option value="closed">Closed</option>
                                    </select>
                                    <button type="submit" name="update_ticket_status" class="btn btn-primary btn-sm">Save</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- MODAL: RESET PASSWORD -->
<div id="resetModal" class="modal">
    <div class="modal-content">
        <h4 style="margin-bottom:14px; font-size:16px;"><i class="fas fa-key text-warning me-2"></i>Reset Student Password</h4>
        <p style="font-size:13px; color:var(--muted); margin-bottom:12px;" id="rst_student_name"></p>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="student_id" id="rst_student_id">
            <div class="form-group">
                <label>New Password (min 6 characters)</label>
                <input type="password" name="new_password" placeholder="Enter new password" minlength="6" required>
            </div>
            <div style="display:flex;gap:8px;margin-top:14px;">
                <button type="submit" name="reset_student_password" class="btn btn-warning" style="flex:1;">Change Password</button>
                <button type="button" class="btn btn-outline" onclick="closeResetModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
const sections = ['dashboardSection','pendingStudentsSection','coursesSection','studentsSection','trainersSection','changeRequestsSection','enrollmentSection','attendanceSection','ticketSection'];
function showSection(id, btn) {
    sections.forEach(s => {
        const el = document.getElementById(s);
        if (el) el.style.display = 'none';
    });
    const target = document.getElementById(id);
    if (target) target.style.display = 'block';
    document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
    if (btn) btn.classList.add('active');
    closeSidebar();
}

function openSidebar(){
    document.getElementById('sidebar').classList.add('open');
    document.getElementById('sidebarOverlay').classList.add('show');
}
function closeSidebar(){
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('show');
}

function openResetModal(id, name) {
    document.getElementById('rst_student_id').value = id;
    document.getElementById('rst_student_name').textContent = name ? 'Student: ' + name : '';
    document.getElementById('resetModal').style.display = 'flex';
}
function closeResetModal() {
    document.getElementById('resetModal').style.display = 'none';
}

/* == CHARTS INITIALIZATION == */
document.addEventListener('DOMContentLoaded', function() {
    const studentCtx = document.getElementById('studentChart');
    if (studentCtx) {
        new Chart(studentCtx, {
            type: 'line',
            data: {
                labels: <?= json_encode($student_labels) ?>,
                datasets: [{
                    label: 'Total Registered Students',
                    data: <?= json_encode($student_values) ?>,
                    borderColor: '#6C9A2E',
                    backgroundColor: 'rgba(108,154,46,.10)',
                    borderWidth: 2.5,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#6C9A2E',
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: 'top' } }
            }
        });
    }

    const enrollmentCtx = document.getElementById('enrollmentChart');
    if (enrollmentCtx) {
        new Chart(enrollmentCtx, {
            type: 'bar',
            data: {
                labels: <?= json_encode($enrollment_labels) ?>,
                datasets: [{
                    label: 'Enrollments',
                    data: <?= json_encode($enrollment_values) ?>,
                    backgroundColor: 'rgba(141,198,63,.80)',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    }
});

/* == CSV & PDF EXPORT UTILITIES == */
function exportTableToCSV(containerId, filename) {
    const container = document.getElementById(containerId);
    const table = container.querySelector('table');
    let csv = [];
    for (let row of table.rows) {
        let cols = [];
        for (let cell of row.cells) {
            let text = cell.innerText.replace(/(\r\n|\n|\r)/gm, '').trim();
            cols.push('"' + text.replace(/"/g, '""') + '"');
        }
        csv.push(cols.join(','));
    }
    const blob = new Blob([csv.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
}

function exportTableToPDF(containerId, title) {
    const element = document.getElementById(containerId);
    const opt = {
        margin:       10,
        filename:     title + '.pdf',
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { scale: 2 },
        jsPDF:        { unit: 'mm', format: 'a4', orientation: 'landscape' }
    };
    html2pdf().set(opt).from(element).save();
}
</script>
</body>
</html>