<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
include "db.php";

/* ======
   CSRF
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
   AUTHENTICATION & ROLE RESOLUTION
   ====== */
$user_id = $_SESSION['user_id'] ?? $_SESSION['id'] ?? $_SESSION['admin_id'] ?? 0;
$user_email = $_SESSION['email'] ?? $_SESSION['user_email'] ?? '';
$raw_role = $_SESSION['role'] ?? $_SESSION['user_role'] ?? $_SESSION['role_name'] ?? '';
$user_role = strtolower(trim((string)$raw_role));

if ($user_role === '1') { $user_role = 'super_admin'; }
if ($user_role === '2') { $user_role = 'admin'; }

if (empty($user_role) || $user_role !== 'super_admin') {
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

if ($user_role !== 'super_admin' || $user_id <= 0) {
    header("Location: index.php?error=" . urlencode("Super Administrator authorization required."));
    exit;
}

function logActivity(PDO $pdo, int $uid, string $message): void {
    try {
        $pdo->prepare("INSERT INTO activities(user_id,message) VALUES(?,?)")->execute([$uid, $message]);
    } catch (Throwable $e) {}
}

function generateCertificateNumber(PDO $pdo): string {
    $year = date('Y');
    $stmt = $pdo->query("SELECT COUNT(*) FROM stp_certificates WHERE YEAR(issued_at)=" . (int)$year);
    $seq = (int)$stmt->fetchColumn() + 1;
    return sprintf("CBT-STP-%s-%06d", $year, $seq);
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

/* == ADD TRAINER == */
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
    $kra_pin          = trim($_POST['kra_pin'] ?? '');

    if (!empty($full_name) && !empty($email) && !empty($password)) {
        $hashed = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users(full_name,email,password,role,status,phone,kra_pin,license_no) VALUES(?,?,?,'teacher','active',?,?,?)");
        $stmt->execute([$full_name, $email, $hashed, $phone, $kra_pin, $license_no]);
        $tid = (int)$pdo->lastInsertId();

        $pdo->prepare("INSERT INTO teachers (user_id, employee_no, specialization, qualification, license_number) VALUES (?,?,?,?,?)")
            ->execute([$tid, $employee_no, $specialization, $qualification, $license_no]);

        logActivity($pdo, $user_id, "Super Admin created trainer: $full_name ($email)");
        $_SESSION['success'] = "Trainer account created successfully.";
    } else {
        $_SESSION['course_errors'] = ["Full name, email, and password are required."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#trainerSection");
    exit;
}

/* == CREATE PAID COURSE == */
if (isset($_POST['create_paid_course'])) {
    validateCsrf();
    $title       = trim($_POST['title'] ?? '');
    $description = trim($_POST['description'] ?? '');
    $category    = trim($_POST['category'] ?? '');
    $price       = (float)($_POST['price'] ?? 0);
    $teacher_id  = intval($_POST['teacher_id'] ?? 0);

    if ($title !== '' && $price > 0 && $teacher_id > 0) {
        $stmt = $pdo->prepare("INSERT INTO courses (title, description, category, course_type, status, teacher_id, price) VALUES (?,?,?,'Paid','Active',?,?)");
        $stmt->execute([$title, $description, $category, $teacher_id, $price]);
        logActivity($pdo, $user_id, "Super Admin created paid course: $title (KES $price)");
        $_SESSION['success'] = "Paid course published.";
    } else {
        $_SESSION['course_errors'] = ["Valid title, price (> 0), and assigned trainer are required."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#paidCoursesSection");
    exit;
}

/* == REFUNDS == */
if (isset($_POST['create_refund'])) {
    validateCsrf();
    $rp_payment = intval($_POST['refund_payment_id'] ?? 0);
    $rp_amount  = (float)($_POST['refund_amount'] ?? 0);
    $rp_reason  = trim($_POST['refund_reason'] ?? '');

    $pay = $pdo->prepare("SELECT user_id FROM payments WHERE id=?");
    $pay->execute([$rp_payment]);
    $puid = (int)$pay->fetchColumn();

    if ($rp_payment > 0 && $puid > 0 && $rp_amount > 0) {
        $pdo->prepare("INSERT INTO stp_refunds(payment_id,user_id,amount,reason,status,processed_by,processed_at) VALUES(?,?,?,?,'completed',?,NOW())")
            ->execute([$rp_payment, $puid, $rp_amount, $rp_reason, $user_id]);
        logActivity($pdo, $user_id, "Processed refund of KES $rp_amount for payment #$rp_payment");
        $_SESSION['success'] = "Refund logged and marked completed.";
    } else {
        $_SESSION['course_errors'] = ["Invalid payment ID or amount."];
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#financeSection");
    exit;
}

/* == CERTIFICATE ISSUANCE == */
if (isset($_POST['issue_certificate'])) {
    validateCsrf();
    $cu = intval($_POST['user_id'] ?? 0);
    $cc = intval($_POST['course_id'] ?? 0);

    if ($cu > 0 && $cc > 0) {
        $check = $pdo->prepare("SELECT id FROM stp_certificates WHERE user_id=? AND course_id=?");
        $check->execute([$cu, $cc]);
        if ($check->fetchColumn()) {
            $_SESSION['course_errors'] = ["Certificate already exists for this student/course."];
        } else {
            $certNo = generateCertificateNumber($pdo);
            $pdo->prepare("INSERT INTO stp_certificates(user_id,course_id,cert_number,status) VALUES(?,?,?,'active')")
                ->execute([$cu, $cc, $certNo]);
            logActivity($pdo, $user_id, "Manually issued certificate $certNo");
            $_SESSION['success'] = "Certificate $certNo issued.";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "#certificateSection");
    exit;
}

$revenue = (float)($pdo->query("SELECT SUM(amount) FROM payments WHERE status='completed'")->fetchColumn() ?: 0);
$pending_payments = (int)$pdo->query("SELECT COUNT(*) FROM payments WHERE status='pending'")->fetchColumn();
$paid_courses_count = (int)$pdo->query("SELECT COUNT(*) FROM courses WHERE course_type='Paid'")->fetchColumn();
$certs_count = (int)$pdo->query("SELECT COUNT(*) FROM stp_certificates")->fetchColumn();

$payments = $pdo->query("
    SELECT p.id, p.amount, p.payment_method, p.status, p.created_at, c.title AS course_title, u.full_name 
    FROM payments p 
    LEFT JOIN courses c ON c.id = p.course_id 
    LEFT JOIN users u ON u.id = p.user_id 
    ORDER BY p.id DESC LIMIT 100
");

$paid_courses = $pdo->query("
    SELECT c.id, c.title, c.price, u.full_name AS trainer_name 
    FROM courses c 
    LEFT JOIN users u ON c.teacher_id = u.id 
    WHERE c.course_type = 'Paid' 
    ORDER BY c.id DESC
");

$certificates = $pdo->query("
    SELECT cert.id, cert.cert_number, cert.issued_at, u.full_name, c.title AS course_title
    FROM stp_certificates cert
    JOIN users u ON u.id = cert.user_id
    JOIN courses c ON c.id = cert.course_id
    ORDER BY cert.id DESC LIMIT 100
");

$trainers_list = $pdo->query("
    SELECT u.id, u.full_name, u.email, t.employee_no, t.specialization 
    FROM users u 
    JOIN teachers t ON t.user_id = u.id 
    ORDER BY u.full_name ASC
");

$students_list = $pdo->query("SELECT u.id, u.full_name FROM users u WHERE u.role = 'student' ORDER BY u.full_name ASC");
$courses_list = $pdo->query("SELECT c.id, c.title FROM courses c ORDER BY c.title ASC");

/* == REVENUE & PAYMENT CHARTS == */
$rev_labels = []; $rev_values = [];
$rq = $pdo->query("SELECT DATE_FORMAT(MIN(created_at),'%b %Y') AS month_name, SUM(amount) AS total FROM payments WHERE status='completed' GROUP BY YEAR(created_at), MONTH(created_at) ORDER BY YEAR(created_at), MONTH(created_at)");
if ($rq) { 
    foreach ($rq as $row) { 
        $rev_labels[] = $row['month_name']; 
        $rev_values[] = (float)$row['total']; 
    } 
}

$methods_labels = []; $methods_values = [];
$mq = $pdo->query("SELECT payment_method, COUNT(*) AS count FROM payments WHERE status='completed' GROUP BY payment_method");
if ($mq) { 
    foreach ($mq as $row) { 
        $methods_labels[] = strtoupper($row['payment_method']); 
        $methods_values[] = (int)$row['count']; 
    } 
}

if (empty($rev_labels)) { $rev_labels = ['Current']; $rev_values = [$revenue]; }
if (empty($methods_labels)) { $methods_labels = ['M-Pesa', 'Bank']; $methods_values = [1, 0]; }

$flash_success = $_SESSION['success'] ?? ''; unset($_SESSION['success']);
$flash_errors  = $_SESSION['course_errors'] ?? []; unset($_SESSION['course_errors']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($branding['org_name']) ?> - Super Admin Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="icon" type="image/png" href="/icons/cbt-ke.png">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
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
.badge-success { background: #e4f3d3; color: #3c5518; }
.badge-pending { background: #fdecc8; color: #8a5a10; }
.badge-danger  { background: #fbe3e3; color: #8f2b2b; }

.form-card { background: var(--card-bg); border-radius: var(--radius); padding: 24px; box-shadow: var(--shadow); border: 1px solid var(--border); margin-bottom: 22px; }
.form-card h3 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 18px; padding-bottom: 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
.form-card h3 i { color: var(--primary); }

.form-group { margin-bottom: 14px; }
.form-group label { font-size: 12px; font-weight: 600; color: var(--muted); display: block; margin-bottom: 6px; text-transform: uppercase; letter-spacing: .4px; }

input[type=text], input[type=email], input[type=password], input[type=number], textarea, select {
    width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; font-size: 14px;
    background: var(--bg); color: var(--text); outline: none; transition: .2s; font-family: inherit;
}
input:focus, textarea:focus, select:focus { border-color: var(--primary); background: #fff; box-shadow: 0 0 0 3px rgba(108,154,46,.15); }
textarea { resize: vertical; min-height: 90px; }

.btn { padding: 9px 18px; border: none; border-radius: 9px; cursor: pointer; font-size: 13px; font-weight: 600; font-family: inherit; transition: .2s; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; }
.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover { background: var(--primary-dark); }
.btn-success { background: var(--success); color: #fff; }
.btn-danger  { background: var(--danger); color: #fff; }
.btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--text); }
.btn-outline:hover { border-color: var(--primary); color: var(--primary); }
.btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 7px; }
.btn-full { width: 100%; justify-content: center; padding: 12px; font-size: 14px; }

.alert { padding: 12px 16px; border-radius: 10px; font-size: 13px; font-weight: 500; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
.alert-error { background: #fbe3e3; color: #8f2b2b; border: 1px solid var(--danger); }
.alert-success { background: #e4f3d3; color: #3c5518; border: 1px solid var(--success); }

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
        <div><span>Super Admin Panel</span></div>
    </div>

    <div class="menu">
        <div class="menu-label">Executive</div>
        <ul>
            <li><a href="#" onclick="showSection('dashboardSection',this)" class="active"><i class="fas fa-chart-pie"></i><span>Executive Overview</span></a></li>
            <li><a href="#" onclick="showSection('financeSection',this)"><i class="fas fa-coins"></i><span>Finance &amp; Refunds</span></a></li>
            <li><a href="#" onclick="showSection('paidCoursesSection',this)"><i class="fas fa-sack-dollar"></i><span>Paid Courses</span></a></li>
        </ul>

        <div class="menu-label">Credentials &amp; Roles</div>
        <ul>
            <li><a href="#" onclick="showSection('certificateSection',this)"><i class="fas fa-certificate"></i><span>Certificates</span></a></li>
            <li><a href="#" onclick="showSection('trainerSection',this)"><i class="fas fa-user-plus"></i><span>Add Trainer</span></a></li>
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

    <!-- 1. EXECUTIVE SUMMARY -->
    <div id="dashboardSection">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Executive Summary</h1>
            </div>
        </div>

        <div class="cards">
            <div class="card"><h3>KES <?= number_format($revenue, 2) ?></h3><p>Total Completed Revenue</p></div>
            <div class="card"><h3><?= $pending_payments ?></h3><p>Pending Payments</p></div>
            <div class="card"><h3><?= $paid_courses_count ?></h3><p>Active Paid Courses</p></div>
            <div class="card"><h3><?= $certs_count ?></h3><p>Certificates Issued</p></div>
        </div>

        <!-- GRAPHS SECTION -->
        <div class="charts">
            <div class="chart-box">
                <h2><i class="fas fa-chart-area"></i> Revenue Trend (Completed Payments)</h2>
                <canvas id="revenueChart"></canvas>
            </div>
            <div class="chart-box">
                <h2><i class="fas fa-pie-chart"></i> Payment Methods Breakdown</h2>
                <canvas id="paymentMethodChart"></canvas>
            </div>
        </div>
    </div>

    <!-- 2. FINANCE & REFUNDS -->
    <div id="financeSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Finance &amp; Refunds</h1>
            </div>
        </div>

        <div class="form-card" style="max-width:540px;">
            <h3><i class="fas fa-money-bill-transfer"></i> Process Student Refund</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Payment ID</label><input type="number" name="refund_payment_id" required></div>
                <div class="form-group"><label>Refund Amount (KES)</label><input type="number" step="0.01" name="refund_amount" required></div>
                <div class="form-group"><label>Reason</label><input type="text" name="refund_reason" required></div>
                <button type="submit" name="create_refund" class="btn btn-danger btn-full">Execute Refund</button>
            </form>
        </div>

        <div class="table-section" id="export_finance">
            <div class="table-header">
                <h2><i class="fas fa-credit-card"></i> Payment Transactions</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_finance', 'Payment_Transactions.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_finance', 'Payment_Transactions')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>ID</th><th>Student</th><th>Course</th><th>Amount</th><th>Method</th><th>Status</th></tr></thead>
                    <tbody>
                        <?php foreach ($payments as $p): ?>
                        <tr>
                            <td>#<?= (int)$p['id'] ?></td>
                            <td><?= htmlspecialchars($p['full_name'] ?? 'Guest') ?></td>
                            <td><?= htmlspecialchars($p['course_title'] ?? 'N/A') ?></td>
                            <td>KES <?= number_format($p['amount'], 2) ?></td>
                            <td><?= strtoupper($p['payment_method']) ?></td>
                            <td><span class="badge badge-<?= $p['status'] === 'completed' ? 'success' : 'pending' ?>"><?= ucfirst($p['status']) ?></span></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 3. PAID COURSES -->
    <div id="paidCoursesSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Paid Course Management</h1>
            </div>
        </div>

        <div class="form-card" style="max-width:640px;">
            <h3><i class="fas fa-sack-dollar"></i> Publish Paid Course</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="150"></div>
                <div class="form-group"><label>Description</label><textarea name="description" required></textarea></div>
                <div class="form-group"><label>Category</label><input type="text" name="category" required></div>
                <div class="form-group"><label>Course Price (KES)</label><input type="number" step="0.01" name="price" required></div>
                <div class="form-group">
                    <label>Assign Trainer</label>
                    <select name="teacher_id" required>
                        <option value="">Select Trainer</option>
                        <?php 
                        $trainers_list->execute();
                        foreach ($trainers_list as $t): 
                        ?>
                            <option value="<?= (int)$t['id'] ?>"><?= htmlspecialchars($t['full_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="submit" name="create_paid_course" class="btn btn-primary btn-full">Publish Paid Course</button>
            </form>
        </div>

        <div class="table-section" id="export_paid_courses">
            <div class="table-header">
                <h2><i class="fas fa-list"></i> Active Paid Courses</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_paid_courses', 'Paid_Courses_Report.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_paid_courses', 'Paid_Courses_Report')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Title</th><th>Trainer</th><th>Price</th></tr></thead>
                    <tbody>
                        <?php foreach ($paid_courses as $pc): ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($pc['title']) ?></strong></td>
                            <td><?= htmlspecialchars($pc['trainer_name'] ?? 'Unassigned') ?></td>
                            <td>KES <?= number_format($pc['price'], 2) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 4. CERTIFICATES -->
    <div id="certificateSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Certificate Issuance</h1>
            </div>
        </div>

        <div class="form-card" style="max-width:540px;">
            <h3><i class="fas fa-certificate"></i> Manual Certificate Generation</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group">
                    <label>Student</label>
                    <select name="user_id" required>
                        <option value="">Select Student</option>
                        <?php foreach ($students_list as $st): ?>
                            <option value="<?= (int)$st['id'] ?>"><?= htmlspecialchars($st['full_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Course</label>
                    <select name="course_id" required>
                        <option value="">Select Course</option>
                        <?php foreach ($courses_list as $cs): ?>
                            <option value="<?= (int)$cs['id'] ?>"><?= htmlspecialchars($cs['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <button type="submit" name="issue_certificate" class="btn btn-primary btn-full">Generate Certificate</button>
            </form>
        </div>

        <div class="table-section" id="export_certificates">
            <div class="table-header">
                <h2><i class="fas fa-list"></i> Issued Certificates Log</h2>
                <div class="export-tools">
                    <button class="btn btn-outline btn-sm" onclick="exportTableToCSV('export_certificates', 'Certificates_Issued.csv')"><i class="fas fa-file-excel text-success"></i> Excel</button>
                    <button class="btn btn-outline btn-sm" onclick="exportTableToPDF('export_certificates', 'Certificates_Issued')"><i class="fas fa-file-pdf text-danger"></i> PDF</button>
                </div>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Cert No</th><th>Student</th><th>Course</th><th>Issued Date</th></tr></thead>
                    <tbody>
                        <?php foreach ($certificates as $cert): ?>
                        <tr>
                            <td><strong><?= htmlspecialchars($cert['cert_number']) ?></strong></td>
                            <td><?= htmlspecialchars($cert['full_name']) ?></td>
                            <td><?= htmlspecialchars($cert['course_title']) ?></td>
                            <td><?= htmlspecialchars($cert['issued_at']) ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- 5. ADD TRAINER -->
    <div id="trainerSection" style="display:none;">
        <div class="topbar">
            <div class="topbar-left">
                <div class="menu-toggle" onclick="openSidebar()"><i class="fas fa-bars"></i></div>
                <h1>Onboard Trainer</h1>
            </div>
        </div>

        <div class="form-card" style="max-width:640px;">
            <h3><i class="fas fa-user-plus"></i> New Trainer Account</h3>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group"><label>Full Name *</label><input type="text" name="full_name" required></div>
                <div class="form-group"><label>Email *</label><input type="email" name="email" required></div>
                <div class="form-group"><label>Password *</label><input type="password" name="password" required minlength="6"></div>
                <div class="form-group"><label>Phone Number *</label><input type="text" name="phone" required></div>
                <div class="form-group"><label>Employee Number *</label><input type="text" name="employee_no" required></div>
                <div class="form-group"><label>Licence / Registration No.</label><input type="text" name="license_no"></div>
                <div class="form-group"><label>Specialization</label><input type="text" name="specialization"></div>
                <div class="form-group"><label>Academic Qualification *</label><input type="text" name="qualification" required></div>
                <div class="form-group"><label>KRA PIN</label><input type="text" name="kra_pin"></div>
                <button type="submit" name="add_teacher" class="btn btn-success btn-full">Create Trainer Account</button>
            </form>
        </div>
    </div>
</div>

<script>
const sections = ['dashboardSection','financeSection','paidCoursesSection','certificateSection','trainerSection'];
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

/* == CHARTS INITIALIZATION == */
document.addEventListener('DOMContentLoaded', function() {
    const revCtx = document.getElementById('revenueChart');
    if (revCtx) {
        new Chart(revCtx, {
            type: 'line',
            data: {
                labels: <?= json_encode($rev_labels) ?>,
                datasets: [{
                    label: 'Revenue (KES)',
                    data: <?= json_encode($rev_values) ?>,
                    borderColor: '<?= htmlspecialchars($branding['color_primary']) ?>',
                    backgroundColor: 'rgba(108,154,46,.10)',
                    borderWidth: 2.5,
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '<?= htmlspecialchars($branding['color_primary']) ?>',
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

    const methodCtx = document.getElementById('paymentMethodChart');
    if (methodCtx) {
        new Chart(methodCtx, {
            type: 'doughnut',
            data: {
                labels: <?= json_encode($methods_labels) ?>,
                datasets: [{
                    data: <?= json_encode($methods_values) ?>,
                    backgroundColor: ['#6C9A2E', '#F5A623', '#4F86C6', '#d64545'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
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