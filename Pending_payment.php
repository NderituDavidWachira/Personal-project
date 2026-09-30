<?php
session_start();
include "db.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];

$course_id = isset($_GET['course_id']) ? (int)$_GET['course_id'] : 0;
if ($course_id <= 0) {
    die("Invalid course.");
}

$checkoutRequestId = $_SESSION['pending_checkout_id'] ?? null;
if (!$checkoutRequestId) {
    header("Location: enroll.php?course_id=" . $course_id);
    exit;
}

if (isset($_GET['check'])) {
    header('Content-Type: application/json');

    $stmt = $pdo->prepare("
        SELECT status
        FROM payments
        WHERE checkout_request_id = ? AND user_id = ? AND course_id = ?
        LIMIT 1
    ");
    $stmt->execute([$checkoutRequestId, $user_id, $course_id]);
    $payment = $stmt->fetch();

    if (!$payment) {
        echo json_encode(['status' => 'unknown']);
        exit;
    }

    if ($payment['status'] === 'completed') {
        $check = $pdo->prepare("
            SELECT id FROM enrollments WHERE user_id = ? AND course_id = ? LIMIT 1
        ");
        $check->execute([$user_id, $course_id]);
        if ($check->fetch()) {
            unset($_SESSION['pending_checkout_id']);
            echo json_encode(['status' => 'completed']);
            exit;
        }

        echo json_encode(['status' => 'processing']);
        exit;
    }

    echo json_encode(['status' => $payment['status']]); 
    exit;
}

/* ===
   GET COURSE 
=== */
$stmt = $pdo->prepare("SELECT id, title FROM courses WHERE id = ? LIMIT 1");
$stmt->execute([$course_id]);
$course = $stmt->fetch();

if (!$course) {
    die("Course not found.");
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Waiting for payment - <?= htmlspecialchars($course['title']) ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 30px; background: #f1f5f9; }
        .card { width: 100%; max-width: 480px; background: #ffffff; border-radius: 16px; padding: 36px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; text-align: center; }
        .spinner { width: 48px; height: 48px; margin: 0 auto 20px; border: 4px solid #e2e8f0; border-top-color: #2563eb; border-radius: 50%; animation: spin 0.9s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        h2 { color: #1e293b; margin-bottom: 10px; font-size: 22px; }
        p { color: #64748b; line-height: 1.6; margin-bottom: 6px; }
        .btn { display: inline-block; margin-top: 18px; padding: 12px 20px; border: none; border-radius: 8px; background: #2563eb; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; }
        .btn:hover { background: #1d4ed8; }
        .hidden { display: none; }
        .status-failed h2 { color: #991b1b; }
        #failedBox, #successBox { display: none; }
    </style>
</head>
<body>
<div class="card">
    <div id="waitingBox">
        <div class="spinner"></div>
        <h2>Waiting for M-Pesa confirmation</h2>
        <p>Check your phone and enter your M-Pesa PIN to complete payment for</p>
        <p><strong><?= htmlspecialchars($course['title']) ?></strong></p>
        <p style="margin-top:14px;font-size:13px;color:#94a3b8;">This page updates automatically — no need to refresh.</p>
    </div>

    <div id="successBox">
        <h2 style="color:#166534;">Payment received!</h2>
        <p>You're enrolled. Taking you to the course...</p>
    </div>

    <div id="failedBox">
        <h2 style="color:#991b1b;">Payment didn't go through</h2>
        <p id="failedReason">Please try again.</p>
        <a class="btn" href="enroll.php?course_id=<?= $course_id ?>">Try Again</a>
    </div>
</div>

<script>
const courseId = <?= (int)$course_id ?>;
let attempts = 0;
const maxAttempts = 40; 
function poll() {
    attempts++;
    fetch('Pending_payment.php?course_id=' + courseId + '&check=1')
        .then(r => r.json())
        .then(data => {
            if (data.status === 'completed') {
                document.getElementById('waitingBox').style.display = 'none';
                document.getElementById('successBox').style.display = 'block';
                setTimeout(() => {
                    window.location.href = 'course1.php?id=' + courseId;
                }, 1200);
                return;
            }
            if (data.status === 'failed') {
                document.getElementById('waitingBox').style.display = 'none';
                document.getElementById('failedBox').style.display = 'block';
                return;
            }
            if (attempts >= maxAttempts) {
                document.getElementById('waitingBox').style.display = 'none';
                document.getElementById('failedBox').style.display = 'block';
                document.getElementById('failedReason').textContent =
                    "We haven't heard back yet. If money left your account, contact support with your phone number and course name; otherwise you can try again.";
                return;
            }
            setTimeout(poll, 3000);
        })
        .catch(() => {
            if (attempts < maxAttempts) setTimeout(poll, 3000);
        });
}

poll();
</script>
</body>
</html>