<?php
require_once __DIR__ . '/Bootstrap.php';
require_once __DIR__ . '/Payment.php';

/* LOGIN CHECK */
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}
$user_id = (int) $_SESSION['user_id'];

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* COURSE */
$course_id = (int) ($_GET['course_id'] ?? 0);
if ($course_id <= 0) {
    die('Invalid course.');
}

$stmt = $pdo->prepare("
    SELECT c.*, u.full_name AS instructor_name
    FROM courses c
    LEFT JOIN teachers t ON t.id = c.teacher_id
    LEFT JOIN users u ON u.id = t.user_id
    WHERE c.id = :id LIMIT 1
");
$stmt->execute([':id' => $course_id]);
$course = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$course || strtolower((string) ($course['status'] ?? 'active')) !== 'active') {
    die('Course not found or not available.');
}

/* USER */
$stmt = $pdo->prepare("SELECT id, phone, full_name, email FROM users WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $user_id]);
$userRow = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$userRow) {
    die('User account not found.');
}
$payerPhone = $userRow['phone'] ?? '';

/* ALREADY ENROLLED? */
$stmt = $pdo->prepare("SELECT id FROM enrollments WHERE user_id = :u AND course_id = :c LIMIT 1");
$stmt->execute([':u' => $user_id, ':c' => $course_id]);
if ($stmt->fetch()) {
    header('Location: course1.php?id=' . $course_id);
    exit;
}

$price = (float) $course['price'];

/* FREE COURSE: AUTO-ENROLL */
if ($price <= 0) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['free_enroll'])) {
        validateCsrf();
        try {
            $pdo->beginTransaction();
            $pdo->prepare("INSERT INTO enrollments (user_id, course_id, progress, status, enrolled_at)
                           VALUES (:u, :c, 0, 'ongoing', NOW())")
                ->execute([':u' => $user_id, ':c' => $course_id]);
            $pdo->prepare("UPDATE courses SET enrolled_students = COALESCE(enrolled_students,0) + 1 WHERE id = :c")
                ->execute([':c' => $course_id]);
            $pdo->commit();
            $_SESSION['success'] = 'Successfully enrolled in course.';
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) { $pdo->rollBack(); }
            error_log('Free enrollment failed: ' . $e->getMessage());
        }
        header('Location: course1.php?id=' . $course_id);
        exit;
    }
}

/* PAID COURSE: STK PUSH */
$errorMessage   = null;
$successMessage = null;
$sentPrompt     = false;

if ($price > 0 && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pay'])) {
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errorMessage = 'Your session expired. Please refresh the page and try again.';
    } else {
        $phoneInput = trim($_POST['phone'] ?? '');
        $r = payments_start_stk($pdo, $user_id, $course_id, $phoneInput);
        
        if ($r[0]) {
            $sentPrompt     = true;
            $successMessage = $r[1] ?? "STK push prompt sent successfully to {$phoneInput}! Please check your phone and enter your M-Pesa PIN.";
        } else {
            $errorMessage = $r[1] ?? 'Unable to trigger STK prompt. Please verify your phone number and try again.';
        }
    }
}

$instructor = !empty($course['instructor_name']) ? $course['instructor_name'] : 'CBT-Kenya Instructor';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enrollment - <?= htmlspecialchars($course['title']) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        :root {
            --primary: #2e7d32;
            --primary-hover: #1b5e20;
            --primary-soft: #e8f5e9;
            --navy: #0f172a;
            --slate: #475569;
            --border: #e2e8f0;
            --bg: #f8fafc;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg); padding: 24px; color: var(--navy); }
        
        .checkout-wrapper {
            width: 100%;
            max-width: 520px;
            background: #ffffff;
            border-radius: 20px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.03);
            border: 1px solid var(--border);
            overflow: hidden;
        }
        .header-banner {
            background: linear-gradient(135deg, #1b5e20 0%, #2e7d32 100%);
            padding: 24px 28px;
            color: #ffffff;
            position: relative;
        }
        .header-banner .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.75rem;
            text-transform: uppercase;
            font-weight: 700;
            background: rgba(255,255,255,0.2);
            padding: 4px 10px;
            border-radius: 999px;
            margin-bottom: 10px;
        }
        .header-banner h1 {
            font-size: 1.35rem;
            font-weight: 700;
            line-height: 1.3;
        }
        .content {
            padding: 28px;
        }
        .summary-card {
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }
        .summary-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 0;
            font-size: 0.9rem;
            color: var(--slate);
        }
        .summary-row.total {
            border-top: 1px dashed var(--border);
            margin-top: 8px;
            padding-top: 12px;
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--navy);
        }
        .summary-row.total .price-val {
            color: var(--primary);
        }
        .alert {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 14px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 0.9rem;
            line-height: 1.45;
        }
        .alert-error {
            background: #fef2f2;
            color: #991b1b;
            border: 1px solid #fee2e2;
        }
        .alert-success {
            background: #ecfdf5;
            color: #065f46;
            border: 1px solid #a7f3d0;
        }
        .alert i {
            font-size: 1.15rem;
            margin-top: 2px;
            flex-shrink: 0;
        }
        .prompt-pending-box {
            text-align: center;
            padding: 24px 16px;
            background: #f0fdf4;
            border: 1.5px dashed #86efac;
            border-radius: 14px;
            margin-bottom: 20px;
        }
        .prompt-pending-box .pulse-icon {
            font-size: 2.2rem;
            color: #16a34a;
            animation: pulse 1.6s infinite ease-in-out;
            margin-bottom: 10px;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.15); opacity: 0.8; }
        }
        .form-group {
            margin-bottom: 18px;
        }
        .form-group label {
            display: block;
            font-size: 0.88rem;
            font-weight: 600;
            margin-bottom: 6px;
            color: var(--navy);
        }
        .input-group {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-group i {
            position: absolute;
            left: 14px;
            color: #94a3b8;
            font-size: 1rem;
        }
        .input-group input {
            width: 100%;
            padding: 12px 14px 12px 42px;
            border: 1.5px solid var(--border);
            border-radius: 10px;
            font-size: 0.95rem;
            color: var(--navy);
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .input-group input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(46, 125, 50, 0.15);
        }
        .info-hint {
            display: flex;
            align-items: flex-start;
            gap: 8px;
            margin-top: 8px;
            font-size: 0.8rem;
            color: var(--slate);
            line-height: 1.4;
        }
        .btn-submit {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 10px;
            background: var(--primary);
            color: #ffffff;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(46, 125, 50, 0.2);
        }
        .btn-submit:hover {
            background: var(--primary-hover);
            transform: translateY(-1px);
        }
        .btn-secondary {
            background: #ffffff;
            color: var(--slate);
            border: 1.5px solid var(--border);
            box-shadow: none;
            margin-top: 10px;
        }
        .btn-secondary:hover {
            background: #f1f5f9;
            color: var(--navy);
            transform: none;
        }
        .trust-badges {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 16px;
            margin-top: 20px;
            font-size: 0.78rem;
            color: #64748b;
        }
        .trust-badges span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .back-link {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            margin-top: 18px;
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--slate);
            text-decoration: none;
            transition: color 0.15s;
        }
        .back-link:hover { color: var(--navy); }
    </style>
</head>
<body>

<div class="checkout-wrapper">
    <div class="header-banner">
        <span class="badge"><i class="fas fa-graduation-cap"></i> Course Enrollment</span>
        <h1><?= htmlspecialchars($course['title']) ?></h1>
    </div>

    <div class="content">
        <div class="summary-card">
            <div class="summary-row">
                <span>Instructor</span>
                <strong><?= htmlspecialchars($instructor) ?></strong>
            </div>
            <div class="summary-row">
                <span>Access</span>
                <strong>Full Lifetime Access</strong>
            </div>
            <div class="summary-row total">
                <span>Total Due</span>
                <span class="price-val"><?= $price > 0 ? 'KES ' . number_format($price) : 'FREE' ?></span>
            </div>
        </div>

        <?php if ($errorMessage): ?>
            <div class="alert alert-error">
                <i class="fas fa-circle-xmark"></i>
                <div>
                    <strong>STK Push Unsuccessful</strong><br>
                    <?= htmlspecialchars($errorMessage) ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($successMessage): ?>
            <div class="alert alert-success">
                <i class="fas fa-circle-check"></i>
                <div>
                    <strong>Prompt Dispatched!</strong><br>
                    <?= htmlspecialchars($successMessage) ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($sentPrompt): ?>
            <div class="prompt-pending-box">
                <div class="pulse-icon"><i class="fas fa-mobile-screen"></i></div>
                <h3 style="font-size:1.05rem; margin-bottom: 6px; color:#14532d;">Check Your Phone</h3>
                <p style="font-size:0.85rem; color:#166534; line-height: 1.45;">
                    Enter your M-Pesa PIN on the prompt to complete the payment. Your enrollment will activate automatically once confirmed.
                </p>
            </div>
            <a href="student.php" class="btn-submit" style="text-decoration: none;">
                <i class="fas fa-home"></i> Go to Student Dashboard
            </a>
            <a href="enroll.php?course_id=<?= (int)$course_id ?>" class="btn-submit btn-secondary" style="text-decoration: none;">
                <i class="fas fa-rotate-right"></i> Try Again / Change Number
            </a>
        <?php elseif ($price > 0): ?>
            <form method="POST" action="enroll.php?course_id=<?= (int) $course_id ?>" onsubmit="handleSubmit()">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                
                <div class="form-group">
                    <label for="phone">M-Pesa Mobile Number</label>
                    <div class="input-group">
                        <i class="fas fa-mobile-screen-button"></i>
                        <input type="tel" id="phone" name="phone" maxlength="15"
                               value="<?= htmlspecialchars($_POST['phone'] ?? $payerPhone, ENT_QUOTES, 'UTF-8') ?>"
                               placeholder="e.g. 0712345678" required autocomplete="tel">
                    </div>
                    <div class="info-hint">
                        <i class="fas fa-circle-info" style="color:var(--primary);"></i>
                        <span>An instant STK prompt will appear on this phone asking for your M-Pesa PIN.</span>
                    </div>
                </div>

                <button type="submit" name="pay" value="1" id="submitBtn" class="btn-submit">
                    <i class="fas fa-lock"></i> Pay KES <?= number_format($price) ?> with M-Pesa
                </button>
            </form>
        <?php else: ?>
            <form method="POST" action="enroll.php?course_id=<?= (int) $course_id ?>" onsubmit="handleSubmit()">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <button type="submit" name="free_enroll" value="1" id="submitBtn" class="btn-submit">
                    <i class="fas fa-check-circle"></i> Enroll for Free
                </button>
            </form>
        <?php endif; ?>

        <div class="trust-badges">
            <span><i class="fas fa-shield-alt" style="color:var(--primary);"></i> Secure Gateway</span>
            <span>•</span>
            <span><i class="fas fa-bolt" style="color:#f59e0b;"></i> Instant Access</span>
        </div>

        <a href="student.php" class="back-link"><i class="fas fa-arrow-left"></i> Return to Dashboard</a>
    </div>
</div>

<script>
function handleSubmit() {
    const btn = document.getElementById('submitBtn');
    if (btn) {
        setTimeout(() => {
            btn.style.opacity = '0.75';
            btn.style.pointerEvents = 'none';
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Sending STK Prompt...';
        }, 10);
    }
}
</script>
</body>
</html>