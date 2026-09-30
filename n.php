<?php
/* ====
   SECURE SESSION COOKIE SETTINGS 
==== */
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
    ini_set('session.cookie_secure', 1);
}

session_start();
include 'db.php';
include 'advance.php';

/* ====
   BANK TRANSFER DETAILS
==== */
define('BANK_NAME', 'Your Bank Name Ltd.');
define('BANK_ACCOUNT_NAME', 'Account name');
define('BANK_ACCOUNT_NUMBER', '0000000000');
define('BANK_BRANCH', 'Main Branch');
define('BANK_SWIFT_CODE', 'XXXXXXXX');

/* ====
   SECURITY HEADERS
==== */
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com;");

/* ====
   AUTH CHECK
==== */
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$user_id = (int) $_SESSION['user_id'];

/* ====
   CSRF TOKEN
==== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ====
   VALIDATE CSRF
==== */
function validateCsrf(): void {
    if (
        empty($_POST['csrf_token']) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        http_response_code(403);
        die("Invalid CSRF token. Request blocked.");
    }
}

/* ====
   COMPUTE LIVE COURSE PROGRESS
==== */
function computeCourseProgress(PDO $pdo, int $user_id, int $course_id): int {

    /* Videos */
    $stmt = $pdo->prepare("
        SELECT cv.id, COALESCE(MAX(vp.watched_percentage), 0) AS pct
        FROM course_videos cv
        LEFT JOIN video_progress vp ON vp.content_id = cv.id AND vp.user_id = :uid
        WHERE cv.course_id = :cid
        GROUP BY cv.id
    ");
    $stmt->execute([':uid' => $user_id, ':cid' => $course_id]);
    $rows        = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $video_count = count($rows);
    $video_sum   = array_sum(array_column($rows, 'pct'));
    $video_progress = $video_count > 0 ? (int) round($video_sum / $video_count) : 0;

    /* Notes */
    $stmt = $pdo->prepare("
        SELECT n.id, COALESCE(MAX(np.completed), 0) AS completed
        FROM notes n
        LEFT JOIN note_progress np ON np.note_id = n.id AND np.user_id = :uid
        WHERE n.course_id = :cid
        GROUP BY n.id
    ");
    $stmt->execute([':uid' => $user_id, ':cid' => $course_id]);
    $noteRows   = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $note_count = count($noteRows);
    $doneNotes  = count(array_filter($noteRows, fn($r) => (int)$r['completed'] === 1));
    $note_progress = $note_count > 0 ? (int) round(($doneNotes / $note_count) * 100) : 0;

    /* Quizzes */
    $stmt = $pdo->prepare("SELECT id FROM quizzes WHERE course_id = :cid");
    $stmt->execute([':cid' => $course_id]);
    $quizIds   = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');
    $quiz_count = count($quizIds);
    $quiz_progress = 0;

    if ($quiz_count > 0) {
        $in      = implode(',', array_map('intval', $quizIds));
        $stmt    = $pdo->prepare("
            SELECT quiz_id, status FROM quiz_results
            WHERE user_id = :uid AND quiz_id IN ($in)
            ORDER BY completed_at DESC
        ");
        $stmt->execute([':uid' => $user_id]);
        $statusMap = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $qid = (int) $row['quiz_id'];
            if (!isset($statusMap[$qid])) {
                $statusMap[$qid] = $row['status'];
            }
        }
        $passed        = count(array_filter($statusMap, fn($s) => $s === 'passed'));
        $quiz_progress = (int) round(($passed / $quiz_count) * 100);
    }

    /* Weighted overall progress */
    $w_video = $video_count > 0 ? 0.60 : 0;
    $w_note  = $note_count  > 0 ? 0.25 : 0;
    $w_quiz  = $quiz_count  > 0 ? 0.15 : 0;
    $w_total = $w_video + $w_note + $w_quiz;
    if ($w_total <= 0) return 0;

    return (int) round(
        ($video_progress * $w_video + $note_progress * $w_note + $quiz_progress * $w_quiz) / $w_total
    );
}

/* ====
   UPDATE PROFILE
==== */
if (isset($_POST['update_profile'])) {
    validateCsrf();
    $full_name = trim(strip_tags($_POST['full_name'] ?? ''));
    $email     = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $phone     = trim(strip_tags($_POST['phone']    ?? ''));
    $location  = trim(strip_tags($_POST['location'] ?? ''));
    $bio       = trim(strip_tags($_POST['bio']      ?? ''));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['flash'] = "Invalid email address.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $full_name = mb_substr($full_name, 0, 120);
    $phone     = mb_substr($phone, 0, 30);
    $location  = mb_substr($location, 0, 120);
    $bio       = mb_substr($bio, 0, 2000);

    $stmt = $pdo->prepare("UPDATE users SET full_name=:fn, email=:em, phone=:ph, location=:lo, bio=:bi WHERE id=:id");
    $stmt->execute([':fn'=>$full_name,':em'=>$email,':ph'=>$phone,':lo'=>$location,':bi'=>$bio,':id'=>$user_id]);

    $stmt = $pdo->prepare("UPDATE students SET full_name=:fn, email=:em, phone=:ph WHERE user_id=:id");
    $stmt->execute([':fn'=>$full_name,':em'=>$email,':ph'=>$phone,':id'=>$user_id]);

    $_SESSION['flash'] = "Profile updated successfully.";
    $_SESSION['active_section'] = 'profile';
    header("Location: student.php");
    exit;
}

/* ====
   SIGN ATTENDANCE
==== */
if (isset($_POST['sign_attendance'])) {
    validateCsrf();
    $att_course_id = (int) ($_POST['course_id'] ?? 0);

    if ($att_course_id <= 0) {
        $_SESSION['flash'] = "Please select a course.";
        $_SESSION['active_section'] = 'attendance';
        header("Location: student.php");
        exit;
    }
    $enrollCheck = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:uid AND course_id=:cid");
    $enrollCheck->execute([':uid'=>$user_id, ':cid'=>$att_course_id]);
    if ($enrollCheck->rowCount() === 0) {
        $_SESSION['flash'] = "You are not enrolled in this course.";
        $_SESSION['active_section'] = 'attendance';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        SELECT id FROM attendance
        WHERE user_id=:uid AND course_id=:cid AND DATE(attendance_date)=CURDATE()
    ");
    $stmt->execute([':uid'=>$user_id,':cid'=>$att_course_id]);
    $already = $stmt->rowCount() > 0;

    if ($already) {
        $_SESSION['flash'] = "You already signed attendance today.";
    } else {
        $stmt = $pdo->prepare("
            INSERT INTO attendance (user_id, course_id, attendance_date, status)
            VALUES (:uid, :cid, CURDATE(), 'present')
        ");
        $stmt->execute([':uid'=>$user_id,':cid'=>$att_course_id]);
        $_SESSION['flash'] = "Attendance signed successfully.";
    }

    $_SESSION['active_section'] = 'attendance';
    header("Location: student.php");
    exit;
}

/* ====
   PAYMENT
==== */

/* ====
   BANK PAYMENT SUBMISSION
==== */
if (isset($_POST['submit_bank_payment'])) {
    validateCsrf();

    $bp_course_id   = (int) ($_POST['course_id'] ?? 0);
    $bp_amount      = (float) ($_POST['amount'] ?? 0);
    $bp_payer_name  = trim(strip_tags($_POST['payer_name'] ?? ''));
    $bp_payer_phone = trim(strip_tags($_POST['payer_phone'] ?? ''));
    $bp_payer_email = trim(strip_tags($_POST['payer_email'] ?? ''));
    $bp_code        = trim(strip_tags($_POST['transaction_code'] ?? ''));
    $bp_date        = trim($_POST['payment_date'] ?? '');
    $bp_notes       = trim(strip_tags($_POST['notes'] ?? ''));

    $bp_payer_name  = mb_substr($bp_payer_name, 0, 150);
    $bp_payer_phone = mb_substr($bp_payer_phone, 0, 30);
    $bp_payer_email = mb_substr($bp_payer_email, 0, 150);
    $bp_code        = mb_substr($bp_code, 0, 100);
    $bp_notes       = mb_substr($bp_notes, 0, 2000);

    $dateOk = (bool) DateTime::createFromFormat('Y-m-d', $bp_date);

    if (
        $bp_course_id <= 0 || $bp_amount <= 0 || $bp_code === '' || !$dateOk ||
        $bp_payer_name === '' || $bp_payer_phone === ''
    ) {
        $_SESSION['flash'] = "Please fill in all required bank payment details correctly.";
        $_SESSION['active_section'] = 'payments';
        header("Location: student.php");
        exit;
    }

    if ($bp_payer_email !== '' && !filter_var($bp_payer_email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['flash'] = "Please enter a valid payer email, or leave it blank.";
        $_SESSION['active_section'] = 'payments';
        header("Location: student.php");
        exit;
    }

    $courseCheck = $pdo->prepare("
        SELECT id, price FROM courses
        WHERE id = :cid AND course_type = 'Paid' AND status = 'Active'
    ");
    $courseCheck->execute([':cid' => $bp_course_id]);
    $courseRow = $courseCheck->fetch(PDO::FETCH_ASSOC);

    $alreadyEnrolled = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:uid AND course_id=:cid");
    $alreadyEnrolled->execute([':uid' => $user_id, ':cid' => $bp_course_id]);

    if (!$courseRow || $alreadyEnrolled->rowCount() > 0) {
        $_SESSION['flash'] = "That course is not available for payment.";
        $_SESSION['active_section'] = 'payments';
        header("Location: student.php");
        exit;
    }

    try {
        $dupCheck = $pdo->prepare("
            SELECT id FROM payments
            WHERE user_id = :uid AND transaction_code = :code
        ");
        $dupCheck->execute([':uid' => $user_id, ':code' => $bp_code]);

        if ($dupCheck->rowCount() > 0) {
            $_SESSION['flash'] = "This transaction code has already been submitted.";
            $_SESSION['active_section'] = 'payments';
            header("Location: student.php");
            exit;
        }

        $stmt = $pdo->prepare("
            INSERT INTO payments
                (user_id, course_id, payer_name, payer_phone, payer_email,
                 amount, payment_method, transaction_code, status,
                 verification_status, notes, payment_date, created_at)
            VALUES
                (:uid, :cid, :payer_name, :payer_phone, :payer_email,
                 :amount, 'bank_transfer', :code, 'pending',
                 'pending', :notes, :pdate, NOW())
        ");
        $stmt->execute([
            ':uid'          => $user_id,
            ':cid'          => $bp_course_id,
            ':payer_name'   => $bp_payer_name,
            ':payer_phone'  => $bp_payer_phone,
            ':payer_email'  => $bp_payer_email !== '' ? $bp_payer_email : null,
            ':amount'       => $bp_amount,
            ':code'         => $bp_code,
            ':notes'        => $bp_notes !== '' ? $bp_notes : null,
            ':pdate'        => $bp_date,
        ]);

        $actStmt = $pdo->prepare("
            INSERT INTO activities (user_id, message, created_at)
            VALUES (:uid, :msg, NOW())
        ");
        $actStmt->execute([
            ':uid' => $user_id,
            ':msg' => "Submitted bank payment (Code: {$bp_code}) for verification",
        ]);

        $_SESSION['flash'] = "Bank payment submitted. An admin will verify your deposit and approve your enrollment shortly.";
    } catch (Throwable $e) {
        $_SESSION['flash'] = "Sorry, something went wrong submitting your bank payment. Please try again or contact support.";
    }

    $_SESSION['active_section'] = 'payments';
    header("Location: student.php");
    exit;
}

/* ====
   CHANGE PASSWORD
==== */
if (isset($_POST['change_password'])) {
    validateCsrf();
    $current_password = (string) ($_POST['current_password'] ?? '');
    $new_password     = (string) ($_POST['new_password']     ?? '');
    $confirm_password = (string) ($_POST['confirm_password'] ?? '');

    if ($new_password !== $confirm_password) {
        $_SESSION['flash'] = "New password and confirmation do not match.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }
    if (strlen($new_password) < 8) {
        $_SESSION['flash'] = "New password must be at least 8 characters.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("SELECT password FROM users WHERE id=:id LIMIT 1");
    $stmt->execute([':id'=>$user_id]);
    $userRow = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$userRow || !password_verify($current_password, $userRow['password'])) {
        $_SESSION['flash'] = "Current password is incorrect.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $newHash = password_hash($new_password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("UPDATE users SET password=:pw WHERE id=:id");
    $stmt->execute([':pw'=>$newHash,':id'=>$user_id]);

    $stmt = $pdo->prepare("
        INSERT INTO user_settings (user_id, password_updated_at)
        VALUES (:uid, NOW())
        ON DUPLICATE KEY UPDATE password_updated_at = NOW()
    ");
    $stmt->execute([':uid'=>$user_id]);
    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    $_SESSION['flash'] = "Password updated successfully.";
    $_SESSION['active_section'] = 'profile';
    header("Location: student.php");
    exit;
}

/* ====
   UPLOAD PROFILE PHOTO
==== */
if (isset($_POST['upload_photo'])) {
    validateCsrf();

    if (!isset($_FILES['profile_photo']) || $_FILES['profile_photo']['error'] !== UPLOAD_ERR_OK) {
        $_SESSION['flash'] = "Please choose a valid image to upload.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $file = $_FILES['profile_photo'];

    if ($file['size'] > 5 * 1024 * 1024) {
        $_SESSION['flash'] = "Image is too large. Max size is 5 MB.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $allowedMimes = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
    $imageInfo    = @getimagesize($file['tmp_name']);
    $detectedMime = $imageInfo['mime'] ?? null;

    if (!$detectedMime || !isset($allowedMimes[$detectedMime])) {
        $_SESSION['flash'] = "Invalid image file. Only JPG, PNG, and WEBP are allowed.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $ext      = $allowedMimes[$detectedMime];
    $filename = 'profile_' . $user_id . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    $destDir  = __DIR__ . '/uploads';
    if (!is_dir($destDir)) {
        mkdir($destDir, 0755, true);
    }
    $htaccessPath = $destDir . '/.htaccess';
    if (!file_exists($htaccessPath)) {
        file_put_contents(
            $htaccessPath,
            "php_flag engine off\n" .
            "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar)$\">\n" .
            "  Require all denied\n" .
            "</FilesMatch>\n"
        );
    }

    if (!move_uploaded_file($file['tmp_name'], $destDir . '/' . $filename)) {
        $_SESSION['flash'] = "Failed to save uploaded image.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("UPDATE users SET profile_image=:img WHERE id=:id");
    $stmt->execute([':img'=>$filename,':id'=>$user_id]);

    $_SESSION['flash'] = "Profile photo updated.";
    $_SESSION['active_section'] = 'profile';
    header("Location: student.php");
    exit;
}

/* ====
   GENERIC SECURE FILE UPLOAD HELPER
   Used by CPD evidence, logbook attachments, job CVs and portfolio files.
==== */
function secureFileUpload(string $fieldName, int $userId, string $prefix, array $allowedMimes, int $maxBytes = 5 * 1024 * 1024): array {
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
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file['tmp_name']);
    if (!$mime || !isset($allowedMimes[$mime])) {
        return ['ok' => false, 'error' => 'Invalid file type.'];
    }
    $ext      = $allowedMimes[$mime];
    $filename = $prefix . '_' . $userId . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    $destDir  = __DIR__ . '/uploads';
    if (!is_dir($destDir)) {
        mkdir($destDir, 0755, true);
    }
    $htaccessPath = $destDir . '/.htaccess';
    if (!file_exists($htaccessPath)) {
        file_put_contents(
            $htaccessPath,
            "php_flag engine off\n" .
            "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar)$\">\n" .
            "  Require all denied\n" .
            "</FilesMatch>\n"
        );
    }
    if (!move_uploaded_file($file['tmp_name'], $destDir . '/' . $filename)) {
        return ['ok' => false, 'error' => 'Failed to save uploaded file.'];
    }
    return ['ok' => true, 'filename' => $filename];
}

const DOC_MIMES   = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png'];

/* ====
   UPDATE EXTENDED PROFILE (license, qualification, KRA PIN)
==== */
if (isset($_POST['update_extended_profile'])) {
    validateCsrf();
    $license = mb_substr(trim(strip_tags($_POST['license_number'] ?? '')), 0, 100);
    $qual    = trim($_POST['qualification_level'] ?? '');
    $kraPin  = strtoupper(mb_substr(trim(strip_tags($_POST['kra_pin'] ?? '')), 0, 20));

    $allowedQual = ['', 'Diploma', 'Degree', 'Masters', 'PhD'];
    if (!in_array($qual, $allowedQual, true)) {
        $qual = '';
    }
    if ($kraPin !== '' && !preg_match('/^[A-Z]\d{9}[A-Z]$/', $kraPin)) {
        $_SESSION['flash'] = "KRA PIN format looks invalid. It should look like A123456789Z.";
        $_SESSION['active_section'] = 'profile';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("UPDATE users SET kra_pin=:pin WHERE id=:id");
    $stmt->execute([':pin' => $kraPin !== '' ? $kraPin : null, ':id' => $user_id]);

    $stmt = $pdo->prepare("
        UPDATE students
        SET license_number=:lic, qualification_level=:qual, verification_status='pending'
        WHERE user_id=:id
    ");
    $stmt->execute([
        ':lic'  => $license !== '' ? $license : null,
        ':qual' => $qual !== '' ? $qual : null,
        ':id'   => $user_id,
    ]);

    $_SESSION['flash'] = "Professional details submitted for admin verification.";
    $_SESSION['active_section'] = 'profile';
    header("Location: student.php");
    exit;
}

/* ====
   GENERATE / FETCH REFERRAL CODE
==== */
if (isset($_POST['generate_referral_code'])) {
    validateCsrf();
    $chk = $pdo->prepare("SELECT id FROM referral_codes WHERE user_id=:uid LIMIT 1");
    $chk->execute([':uid' => $user_id]);
    if ($chk->rowCount() === 0) {
        $codeStmt = $pdo->prepare("SELECT student_no FROM students WHERE user_id=:uid LIMIT 1");
        $codeStmt->execute([':uid' => $user_id]);
        $base = $codeStmt->fetchColumn() ?: ('U' . $user_id);
        $code = strtoupper(preg_replace('/[^A-Z0-9]/i', '', $base)) . strtoupper(bin2hex(random_bytes(2)));
        $ins  = $pdo->prepare("INSERT INTO referral_codes (user_id, code, status) VALUES (:uid, :code, 'active')");
        $ins->execute([':uid' => $user_id, ':code' => $code]);
        $_SESSION['flash'] = "Your referral code has been generated.";
    } else {
        $_SESSION['flash'] = "You already have a referral code.";
    }
    $_SESSION['active_section'] = 'referrals';
    header("Location: student.php");
    exit;
}

/* ====
   LOG A CPD / CME POINT ENTRY
==== */
if (isset($_POST['submit_cpd_point'])) {
    validateCsrf();
    $cpdTitle = mb_substr(trim(strip_tags($_POST['activity_title'] ?? '')), 0, 255);
    $cpdType  = trim($_POST['activity_type'] ?? 'course');
    $cpdPts   = (float) ($_POST['points'] ?? 0);
    $cpdDate  = trim($_POST['date_earned'] ?? '');

    $allowedTypes = ['course','workshop','conference','supervision','publication','other'];
    if (!in_array($cpdType, $allowedTypes, true)) { $cpdType = 'other'; }
    $dateOk = (bool) DateTime::createFromFormat('Y-m-d', $cpdDate);

    if ($cpdTitle === '' || $cpdPts <= 0 || !$dateOk) {
        $_SESSION['flash'] = "Please fill in the activity title, points, and a valid date.";
        $_SESSION['active_section'] = 'cpd';
        header("Location: student.php");
        exit;
    }

    $upload = secureFileUpload('evidence_file', $user_id, 'cpd', DOC_MIMES);
    if (!$upload['ok']) {
        $_SESSION['flash'] = $upload['error'];
        $_SESSION['active_section'] = 'cpd';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO cpd_points (user_id, activity_title, activity_type, points, date_earned, evidence_path, verification_status, created_at)
        VALUES (:uid, :title, :type, :pts, :date, :ev, 'pending', NOW())
    ");
    $stmt->execute([
        ':uid'=>$user_id, ':title'=>$cpdTitle, ':type'=>$cpdType, ':pts'=>$cpdPts,
        ':date'=>$cpdDate, ':ev'=>$upload['filename'],
    ]);

    $_SESSION['flash'] = "CPD point logged and awaiting verification.";
    $_SESSION['active_section'] = 'cpd';
    header("Location: student.php");
    exit;
}

/* ====
   SUBMIT SUPERVISION / INTERNSHIP LOGBOOK ENTRY
==== */
if (isset($_POST['submit_logbook_entry'])) {
    validateCsrf();
    $lbDate  = trim($_POST['session_date'] ?? '');
    $lbHours = (float) ($_POST['hours'] ?? 0);
    $lbDesc  = mb_substr(trim(strip_tags($_POST['activity_description'] ?? '')), 0, 3000);
    $lbComp  = mb_substr(trim(strip_tags($_POST['competencies_covered'] ?? '')), 0, 1000);
    $lbRef   = mb_substr(trim(strip_tags($_POST['client_case_ref'] ?? '')), 0, 100);

    $dateOk = (bool) DateTime::createFromFormat('Y-m-d', $lbDate);
    if (!$dateOk || $lbHours <= 0 || $lbDesc === '') {
        $_SESSION['flash'] = "Please provide a valid date, hours, and activity description.";
        $_SESSION['active_section'] = 'logbook';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO supervision_logbooks
            (student_id, session_date, hours, activity_description, competencies_covered, client_case_ref, supervisor_signoff, created_at)
        VALUES (:sid, :date, :hours, :desc, :comp, :ref, 0, NOW())
    ");
    $stmt->execute([
        ':sid'=>$user_id, ':date'=>$lbDate, ':hours'=>$lbHours,
        ':desc'=>$lbDesc, ':comp'=>$lbComp !== '' ? $lbComp : null, ':ref'=>$lbRef !== '' ? $lbRef : null,
    ]);

    $_SESSION['flash'] = "Logbook entry submitted, pending supervisor sign-off.";
    $_SESSION['active_section'] = 'logbook';
    header("Location: student.php");
    exit;
}

/* ====
   APPLY TO A JOB POSTING
==== */
if (isset($_POST['apply_job'])) {
    validateCsrf();
    $jobId  = (int) ($_POST['job_id'] ?? 0);
    $letter = mb_substr(trim(strip_tags($_POST['cover_letter'] ?? '')), 0, 3000);

    $jobChk = $pdo->prepare("SELECT id FROM job_postings WHERE id=:id AND status='open'");
    $jobChk->execute([':id' => $jobId]);
    if ($jobChk->rowCount() === 0) {
        $_SESSION['flash'] = "That job posting is no longer available.";
        $_SESSION['active_section'] = 'jobs';
        header("Location: student.php");
        exit;
    }

    $dupChk = $pdo->prepare("SELECT id FROM job_applications WHERE job_id=:jid AND user_id=:uid");
    $dupChk->execute([':jid' => $jobId, ':uid' => $user_id]);
    if ($dupChk->rowCount() > 0) {
        $_SESSION['flash'] = "You have already applied to this job.";
        $_SESSION['active_section'] = 'jobs';
        header("Location: student.php");
        exit;
    }

    $upload = secureFileUpload('cv_file', $user_id, 'cv', DOC_MIMES);
    if (!$upload['ok']) {
        $_SESSION['flash'] = $upload['error'];
        $_SESSION['active_section'] = 'jobs';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO job_applications (job_id, user_id, cv_path, cover_letter, status, applied_at)
        VALUES (:jid, :uid, :cv, :letter, 'submitted', NOW())
    ");
    $stmt->execute([':jid'=>$jobId, ':uid'=>$user_id, ':cv'=>$upload['filename'], ':letter'=>$letter !== '' ? $letter : null]);

    $_SESSION['flash'] = "Application submitted successfully.";
    $_SESSION['active_section'] = 'jobs';
    header("Location: student.php");
    exit;
}

/* ====
   FORUM: START NEW TOPIC
==== */
if (isset($_POST['post_forum_topic'])) {
    validateCsrf();
    $fCourseId = (int) ($_POST['course_id'] ?? 0);
    $fTitle    = mb_substr(trim(strip_tags($_POST['title'] ?? '')), 0, 255);
    $fMessage  = mb_substr(trim(strip_tags($_POST['message'] ?? '')), 0, 4000);

    $enrollChk = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:uid AND course_id=:cid");
    $enrollChk->execute([':uid'=>$user_id, ':cid'=>$fCourseId]);

    if ($enrollChk->rowCount() === 0 || $fTitle === '' || $fMessage === '') {
        $_SESSION['flash'] = "Please select one of your courses and fill in a title and message.";
        $_SESSION['active_section'] = 'forums';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO forum_topics (course_id, user_id, title, message, status, created_at)
        VALUES (:cid, :uid, :title, :msg, 'open', NOW())
    ");
    $stmt->execute([':cid'=>$fCourseId, ':uid'=>$user_id, ':title'=>$fTitle, ':msg'=>$fMessage]);

    $_SESSION['flash'] = "Discussion topic posted.";
    $_SESSION['active_section'] = 'forums';
    header("Location: student.php");
    exit;
}

/* ====
   FORUM: REPLY TO A TOPIC
==== */
if (isset($_POST['post_forum_reply'])) {
    validateCsrf();
    $fTopicId = (int) ($_POST['topic_id'] ?? 0);
    $fReply   = mb_substr(trim(strip_tags($_POST['message'] ?? '')), 0, 4000);

    $topicChk = $pdo->prepare("
        SELECT ft.id FROM forum_topics ft
        INNER JOIN enrollments e ON e.course_id = ft.course_id AND e.user_id = :uid
        WHERE ft.id = :tid
    ");
    $topicChk->execute([':uid'=>$user_id, ':tid'=>$fTopicId]);

    if ($topicChk->rowCount() === 0 || $fReply === '') {
        $_SESSION['flash'] = "Unable to post that reply.";
        $_SESSION['active_section'] = 'forums';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO forum_replies (topic_id, user_id, message, created_at) VALUES (:tid, :uid, :msg, NOW())");
    $stmt->execute([':tid'=>$fTopicId, ':uid'=>$user_id, ':msg'=>$fReply]);

    $_SESSION['flash'] = "Reply posted.";
    $_SESSION['active_section'] = 'forums';
    header("Location: student.php");
    exit;
}

/* ====
   ALUMNI PROFILE: JOIN / UPDATE
==== */
if (isset($_POST['update_alumni_profile'])) {
    validateCsrf();
    $gradYear  = (int) ($_POST['graduation_year'] ?? 0);
    $currRole  = mb_substr(trim(strip_tags($_POST['current_role'] ?? '')), 0, 150);
    $org       = mb_substr(trim(strip_tags($_POST['organization'] ?? '')), 0, 150);
    $testimon  = mb_substr(trim(strip_tags($_POST['testimonial'] ?? '')), 0, 2000);
    $isPublic  = isset($_POST['is_public']) ? 1 : 0;
    $isMentor  = isset($_POST['is_mentor_available']) ? 1 : 0;

    $stmt = $pdo->prepare("
        INSERT INTO alumni (user_id, graduation_year, current_role, organization, testimonial, is_public, is_mentor_available, created_at)
        VALUES (:uid, :gy, :role, :org, :test, :pub, :mentor, NOW())
        ON DUPLICATE KEY UPDATE
            graduation_year=:gy2, current_role=:role2, organization=:org2, testimonial=:test2, is_public=:pub2, is_mentor_available=:mentor2
    ");
    $stmt->execute([
        ':uid'=>$user_id, ':gy'=>$gradYear ?: null, ':role'=>$currRole ?: null, ':org'=>$org ?: null,
        ':test'=>$testimon ?: null, ':pub'=>$isPublic, ':mentor'=>$isMentor,
        ':gy2'=>$gradYear ?: null, ':role2'=>$currRole ?: null, ':org2'=>$org ?: null,
        ':test2'=>$testimon ?: null, ':pub2'=>$isPublic, ':mentor2'=>$isMentor,
    ]);

    $_SESSION['flash'] = "Alumni profile saved.";
    $_SESSION['active_section'] = 'alumni';
    header("Location: student.php");
    exit;
}

/* ====
   REQUEST MENTORSHIP
==== */
if (isset($_POST['request_mentorship'])) {
    validateCsrf();
    $mentorId = (int) ($_POST['mentor_id'] ?? 0);
    $focus    = mb_substr(trim(strip_tags($_POST['focus_area'] ?? '')), 0, 255);

    if ($mentorId <= 0 || $mentorId === $user_id) {
        $_SESSION['flash'] = "Please choose a valid mentor.";
        $_SESSION['active_section'] = 'alumni';
        header("Location: student.php");
        exit;
    }

    $dupChk = $pdo->prepare("
        SELECT id FROM mentorship_matches
        WHERE mentor_id=:mid AND mentee_id=:uid AND status IN ('requested','active')
    ");
    $dupChk->execute([':mid'=>$mentorId, ':uid'=>$user_id]);
    if ($dupChk->rowCount() > 0) {
        $_SESSION['flash'] = "You already have a pending or active mentorship with this mentor.";
        $_SESSION['active_section'] = 'alumni';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO mentorship_matches (mentor_id, mentee_id, focus_area, status, matched_at)
        VALUES (:mid, :uid, :focus, 'requested', NOW())
    ");
    $stmt->execute([':mid'=>$mentorId, ':uid'=>$user_id, ':focus'=>$focus !== '' ? $focus : null]);

    $_SESSION['flash'] = "Mentorship request sent.";
    $_SESSION['active_section'] = 'alumni';
    header("Location: student.php");
    exit;
}

/* ====
   PORTFOLIO: ADD ITEM
==== */
if (isset($_POST['add_portfolio_item'])) {
    validateCsrf();
    $pTitle = mb_substr(trim(strip_tags($_POST['title'] ?? '')), 0, 255);
    $pDesc  = mb_substr(trim(strip_tags($_POST['description'] ?? '')), 0, 2000);
    $pCat   = mb_substr(trim(strip_tags($_POST['category'] ?? '')), 0, 150);
    $pPublic = isset($_POST['is_public']) ? 1 : 0;

    if ($pTitle === '') {
        $_SESSION['flash'] = "Please give your portfolio item a title.";
        $_SESSION['active_section'] = 'portfolio';
        header("Location: student.php");
        exit;
    }

    $upload = secureFileUpload('portfolio_file', $user_id, 'portfolio', DOC_MIMES);
    if (!$upload['ok']) {
        $_SESSION['flash'] = $upload['error'];
        $_SESSION['active_section'] = 'portfolio';
        header("Location: student.php");
        exit;
    }

    $stmt = $pdo->prepare("
        INSERT INTO portfolios (user_id, title, description, category, file_path, is_public, created_at)
        VALUES (:uid, :title, :desc, :cat, :file, :pub, NOW())
    ");
    $stmt->execute([
        ':uid'=>$user_id, ':title'=>$pTitle, ':desc'=>$pDesc !== '' ? $pDesc : null,
        ':cat'=>$pCat !== '' ? $pCat : null, ':file'=>$upload['filename'], ':pub'=>$pPublic,
    ]);

    $_SESSION['flash'] = "Portfolio item added.";
    $_SESSION['active_section'] = 'portfolio';
    header("Location: student.php");
    exit;
}

/* ====
   ENROLLED COURSE IDs + LIVE PROGRESS MAP
==== */
$enrolledCourseMap = [];
$stmt = $pdo->prepare("SELECT course_id, status FROM enrollments WHERE user_id=:uid");
$stmt->execute([':uid'=>$user_id]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
    $enrolledCourseMap[(int)$r['course_id']] = $r['status'];
}

/* ====
   COMPUTE LIVE PROGRESS + AUTO-COMPLETE COURSES AT 100%
==== */
$courseProgressMap = [];
foreach (array_keys($enrolledCourseMap) as $cid) {
    $pct = computeCourseProgress($pdo, $user_id, $cid);
    $courseProgressMap[$cid] = $pct;

    if ($pct >= 100 && $enrolledCourseMap[$cid] !== 'completed') {
        $upd = $pdo->prepare("
            UPDATE enrollments
            SET status = 'completed', completed_at = NOW()
            WHERE user_id = :uid AND course_id = :cid
        ");
        $upd->execute([':uid' => $user_id, ':cid' => $cid]);
        $enrolledCourseMap[$cid] = 'completed';

        $titleStmt = $pdo->prepare("SELECT title FROM courses WHERE id=:cid LIMIT 1");
        $titleStmt->execute([':cid' => $cid]);
        $ctitle = $titleStmt->fetchColumn() ?: 'a course';

        $actStmt = $pdo->prepare("
            INSERT INTO activities (user_id, message, created_at)
            VALUES (:uid, :msg, NOW())
        ");
        $actStmt->execute([':uid' => $user_id, ':msg' => " Completed course: {$ctitle}"]);
    }
}

/* ====
   FETCH ALL DATA
==== */
$stmt = $pdo->prepare("
    SELECT COUNT(*) AS enrolled,
           SUM(status='completed') AS completed,
           SUM(status<>'completed') AS ongoing
    FROM enrollments WHERE user_id=:uid
");
$stmt->execute([':uid'=>$user_id]);
$data = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];

$enrolled  = (int) ($data['enrolled']  ?? 0);
$completed = (int) ($data['completed'] ?? 0);
$ongoing   = (int) ($data['ongoing']   ?? 0);

$progress = $enrolled > 0
    ? (int) round(array_sum($courseProgressMap) / count($courseProgressMap))
    : 0;

$total_courses     = $enrolled;
$active_courses    = $ongoing;
$completed_courses = $completed;

/* Certificates count */
$stmt = $pdo->prepare("SELECT COUNT(*) FROM certificates WHERE user_id=:uid");
$stmt->execute([':uid'=>$user_id]);
$certificates_earned = (int) $stmt->fetchColumn();
$stmt = $pdo->prepare("
    SELECT c.id, c.title, c.lessons, e.status
    FROM courses c
    INNER JOIN enrollments e ON c.id = e.course_id
    WHERE e.user_id = :uid
");
$stmt->execute([':uid'=>$user_id]);
$courses_widget_rows = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $row['progress'] = $courseProgressMap[(int)$row['id']] ?? 0;
    $courses_widget_rows[] = $row;
}
usort($courses_widget_rows, fn($a, $b) => $b['progress'] <=> $a['progress']);
$courses_widget_rows = array_slice($courses_widget_rows, 0, 5);

/* Activities */
$stmt = $pdo->prepare("SELECT message, created_at FROM activities WHERE user_id=:uid ORDER BY created_at DESC LIMIT 5");
$stmt->execute([':uid'=>$user_id]);
$activities_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Bookmarks */
$stmt = $pdo->prepare("SELECT title, created_at FROM bookmarks WHERE user_id=:uid ORDER BY created_at DESC LIMIT 10");
$stmt->execute([':uid'=>$user_id]);
$bookmarks_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Certificates */
$stmt = $pdo->prepare("SELECT * FROM certificates WHERE user_id=:uid ORDER BY issued_at DESC");
$stmt->execute([':uid'=>$user_id]);
$certs_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Notifications */
$stmt = $pdo->prepare("
    SELECT message, created_at AS notification_date, 'notification' AS type
    FROM notifications WHERE user_id=:uid1
    UNION ALL
    SELECT CONCAT('[Announcement] ', a.title, ' - ', a.message), a.created_at, 'announcement'
    FROM announcements a
    INNER JOIN enrollments e ON e.course_id=a.course_id
    WHERE e.user_id=:uid2
    ORDER BY notification_date DESC LIMIT 10
");
$stmt->execute([':uid1'=>$user_id,':uid2'=>$user_id]);
$notifications_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* User profile */
$stmt = $pdo->prepare("
    SELECT u.*, s.student_no
    FROM users u
    LEFT JOIN students s ON s.user_id = u.id
    WHERE u.id = :id LIMIT 1
");
$stmt->execute([':id'=>$user_id]);
$profile = $stmt->fetch(PDO::FETCH_ASSOC)
    ?: ['full_name'=>'Unknown','email'=>'','phone'=>'','location'=>'','bio'=>'','profile_image'=>'','created_at'=>date('Y-m-d'),'student_no'=>''];

/* Active courses */
$stmt = $pdo->prepare("
    SELECT c.id, c.title, c.teacher_id, c.lessons
    FROM enrollments e INNER JOIN courses c ON e.course_id=c.id
    WHERE e.user_id=:uid AND e.status<>'completed' ORDER BY e.id DESC
");
$stmt->execute([':uid'=>$user_id]);
$active_courses_list = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $row['progress'] = $courseProgressMap[(int)$row['id']] ?? 0;
    $active_courses_list[] = $row;
}

$stmt = $pdo->prepare("
    SELECT c.title, e.completed_at
    FROM courses c
    INNER JOIN enrollments e ON e.course_id = c.id
    WHERE e.user_id = :uid AND e.status = 'completed'
    ORDER BY e.completed_at DESC
");
$stmt->execute([':uid' => $user_id]);
$completed_courses_list = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Assignments */
$stmt = $pdo->prepare("
    SELECT a.* FROM assignments a
    INNER JOIN enrollments e ON e.course_id=a.course_id
    WHERE e.user_id=:uid ORDER BY a.due_date ASC LIMIT 10
");
$stmt->execute([':uid'=>$user_id]);
$assignments_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Materials */
$materials_rows   = $pdo->query("SELECT * FROM course_materials ORDER BY id DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
$live_classes_rows = $pdo->query("SELECT * FROM live_classes ORDER BY schedule_time ASC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);

/* Browse courses */
$search = trim(strip_tags($_GET['search'] ?? ''));
$search = mb_substr($search, 0, 100); // security: cap search length
if ($search !== '') {
    $like = "%{$search}%";
    $stmt = $pdo->prepare("
        SELECT id, title, description, price, lessons, enrolled_students, teacher_id
        FROM courses WHERE status='Active' AND title LIKE :like ORDER BY created_at DESC
    ");
    $stmt->execute([':like'=>$like]);
} else {
    $stmt = $pdo->query("
        SELECT id, title, description, price, lessons, enrolled_students, teacher_id
        FROM courses WHERE status='Active' ORDER BY created_at DESC
    ");
}
$browseCoursesData = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $course) {
    $course['instructor'] = 'Unknown';
    if (!empty($course['teacher_id'])) {
        $s2 = $pdo->prepare("
            SELECT u.full_name FROM teachers t INNER JOIN users u ON u.id=t.user_id WHERE t.id=:tid LIMIT 1
        ");
        $s2->execute([':tid'=>(int)$course['teacher_id']]);
        $t = $s2->fetch(PDO::FETCH_ASSOC);
        if ($t) { $course['instructor'] = $t['full_name']; }
    }
    $browseCoursesData[] = $course;
}

/* Trending / instructors / categories */
$trendingCourses_rows = $pdo->query("
    SELECT title, enrolled_students FROM courses WHERE status='Active'
    ORDER BY enrolled_students DESC LIMIT 5
")->fetchAll(PDO::FETCH_ASSOC);

$topInstructors_rows = $pdo->query("
    SELECT u.full_name, t.specialization, t.experience_years, COUNT(c.id) AS courses_count
    FROM teachers t INNER JOIN users u ON u.id=t.user_id
    LEFT JOIN courses c ON c.teacher_id=t.id
    GROUP BY t.id, u.full_name, t.specialization, t.experience_years
    ORDER BY courses_count DESC LIMIT 5
")->fetchAll(PDO::FETCH_ASSOC);

$categories = [];
$cat_result = $pdo->query("SELECT DISTINCT category FROM courses WHERE status='Active' AND category IS NOT NULL AND category != ''");
foreach ($cat_result->fetchAll(PDO::FETCH_ASSOC) as $row) { $categories[] = $row['category']; }
if (empty($categories)) {
    $categories = ["Web Development","Programming","UI/UX Design","Cyber Security","Data Science","Mobile Development"];
}

$courseBenefits = [
    ["title"=>"Learn Anytime",      "description"=>"Access courses 24/7 from any device."],
    ["title"=>"Expert Instructors", "description"=>"Learn from industry professionals."],
    ["title"=>"Certified Learning", "description"=>"Get certificates after completion."],
];

/* Progress section */
$progressTotalCourses     = $enrolled;
$progressCompletedCourses = $completed;
$progressOngoingCourses   = $ongoing;
$overallProgress = ($progressTotalCourses > 0)
    ? (int) round(($progressCompletedCourses / $progressTotalCourses) * 100) : 0;

$stmt = $pdo->prepare("
    SELECT c.id, c.title, e.status FROM enrollments e
    INNER JOIN courses c ON e.course_id=c.id
    WHERE e.user_id=:uid
");
$stmt->execute([':uid'=>$user_id]);
$courseProgressRows = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $row['progress'] = $courseProgressMap[(int)$row['id']] ?? 0;
    $courseProgressRows[] = $row;
}
usort($courseProgressRows, fn($a, $b) => $b['progress'] <=> $a['progress']);

$stmt = $pdo->prepare("SELECT * FROM quiz_results WHERE user_id=:uid ORDER BY completed_at DESC LIMIT 10");
$stmt->execute([':uid'=>$user_id]);
$quizPerformance_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM certificates WHERE user_id=:uid ORDER BY issued_at DESC");
$stmt->execute([':uid'=>$user_id]);
$progressCertificates_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM learning_stats WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$analytics = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['study_hours'=>0,'lessons_completed'=>0,'assignments_submitted'=>0];

$progressAchievements = [];
if ($progressCompletedCourses > 0)
    $progressAchievements[] = ["title"=>" Completed Courses","description"=>"$progressCompletedCourses course(s) completed"];
if ($overallProgress >= 50)
    $progressAchievements[] = ["title"=>" Learning Progress","description"=>"You reached {$overallProgress}% overall"];

$stmt = $pdo->prepare("SELECT * FROM quiz_results WHERE user_id=:uid ORDER BY score DESC LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$topQuiz = $stmt->fetch(PDO::FETCH_ASSOC);
if ($topQuiz)
    $progressAchievements[] = ["title"=>"⭐ Top Quiz Performer","description"=>($topQuiz['quiz_title']??'Quiz')." - Score: ".$topQuiz['score']."%"];

/* Payments */
$stmt = $pdo->prepare("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE user_id=:uid AND status='completed'");
$stmt->execute([':uid'=>$user_id]);
$totalPaid = $stmt->fetchColumn() ?? 0;

$stmt = $pdo->prepare("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE user_id=:uid AND status='pending'");
$stmt->execute([':uid'=>$user_id]);
$pendingPayments = $stmt->fetchColumn() ?? 0;

$stmt = $pdo->prepare("SELECT * FROM payments WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid'=>$user_id]);
$transactions_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM invoices WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid'=>$user_id]);
$invoices_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM payment_methods WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid'=>$user_id]);
$paymentMethods_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$invoices_count     = count($invoices_rows);
$transactions_count = count($transactions_rows);

/* Payable courses */
$stmt = $pdo->prepare("
    SELECT id, title, price FROM courses
    WHERE course_type='Paid'
      AND status='Active'
      AND id NOT IN (
          SELECT course_id FROM enrollments WHERE user_id=:uid
      )
    ORDER BY title ASC
");
$stmt->execute([':uid'=>$user_id]);
$payableCoursesData  = $stmt->fetchAll(PDO::FETCH_ASSOC);
$hasPayableCourses   = !empty($payableCoursesData);

/* Settings */
$stmt = $pdo->prepare("SELECT * FROM user_settings WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$settingsRow = $stmt->fetch(PDO::FETCH_ASSOC)
    ?: ['theme'=>'light','email_notifications'=>1,'sms_notifications'=>1,'password_updated_at'=>null];

/* Tickets */
$stmt = $pdo->prepare("SELECT * FROM tickets WHERE user_id=:uid ORDER BY id DESC");
$stmt->execute([':uid'=>$user_id]);
$tickets_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Attendance history */
$stmt = $pdo->prepare("
    SELECT a.*, c.title FROM attendance a
    JOIN courses c ON a.course_id=c.id
    WHERE a.user_id=:uid ORDER BY a.attendance_date DESC
");
$stmt->execute([':uid'=>$user_id]);
$att_history_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$att_courses_stmt = $pdo->prepare("
    SELECT c.id, c.title FROM courses c
    INNER JOIN enrollments e ON e.course_id = c.id
    WHERE e.user_id = :uid
    ORDER BY c.title ASC
");
$att_courses_stmt->execute([':uid'=>$user_id]);
$att_courses_rows = $att_courses_stmt->fetchAll(PDO::FETCH_ASSOC);

/* Extended profile fields (license, qualification, verification, KRA PIN) */
$stmt = $pdo->prepare("SELECT license_number, qualification_level, verification_status FROM students WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$extendedProfile = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['license_number'=>null,'qualification_level'=>null,'verification_status'=>'unverified'];

/* Professional Practice Support Hub */
$resourceCategories = $pdo->query("SELECT * FROM resource_hub_categories ORDER BY sort_order ASC, name ASC")->fetchAll(PDO::FETCH_ASSOC);
$resourceItemsRows  = $pdo->query("
    SELECT * FROM resource_hub_items
    WHERE access_level IN ('all','students')
    ORDER BY created_at DESC
")->fetchAll(PDO::FETCH_ASSOC);
$resourceItemsByCategory = [];
foreach ($resourceItemsRows as $ri) {
    $resourceItemsByCategory[(int)$ri['category_id']][] = $ri;
}

/* Referral system */
$stmt = $pdo->prepare("SELECT * FROM referral_codes WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$myReferralCode = $stmt->fetch(PDO::FETCH_ASSOC);

$myReferrals_rows = [];
$myRewardsTotal   = 0;
if ($myReferralCode) {
    $stmt = $pdo->prepare("SELECT * FROM referrals WHERE referral_code_id=:rcid ORDER BY created_at DESC");
    $stmt->execute([':rcid'=>$myReferralCode['id']]);
    $myReferrals_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("
        SELECT COALESCE(SUM(rr.amount),0) AS total
        FROM referral_rewards rr
        INNER JOIN referrals r ON r.id = rr.referral_id
        WHERE r.referral_code_id = :rcid AND rr.status IN ('approved','paid')
    ");
    $stmt->execute([':rcid'=>$myReferralCode['id']]);
    $myRewardsTotal = (float) ($stmt->fetchColumn() ?? 0);
}

/* Referral link (shareable registration URL carrying the code) */
$myReferralLink = '';
if ($myReferralCode) {
    $scheme = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ? 'https://' : 'http://';
    $host   = preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST'] ?? '');
    $base   = rtrim(str_replace('student.php', '', $_SERVER['PHP_SELF'] ?? ''), '/');
    $myReferralLink = $scheme . $host . $base . '/register.php?ref=' . urlencode($myReferralCode['code']);
}

/* CPD / CME points */
$stmt = $pdo->prepare("SELECT * FROM cpd_points WHERE user_id=:uid ORDER BY date_earned DESC");
$stmt->execute([':uid'=>$user_id]);
$cpdPoints_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$cpdVerifiedTotal = array_sum(array_map(fn($r) => $r['verification_status'] === 'verified' ? (float)$r['points'] : 0, $cpdPoints_rows));
$cpdPendingTotal  = array_sum(array_map(fn($r) => $r['verification_status'] === 'pending'  ? (float)$r['points'] : 0, $cpdPoints_rows));

/* Supervision / internship logbook */
$stmt = $pdo->prepare("SELECT * FROM supervision_logbooks WHERE student_id=:uid ORDER BY session_date DESC");
$stmt->execute([':uid'=>$user_id]);
$logbook_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$logbookSignedHours = array_sum(array_map(fn($r) => (int)$r['supervisor_signoff'] === 1 ? (float)$r['hours'] : 0, $logbook_rows));
$logbookPendingHours = array_sum(array_map(fn($r) => (int)$r['supervisor_signoff'] === 0 ? (float)$r['hours'] : 0, $logbook_rows));

/* Job board */
$jobPostings_rows = $pdo->query("SELECT * FROM job_postings WHERE status='open' ORDER BY created_at DESC LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);
$stmt = $pdo->prepare("
    SELECT ja.*, jp.title AS job_title, jp.organization
    FROM job_applications ja
    INNER JOIN job_postings jp ON jp.id = ja.job_id
    WHERE ja.user_id = :uid
    ORDER BY ja.applied_at DESC
");
$stmt->execute([':uid'=>$user_id]);
$myJobApplications_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$appliedJobIds = array_column($myJobApplications_rows, 'job_id');

/* Discussion forums (topics across my enrolled courses) */
$myCourseIds = array_keys($enrolledCourseMap);
$forumTopics_rows = [];
if (!empty($myCourseIds)) {
    $in = implode(',', array_map('intval', $myCourseIds));
    $stmt = $pdo->query("
        SELECT ft.*, c.title AS course_title, u.full_name AS author_name,
               (SELECT COUNT(*) FROM forum_replies fr WHERE fr.topic_id = ft.id) AS reply_count
        FROM forum_topics ft
        INNER JOIN courses c ON c.id = ft.course_id
        LEFT JOIN users u ON u.id = ft.user_id
        WHERE ft.course_id IN ($in)
        ORDER BY ft.created_at DESC
        LIMIT 25
    ");
    $forumTopics_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
$forumRepliesByTopic = [];
if (!empty($forumTopics_rows)) {
    $topicIds = implode(',', array_map(fn($t) => (int)$t['id'], $forumTopics_rows));
    $stmt = $pdo->query("
        SELECT fr.*, u.full_name AS author_name
        FROM forum_replies fr
        LEFT JOIN users u ON u.id = fr.user_id
        WHERE fr.topic_id IN ($topicIds)
        ORDER BY fr.created_at ASC
    ");
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $forumRepliesByTopic[(int)$r['topic_id']][] = $r;
    }
}

/* Alumni network & mentorship */
$stmt = $pdo->prepare("SELECT * FROM alumni WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid'=>$user_id]);
$myAlumniProfile = $stmt->fetch(PDO::FETCH_ASSOC);

$availableMentors_rows = $pdo->query("
    SELECT al.*, u.full_name, u.id AS mentor_user_id
    FROM alumni al
    INNER JOIN users u ON u.id = al.user_id
    WHERE al.is_mentor_available = 1 AND al.user_id != " . (int)$user_id . "
    ORDER BY al.created_at DESC LIMIT 20
")->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("
    SELECT mm.*, u.full_name AS mentor_name
    FROM mentorship_matches mm
    INNER JOIN users u ON u.id = mm.mentor_id
    WHERE mm.mentee_id = :uid
    ORDER BY mm.matched_at DESC
");
$stmt->execute([':uid'=>$user_id]);
$myMentorships_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Digital portfolio */
$stmt = $pdo->prepare("SELECT * FROM portfolios WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid'=>$user_id]);
$portfolio_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Promotional / advertising slots (CBT-Kenya programmes, events, partner announcements) */
$promoSlots_rows = [];
try {
    $promoSlots_rows = $pdo->query("
        SELECT * FROM promo_slots
        WHERE status='active' AND (starts_at IS NULL OR starts_at <= NOW()) AND (ends_at IS NULL OR ends_at >= NOW())
        ORDER BY sort_order ASC, created_at DESC LIMIT 5
    ")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    $promoSlots_rows = [];
}

/* Flash */
$flash = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);
$active_section_map = [
    'profile'  => 'profileSection',
    'payments'   => 'paymentsSection',
    'attendance' => 'attendanceSection',
    'browse' => 'browseCoursesSection',
    'resourcehub' => 'resourceHubSection',
    'referrals'   => 'referralsSection',
    'cpd'         => 'cpdSection',
    'logbook'     => 'logbookSection',
    'jobs'        => 'jobsSection',
    'forums'      => 'forumsSection',
    'alumni'      => 'alumniSection',
    'portfolio'   => 'portfolioSection',
];
$active_section_key = $_SESSION['active_section'] ?? '';
unset($_SESSION['active_section']);
if ($active_section_key === '' && isset($_GET['search'])) {
    $active_section_key = 'browse';
}

$active_section_id = $active_section_map[$active_section_key] ?? '';
$active_section_js = json_encode($active_section_id, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP);
$csrf_js = json_encode($_SESSION['csrf_token'], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP);
$referral_link_js = json_encode($myReferralLink, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Student Dashboard - CBT-Kenya Skills Transfer Program</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
/* =====
   CSS VARIABLES - CBT-Kenya brand palette
   (deep teal = clinical calm / trust, warm gold = growth & achievement)
===== */
:root {
    --teal:        #0e6b64;
    --teal-dark:   #0a4f4a;
    --teal-light:  #12a89d;
    --navy:        #0f2a2e;
    --slate:       #16383c;
    --gold:        #d9a441;
    --gold-dark:   #b9862c;
    --green:       #10b981;
    --red:         #ef4444;
    --gray-100:    #f4f7f6;
    --gray-200:    #e3ebe9;
    --gray-500:    #64807d;
    --gray-900:    #12211f;
    --white:       #ffffff;
    --radius:      14px;
    --shadow:      0 4px 20px rgba(14,107,100,0.09);
    --sidebar-w:   260px;
    --transition:  0.25s ease;

    /* Back-compat aliases so any legacy references still resolve to brand colours */
    --blue:        var(--teal);
    --blue-dark:   var(--teal-dark);
}

/* =====
   RESET
===== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { width: 100%; min-height: 100vh; background: var(--gray-100); font-family: 'Inter', 'Segoe UI', Arial, sans-serif; color: var(--gray-900); }
a { text-decoration: none; color: inherit; }
img { max-width: 100%; }
h1, h2, h3, h4, .card-title, .page-header h1, .sidebar-logo h2 { font-family: 'Poppins', 'Segoe UI', Arial, sans-serif; }

/* =====
   LAYOUT SHELL
===== */
.layout { display: flex; min-height: 100vh; }

/* =====
   SIDEBAR
===== */
.sidebar {
    width: var(--sidebar-w);
    background: linear-gradient(180deg, var(--navy) 0%, var(--teal-dark) 100%);
    position: fixed;
    top: 0; left: 0;
    height: 100vh;
    overflow-y: auto;
    z-index: 900;
    display: flex;
    flex-direction: column;
    transition: transform var(--transition);
}
.sidebar-logo {
    padding: 26px 20px;
    text-align: center;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}
.sidebar-logo h2 { color: var(--white); font-size: 1.45rem; font-weight: 700; letter-spacing: 0.2px; }
.sidebar-logo h2 span { color: var(--gold); }
.sidebar-logo p  { color: #9db8b4; font-size: 0.76rem; margin-top: 4px; letter-spacing: 0.4px; text-transform: uppercase; }

.nav-menu { list-style: none; padding: 12px 0; flex: 1; }
.nav-menu li a {
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 13px 22px;
    color: #a9c3bf;
    font-size: 0.93rem;
    font-weight: 500;
    transition: all var(--transition);
    border-left: 3px solid transparent;
}
.nav-menu li a i { width: 20px; text-align: center; font-size: 0.95rem; }
.nav-menu li a:hover,
.nav-menu li.active a {
    background: rgba(255,255,255,0.08);
    color: var(--white);
    border-left-color: var(--gold);
}
.nav-menu li.logout a { color: #f87171; }
.nav-menu li.logout a:hover { background: rgba(239,68,68,0.12); border-left-color: var(--red); }

.sidebar-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.5);
    z-index: 899;
}

/* =====
   TOPBAR 
===== */
.topbar {
    display: none;
    position: sticky;
    top: 0;
    z-index: 800;
    background: var(--white);
    padding: 14px 18px;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 2px 8px rgba(14,107,100,0.10);
    border-bottom: 3px solid var(--gold);
}
.topbar h2 { font-size: 1.05rem; color: var(--navy); font-weight: 700; }
.hamburger {
    background: none; border: none;
    font-size: 1.4rem; color: var(--teal);
    cursor: pointer; padding: 4px;
}

/* =====
   MAIN CONTENT
===== */
.main {
    margin-left: var(--sidebar-w);
    flex: 1;
    padding: 28px 24px;
    min-height: 100vh;
}

/* =====
   CARDS / BOXES
===== */
.card {
    background: var(--white);
    border-radius: var(--radius);
    padding: 26px;
    box-shadow: var(--shadow);
    margin-bottom: 22px;
    border-top: 3px solid transparent;
}
.card-title {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.15rem;
    font-weight: 700;
    color: var(--navy);
    margin-bottom: 20px;
}
.card-title i { color: var(--teal); }

.page-header {
    background: linear-gradient(135deg, var(--navy) 0%, var(--teal) 60%, var(--teal-light) 100%);
    border-radius: var(--radius);
    padding: 30px 28px;
    margin-bottom: 24px;
    color: var(--white);
    position: relative;
    overflow: hidden;
}
.page-header::after {
    content: "";
    position: absolute;
    right: -40px; top: -40px;
    width: 180px; height: 180px;
    background: rgba(217,164,65,0.18);
    border-radius: 50%;
}
.page-header h1 { font-size: 1.6rem; margin-bottom: 6px; position: relative; }
.page-header p  { opacity: 0.85; font-size: 0.95rem; position: relative; }

/* =====
   PROMO / ADVERTISING BANNER
   Designated space for CBT-Kenya programmes, courses, events & partner announcements
===== */
.promo-strip {
    display: flex;
    gap: 16px;
    overflow-x: auto;
    padding-bottom: 4px;
    margin-bottom: 22px;
    scrollbar-width: thin;
}
.promo-card {
    flex: 0 0 auto;
    width: 300px;
    background: linear-gradient(135deg, var(--teal) 0%, var(--teal-dark) 100%);
    border-radius: var(--radius);
    padding: 18px 20px;
    color: var(--white);
    box-shadow: var(--shadow);
    position: relative;
    border-left: 4px solid var(--gold);
}
.promo-card .promo-tag {
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    background: rgba(217,164,65,0.25);
    color: var(--gold);
    padding: 3px 9px;
    border-radius: 99px;
    margin-bottom: 10px;
}
.promo-card h4 { font-size: 1rem; margin-bottom: 6px; }
.promo-card p  { font-size: 0.82rem; opacity: 0.9; margin-bottom: 10px; }
.promo-card a.promo-link { font-size: 0.8rem; font-weight: 700; color: var(--gold); }
.promo-card a.promo-link i { margin-left: 4px; }

/* =====
   STAT CARDS GRID
===== */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 16px;
    margin-bottom: 22px;
}
.stat-box {
    background: var(--white);
    border-radius: var(--radius);
    padding: 22px 18px;
    box-shadow: var(--shadow);
    border: 1px solid var(--teal);
    transition: transform var(--transition), box-shadow var(--transition);
}
.stat-box:hover { transform: translateY(-4px); box-shadow: 0 10px 28px rgba(14,107,100,0.14); }
.stat-box i { font-size: 1.6rem; color: var(--teal); margin-bottom: 12px; display: block; }
.stat-box h2 { font-size: 2rem; color: var(--navy); margin-bottom: 4px; font-family: 'Poppins', sans-serif; }
.stat-box p  { color: var(--gray-500); font-size: 0.88rem; }

.stat-box.green { border-top-color: var(--green); }
.stat-box.green i { color: var(--green); }
.stat-box.red   { border-top-color: var(--red); }
.stat-box.red i { color: var(--red); }
.stat-box.gold  { border-top-color: var(--gold); }
.stat-box.gold i { color: var(--gold-dark); }

/* =====
   TWO-COL GRID 
===== */
.two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 22px;
}

/* =====
   ACTIVITY ITEMS
===== */
.activity-item {
    padding: 14px 16px;
    border-radius: 10px;
    border: 1px solid var(--teal);
    background: var(--gray-100);
    margin-bottom: 12px;
    transition: transform var(--transition);
}
.activity-item:hover { transform: translateX(4px); }
.activity-item p    { font-weight: 600; font-size: 0.95rem; color: var(--navy); margin-bottom: 4px; }
.activity-item span { color: var(--gray-500); font-size: 0.83rem; }

.course-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 16px 0;
    border-bottom: 1px solid var(--gray-200);
}
.course-row:last-child { border-bottom: none; }
.course-info h4 { font-size: 0.97rem; margin-bottom: 4px; }
.course-info p  { color: var(--gray-500); font-size: 0.83rem; }
.progress-bar-wrap {
    width: 160px; height: 8px;
    background: var(--gray-200);
    border-radius: 99px; overflow: hidden;
    margin-top: 7px;
}
.progress-fill { height: 100%; background: linear-gradient(90deg, var(--teal) 0%, var(--gold) 100%); border-radius: 99px; }

/* =====
   BUTTONS
===== */
.btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 18px;
    background: var(--teal);
    color: var(--white);
    border: none;
    border-radius: 10px;
    cursor: pointer;
    font-size: 0.88rem;
    font-weight: 600;
    transition: background var(--transition), transform var(--transition);
}
.btn:hover { background: var(--teal-dark); transform: translateY(-1px); }
.btn.green { background: var(--green); }
.btn.green:hover { background: #059669; }
.btn.gold  { background: var(--gold); color: var(--navy); }
.btn.gold:hover { background: var(--gold-dark); color: var(--white); }
.btn.dark  { background: var(--navy); }
.btn.dark:hover  { background: var(--slate); }
.btn.muted { background: var(--gray-200); color: var(--gray-500); cursor: default; }
.btn.muted:hover { background: var(--gray-200); transform: none; }
.btn.outline { background: var(--white); color: var(--teal); border: 2px solid var(--teal); }
.btn.outline:hover { background: var(--teal); color: var(--white); }
.btn.small { padding: 7px 13px; font-size: 0.82rem; }
.btn-row   { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }

/* =====
   FORM INPUTS
===== */
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-weight: 600; font-size: 0.88rem; margin-bottom: 6px; color: var(--navy); }
.form-group input,
.form-group select,
.form-group textarea {
    width: 100%;
    padding: 11px 13px;
    border: 1px solid var(--gray-200);
    border-radius: 9px;
    font-size: 0.93rem;
    color: var(--gray-900);
    background: var(--white);
    transition: border-color var(--transition), box-shadow var(--transition);
    outline: none;
}
.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
    border-color: var(--teal);
    box-shadow: 0 0 0 3px rgba(14,107,100,0.14);
}
.form-group textarea { resize: vertical; min-height: 90px; }
.form-hint { font-size: 0.78rem; color: var(--gray-500); margin-top: 4px; }

/* =====
   TABLE
===== */
.data-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
.data-table th {
    background: var(--navy); color: var(--white);
    padding: 11px 13px; text-align: left; font-size: 0.85rem;
    position: sticky; top: 0; z-index: 1;
}
.data-table th:first-child { border-radius: 8px 0 0 0; }
.data-table th:last-child  { border-radius: 0 8px 0 0; }
.data-table td { padding: 11px 13px; font-size: 0.88rem; border-bottom: 1px solid var(--gray-200); }
.data-table tr:hover td { background: var(--gray-100); }

/* Scrollable wrapper for tables that can grow past 10 rows */
.table-scroll {
    max-height: 420px;
    overflow-y: auto;
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid var(--gray-200);
    margin-top: 12px;
}
.table-scroll .data-table { margin-top: 0; }
.table-scroll::-webkit-scrollbar { width: 8px; height: 8px; }
.table-scroll::-webkit-scrollbar-track { background: var(--gray-100); }
.table-scroll::-webkit-scrollbar-thumb { background: var(--gray-200); border-radius: 8px; }
.table-scroll::-webkit-scrollbar-thumb:hover { background: var(--gray-500); }

/* =====
   TAGS / BADGES
===== */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 99px;
    font-size: 0.78rem;
    font-weight: 700;
}
.badge-open     { background:#fef3c7; color:#92400e; }
.badge-progress { background:#dbeafe; color:#1e40af; }
.badge-resolved { background:#d1fae5; color:#065f46; }
.badge-closed   { background:#f1f5f9; color:#475569; }
.badge-pending  { background:#fef3c7; color:#92400e; }
.badge-success  { background:#d1fae5; color:#065f46; }
.badge-failed   { background:#fee2e2; color:#991b1b; }

.chip-wrap { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 12px; }
.chip {
    padding: 7px 14px;
    background: var(--gray-100);
    border: 1px solid var(--gray-200);
    border-radius: 99px;
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--navy);
    cursor: pointer;
    transition: background var(--transition);
}
.chip:hover { background: var(--teal); color: var(--white); border-color: var(--teal); }

/* =====
   FLASH MESSAGE
===== */
.flash {
    background: #d1fae5; color: #065f46;
    border: 1px solid #6ee7b7;
    border-radius: 10px;
    padding: 13px 18px;
    margin-bottom: 20px;
    font-weight: 600;
}
.flash.error { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }

/* =====
   MODAL
===== */
.modal-overlay {
    display: none;
    position: fixed; inset: 0;
    background: rgba(15,42,46,0.68);
    z-index: 9000;
    align-items: center;
    justify-content: center;
    padding: 16px;
    overflow-y: auto;
}
.modal-overlay.active { display: flex; }
.modal-box {
    margin-top:auto;
    background: var(--white);
    border-radius: var(--radius);
    padding: 20px;
    width: 100%;
    max-width: 520px;
    position: relative;
    animation: popIn 0.2s ease;
    }
@keyframes popIn { from { transform: scale(0.93); opacity: 0; } to { transform: scale(1); opacity: 1; } }
.modal-close {
    position: absolute; top: 14px; right: 16px;
    width: 30px; height: 30px;
    background: var(--gray-200); border: none;
    border-radius: 50%; cursor: pointer;
    font-size: 1rem; display: flex; align-items: center; justify-content: center;
    transition: background var(--transition);
}
.modal-close:hover { background: var(--red); color: var(--white); }
.modal-title { font-size: 1.1rem; font-weight: 700; color: var(--navy); margin-bottom: 20px; }

.enroll-label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 13px;
    border-radius: 10px;
    font-size: 0.82rem;
    font-weight: 700;
    white-space: nowrap;
}
.enroll-label.enrolled  { background: #d1fae5; color: #065f46; }
.enroll-label.completed { background: #dbeafe; color: #1e40af; cursor: pointer; }
.enroll-label.completed:hover { background: #bfdbfe; }

/* =====
   BANK DETAILS BOX
===== */
.bank-details {
    background: var(--gray-100);
    border: 1px dashed var(--teal);
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 18px;
}
.bank-details .bd-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    font-size: 0.9rem;
    border-bottom: 1px solid var(--gray-200);
}
.bank-details .bd-row:last-child { border-bottom: none; }
.bank-details .bd-label { color: var(--gray-500); font-weight: 600; }
.bank-details .bd-value { color: var(--navy); font-weight: 700; }

/* =====
   REFERRAL LINK BOX
===== */
.referral-link-box {
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--gray-100);
    border: 1px dashed var(--teal);
    border-radius: 10px;
    padding: 12px 14px;
    margin-top: 16px;
    flex-wrap: wrap;
}
.referral-link-box input {
    flex: 1;
    min-width: 200px;
    border: none;
    background: transparent;
    font-size: 0.85rem;
    color: var(--navy);
    font-weight: 600;
    outline: none;
}

/* =====
   PROFILE IMAGE
===== */
.profile-img {
    width: 90px; height: 90px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid var(--teal);
    box-shadow: 0 0 0 3px rgba(217,164,65,0.35);
    margin-bottom: 14px;
}

/* =====
   SECTION 
===== */
.section { display: none; }

/* =====
   RESPONSIVE 
===== */
@media (max-width: 900px) {
    .two-col { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 640px) {
    .topbar   { display: flex; }
    .sidebar  { transform: translateX(-100%); }
    .sidebar.open { transform: translateX(0); }
    .sidebar-overlay.active { display: block; }

    .main { margin-left: 0; padding: 16px 14px; }

    .stats-grid { grid-template-columns: 1fr 1fr; gap: 12px; }
    .stat-box h2 { font-size: 1.6rem; }
    .card { padding: 18px; }
    .page-header h1 { font-size: 1.25rem; }
    .course-row { flex-direction: column; align-items: flex-start; }
    .progress-bar-wrap { width: 100%; }
    .data-table { font-size: 0.8rem; }
    .data-table th, .data-table td { padding: 8px; }
    .table-scroll { max-height: 340px; }
    .promo-card { width: 240px; }
}
</style>
</head>
<body>

<!-- MOBILE TOPBAR -->
<div class="topbar">
    <button class="hamburger" onclick="toggleSidebar()" aria-label="Menu">
        <i class="fas fa-bars"></i>
    </button>
    <h2>CBT-Kenya STP</h2>
    <span style="width:36px;"></span>
</div>

<!-- SIDEBAR OVERLAY -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<div class="layout">
<!-- SIDEBAR -->
<nav class="sidebar" id="sidebar" role="navigation" aria-label="Main menu">
    <div class="sidebar-logo">
        <h2><img src="cbt-ke.png"></h2>
        <p>Skills Transfer Program</p>
    </div>
    <ul class="nav-menu" id="navMenu">
        <li class="active"><a href="#" onclick="showSection('dashboardContent',this)"><i class="fas fa-home"></i>Dashboard</a></li>
        <li><a href="#" onclick="showSection('coursesSection',this)"><i class="fas fa-book-open"></i>My Courses</a></li>
        <li><a href="#" onclick="showSection('browseCoursesSection',this)"><i class="fas fa-search"></i>Browse Courses</a></li>
        <li><a href="#" onclick="showSection('progressSection',this)"><i class="fas fa-chart-line"></i>Progress</a></li>
        <li><a href="#" onclick="showSection('paymentsSection',this)"><i class="fas fa-credit-card"></i>Payments</a></li>
        <li><a href="#" onclick="showSection('attendanceSection',this)"><i class="fas fa-user-check"></i>Attendance</a></li>
        <li><a href="#" onclick="showSection('notificationsSection',this)"><i class="fas fa-bell"></i>Notifications</a></li>
        <li><a href="#" onclick="showSection('bookmarksSection',this)"><i class="fas fa-bookmark"></i>Bookmarks</a></li>
        <li><a href="#" onclick="showSection('ticketSection',this)"><i class="fas fa-ticket-alt"></i>Raise Ticket</a></li>
        <li><a href="#" onclick="showSection('resourceHubSection',this)"><i class="fas fa-briefcase-medical"></i>Practice Resource Hub</a></li>
        <li><a href="#" onclick="showSection('referralsSection',this)"><i class="fas fa-user-friends"></i>Referrals</a></li>
        <li><a href="#" onclick="showSection('cpdSection',this)"><i class="fas fa-graduation-cap"></i>CPD Points</a></li>
        <li><a href="#" onclick="showSection('logbookSection',this)"><i class="fas fa-notes-medical"></i>Supervision Logbook</a></li>
        <li><a href="#" onclick="showSection('jobsSection',this)"><i class="fas fa-briefcase"></i>Job Board</a></li>
        <li><a href="#" onclick="showSection('forumsSection',this)"><i class="fas fa-comments"></i>Discussion Forums</a></li>
        <li><a href="#" onclick="showSection('alumniSection',this)"><i class="fas fa-user-graduate"></i>Alumni &amp; Mentors</a></li>
        <li><a href="#" onclick="showSection('portfolioSection',this)"><i class="fas fa-folder-open"></i>Portfolio</a></li>
        <li><a href="#" onclick="showSection('profileSection',this)"><i class="fas fa-user"></i>Profile</a></li>
        <li><a href="#" onclick="showSection('settingsSection',this)"><i class="fas fa-cog"></i>Settings</a></li>
        <li class="logout"><a href="index.php"><i class="fas fa-sign-out-alt"></i>Logout</a></li>
    </ul>
</nav>

<!-- MAIN -->
<main class="main">

<?php if ($flash): ?>
    <div class="flash"><?= htmlspecialchars($flash) ?></div>
<?php endif; ?>

<!-- ===
     DASHBOARD
=== -->
<div id="dashboardContent" class="section">
    <div class="page-header">
        <h1>Welcome back, <?= htmlspecialchars($profile['full_name'] ?? 'Student') ?> </h1>
        <p>Track your learning progress and manage your courses.</p>
    </div>

    <?php if (!empty($promoSlots_rows)): ?>
    <div class="promo-strip">
        <?php foreach ($promoSlots_rows as $promo): ?>
            <div class="promo-card">
                <span class="promo-tag"><?= htmlspecialchars($promo['tag'] ?? 'CBT-Kenya') ?></span>
                <h4><?= htmlspecialchars($promo['title'] ?? '') ?></h4>
                <?php if (!empty($promo['description'])): ?><p><?= htmlspecialchars(mb_strimwidth($promo['description'],0,110,'…')) ?></p><?php endif; ?>
                <?php if (!empty($promo['link_url'])): ?>
                    <a class="promo-link" href="<?= htmlspecialchars($promo['link_url'], ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer">Learn more <i class="fas fa-arrow-right"></i></a>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <div class="stats-grid">
        <div class="stat-box"><i class="fas fa-book"></i><h2><?= $enrolled ?></h2><p>Enrolled</p></div>
        <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= $completed ?></h2><p>Completed</p></div>
        <div class="stat-box gold"><i class="fas fa-spinner"></i><h2><?= $ongoing ?></h2><p>Ongoing</p></div>
        <div class="stat-box"><i class="fas fa-chart-pie"></i><h2><?= $progress ?>%</h2><p>Progress</p></div>
    </div>

    <div class="two-col">
        <div class="card">
            <div class="card-title"><i class="fas fa-play-circle"></i>Continue Learning</div>
            <?php foreach ($courses_widget_rows as $row): ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($row['title']) ?></h4>
                        <p><?= (int)$row['progress'] ?>% completed</p>
                        <div class="progress-bar-wrap"><div class="progress-fill" style="width:<?= (int)$row['progress'] ?>%"></div></div>
                    </div>
                    <a href="course1.php?id=<?= (int)$row['id'] ?>" class="btn small <?= ($row['status'] ?? '') === 'completed' ? 'dark' : '' ?>">
                        <?php if (($row['status'] ?? '') === 'completed'): ?>
                            <i class="fas fa-check-double"></i> Review
                        <?php else: ?>
                            <i class="fas fa-play"></i> Continue
                        <?php endif; ?>
                    </a>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="card">
            <div class="card-title"><i class="fas fa-history"></i>Recent Activities</div>
            <?php foreach ($activities_rows as $act): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($act['message']) ?></p>
                    <span><?= htmlspecialchars($act['created_at']) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<!-- ===
     MY COURSES
=== -->
<div id="coursesSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-book-open"></i>My Courses</div>
        <div class="stats-grid">
            <div class="stat-box"><i class="fas fa-book"></i><h2><?= $total_courses ?></h2><p>Total</p></div>
            <div class="stat-box"><i class="fas fa-play-circle"></i><h2><?= $active_courses ?></h2><p>Active</p></div>
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= $completed_courses ?></h2><p>Completed</p></div>
            <div class="stat-box gold"><i class="fas fa-award"></i><h2><?= $certificates_earned ?></h2><p>Certificates</p></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-play-circle"></i>Continue Learning</div>
        <?php if (!empty($courses_widget_rows)): ?>
            <?php foreach ($courses_widget_rows as $row):
                $pct = min(100, max(0, (int)($row['progress'] ?? 0)));
                $isCompleted = ($row['status'] ?? '') === 'completed';
            ?>
                <div class="course-row">
                    <div class="course-info" style="flex:1;">
                        <h4><?= htmlspecialchars($row['title']) ?></h4>
                        <p style="margin-bottom:6px;color:var(--gray-500);font-size:0.83rem;">
                            <?= (int)($row['lessons'] ?? 0) ?> lessons
                            &nbsp;•&nbsp;
                            <strong style="color:var(--navy);"><?= $pct ?>%</strong> completed
                            <?php if ($isCompleted): ?>
                                &nbsp;•&nbsp;<span style="color:var(--teal);font-weight:700;">Completed</span>
                            <?php endif; ?>
                        </p>
                        <div class="progress-bar-wrap" style="width:100%;max-width:320px;">
                            <div class="progress-fill" style="width:<?= $pct ?>%;"></div>
                        </div>
                    </div>
                    <a href="course1.php?id=<?= (int)$row['id'] ?>" class="btn small <?= $isCompleted ? 'dark' : '' ?>" style="flex-shrink:0;">
                        <?php if ($isCompleted): ?>
                            <i class="fas fa-check-double"></i> Review
                        <?php else: ?>
                            <i class="fas fa-play"></i> Continue
                        <?php endif; ?>
                    </a>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item">
                <p>No courses in progress</p>
                <span>
                    <a href="#" onclick="showSection('browseCoursesSection',
                        document.querySelector('#navMenu li a[onclick*=browseCoursesSection]'))"
                        style="color:var(--teal);font-weight:600;">
                        Browse courses to get started →
                    </a>
                </span>
            </div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-folder-open"></i>Course Materials</div>
        <?php if (!empty($materials_rows)): ?>
            <?php foreach ($materials_rows as $mat): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($mat['title'] ?? '') ?></p>
                    <span>Downloaded <?= (int)($mat['downloads'] ?? 0) ?> times</span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No materials available</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-video"></i>Upcoming Live Classes</div>
        <?php if (!empty($live_classes_rows)): ?>
            <?php foreach ($live_classes_rows as $live): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($live['title'] ?? '') ?></p>
                    <span><?= !empty($live['schedule_time']) ? date("d F Y • h:i A", strtotime($live['schedule_time'])) : 'N/A' ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No live classes scheduled</p></div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     PROGRESS
=== -->
<div id="progressSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-chart-line"></i>Learning Progress</div>
        <div class="stats-grid">
            <div class="stat-box"><i class="fas fa-book-open"></i><h2><?= $progressTotalCourses ?></h2><p>Enrolled</p></div>
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= $progressCompletedCourses ?></h2><p>Completed</p></div>
            <div class="stat-box gold"><i class="fas fa-spinner"></i><h2><?= $progressOngoingCourses ?></h2><p>Ongoing</p></div>
            <div class="stat-box"><i class="fas fa-chart-pie"></i><h2><?= $overallProgress ?>%</h2><p>Overall</p></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-laptop-code"></i>Course Progress</div>
        <?php if (!empty($courseProgressRows)): ?>
            <?php foreach ($courseProgressRows as $cp): ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($cp['title'] ?? '') ?></h4>
                        <p><?= (int)($cp['progress'] ?? 0) ?>% completed</p>
                        <div class="progress-bar-wrap"><div class="progress-fill" style="width:<?= (int)($cp['progress'] ?? 0) ?>%"></div></div>
                    </div>
                    <span style="color:<?= ($cp['status'] ?? '') === 'completed' ? 'var(--teal)' : 'var(--green)' ?>;font-weight:700;">
                        <?= ucfirst($cp['status'] ?? 'ongoing') ?>
                    </span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No progress data</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-question-circle"></i>Quiz Performance</div>
        <?php if (!empty($quizPerformance_rows)): ?>
            <?php foreach ($quizPerformance_rows as $qp): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($qp['quiz_title'] ?? '') ?></p>
                    <span>Score: <?= (int)($qp['score'] ?? 0) ?>% • <?= ucfirst($qp['status'] ?? '') ?> • <?= !empty($qp['created_at']) ? date("d M Y", strtotime($qp['created_at'])) : '' ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No quiz results yet</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-award"></i>Certificates</div>
        <?php if (!empty($progressCertificates_rows)): ?>
            <?php foreach ($progressCertificates_rows as $cert):
                $qrPath = $cert['qr_code_path'] ?? null;
                $qrSrc  = null;
                if (!empty($qrPath)) {
                    $qrBase = basename(strip_tags(trim($qrPath)));
                    $qrExt  = strtolower(pathinfo($qrBase, PATHINFO_EXTENSION));
                    if (in_array($qrExt, ['png','jpg','jpeg','svg'], true) && is_file(__DIR__ . '/uploads/' . $qrBase)) {
                        $qrSrc = 'uploads/' . $qrBase;
                    }
                }
            ?>
                <div class="activity-item" style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;">
                    <div>
                        <p><?= htmlspecialchars($cert['title'] ?? '') ?></p>
                        <span>Issued <?= !empty($cert['issued_at']) ? date("d F Y", strtotime($cert['issued_at'])) : '' ?>
                        <?php if (!empty($cert['certificate_code'])): ?>
                            &nbsp;•&nbsp;Cert No: <strong style="color:var(--navy);"><?= htmlspecialchars($cert['certificate_code']) ?></strong>
                        <?php endif; ?>
                        </span>
                    </div>
                    <?php if ($qrSrc): ?>
                        <img src="<?= htmlspecialchars($qrSrc, ENT_QUOTES, 'UTF-8') ?>" alt="Certificate verification QR code" style="width:64px;height:64px;border-radius:8px;border:1px solid var(--gray-200);">
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No certificates yet</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-chart-bar"></i>Learning Analytics</div>
        <div class="activity-item"><p>Total Study Hours</p><span><?= (int)($analytics['study_hours'] ?? 0) ?> hrs</span></div>
        <div class="activity-item"><p>Lessons Completed</p><span><?= (int)($analytics['lessons_completed'] ?? 0) ?></span></div>
        <div class="activity-item"><p>Assignments Submitted</p><span><?= (int)($analytics['assignments_submitted'] ?? 0) ?></span></div>
        <div class="activity-item"><p>Avg Daily Study</p><span><?= round(($analytics['study_hours'] ?? 0) / 30, 1) ?> hrs/day</span></div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-trophy"></i>Achievements</div>
        <?php if (!empty($progressAchievements)): ?>
            <?php foreach ($progressAchievements as $a): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($a['title']) ?></p>
                    <span><?= htmlspecialchars($a['description']) ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No achievements yet</p></div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     BROWSE COURSES
=== -->
<div id="browseCoursesSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-search"></i>Browse Courses</div>
        <form method="GET" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
            <input type="hidden" name="section" value="browse">
            <div class="form-group" style="flex:1;margin:0;">
                <input type="text" name="search" value="<?= htmlspecialchars($search) ?>" placeholder="Search courses by title…" maxlength="100">
            </div>
            <button type="submit" class="btn"><i class="fas fa-search"></i> Search</button>
        </form>

        <div class="card-title" style="font-size:1rem;"><i class="fas fa-layer-group"></i>Categories</div>
        <div class="chip-wrap">
            <?php foreach ($categories as $cat): ?>
                <span class="chip"><?= htmlspecialchars($cat) ?></span>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-star"></i>Featured Courses</div>
        <?php if (!empty($browseCoursesData)): ?>
            <?php foreach ($browseCoursesData as $course):
                $cid         = (int)$course['id'];
                $enrollStatus = $enrolledCourseMap[$cid] ?? null;
            ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($course['title']) ?></h4>
                        <p><?= htmlspecialchars(mb_strimwidth($course['description'], 0, 90, '…')) ?></p>
                        <p style="color:var(--teal);font-weight:700;margin-top:6px;">KES <?= number_format($course['price']) ?></p>
                        <p style="color:var(--gray-500);font-size:0.82rem;">
                            <?= htmlspecialchars($course['instructor']) ?> • <?= (int)$course['lessons'] ?> lessons • <?= number_format($course['enrolled_students']) ?> students
                        </p>
                    </div>

                    <?php if ($enrollStatus === null): ?>
                        <button type="button" class="btn small" onclick="openEnrollChoice(<?= $cid ?>, <?= json_encode($course['title'], JSON_HEX_APOS|JSON_HEX_QUOT) ?>)">
                            <i class="fas fa-plus"></i> Enroll
                        </button>
                    <?php elseif ($enrollStatus === 'completed'): ?>
                        <a href="course1.php?id=<?= $cid ?>" class="enroll-label completed" title="Course completed - click to review">
                            <i class="fas fa-check-double"></i> Completed
                        </a>
                    <?php else: ?>
                        <a href="course1.php?id=<?= $cid ?>" class="btn small green">
                            <i class="fas fa-play"></i> Continue
                        </a>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No courses found</p><span>Try a different keyword</span></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-fire"></i>Trending Courses</div>
        <?php foreach ($trendingCourses_rows as $trend): ?>
            <div class="activity-item">
                <p><?= htmlspecialchars($trend['title']) ?></p>
                <span><?= number_format($trend['enrolled_students']) ?> students</span>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-chalkboard-teacher"></i>Top Instructors</div>
        <?php foreach ($topInstructors_rows as $inst): ?>
            <div class="activity-item">
                <p><?= htmlspecialchars($inst['full_name']) ?></p>
                <span><?= htmlspecialchars($inst['specialization'] ?? '') ?> • <?= (int)$inst['experience_years'] ?> yrs • <?= (int)$inst['courses_count'] ?> courses</span>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-gift"></i>Why Learn With Us?</div>
        <?php foreach ($courseBenefits as $b): ?>
            <div class="activity-item">
                <p><?= htmlspecialchars($b['title']) ?></p>
                <span><?= htmlspecialchars($b['description']) ?></span>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ===
     ATTENDANCE
=== -->
<div id="attendanceSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-check"></i>Sign Attendance</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="sign_attendance" value="1">
            <div class="form-group">
                <label>Select Course</label>
                <select name="course_id" required>
                    <option value="">-- Choose Course --</option>
                    <?php foreach ($att_courses_rows as $c): ?>
                        <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="btn"><i class="fas fa-signature"></i> Sign Attendance</button>
        </form>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-calendar-check"></i>Attendance History</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead>
                <tr><th>Course</th><th>Status</th><th>Date</th></tr>
            </thead>
            <tbody>
            <?php if (!empty($att_history_rows)): ?>
                <?php foreach ($att_history_rows as $row): ?>
                    <tr>
                        <td><?= htmlspecialchars($row['title']) ?></td>
                        <td><?= htmlspecialchars($row['status']) ?></td>
                        <td><?= htmlspecialchars($row['attendance_date'] ?? '') ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="3" style="color:var(--gray-500);">No attendance records</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     PAYMENTS
=== -->
<div id="paymentsSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:18px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-credit-card"></i>Payments &amp; Billing</div>
            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <?php if ($hasPayableCourses): ?>
                    <button class="btn" onclick="openModal('paymentModal')"><i class="fas fa-plus"></i> Pay via M-Pesa</button>
                    <button class="btn outline" onclick="openModal('bankPaymentModal')"><i class="fas fa-university"></i> Pay via Bank</button>
                <?php else: ?>
                    <span class="btn muted"><i class="fas fa-check-circle"></i> All Courses Enrolled</span>
                <?php endif; ?>
            </div>
        </div>
        <div class="stats-grid">
            <div class="stat-box"><i class="fas fa-wallet"></i><h2>KES <?= number_format($totalPaid) ?></h2><p>Total Paid</p></div>
            <div class="stat-box red"><i class="fas fa-clock"></i><h2>KES <?= number_format($pendingPayments) ?></h2><p>Pending</p></div>
            <div class="stat-box"><i class="fas fa-receipt"></i><h2><?= $invoices_count ?></h2><p>Invoices</p></div>
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= $transactions_count ?></h2><p>Transactions</p></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-money-check-alt"></i>Payment Methods</div>
        <?php if (!empty($paymentMethods_rows)): ?>
            <?php foreach ($paymentMethods_rows as $m): ?>
                <div class="activity-item"><p><?= htmlspecialchars($m['method_type'] ?? '') ?></p><span><?= htmlspecialchars($m['account_number'] ?? '') ?></span></div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No payment methods added</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-receipt"></i>Transactions</div>
        <?php if (!empty($transactions_rows)): ?>
            <div class="table-scroll">
            <table class="data-table">
                <thead>
                    <tr><th>Course ID</th><th>Amount</th><th>Method</th><th>Status</th><th>Date</th></tr>
                </thead>
                <tbody>
                <?php foreach ($transactions_rows as $t):
                    $tStatus = strtolower($t['status'] ?? '');
                    $tMethod = strtolower($t['payment_method'] ?? '');
                    if ($tStatus === 'pending' && $tMethod === 'bank_transfer') {
                        $tBadge = '<span class="badge badge-pending">Pending Review</span>';
                    } else {
                        $tBadge = match($tStatus) {
                            'completed' => '<span class="badge badge-success">Completed</span>',
                            'pending'   => '<span class="badge badge-pending">Processing</span>',
                            'failed'    => '<span class="badge badge-failed">Failed</span>',
                            default     => htmlspecialchars(ucfirst($t['status'] ?? ''))
                        };
                    }
                    $methodLabel = match($tMethod) {
                        'bank_transfer' => 'Bank Transfer',
                        'mpesa'         => 'M-Pesa',
                        'card'          => 'Card',
                        default         => ucfirst($t['payment_method'] ?? 'M-Pesa')
                    };
                ?>
                    <tr>
                        <td><?= (int)$t['course_id'] ?></td>
                        <td>KES <?= number_format($t['amount']) ?></td>
                        <td><?= htmlspecialchars($methodLabel) ?></td>
                        <td><?= $tBadge ?></td>
                        <td><?= date("d M Y", strtotime($t['created_at'])) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php else: ?>
            <div class="activity-item"><p>No transactions yet</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-file-invoice"></i>Invoices</div>
        <?php if (!empty($invoices_rows)): ?>
            <?php foreach ($invoices_rows as $inv): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($inv['invoice_no'] ?? '') ?></p>
                    <span><?= htmlspecialchars($inv['description'] ?? '') ?> • <?= ucfirst($inv['status'] ?? '') ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No invoices yet</p></div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     NOTIFICATIONS
=== -->
<div id="notificationsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-bell"></i>Notifications &amp; Announcements</div>
        <?php if (!empty($notifications_rows)): ?>
            <?php foreach ($notifications_rows as $note): ?>
                <div class="activity-item" style="border-left-color:<?= $note['type']==='announcement' ? 'var(--gold)' : 'var(--teal)' ?>">
                    <p>
                        <?= $note['type']==='announcement' ? '<i class="fas fa-bullhorn" style="color:var(--gold-dark)"></i> ' : '<i class="fas fa-bell" style="color:var(--teal)"></i> ' ?>
                        <?= htmlspecialchars($note['message']) ?>
                    </p>
                    <span><?= date("F j, Y g:i A", strtotime($note['notification_date'])) ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No notifications</p><span>You're all caught up </span></div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     BOOKMARKS
=== -->
<div id="bookmarksSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-bookmark"></i>My Bookmarks</div>
        <?php if (!empty($bookmarks_rows)): ?>
            <?php foreach ($bookmarks_rows as $bm): ?>
                <div class="activity-item">
                    <p><?= htmlspecialchars($bm['title']) ?></p>
                    <span><?= date("F j, Y H:i", strtotime($bm['created_at'])) ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No bookmarks yet</p></div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     RAISE TICKET
=== -->
<div id="ticketSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-ticket-alt"></i>Raise a Support Ticket</div>
        <form method="POST" action="create_ticket.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div class="form-group">
                <label>Ticket Type</label>
                <select name="type" required>
                    <option value="">-- Select Type --</option>
                    <option value="academic">Academic</option>
                    <option value="technical">Technical</option>
                    <option value="attendance">Attendance</option>
                    <option value="general">General</option>
                </select>
            </div>
            <div class="form-group">
                <label>Subject</label>
                <input type="text" name="subject" required placeholder="Brief subject…" maxlength="150">
            </div>
            <div class="form-group">
                <label>Message</label>
                <textarea name="message" required placeholder="Describe your issue…" maxlength="4000"></textarea>
            </div>
            <button type="submit" name="submit_ticket" class="btn"><i class="fas fa-paper-plane"></i> Submit Ticket</button>
        </form>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Tickets</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Type</th><th>Subject</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
            <?php if (!empty($tickets_rows)): ?>
                <?php foreach ($tickets_rows as $ticket):
                    $badge = match($ticket['status']) {
                        'open'        => '<span class="badge badge-open">🟡 Open</span>',
                        'in_progress' => '<span class="badge badge-progress">🔵 In Progress</span>',
                        'resolved'    => '<span class="badge badge-resolved">🟢 Resolved</span>',
                        'closed'      => '<span class="badge badge-closed">⚫ Closed</span>',
                        default       => htmlspecialchars($ticket['status'])
                    };
                ?>
                    <tr>
                        <td><?= htmlspecialchars($ticket['type']) ?></td>
                        <td><?= htmlspecialchars($ticket['subject']) ?></td>
                        <td><?= $badge ?></td>
                        <td><?= htmlspecialchars($ticket['created_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="4" style="color:var(--gray-500);">No tickets raised yet</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     PROFILE
=== -->
<div id="profileSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user"></i>My Profile</div>

        <?php
        $image = $profile['profile_image'] ?? '';
        $src   = "https://ui-avatars.com/api/?name=".urlencode($profile['full_name'] ?? 'S')."&background=0e6b64&color=fff&size=200";
        if (!empty($image)) {
            $image = strip_tags(trim($image));
            $image = basename($image);
            $ext   = strtolower(pathinfo($image, PATHINFO_EXTENSION));
            if (in_array($ext, ['jpg','jpeg','png','webp'], true)) {
                $fp = __DIR__ . "/uploads/" . $image;
                if (is_file($fp)) { $src = "uploads/" . $image; }
            }
        }
        ?>
        <img src="<?= htmlspecialchars($src, ENT_QUOTES, 'UTF-8') ?>" alt="Profile photo" class="profile-img">

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:16px;">
            <div class="activity-item"><p>Student No.</p><span><?= htmlspecialchars($profile['student_no'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Full Name</p><span><?= htmlspecialchars($profile['full_name']) ?></span></div>
            <div class="activity-item"><p>Email</p><span><?= htmlspecialchars($profile['email']) ?></span></div>
            <div class="activity-item"><p>Phone</p><span><?= htmlspecialchars($profile['phone'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Location</p><span><?= htmlspecialchars($profile['location'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Joined</p><span><?= date("d F Y", strtotime($profile['created_at'])) ?></span></div>
            <div class="activity-item"><p>Courses</p><span><?= $total_courses ?></span></div>
        </div>

        <?php if (!empty($profile['bio'])): ?>
            <div class="activity-item" style="margin-bottom:16px;"><p>Bio</p><span><?= nl2br(htmlspecialchars($profile['bio'])) ?></span></div>
        <?php endif; ?>

        <div class="btn-row">
            <button class="btn" onclick="openModal('profileModal')"><i class="fas fa-user-edit"></i> Edit Profile</button>
            <button class="btn green" onclick="openModal('passwordModal')"><i class="fas fa-lock"></i> Change Password</button>
            <button class="btn dark" onclick="openModal('photoModal')"><i class="fas fa-image"></i> Upload Photo</button>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-id-card"></i>Professional Details</div>
        <?php
        $verifBadge = match($extendedProfile['verification_status'] ?? 'unverified') {
            'verified' => '<span class="badge badge-success">Verified</span>',
            'pending'  => '<span class="badge badge-pending">Pending Review</span>',
            'rejected' => '<span class="badge badge-failed">Rejected - please update</span>',
            default    => '<span class="badge badge-closed">Not Submitted</span>',
        };
        ?>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:16px;">
            <div class="activity-item"><p>KRA PIN</p><span><?= htmlspecialchars($profile['kra_pin'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Licence / Registration No.</p><span><?= htmlspecialchars($extendedProfile['license_number'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Qualification Level</p><span><?= htmlspecialchars($extendedProfile['qualification_level'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Verification Status</p><span><?= $verifBadge ?></span></div>
        </div>
        <div class="btn-row" style="margin-top:0;">
            <button class="btn outline" onclick="openModal('extendedProfileModal')"><i class="fas fa-file-signature"></i> Update Professional Details</button>
        </div>
    </div>
</div>

<!-- ===
     SETTINGS
=== -->
<div id="settingsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-cog"></i>Settings</div>
        <div class="activity-item"><p>Account Email</p><span><?= htmlspecialchars($profile['email'] ?? '') ?></span></div>
        <div class="activity-item"><p>Password Last Updated</p><span><?= !empty($settingsRow['password_updated_at']) ? date("d M Y", strtotime($settingsRow['password_updated_at'])) : 'Never' ?></span></div>
        <div class="activity-item"><p>Notifications</p><span>Email: <?= !empty($settingsRow['email_notifications']) ? 'On ✅' : 'Off ❌' ?> &nbsp;|&nbsp; SMS: <?= !empty($settingsRow['sms_notifications']) ? 'On ✅' : 'Off ❌' ?></span></div>
        <div class="activity-item"><p>Theme</p><span><?= ucfirst($settingsRow['theme'] ?? 'light') ?></span></div>
    </div>
</div>

<!-- ===
     PROFESSIONAL PRACTICE SUPPORT HUB
=== -->
<div id="resourceHubSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-briefcase-medical"></i>Professional Practice Support Hub</div>
        <p style="color:var(--gray-500);font-size:0.9rem;margin-bottom:6px;">Resources to help you transition into and sustain professional practice.</p>
    </div>
    <?php if (!empty($resourceCategories)): ?>
        <?php foreach ($resourceCategories as $cat):
            $items = $resourceItemsByCategory[(int)$cat['id']] ?? [];
        ?>
            <div class="card">
                <div class="card-title" style="font-size:1rem;"><i class="fas fa-folder"></i><?= htmlspecialchars($cat['name']) ?></div>
                <?php if (!empty($cat['description'])): ?><p style="color:var(--gray-500);font-size:0.85rem;margin-bottom:10px;"><?= htmlspecialchars($cat['description']) ?></p><?php endif; ?>
                <?php if (!empty($items)): ?>
                    <?php foreach ($items as $item): ?>
                        <div class="activity-item">
                            <p><?= htmlspecialchars($item['title']) ?></p>
                            <span>
                                <?= htmlspecialchars(ucfirst($item['resource_type'] ?? 'document')) ?>
                                <?php if (!empty($item['description'])): ?> • <?= htmlspecialchars(mb_strimwidth($item['description'],0,100,'…')) ?><?php endif; ?>
                                <?php if (!empty($item['external_link'])): ?>
                                    &nbsp;•&nbsp;<a href="<?= htmlspecialchars($item['external_link'], ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;">Open link</a>
                                <?php elseif (!empty($item['file_path'])): ?>
                                    &nbsp;•&nbsp;<a href="uploads/<?= htmlspecialchars(basename($item['file_path']), ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;">Download</a>
                                <?php endif; ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="activity-item"><p>No resources published yet</p></div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="card"><div class="activity-item"><p>Resource hub categories have not been set up yet</p></div></div>
    <?php endif; ?>
</div>

<!-- ===
     REFERRAL & AFFILIATE SYSTEM
=== -->
<div id="referralsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-friends"></i>Referral Programme</div>
        <?php if ($myReferralCode): ?>
            <div class="stats-grid">
                <div class="stat-box"><i class="fas fa-hashtag"></i><h2 style="font-size:1.4rem;"><?= htmlspecialchars($myReferralCode['code']) ?></h2><p>Your Referral Code</p></div>
                <div class="stat-box"><i class="fas fa-users"></i><h2><?= count($myReferrals_rows) ?></h2><p>People Referred</p></div>
                <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= count(array_filter($myReferrals_rows, fn($r)=>$r['status']==='converted')) ?></h2><p>Converted</p></div>
                <div class="stat-box gold"><i class="fas fa-coins"></i><h2>KES <?= number_format($myRewardsTotal) ?></h2><p>Rewards Earned</p></div>
            </div>
            <p style="color:var(--gray-500);font-size:0.88rem;">Share your referral link - anyone who registers through it is automatically credited to you.</p>

            <div class="referral-link-box">
                <i class="fas fa-link" style="color:var(--teal);"></i>
                <input type="text" id="referralLinkInput" value="<?= htmlspecialchars($myReferralLink, ENT_QUOTES, 'UTF-8') ?>" readonly onclick="this.select();">
                <button type="button" class="btn small gold" onclick="copyReferralLink()"><i class="fas fa-copy"></i> Copy Link</button>
            </div>
            <div class="btn-row" style="margin-top:12px;">
                <a class="btn small outline" target="_blank" rel="noopener noreferrer"
                   href="https://api.whatsapp.com/send?text=<?= urlencode('Join me on the CBT-Kenya Skills Transfer Program! Register using my referral link: ' . $myReferralLink) ?>">
                    <i class="fab fa-whatsapp"></i> Share on WhatsApp
                </a>
                <a class="btn small outline" target="_blank" rel="noopener noreferrer"
                   href="mailto:?subject=<?= rawurlencode('Join CBT-Kenya STP') ?>&body=<?= rawurlencode('Register using my referral link: ' . $myReferralLink) ?>">
                    <i class="fas fa-envelope"></i> Share via Email
                </a>
            </div>
        <?php else: ?>
            <p style="color:var(--gray-500);font-size:0.9rem;margin-bottom:14px;">You don't have a referral code yet. Generate one to start referring people to CBT-Kenya STP.</p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="generate_referral_code" value="1">
                <button type="submit" class="btn"><i class="fas fa-magic"></i> Generate My Referral Code</button>
            </form>
        <?php endif; ?>
    </div>

    <?php if ($myReferralCode): ?>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>Referral Activity</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Referred</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
            <?php if (!empty($myReferrals_rows)): ?>
                <?php foreach ($myReferrals_rows as $ref):
                    $rBadge = match($ref['status']) {
                        'converted' => '<span class="badge badge-success">Converted</span>',
                        'enrolled'  => '<span class="badge badge-progress">Enrolled</span>',
                        'registered'=> '<span class="badge badge-pending">Registered</span>',
                        'expired'   => '<span class="badge badge-closed">Expired</span>',
                        default     => '<span class="badge badge-pending">Pending</span>',
                    };
                ?>
                    <tr>
                        <td><?= htmlspecialchars($ref['referred_email'] ?? 'Not yet identified') ?></td>
                        <td><?= $rBadge ?></td>
                        <td><?= htmlspecialchars($ref['created_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="3" style="color:var(--gray-500);">No referrals yet - share your code to get started</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
    <?php endif; ?>
</div>

<!-- ===
     CPD / CME POINTS
=== -->
<div id="cpdSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:18px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-graduation-cap"></i>CPD / CME Points</div>
            <button class="btn" onclick="openModal('cpdModal')"><i class="fas fa-plus"></i> Log Activity</button>
        </div>
        <div class="stats-grid">
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= number_format($cpdVerifiedTotal, 1) ?></h2><p>Verified Points</p></div>
            <div class="stat-box gold"><i class="fas fa-clock"></i><h2><?= number_format($cpdPendingTotal, 1) ?></h2><p>Pending Verification</p></div>
        </div>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>CPD Activity Log</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Activity</th><th>Type</th><th>Points</th><th>Date</th><th>Status</th></tr></thead>
            <tbody>
            <?php if (!empty($cpdPoints_rows)): ?>
                <?php foreach ($cpdPoints_rows as $cp):
                    $cBadge = match($cp['verification_status']) {
                        'verified' => '<span class="badge badge-success">Verified</span>',
                        'rejected' => '<span class="badge badge-failed">Rejected</span>',
                        default    => '<span class="badge badge-pending">Pending</span>',
                    };
                ?>
                    <tr>
                        <td><?= htmlspecialchars($cp['activity_title']) ?></td>
                        <td><?= htmlspecialchars(ucfirst($cp['activity_type'])) ?></td>
                        <td><?= number_format((float)$cp['points'], 1) ?></td>
                        <td><?= htmlspecialchars($cp['date_earned']) ?></td>
                        <td><?= $cBadge ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="5" style="color:var(--gray-500);">No CPD activity logged yet</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     SUPERVISION / INTERNSHIP LOGBOOK
=== -->
<div id="logbookSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:18px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-notes-medical"></i>Supervision / Internship Logbook</div>
            <button class="btn" onclick="openModal('logbookModal')"><i class="fas fa-plus"></i> Log Session</button>
        </div>
        <div class="stats-grid">
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= number_format($logbookSignedHours, 1) ?></h2><p>Signed-off Hours</p></div>
            <div class="stat-box gold"><i class="fas fa-clock"></i><h2><?= number_format($logbookPendingHours, 1) ?></h2><p>Pending Sign-off</p></div>
        </div>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>Session History</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Date</th><th>Hours</th><th>Activity</th><th>Sign-off</th></tr></thead>
            <tbody>
            <?php if (!empty($logbook_rows)): ?>
                <?php foreach ($logbook_rows as $lb): ?>
                    <tr>
                        <td><?= htmlspecialchars($lb['session_date']) ?></td>
                        <td><?= number_format((float)$lb['hours'], 1) ?></td>
                        <td><?= htmlspecialchars(mb_strimwidth($lb['activity_description'],0,80,'…')) ?></td>
                        <td><?= (int)$lb['supervisor_signoff'] === 1 ? '<span class="badge badge-success">Signed</span>' : '<span class="badge badge-pending">Pending</span>' ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="4" style="color:var(--gray-500);">No logbook entries yet</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     JOB & PLACEMENT BOARD
=== -->
<div id="jobsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-briefcase"></i>Job &amp; Placement Opportunities</div>
        <?php if (!empty($jobPostings_rows)): ?>
            <?php foreach ($jobPostings_rows as $job):
                $jid = (int)$job['id'];
                $alreadyApplied = in_array($jid, $appliedJobIds, true);
            ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($job['title']) ?></h4>
                        <p><?= htmlspecialchars($job['organization'] ?? '') ?> • <?= htmlspecialchars($job['location'] ?? 'Location not specified') ?> • <?= htmlspecialchars(ucwords(str_replace('_',' ', $job['employment_type'] ?? ''))) ?></p>
                        <?php if (!empty($job['application_deadline'])): ?>
                            <p style="color:var(--gray-500);font-size:0.82rem;">Apply by <?= date("d M Y", strtotime($job['application_deadline'])) ?></p>
                        <?php endif; ?>
                    </div>
                    <?php if ($alreadyApplied): ?>
                        <span class="enroll-label enrolled"><i class="fas fa-check"></i> Applied</span>
                    <?php else: ?>
                        <button type="button" class="btn small" onclick="openJobApplyModal(<?= $jid ?>, <?= json_encode($job['title'], JSON_HEX_APOS|JSON_HEX_QUOT) ?>)"><i class="fas fa-paper-plane"></i> Apply</button>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No open job postings right now</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Applications</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Job</th><th>Organization</th><th>Status</th><th>Applied</th></tr></thead>
            <tbody>
            <?php if (!empty($myJobApplications_rows)): ?>
                <?php foreach ($myJobApplications_rows as $app):
                    $aBadge = match($app['status']) {
                        'shortlisted' => '<span class="badge badge-progress">Shortlisted</span>',
                        'hired'       => '<span class="badge badge-success">Hired</span>',
                        'rejected'    => '<span class="badge badge-failed">Rejected</span>',
                        default       => '<span class="badge badge-pending">Submitted</span>',
                    };
                ?>
                    <tr>
                        <td><?= htmlspecialchars($app['job_title']) ?></td>
                        <td><?= htmlspecialchars($app['organization'] ?? '') ?></td>
                        <td><?= $aBadge ?></td>
                        <td><?= htmlspecialchars($app['applied_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="4" style="color:var(--gray-500);">You haven't applied to any jobs yet</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     DISCUSSION FORUMS
=== -->
<div id="forumsSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:10px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-comments"></i>Discussion Forums</div>
            <button class="btn" onclick="openModal('newTopicModal')"><i class="fas fa-plus"></i> New Topic</button>
        </div>
        <p style="color:var(--gray-500);font-size:0.88rem;">Peer discussions for the courses you're enrolled in.</p>
    </div>

    <?php if (!empty($forumTopics_rows)): ?>
        <?php foreach ($forumTopics_rows as $topic):
            $tid = (int)$topic['id'];
            $replies = $forumRepliesByTopic[$tid] ?? [];
        ?>
            <div class="card">
                <div class="card-title" style="font-size:1rem;"><i class="fas fa-comment-dots"></i><?= htmlspecialchars($topic['title']) ?></div>
                <p style="color:var(--gray-500);font-size:0.82rem;margin-bottom:10px;">
                    <?= htmlspecialchars($topic['course_title']) ?> • by <?= htmlspecialchars($topic['author_name'] ?? 'Unknown') ?> • <?= htmlspecialchars($topic['created_at']) ?>
                    <?php if ($topic['status'] === 'closed'): ?> • <span class="badge badge-closed">Closed</span><?php endif; ?>
                </p>
                <p style="font-size:0.92rem;margin-bottom:14px;"><?= nl2br(htmlspecialchars($topic['message'])) ?></p>

                <?php foreach ($replies as $rep): ?>
                    <div class="activity-item" style="margin-left:18px;">
                        <p><?= htmlspecialchars($rep['author_name'] ?? 'Unknown') ?></p>
                        <span><?= nl2br(htmlspecialchars($rep['message'])) ?></span>
                    </div>
                <?php endforeach; ?>

                <?php if ($topic['status'] !== 'closed'): ?>
                <form method="POST" style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="post_forum_reply" value="1">
                    <input type="hidden" name="topic_id" value="<?= $tid ?>">
                    <input type="text" name="message" required maxlength="4000" placeholder="Write a reply…" style="flex:1;min-width:200px;padding:10px 12px;border:1px solid var(--gray-200);border-radius:9px;">
                    <button type="submit" class="btn small"><i class="fas fa-reply"></i> Reply</button>
                </form>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="card"><div class="activity-item"><p>No discussion topics yet - start one!</p></div></div>
    <?php endif; ?>
</div>

<!-- ===
     ALUMNI NETWORK & MENTORSHIP
=== -->
<div id="alumniSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-graduate"></i>Alumni Profile</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="update_alumni_profile" value="1">
            <div class="form-group"><label>Graduation Year</label><input type="number" name="graduation_year" min="2000" max="2100" value="<?= htmlspecialchars($myAlumniProfile['graduation_year'] ?? '') ?>"></div>
            <div class="form-group"><label>Current Role</label><input type="text" name="current_role" maxlength="150" value="<?= htmlspecialchars($myAlumniProfile['current_role'] ?? '') ?>"></div>
            <div class="form-group"><label>Organization</label><input type="text" name="organization" maxlength="150" value="<?= htmlspecialchars($myAlumniProfile['organization'] ?? '') ?>"></div>
            <div class="form-group"><label>Testimonial</label><textarea name="testimonial" maxlength="2000"><?= htmlspecialchars($myAlumniProfile['testimonial'] ?? '') ?></textarea></div>
            <div class="form-group">
                <label><input type="checkbox" name="is_public" value="1" style="width:auto;margin-right:8px;" <?= !empty($myAlumniProfile['is_public']) ? 'checked' : '' ?>> Make my alumni profile public</label>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="is_mentor_available" value="1" style="width:auto;margin-right:8px;" <?= !empty($myAlumniProfile['is_mentor_available']) ? 'checked' : '' ?>> I'm available to mentor others</label>
            </div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Save Alumni Profile</button>
        </form>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-user-friends"></i>Available Mentors</div>
        <?php if (!empty($availableMentors_rows)): ?>
            <?php foreach ($availableMentors_rows as $mentor): ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($mentor['full_name']) ?></h4>
                        <p><?= htmlspecialchars($mentor['current_role'] ?? '') ?> <?= !empty($mentor['organization']) ? '• '.htmlspecialchars($mentor['organization']) : '' ?></p>
                    </div>
                    <button type="button" class="btn small" onclick="openMentorRequestModal(<?= (int)$mentor['mentor_user_id'] ?>, <?= json_encode($mentor['full_name'], JSON_HEX_APOS|JSON_HEX_QUOT) ?>)"><i class="fas fa-hand-holding-heart"></i> Request</button>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No mentors listed yet</p></div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Mentorship Requests</div>
        <div class="table-scroll">
        <table class="data-table">
            <thead><tr><th>Mentor</th><th>Focus Area</th><th>Status</th></tr></thead>
            <tbody>
            <?php if (!empty($myMentorships_rows)): ?>
                <?php foreach ($myMentorships_rows as $mm):
                    $mBadge = match($mm['status']) {
                        'active'    => '<span class="badge badge-success">Active</span>',
                        'completed' => '<span class="badge badge-closed">Completed</span>',
                        'declined'  => '<span class="badge badge-failed">Declined</span>',
                        default     => '<span class="badge badge-pending">Requested</span>',
                    };
                ?>
                    <tr>
                        <td><?= htmlspecialchars($mm['mentor_name']) ?></td>
                        <td><?= htmlspecialchars($mm['focus_area'] ?? '-') ?></td>
                        <td><?= $mBadge ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="3" style="color:var(--gray-500);">No mentorship requests yet</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        </div>
    </div>
</div>

<!-- ===
     DIGITAL PORTFOLIO
=== -->
<div id="portfolioSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:10px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-folder-open"></i>Digital Portfolio</div>
            <button class="btn" onclick="openModal('portfolioModal')"><i class="fas fa-plus"></i> Add Item</button>
        </div>
        <p style="color:var(--gray-500);font-size:0.88rem;">Case studies, competency evidence, and publications you want to showcase.</p>
    </div>
    <?php if (!empty($portfolio_rows)): ?>
        <?php foreach ($portfolio_rows as $pf): ?>
            <div class="card">
                <div class="card-title" style="font-size:1rem;"><i class="fas fa-file-alt"></i><?= htmlspecialchars($pf['title']) ?></div>
                <p style="color:var(--gray-500);font-size:0.82rem;margin-bottom:8px;">
                    <?= htmlspecialchars($pf['category'] ?? 'General') ?> • <?= htmlspecialchars($pf['created_at']) ?>
                    <?= !empty($pf['is_public']) ? ' • <span class="badge badge-success">Public</span>' : ' • <span class="badge badge-closed">Private</span>' ?>
                </p>
                <?php if (!empty($pf['description'])): ?><p style="font-size:0.9rem;margin-bottom:8px;"><?= nl2br(htmlspecialchars($pf['description'])) ?></p><?php endif; ?>
                <?php if (!empty($pf['file_path'])): ?>
                    <a href="uploads/<?= htmlspecialchars(basename($pf['file_path']), ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;font-size:0.85rem;"><i class="fas fa-download"></i> View file</a>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php else: ?>
        <div class="card"><div class="activity-item"><p>No portfolio items yet</p></div></div>
    <?php endif; ?>
</div>

</main>
</div>

<!-- ===
     PAYMENT MODAL (M-PESA)
=== -->
<div id="paymentModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('paymentModal')">✕</button>
        <div class="modal-title"><i class="fas fa-credit-card"></i> Make a Payment</div>

        <?php if ($hasPayableCourses): ?>
        <form method="GET" action="enroll.php" style="display:flex;flex-direction:column;gap:0;">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" id="paymentCourseSelect" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach ($payableCoursesData as $pc): ?>
                        <option value="<?= (int)$pc['id'] ?>">
                            <?= htmlspecialchars($pc['title']) ?> (KES <?= number_format($pc['price']) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;">
                <i class="fas fa-arrow-right"></i> Continue to Enrollment
            </button>
        </form>
        <?php else: ?>
            <div class="activity-item" style="text-align:center;padding:30px 16px;">
                <p style="font-size:1.1rem;"> You are enrolled in all available paid courses!</p>
                <span>Check back later for new courses.</span>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     BANK PAYMENT MODAL
=== -->
<div id="bankPaymentModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('bankPaymentModal')">✕</button>
        <div class="modal-title"><i class="fas fa-university"></i> Pay via Bank Transfer</div>

        <div class="bank-details">
            <div class="bd-row"><span class="bd-label">Bank Name</span><span class="bd-value"><?= htmlspecialchars(BANK_NAME) ?></span></div>
            <div class="bd-row"><span class="bd-label">Account Name</span><span class="bd-value"><?= htmlspecialchars(BANK_ACCOUNT_NAME) ?></span></div>
            <div class="bd-row"><span class="bd-label">Account Number</span><span class="bd-value"><?= htmlspecialchars(BANK_ACCOUNT_NUMBER) ?></span></div>
            <div class="bd-row"><span class="bd-label">Branch</span><span class="bd-value"><?= htmlspecialchars(BANK_BRANCH) ?></span></div>
            <div class="bd-row"><span class="bd-label">Swift Code</span><span class="bd-value"><?= htmlspecialchars(BANK_SWIFT_CODE) ?></span></div>
        </div>

        <?php if ($hasPayableCourses): ?>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="submit_bank_payment" value="1">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach ($payableCoursesData as $pc): ?>
                        <option value="<?= (int)$pc['id'] ?>" data-price="<?= (int)$pc['price'] ?>">
                            <?= htmlspecialchars($pc['title']) ?> (KES <?= number_format($pc['price']) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label>Amount Deposited (KES)</label>
                <input type="number" name="amount" min="1" step="0.01" required placeholder="e.g. 5000">
            </div>
            <div class="form-group">
                <label>Payer Full Name</label>
                <input type="text" name="payer_name" required maxlength="150"
                       value="<?= htmlspecialchars($profile['full_name'] ?? '') ?>"
                       placeholder="Name on the deposit slip">
            </div>
            <div class="form-group">
                <label>Payer Phone Number</label>
                <input type="tel" name="payer_phone" required maxlength="30"
                       value="<?= htmlspecialchars($profile['phone'] ?? '') ?>"
                       placeholder="e.g. 07XXXXXXXX">
            </div>
            <div class="form-group">
                <label>Payer Email (optional)</label>
                <input type="email" name="payer_email" maxlength="150"
                       value="<?= htmlspecialchars($profile['email'] ?? '') ?>">
            </div>
            <div class="form-group">
                <label>Bank Transaction Code / Slip No.</label>
                <input type="text" name="transaction_code" required maxlength="100" placeholder="e.g. FT23A1B2C3">
            </div>
            <div class="form-group">
                <label>Date of Deposit</label>
                <input type="date" name="payment_date" required max="<?= date('Y-m-d') ?>">
            </div>
            <div class="form-group">
                <label>Notes (optional)</label>
                <textarea name="notes" maxlength="2000" placeholder="Any extra info for the admin…"></textarea>
            </div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;margin-top:14px;">
                <i class="fas fa-paper-plane"></i> Submit for Verification
            </button>
        </form>
        <?php else: ?>
            <div class="activity-item" style="text-align:center;padding:30px 16px;">
                <p style="font-size:1.1rem;"> You are enrolled in all available paid courses!</p>
                <span>Check back later for new courses.</span>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- ===
     CHOOSE PAYMENT METHOD MODAL
=== -->
<div id="chooseMethodModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('chooseMethodModal')">✕</button>
        <div class="modal-title" id="chooseMethodTitle"><i class="fas fa-wallet"></i> Choose Payment Method</div>
        <p style="color:var(--gray-500);font-size:0.88rem;margin-bottom:18px;">Select how you'd like to pay for this course.</p>
        <div style="display:flex;flex-direction:column;gap:12px;">
            <a id="mpesaEnrollLink" href="#" class="btn" style="width:100%;justify-content:center;">
                <i class="fas fa-mobile-alt"></i> Pay via M-Pesa
            </a>
            <button type="button" class="btn outline" style="width:100%;justify-content:center;" onclick="chooseBankPayment()">
                <i class="fas fa-university"></i> Pay via Bank Transfer
            </button>
        </div>
    </div>
</div>

<!-- ===
     PROFILE EDIT MODAL
=== -->
<div id="profileModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('profileModal')">✕</button>
        <div class="modal-title"><i class="fas fa-user-edit"></i> Update Profile</div>
        <form method="POST" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div class="form-group"><label>Student No.</label><input type="text" value="<?= htmlspecialchars($profile['student_no'] ?? '-') ?>" disabled></div>
            <div class="form-group"><label>Full Name</label><input type="text" name="full_name" value="<?= htmlspecialchars($profile['full_name'] ?? '') ?>" required maxlength="120"></div>
            <div class="form-group"><label>Email</label><input type="email" name="email" value="<?= htmlspecialchars($profile['email'] ?? '') ?>" required></div>
            <div class="form-group"><label>Phone</label><input type="tel" name="phone" value="<?= htmlspecialchars($profile['phone'] ?? '') ?>" maxlength="30"></div>
            <div class="form-group"><label>Location</label><input type="text" name="location" value="<?= htmlspecialchars($profile['location'] ?? '') ?>" maxlength="120"></div>
            <div class="form-group"><label>Bio</label><textarea name="bio" maxlength="2000"><?= htmlspecialchars($profile['bio'] ?? '') ?></textarea></div>
            <button type="submit" name="update_profile" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Save Changes</button>
        </form>
    </div>
</div>

<!-- ===
     CHANGE PASSWORD MODAL
=== -->
<div id="passwordModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('passwordModal')">✕</button>
        <div class="modal-title"><i class="fas fa-lock"></i> Change Password</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div class="form-group"><label>Current Password</label><input type="password" name="current_password" required autocomplete="current-password"></div>
            <div class="form-group"><label>New Password</label><input type="password" name="new_password" required autocomplete="new-password" minlength="8"></div>
            <div class="form-group"><label>Confirm Password</label><input type="password" name="confirm_password" required autocomplete="new-password" minlength="8"></div>
            <button type="submit" name="change_password" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-key"></i> Update Password</button>
        </form>
    </div>
</div>

<!-- ===
     UPLOAD PHOTO MODAL
=== -->
<div id="photoModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('photoModal')">✕</button>
        <div class="modal-title"><i class="fas fa-camera"></i> Upload Profile Photo</div>
        <form method="POST" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <div class="form-group"><label>Choose Image (JPG / PNG / WEBP, max 5 MB)</label><input type="file" name="profile_photo" accept="image/jpeg,image/png,image/webp" required></div>
            <button type="submit" name="upload_photo" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-upload"></i> Upload Photo</button>
        </form>
    </div>
</div>

<!-- ===
     EXTENDED PROFESSIONAL PROFILE MODAL
=== -->
<div id="extendedProfileModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('extendedProfileModal')">✕</button>
        <div class="modal-title"><i class="fas fa-file-signature"></i> Update Professional Details</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="update_extended_profile" value="1">
            <div class="form-group">
                <label>Professional Licence / Registration No.</label>
                <input type="text" name="license_number" maxlength="100" value="<?= htmlspecialchars($extendedProfile['license_number'] ?? '') ?>" placeholder="e.g. board registration number">
            </div>
            <div class="form-group">
                <label>Academic Qualification Level</label>
                <select name="qualification_level">
                    <option value="">-- Select --</option>
                    <?php foreach (['Diploma','Degree','Masters','PhD'] as $q): ?>
                        <option value="<?= $q ?>" <?= ($extendedProfile['qualification_level'] ?? '') === $q ? 'selected' : '' ?>><?= $q ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label>KRA PIN</label>
                <input type="text" name="kra_pin" maxlength="11" value="<?= htmlspecialchars($profile['kra_pin'] ?? '') ?>" placeholder="e.g. A123456789Z">
                <div class="form-hint">Used for eTIMS-compliant invoicing.</div>
            </div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Submit for Verification</button>
        </form>
    </div>
</div>

<!-- ===
     LOG CPD POINT MODAL
=== -->
<div id="cpdModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('cpdModal')">✕</button>
        <div class="modal-title"><i class="fas fa-graduation-cap"></i> Log CPD / CME Activity</div>
        <form method="POST" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="submit_cpd_point" value="1">
            <div class="form-group"><label>Activity Title</label><input type="text" name="activity_title" required maxlength="255" placeholder="e.g. Ethics in Clinical Practice Workshop"></div>
            <div class="form-group">
                <label>Activity Type</label>
                <select name="activity_type">
                    <option value="course">Course</option>
                    <option value="workshop">Workshop</option>
                    <option value="conference">Conference</option>
                    <option value="supervision">Supervision</option>
                    <option value="publication">Publication</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <div class="form-group"><label>Points</label><input type="number" name="points" min="0.5" step="0.5" required placeholder="e.g. 2"></div>
            <div class="form-group"><label>Date Earned</label><input type="date" name="date_earned" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Evidence (PDF/JPG/PNG, optional)</label><input type="file" name="evidence_file" accept="application/pdf,image/jpeg,image/png"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit</button>
        </form>
    </div>
</div>

<!-- ===
     LOGBOOK ENTRY MODAL
=== -->
<div id="logbookModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('logbookModal')">✕</button>
        <div class="modal-title"><i class="fas fa-notes-medical"></i> Log Supervision Session</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="submit_logbook_entry" value="1">
            <div class="form-group"><label>Session Date</label><input type="date" name="session_date" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Hours</label><input type="number" name="hours" min="0.5" step="0.5" required></div>
            <div class="form-group"><label>Activity Description</label><textarea name="activity_description" required maxlength="3000" placeholder="What did the session cover?"></textarea></div>
            <div class="form-group"><label>Competencies Covered</label><input type="text" name="competencies_covered" maxlength="1000" placeholder="e.g. Risk assessment, case formulation"></div>
            <div class="form-group"><label>Client / Case Reference (anonymised, optional)</label><input type="text" name="client_case_ref" maxlength="100" placeholder="Never use identifying client information"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit for Sign-off</button>
        </form>
    </div>
</div>

<!-- ===
     JOB APPLICATION MODAL
=== -->
<div id="jobApplyModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('jobApplyModal')">✕</button>
        <div class="modal-title" id="jobApplyTitle"><i class="fas fa-paper-plane"></i> Apply for Job</div>
        <form method="POST" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="apply_job" value="1">
            <input type="hidden" name="job_id" id="jobApplyJobId" value="">
            <div class="form-group"><label>CV / Resume (PDF/JPG/PNG)</label><input type="file" name="cv_file" accept="application/pdf,image/jpeg,image/png"></div>
            <div class="form-group"><label>Cover Note (optional)</label><textarea name="cover_letter" maxlength="3000" placeholder="Briefly tell them why you're a fit…"></textarea></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit Application</button>
        </form>
    </div>
</div>

<!-- ===
     NEW FORUM TOPIC MODAL
=== -->
<div id="newTopicModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('newTopicModal')">✕</button>
        <div class="modal-title"><i class="fas fa-comment-dots"></i> Start a Discussion Topic</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="post_forum_topic" value="1">
            <div class="form-group">
                <label>Course</label>
                <select name="course_id" required>
                    <option value="">-- Select one of your courses --</option>
                    <?php foreach ($att_courses_rows as $c): ?>
                        <option value="<?= (int)$c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="255"></div>
            <div class="form-group"><label>Message</label><textarea name="message" required maxlength="4000"></textarea></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Post Topic</button>
        </form>
    </div>
</div>

<!-- ===
     MENTORSHIP REQUEST MODAL
=== -->
<div id="mentorRequestModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('mentorRequestModal')">✕</button>
        <div class="modal-title" id="mentorRequestTitle"><i class="fas fa-hand-holding-heart"></i> Request Mentorship</div>
        <form method="POST" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="request_mentorship" value="1">
            <input type="hidden" name="mentor_id" id="mentorRequestMentorId" value="">
            <div class="form-group"><label>What would you like guidance on?</label><input type="text" name="focus_area" maxlength="255" placeholder="e.g. Starting a private practice"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Send Request</button>
        </form>
    </div>
</div>

<!-- ===
     PORTFOLIO ITEM MODAL
=== -->
<div id="portfolioModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('portfolioModal')">✕</button>
        <div class="modal-title"><i class="fas fa-folder-open"></i> Add Portfolio Item</div>
        <form method="POST" enctype="multipart/form-data" style="display:flex;flex-direction:column;gap:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="add_portfolio_item" value="1">
            <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="255"></div>
            <div class="form-group"><label>Category</label><input type="text" name="category" maxlength="150" placeholder="e.g. Case Study, Publication"></div>
            <div class="form-group"><label>Description</label><textarea name="description" maxlength="2000"></textarea></div>
            <div class="form-group"><label>File (PDF/JPG/PNG, optional)</label><input type="file" name="portfolio_file" accept="application/pdf,image/jpeg,image/png"></div>
            <div class="form-group">
                <label><input type="checkbox" name="is_public" value="1" style="width:auto;margin-right:8px;"> Make this item public</label>
            </div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Add to Portfolio</button>
        </form>
    </div>
</div>

<script>
/* ==
   SIDEBAR 
== */
function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebarOverlay').classList.toggle('active');
}
function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('active');
}

/* ==
   SECTION SWITCHING
== */
const ALL_SECTIONS = [
    'dashboardContent','coursesSection','browseCoursesSection',
    'progressSection','paymentsSection',
    'attendanceSection','notificationsSection','bookmarksSection',
    'ticketSection','resourceHubSection','referralsSection','cpdSection',
    'logbookSection','jobsSection','forumsSection','alumniSection',
    'portfolioSection','profileSection','settingsSection'
];

function showSection(id, linkEl) {
    ALL_SECTIONS.forEach(s => {
        const el = document.getElementById(s);
        if (el) el.style.display = 'none';
    });
    const target = document.getElementById(id);
    if (target) target.style.display = 'block';

    document.querySelectorAll('#navMenu li').forEach(li => li.classList.remove('active'));
    if (linkEl) linkEl.closest('li').classList.add('active');

    closeSidebar();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

const ACTIVE_SECTION = <?= $active_section_js ?>;

window.addEventListener('load', function () {
    const targetId = ACTIVE_SECTION || 'dashboardContent';
    const target   = document.getElementById(targetId);
    if (target) target.style.display = 'block';

    document.querySelectorAll('#navMenu li').forEach(li => li.classList.remove('active'));
    const navLink = document.querySelector(`#navMenu li a[onclick*="${targetId}"]`);
    if (navLink) navLink.closest('li').classList.add('active');
});

/* ==
   MODALS
== */
const MODAL_IDS = [
    'paymentModal','profileModal','passwordModal','photoModal','bankPaymentModal','chooseMethodModal',
    'extendedProfileModal','cpdModal','logbookModal','jobApplyModal','newTopicModal','mentorRequestModal','portfolioModal'
];

function openModal(id)  { document.getElementById(id).classList.add('active'); document.body.style.overflow = 'hidden'; }
function closeModal(id) { document.getElementById(id).classList.remove('active'); document.body.style.overflow = ''; }

document.addEventListener('click', function(e) {
    MODAL_IDS.forEach(id => {
        const el = document.getElementById(id);
        if (el && e.target === el) closeModal(id);
    });
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        MODAL_IDS.forEach(id => {
            const el = document.getElementById(id);
            if (el && el.classList.contains('active')) closeModal(id);
        });
    }
});

/* ==
   ENROLL 
== */
let pendingEnrollCourseId = null;

function openEnrollChoice(courseId, courseTitle) {
    pendingEnrollCourseId = courseId;
    document.getElementById('chooseMethodTitle').innerHTML =
        '<i class="fas fa-wallet"></i> Pay for "' + courseTitle + '"';
    document.getElementById('mpesaEnrollLink').href = 'enroll.php?course_id=' + encodeURIComponent(courseId);
    openModal('chooseMethodModal');
}

function chooseBankPayment() {
    closeModal('chooseMethodModal');
    openModal('bankPaymentModal');
    if (pendingEnrollCourseId !== null) {
        const sel = document.querySelector('#bankPaymentModal select[name="course_id"]');
        if (sel) sel.value = String(pendingEnrollCourseId);
    }
}

/* ==
   JOB BOARD
== */
function openJobApplyModal(jobId, jobTitle) {
    document.getElementById('jobApplyJobId').value = jobId;
    document.getElementById('jobApplyTitle').innerHTML = '<i class="fas fa-paper-plane"></i> Apply - ' + jobTitle;
    openModal('jobApplyModal');
}

/* ==
   MENTORSHIP
== */
function openMentorRequestModal(mentorUserId, mentorName) {
    document.getElementById('mentorRequestMentorId').value = mentorUserId;
    document.getElementById('mentorRequestTitle').innerHTML = '<i class="fas fa-hand-holding-heart"></i> Request Mentorship - ' + mentorName;
    openModal('mentorRequestModal');
}

/* ==
   REFERRALS - copy link
== */
function copyReferralLink() {
    const input = document.getElementById('referralLinkInput');
    if (!input || !input.value) return;
    input.select();
    input.setSelectionRange(0, 99999);

    const finish = (ok) => {
        const btn = document.querySelector('.referral-link-box .btn');
        if (!btn) return;
        const original = btn.innerHTML;
        btn.innerHTML = ok ? '<i class="fas fa-check"></i> Copied!' : '<i class="fas fa-times"></i> Copy failed';
        setTimeout(() => { btn.innerHTML = original; }, 1800);
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(input.value).then(() => finish(true)).catch(() => finish(false));
    } else {
        try {
            const ok = document.execCommand('copy');
            finish(ok);
        } catch (e) {
            finish(false);
        }
    }
}
</script>
</body>
</html>