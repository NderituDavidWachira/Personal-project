<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
 * student.php - student dashboard.
 * Payments live in payment.php / includes/KcbBuni.php / kcb_callback.php,
 * config in config.php, shared helpers in helpers.php.
 */
require_once __DIR__ . '/Bootstrap.php';   // session, headers, $pdo
require_once __DIR__ . '/Payment.php';     // config + helpers + payments_handle_post()
require_once __DIR__ . '/Certificates.php';
require_once __DIR__ . '/Progress.php';
if (is_file(__DIR__ . '/advance.php')) { include __DIR__ . '/advance.php'; }

$routeAction = $_GET['action'] ?? '';

/* ==== PUBLIC ROUTE: CERTIFICATE VERIFICATION ==== */
if ($routeAction === 'verify') {
    $verifyCodeParam = preg_replace('/[^A-Za-z0-9\-]/', '', trim($_GET['code'] ?? ''));
    $vSearched       = $verifyCodeParam !== '';
    $vCert           = $vSearched ? find_certificate_by_code($pdo, $verifyCodeParam) : null;
    $vCourseTitle    = $vCert ? strip_cert_prefix($vCert['title'] ?? '') : '';
    require __DIR__ . '/views/verify.php';
    exit;
}

/* ==== AUTH ==== */
if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

if ($routeAction === 'logout') {
    $_SESSION = [];
    session_destroy();
    header('Location: index.php');
    exit;
}

$user_id = (int) $_SESSION['user_id'];

$statusCheck = $pdo->prepare("SELECT status, role FROM users WHERE id = :id LIMIT 1");
$statusCheck->execute([':id' => $user_id]);
$statusRow = $statusCheck->fetch(PDO::FETCH_ASSOC);

if (!$statusRow || $statusRow['role'] !== 'student' || strtolower($statusRow['status']) !== 'active') {
    session_unset();
    session_destroy();
    header('Location: index.php?notice=' . urlencode('Your account is pending admin approval or is inactive. Please contact support.'));
    exit;
}

/* ==== PRIVATE ROUTE: VIEW / PRINT OWN CERTIFICATE ==== */
if ($routeAction === 'certificate') {
    $certCodeParam = preg_replace('/[^A-Za-z0-9\-]/', '', trim($_GET['code'] ?? ''));
    $certIdParam   = (int) ($_GET['id'] ?? 0);

    $cert = ($certCodeParam !== '' || $certIdParam > 0)
        ? find_owned_certificate($pdo, $user_id, $certCodeParam, $certIdParam)
        : null;

    if (!$cert) {
        http_response_code(404);
        die('Certificate not found.');
    }

    if (empty($cert['certificate_code']) && $cert['source'] === 'certificates') {
        try {
            $newCode = generateCertificateNumber($pdo);
            $pdo->prepare("UPDATE certificates SET certificate_code = :code WHERE id = :id")
                ->execute([':code' => $newCode, ':id' => $cert['id']]);
            $cert['certificate_code'] = $newCode;
        } catch (Throwable $e) { /* fall back to display id below */ }
    }

    $courseTitle          = strip_cert_prefix($cert['title'] ?? '');
    $participant          = $cert['full_name'] ?? 'Student';
    $issuedDate           = !empty($cert['issued_at']) ? date('d F Y', strtotime($cert['issued_at'])) : date('d F Y');
    $certificateNoDisplay = !empty($cert['certificate_code']) ? $cert['certificate_code'] : ('CBT-STP-ID-' . $cert['id']);

    $scheme    = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ? 'https://' : 'http://';
    $host      = preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST'] ?? '');
    $selfBase  = strtok($_SERVER['PHP_SELF'] ?? 'student.php', '?');
    $verifyUrl = $scheme . $host . $selfBase . '?action=verify&code=' . urlencode($certificateNoDisplay);

    require __DIR__ . '/views/certificate.php';
    exit;
}

/* ==== CSRF TOKEN ==== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ==== PAYMENTS: STK push, bank, paybill (see payment.php) ==== */
payments_handle_post($pdo, $user_id);

/* ==== UPDATE PROFILE ==== */
if (isset($_POST['update_profile'])) {
    validateCsrf();
    $email    = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
    $phone    = mb_substr(trim(strip_tags($_POST['phone']    ?? '')), 0, 30);
    $location = mb_substr(trim(strip_tags($_POST['location'] ?? '')), 0, 120);
    $bio      = mb_substr(trim(strip_tags($_POST['bio']      ?? '')), 0, 2000);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash_redirect('Invalid email address.', 'profile');
    }

    $pdo->prepare("UPDATE users SET email=:em, phone=:ph, location=:lo, bio=:bi WHERE id=:id AND role='student'")
        ->execute([':em' => $email, ':ph' => $phone, ':lo' => $location, ':bi' => $bio, ':id' => $user_id]);
    $pdo->prepare("UPDATE students SET email=:em, phone=:ph WHERE user_id=:id")
        ->execute([':em' => $email, ':ph' => $phone, ':id' => $user_id]);

    flash_redirect('Profile updated successfully.', 'profile');
}

/* ==== SIGN ATTENDANCE ==== */
if (isset($_POST['sign_attendance'])) {
    validateCsrf();
    $att_course_id = (int) ($_POST['course_id'] ?? 0);
    if ($att_course_id <= 0) {
        flash_redirect('Please select a course.', 'attendance');
    }

    $enrollCheck = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:uid AND course_id=:cid AND status NOT IN ('pending','rejected','deleted')");
    $enrollCheck->execute([':uid' => $user_id, ':cid' => $att_course_id]);
    if (!$enrollCheck->fetch()) {
        flash_redirect('You are not enrolled in this course.', 'attendance');
    }

    $stmt = $pdo->prepare("SELECT id FROM attendance WHERE user_id=:uid AND course_id=:cid AND DATE(attendance_date)=CURDATE()");
    $stmt->execute([':uid' => $user_id, ':cid' => $att_course_id]);
    if ($stmt->fetch()) {
        flash_redirect('You already signed attendance today.', 'attendance');
    }

    $pdo->prepare("INSERT INTO attendance (user_id, course_id, attendance_date, status) VALUES (:uid, :cid, CURDATE(), 'present')")
        ->execute([':uid' => $user_id, ':cid' => $att_course_id]);
    flash_redirect('Attendance signed successfully.', 'attendance');
}

/* ==== CHANGE PASSWORD ==== */
if (isset($_POST['change_password'])) {
    validateCsrf();
    $current = (string) ($_POST['current_password'] ?? '');
    $new     = (string) ($_POST['new_password'] ?? '');
    $confirm = (string) ($_POST['confirm_password'] ?? '');

    if ($new !== $confirm)  { flash_redirect('New password and confirmation do not match.', 'profile'); }
    if (strlen($new) < 8)   { flash_redirect('New password must be at least 8 characters.', 'profile'); }

    $stmt = $pdo->prepare("SELECT password FROM users WHERE id=:id LIMIT 1");
    $stmt->execute([':id' => $user_id]);
    $userRow = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$userRow || !password_verify($current, $userRow['password'])) {
        flash_redirect('Current password is incorrect.', 'profile');
    }

    $pdo->prepare("UPDATE users SET password=:pw WHERE id=:id AND role='student'")
        ->execute([':pw' => password_hash($new, PASSWORD_DEFAULT), ':id' => $user_id]);
    $pdo->prepare("INSERT INTO user_settings (user_id, password_updated_at) VALUES (:uid, NOW())
                   ON DUPLICATE KEY UPDATE password_updated_at = NOW()")
        ->execute([':uid' => $user_id]);

    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    flash_redirect('Password updated successfully.', 'profile');
}

/* ==== UPLOAD PROFILE PHOTO ==== */
if (isset($_POST['upload_photo'])) {
    validateCsrf();
    $up = secureFileUpload('profile_photo', $user_id, 'profile',
        ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp']);
    if (!$up['ok'])            { flash_redirect($up['error'], 'profile'); }
    if (empty($up['filename'])) { flash_redirect('Please choose a valid image to upload.', 'profile'); }

    $pdo->prepare("UPDATE users SET profile_image=:img WHERE id=:id AND role='student'")
        ->execute([':img' => $up['filename'], ':id' => $user_id]);
    flash_redirect('Profile photo updated.', 'profile');
}

/* ==== UPDATE EXTENDED PROFILE ==== */
if (isset($_POST['update_extended_profile'])) {
    validateCsrf();
    $license = mb_substr(trim(strip_tags($_POST['license_number'] ?? '')), 0, 100);
    $qual    = trim($_POST['qualification_level'] ?? '');
    $kraPin  = strtoupper(mb_substr(trim(strip_tags($_POST['kra_pin'] ?? '')), 0, 20));

    if (!in_array($qual, ['', 'Diploma', 'Degree', 'Masters', 'PhD'], true)) { $qual = ''; }
    if ($kraPin !== '' && !preg_match('/^[A-Z]\d{9}[A-Z]$/', $kraPin)) {
        flash_redirect('KRA PIN format looks invalid. It should look like A123456789Z.', 'profile');
    }

    $pdo->prepare("UPDATE users SET kra_pin=:pin WHERE id=:id AND role='student'")
        ->execute([':pin' => $kraPin !== '' ? $kraPin : null, ':id' => $user_id]);
    $pdo->prepare("UPDATE students SET license_number=:lic, qualification_level=:qual, verification_status='pending' WHERE user_id=:id")
        ->execute([':lic' => $license !== '' ? $license : null, ':qual' => $qual !== '' ? $qual : null, ':id' => $user_id]);

    flash_redirect('Professional details submitted for admin verification.', 'profile');
}

/* ==== REFERRAL CODE ==== */
if (isset($_POST['generate_referral_code'])) {
    validateCsrf();
    $chk = $pdo->prepare("SELECT id FROM referral_codes WHERE user_id=:uid LIMIT 1");
    $chk->execute([':uid' => $user_id]);
    if (!$chk->fetch()) {
        $codeStmt = $pdo->prepare("SELECT student_no FROM students WHERE user_id=:uid LIMIT 1");
        $codeStmt->execute([':uid' => $user_id]);
        $base = $codeStmt->fetchColumn() ?: ('U' . $user_id);
        $code = strtoupper(preg_replace('/[^A-Z0-9]/i', '', $base)) . strtoupper(bin2hex(random_bytes(2)));
        $pdo->prepare("INSERT INTO referral_codes (user_id, code, status) VALUES (:uid, :code, 'active')")
            ->execute([':uid' => $user_id, ':code' => $code]);
        flash_redirect('Your referral code has been generated.', 'referrals');
    }
    flash_redirect('You already have a referral code.', 'referrals');
}

/* ==== CPD: LOG ENTRY ==== */
if (isset($_POST['submit_cpd_point'])) {
    validateCsrf();
    $cpdTitle = mb_substr(trim(strip_tags($_POST['activity_title'] ?? '')), 0, 255);
    $cpdType  = trim($_POST['activity_type'] ?? 'course');
    $cpdPts   = (float) ($_POST['points'] ?? 0);
    $cpdDate  = trim($_POST['date_earned'] ?? '');

    if (!in_array($cpdType, ['course','workshop','conference','supervision','publication','other'], true)) { $cpdType = 'other'; }
    if ($cpdTitle === '' || $cpdPts <= 0 || !DateTime::createFromFormat('Y-m-d', $cpdDate)) {
        flash_redirect('Please fill in the activity title, points, and a valid date.', 'cpd');
    }

    $upload = secureFileUpload('evidence_file', $user_id, 'cpd', DOC_MIMES);
    if (!$upload['ok']) { flash_redirect($upload['error'], 'cpd'); }

    $pdo->prepare("INSERT INTO cpd_points (user_id, activity_title, activity_type, points, date_earned, evidence_path, verification_status, created_at)
                   VALUES (:uid, :title, :type, :pts, :date, :ev, 'pending', NOW())")
        ->execute([':uid' => $user_id, ':title' => $cpdTitle, ':type' => $cpdType, ':pts' => $cpdPts,
                   ':date' => $cpdDate, ':ev' => $upload['filename']]);
    flash_redirect('CPD point logged and awaiting verification.', 'cpd');
}

/* ==== CPD: DELETE PENDING ENTRY ==== */
if (isset($_POST['delete_cpd_point'])) {
    validateCsrf();
    $cpdId = (int) ($_POST['cpd_id'] ?? 0);
    $own = $pdo->prepare("SELECT id, evidence_path FROM cpd_points WHERE id=:id AND user_id=:uid AND verification_status='pending' LIMIT 1");
    $own->execute([':id' => $cpdId, ':uid' => $user_id]);
    $existing = $own->fetch(PDO::FETCH_ASSOC);

    if ($existing) {
        if (!empty($existing['evidence_path'])) {
            $old = __DIR__ . '/uploads/' . basename($existing['evidence_path']);
            if (is_file($old)) { @unlink($old); }
        }
        $pdo->prepare("DELETE FROM cpd_points WHERE id=:id AND user_id=:uid")->execute([':id' => $cpdId, ':uid' => $user_id]);
        flash_redirect('CPD entry removed.', 'cpd');
    }
    flash_redirect('Unable to remove that CPD entry (only pending entries can be removed).', 'cpd');
}

/* ==== LOGBOOK ENTRY ==== */
if (isset($_POST['submit_logbook_entry'])) {
    validateCsrf();
    $lbDate  = trim($_POST['session_date'] ?? '');
    $lbHours = (float) ($_POST['hours'] ?? 0);
    $lbDesc  = mb_substr(trim(strip_tags($_POST['activity_description'] ?? '')), 0, 3000);
    $lbComp  = mb_substr(trim(strip_tags($_POST['competencies_covered'] ?? '')), 0, 1000);
    $lbRef   = mb_substr(trim(strip_tags($_POST['client_case_ref'] ?? '')), 0, 100);

    if (!DateTime::createFromFormat('Y-m-d', $lbDate) || $lbHours <= 0 || $lbDesc === '') {
        flash_redirect('Please provide a valid date, hours, and activity description.', 'logbook');
    }

    $pdo->prepare("INSERT INTO supervision_logbooks
                   (student_id, session_date, hours, activity_description, competencies_covered, client_case_ref, supervisor_signoff, created_at)
                   VALUES (:sid, :date, :hours, :desc, :comp, :ref, 0, NOW())")
        ->execute([':sid' => $user_id, ':date' => $lbDate, ':hours' => $lbHours, ':desc' => $lbDesc,
                   ':comp' => $lbComp !== '' ? $lbComp : null, ':ref' => $lbRef !== '' ? $lbRef : null]);
    flash_redirect('Logbook entry submitted, pending supervisor sign-off.', 'logbook');
}

/* ==== JOB APPLICATION ==== */
if (isset($_POST['apply_job'])) {
    validateCsrf();
    $jobId  = (int) ($_POST['job_id'] ?? 0);
    $letter = mb_substr(trim(strip_tags($_POST['cover_letter'] ?? '')), 0, 3000);

    $jobChk = $pdo->prepare("SELECT id FROM job_postings WHERE id=:id AND status='open'");
    $jobChk->execute([':id' => $jobId]);
    if (!$jobChk->fetch()) { flash_redirect('That job posting is no longer available.', 'jobs'); }

    $dup = $pdo->prepare("SELECT id FROM job_applications WHERE job_id=:jid AND user_id=:uid");
    $dup->execute([':jid' => $jobId, ':uid' => $user_id]);
    if ($dup->fetch()) { flash_redirect('You have already applied to this job.', 'jobs'); }

    $upload = secureFileUpload('cv_file', $user_id, 'cv', DOC_MIMES);
    if (!$upload['ok']) { flash_redirect($upload['error'], 'jobs'); }

    $pdo->prepare("INSERT INTO job_applications (job_id, user_id, cv_path, cover_letter, status, applied_at)
                   VALUES (:jid, :uid, :cv, :letter, 'submitted', NOW())")
        ->execute([':jid' => $jobId, ':uid' => $user_id, ':cv' => $upload['filename'], ':letter' => $letter !== '' ? $letter : null]);
    flash_redirect('Application submitted successfully.', 'jobs');
}

/* ==== FORUM: NEW TOPIC ==== */
if (isset($_POST['post_forum_topic'])) {
    validateCsrf();
    $fCourseId = (int) ($_POST['course_id'] ?? 0);
    $fTitle    = mb_substr(trim(strip_tags($_POST['title'] ?? '')), 0, 255);
    $fMessage  = mb_substr(trim(strip_tags($_POST['message'] ?? '')), 0, 4000);

    $chk = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:uid AND course_id=:cid AND status NOT IN ('pending','rejected','deleted')");
    $chk->execute([':uid' => $user_id, ':cid' => $fCourseId]);
    if (!$chk->fetch() || $fTitle === '' || $fMessage === '') {
        flash_redirect('Please select one of your courses and fill in a title and message.', 'forums');
    }

    $pdo->prepare("INSERT INTO forum_topics (course_id, user_id, title, message, status, created_at) VALUES (:cid, :uid, :title, :msg, 'open', NOW())")
        ->execute([':cid' => $fCourseId, ':uid' => $user_id, ':title' => $fTitle, ':msg' => $fMessage]);
    flash_redirect('Discussion topic posted.', 'forums');
}

/* ==== FORUM: REPLY ==== */
if (isset($_POST['post_forum_reply'])) {
    validateCsrf();
    $fTopicId = (int) ($_POST['topic_id'] ?? 0);
    $fReply   = mb_substr(trim(strip_tags($_POST['message'] ?? '')), 0, 4000);

    $chk = $pdo->prepare("
        SELECT ft.id FROM forum_topics ft
        INNER JOIN enrollments e ON e.course_id = ft.course_id AND e.user_id = :uid
        WHERE ft.id = :tid AND ft.status <> 'closed' AND e.status NOT IN ('pending','rejected','deleted')
    ");
    $chk->execute([':uid' => $user_id, ':tid' => $fTopicId]);
    if (!$chk->fetch() || $fReply === '') { flash_redirect('Unable to post that reply.', 'forums'); }

    $pdo->prepare("INSERT INTO forum_replies (topic_id, user_id, message, created_at) VALUES (:tid, :uid, :msg, NOW())")
        ->execute([':tid' => $fTopicId, ':uid' => $user_id, ':msg' => $fReply]);
    flash_redirect('Reply posted.', 'forums');
}

/* ==== ALUMNI PROFILE (needs a UNIQUE index on alumni.user_id) ==== */
if (isset($_POST['update_alumni_profile'])) {
    validateCsrf();
    $gradYear = (int) ($_POST['graduation_year'] ?? 0);
    $currRole = mb_substr(trim(strip_tags($_POST['current_role'] ?? '')), 0, 150);
    $org      = mb_substr(trim(strip_tags($_POST['organization'] ?? '')), 0, 150);
    $testimon = mb_substr(trim(strip_tags($_POST['testimonial'] ?? '')), 0, 2000);
    $isPublic = isset($_POST['is_public']) ? 1 : 0;
    $isMentor = isset($_POST['is_mentor_available']) ? 1 : 0;

    $pdo->prepare("
        INSERT INTO alumni (user_id, graduation_year, `current_role`, organization, testimonial, is_public, is_mentor_available, created_at)
        VALUES (:uid, :gy, :role, :org, :test, :pub, :mentor, NOW())
        ON DUPLICATE KEY UPDATE graduation_year=:gy2, `current_role`=:role2, organization=:org2,
            testimonial=:test2, is_public=:pub2, is_mentor_available=:mentor2
    ")->execute([
        ':uid' => $user_id, ':gy' => $gradYear ?: null, ':role' => $currRole ?: null, ':org' => $org ?: null,
        ':test' => $testimon ?: null, ':pub' => $isPublic, ':mentor' => $isMentor,
        ':gy2' => $gradYear ?: null, ':role2' => $currRole ?: null, ':org2' => $org ?: null,
        ':test2' => $testimon ?: null, ':pub2' => $isPublic, ':mentor2' => $isMentor,
    ]);
    flash_redirect('Alumni profile saved.', 'alumni');
}

/* ==== REQUEST MENTORSHIP ==== */
if (isset($_POST['request_mentorship'])) {
    validateCsrf();
    $mentorId = (int) ($_POST['mentor_id'] ?? 0);
    $focus    = mb_substr(trim(strip_tags($_POST['focus_area'] ?? '')), 0, 255);

    if ($mentorId <= 0 || $mentorId === $user_id) { flash_redirect('Please choose a valid mentor.', 'alumni'); }

    $ok = $pdo->prepare("SELECT id FROM alumni WHERE user_id=:m AND is_mentor_available=1 LIMIT 1");
    $ok->execute([':m' => $mentorId]);
    if (!$ok->fetch()) { flash_redirect('That person is not currently available as a mentor.', 'alumni'); }

    $dup = $pdo->prepare("SELECT id FROM mentorship_matches WHERE mentor_id=:mid AND mentee_id=:uid AND status IN ('requested','active')");
    $dup->execute([':mid' => $mentorId, ':uid' => $user_id]);
    if ($dup->fetch()) { flash_redirect('You already have a pending or active mentorship with this mentor.', 'alumni'); }

    $pdo->prepare("INSERT INTO mentorship_matches (mentor_id, mentee_id, focus_area, status, matched_at) VALUES (:mid, :uid, :focus, 'requested', NOW())")
        ->execute([':mid' => $mentorId, ':uid' => $user_id, ':focus' => $focus !== '' ? $focus : null]);
    flash_redirect('Mentorship request sent.', 'alumni');
}

/* ==== PORTFOLIO: ADD ==== */
if (isset($_POST['add_portfolio_item'])) {
    validateCsrf();
    $pTitle  = mb_substr(trim(strip_tags($_POST['title'] ?? '')), 0, 255);
    $pDesc   = mb_substr(trim(strip_tags($_POST['description'] ?? '')), 0, 2000);
    $pCat    = mb_substr(trim(strip_tags($_POST['category'] ?? '')), 0, 150);
    $pPublic = isset($_POST['is_public']) ? 1 : 0;

    if ($pTitle === '') { flash_redirect('Please give your portfolio item a title.', 'portfolio'); }

    $upload = secureFileUpload('portfolio_file', $user_id, 'portfolio', DOC_MIMES);
    if (!$upload['ok']) { flash_redirect($upload['error'], 'portfolio'); }

    $pdo->prepare("INSERT INTO portfolios (user_id, title, description, category, file_path, is_public, created_at)
                   VALUES (:uid, :title, :desc, :cat, :file, :pub, NOW())")
        ->execute([':uid' => $user_id, ':title' => $pTitle, ':desc' => $pDesc !== '' ? $pDesc : null,
                   ':cat' => $pCat !== '' ? $pCat : null, ':file' => $upload['filename'], ':pub' => $pPublic]);
    flash_redirect('Portfolio item added.', 'portfolio');
}

/* ==== PORTFOLIO: EDIT ==== */
if (isset($_POST['edit_portfolio_item'])) {
    validateCsrf();
    $pfId    = (int) ($_POST['portfolio_id'] ?? 0);
    $pTitle  = mb_substr(trim(strip_tags($_POST['title'] ?? '')), 0, 255);
    $pDesc   = mb_substr(trim(strip_tags($_POST['description'] ?? '')), 0, 2000);
    $pCat    = mb_substr(trim(strip_tags($_POST['category'] ?? '')), 0, 150);
    $pPublic = isset($_POST['is_public']) ? 1 : 0;

    $own = $pdo->prepare("SELECT id, file_path FROM portfolios WHERE id=:id AND user_id=:uid LIMIT 1");
    $own->execute([':id' => $pfId, ':uid' => $user_id]);
    $existing = $own->fetch(PDO::FETCH_ASSOC);
    if (!$existing || $pTitle === '') { flash_redirect('Unable to update that portfolio item.', 'portfolio'); }

    $newFilename = $existing['file_path'];
    $upload = secureFileUpload('portfolio_file', $user_id, 'portfolio', DOC_MIMES);
    if (!$upload['ok']) { flash_redirect($upload['error'], 'portfolio'); }
    if (!empty($upload['filename'])) {
        if (!empty($existing['file_path'])) {
            $old = __DIR__ . '/uploads/' . basename($existing['file_path']);
            if (is_file($old)) { @unlink($old); }
        }
        $newFilename = $upload['filename'];
    }

    $pdo->prepare("UPDATE portfolios SET title=:title, description=:desc, category=:cat, file_path=:file, is_public=:pub WHERE id=:id AND user_id=:uid")
        ->execute([':title' => $pTitle, ':desc' => $pDesc !== '' ? $pDesc : null, ':cat' => $pCat !== '' ? $pCat : null,
                   ':file' => $newFilename, ':pub' => $pPublic, ':id' => $pfId, ':uid' => $user_id]);
    flash_redirect('Portfolio item updated.', 'portfolio');
}

/* ==== PORTFOLIO: DELETE ==== */
if (isset($_POST['delete_portfolio_item'])) {
    validateCsrf();
    $pfId = (int) ($_POST['portfolio_id'] ?? 0);
    $own = $pdo->prepare("SELECT id, file_path FROM portfolios WHERE id=:id AND user_id=:uid LIMIT 1");
    $own->execute([':id' => $pfId, ':uid' => $user_id]);
    $existing = $own->fetch(PDO::FETCH_ASSOC);

    if ($existing) {
        if (!empty($existing['file_path'])) {
            $old = __DIR__ . '/uploads/' . basename($existing['file_path']);
            if (is_file($old)) { @unlink($old); }
        }
        $pdo->prepare("DELETE FROM portfolios WHERE id=:id AND user_id=:uid")->execute([':id' => $pfId, ':uid' => $user_id]);
        flash_redirect('Portfolio item deleted.', 'portfolio');
    }
    flash_redirect('Unable to delete that portfolio item.', 'portfolio');
}

/* ==== ENROLLMENTS, LIVE PROGRESS, AUTO-COMPLETE AT 100% ==== */
$INACTIVE = ['pending', 'rejected', 'deleted'];

$enrolledCourseMap = [];
$stmt = $pdo->prepare("SELECT course_id, status FROM enrollments WHERE user_id=:uid AND status <> 'deleted'");
$stmt->execute([':uid' => $user_id]);
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
    $enrolledCourseMap[(int) $r['course_id']] = $r['status'];
}

$activeEnrolledCourseIds = array_keys(array_filter($enrolledCourseMap, fn($s) => !in_array($s, $INACTIVE, true)));

$courseProgressMap = [];
foreach (array_keys($enrolledCourseMap) as $cid) {
    $pct = computeCourseProgress($pdo, $user_id, $cid);
    $courseProgressMap[$cid] = $pct;

    if ($pct >= 100 && $enrolledCourseMap[$cid] !== 'completed' && in_array($cid, $activeEnrolledCourseIds, true)) {
        $pdo->prepare("UPDATE enrollments SET status='completed', completed_at=NOW() WHERE user_id=:uid AND course_id=:cid")
            ->execute([':uid' => $user_id, ':cid' => $cid]);
        $enrolledCourseMap[$cid] = 'completed';

        $t = $pdo->prepare("SELECT title FROM courses WHERE id=:cid LIMIT 1");
        $t->execute([':cid' => $cid]);
        $ctitle = $t->fetchColumn() ?: 'a course';

        payments_log_activity($pdo, $user_id, "Completed course: {$ctitle}");
        issueCertificateIfMissing($pdo, $user_id, $cid, $ctitle);
    }
}

/* ==== DASHBOARD DATA ==== */
$enrolled  = count($enrolledCourseMap);
$completed = count(array_filter($enrolledCourseMap, fn($s) => $s === 'completed'));
$ongoing   = count(array_filter($enrolledCourseMap, fn($s) => !in_array($s, array_merge($INACTIVE, ['completed']), true)));
$progress  = $enrolled > 0 ? (int) round(array_sum($courseProgressMap) / count($courseProgressMap)) : 0;

$total_courses     = $enrolled;
$active_courses    = $ongoing;
$completed_courses = $completed;

$certs_rows = fetchAllStudentCertificates($pdo, $user_id);
$certificates_earned = count($certs_rows);

$stmt = $pdo->prepare("
    SELECT c.id, c.title, c.lessons, e.status
    FROM courses c INNER JOIN enrollments e ON c.id = e.course_id
    WHERE e.user_id = :uid AND e.status NOT IN ('rejected','deleted')
");
$stmt->execute([':uid' => $user_id]);
$courses_widget_rows = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $row['progress'] = $courseProgressMap[(int) $row['id']] ?? 0;
    $courses_widget_rows[] = $row;
}
usort($courses_widget_rows, fn($a, $b) => $b['progress'] <=> $a['progress']);
$courseProgressRows  = $courses_widget_rows;               // progress page shows all of them
$courses_widget_rows = array_slice($courses_widget_rows, 0, 5);

$stmt = $pdo->prepare("SELECT message, created_at FROM activities WHERE user_id=:uid ORDER BY created_at DESC LIMIT 5");
$stmt->execute([':uid' => $user_id]);
$activities_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT title, created_at FROM bookmarks WHERE user_id=:uid ORDER BY created_at DESC LIMIT 10");
$stmt->execute([':uid' => $user_id]);
$bookmarks_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("
    SELECT message, created_at AS notification_date, 'notification' AS type
    FROM notifications WHERE user_id=:uid1
    UNION ALL
    SELECT CONCAT('[Announcement] ', a.title, ' - ', a.message), a.created_at, 'announcement'
    FROM announcements a
    INNER JOIN enrollments e ON e.course_id=a.course_id
    WHERE e.user_id=:uid2 AND e.status NOT IN ('pending','rejected','deleted')
    ORDER BY notification_date DESC LIMIT 10
");
$stmt->execute([':uid1' => $user_id, ':uid2' => $user_id]);
$notifications_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Profile (explicit columns: never pull the password hash into the view) */
$stmt = $pdo->prepare("
    SELECT u.id, u.full_name, u.email, u.phone, u.location, u.bio, u.profile_image, u.created_at, u.kra_pin, s.student_no
    FROM users u LEFT JOIN students s ON s.user_id = u.id
    WHERE u.id = :id LIMIT 1
");
$stmt->execute([':id' => $user_id]);
$profile = $stmt->fetch(PDO::FETCH_ASSOC)
    ?: ['full_name' => 'Unknown', 'email' => '', 'phone' => '', 'location' => '', 'bio' => '', 'profile_image' => '',
        'created_at' => date('Y-m-d'), 'student_no' => '', 'kra_pin' => ''];

/* Materials */
$materials_rows = [];
if (!empty($activeEnrolledCourseIds)) {
    $in = implode(',', array_map('intval', $activeEnrolledCourseIds));
    try {
        $materials_rows = $pdo->query("SELECT cm.* FROM course_materials cm WHERE cm.course_id IN ($in) ORDER BY cm.id DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        try {
            $materials_rows = $pdo->query("
                SELECT id, title, course_id, file_path, 0 AS downloads FROM notes
                WHERE course_id IN ($in) AND file_path IS NOT NULL AND file_path != '' ORDER BY id DESC LIMIT 10
            ")->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e2) { $materials_rows = []; }
    }
}

/* Live classes */
$live_classes_rows = [];
if (!empty($activeEnrolledCourseIds)) {
    $in = implode(',', array_map('intval', $activeEnrolledCourseIds));
    $live_classes_rows = $pdo->query("SELECT lc.* FROM live_classes lc WHERE lc.course_id IN ($in) ORDER BY lc.schedule_time ASC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);
}

/* Browse courses (instructor via JOIN instead of one query per course) */
$search = mb_substr(trim(strip_tags($_GET['search'] ?? '')), 0, 100);
$sql = "
    SELECT c.id, c.title, c.description, c.price, c.lessons, c.enrolled_students, c.teacher_id, u.full_name AS instructor
    FROM courses c
    LEFT JOIN teachers t ON t.id = c.teacher_id
    LEFT JOIN users u ON u.id = t.user_id
    WHERE c.status='Active'" . ($search !== '' ? " AND c.title LIKE :like" : "") . "
    ORDER BY c.created_at DESC";
$stmt = $pdo->prepare($sql);
$stmt->execute($search !== '' ? [':like' => "%{$search}%"] : []);
$browseCoursesData = [];
foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $course) {
    $course['instructor'] = $course['instructor'] ?: 'Unknown';
    $browseCoursesData[] = $course;
}

$trendingCourses_rows = $pdo->query("SELECT title, enrolled_students FROM courses WHERE status='Active' ORDER BY enrolled_students DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

$topInstructors_rows = $pdo->query("
    SELECT u.full_name, t.specialization, t.experience_years, COUNT(c.id) AS courses_count
    FROM teachers t INNER JOIN users u ON u.id=t.user_id
    LEFT JOIN courses c ON c.teacher_id=t.id
    GROUP BY t.id, u.full_name, t.specialization, t.experience_years
    ORDER BY courses_count DESC LIMIT 5
")->fetchAll(PDO::FETCH_ASSOC);

$categories = array_column($pdo->query("SELECT DISTINCT category FROM courses WHERE status='Active' AND category IS NOT NULL AND category != ''")->fetchAll(PDO::FETCH_ASSOC), 'category');
if (empty($categories)) {
    $categories = ['Web Development', 'Programming', 'UI/UX Design', 'Cyber Security', 'Data Science', 'Mobile Development'];
}

$courseBenefits = [
    ['title' => 'Learn Anytime',      'description' => 'Access courses 24/7 from any device.'],
    ['title' => 'Expert Instructors', 'description' => 'Learn from industry professionals.'],
    ['title' => 'Certified Learning', 'description' => 'Get certificates after completion.'],
];

/* Progress page */
$progressTotalCourses     = $enrolled;
$progressCompletedCourses = $completed;
$progressOngoingCourses   = $ongoing;
$overallProgress = $progressTotalCourses > 0 ? (int) round(($progressCompletedCourses / $progressTotalCourses) * 100) : 0;

$stmt = $pdo->prepare("SELECT * FROM quiz_results WHERE user_id=:uid ORDER BY completed_at DESC LIMIT 10");
$stmt->execute([':uid' => $user_id]);
$quizPerformance_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$progressCertificates_rows = $certs_rows;

$stmt = $pdo->prepare("SELECT * FROM learning_stats WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$analytics = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['study_hours' => 0, 'lessons_completed' => 0, 'assignments_submitted' => 0];

$progressAchievements = [];
if ($progressCompletedCourses > 0) {
    $progressAchievements[] = ['title' => 'Completed Courses', 'description' => "$progressCompletedCourses course(s) completed"];
}
if ($overallProgress >= 50) {
    $progressAchievements[] = ['title' => 'Learning Progress', 'description' => "You reached {$overallProgress}% overall"];
}
$stmt = $pdo->prepare("SELECT * FROM quiz_results WHERE user_id=:uid ORDER BY score DESC LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$topQuiz = $stmt->fetch(PDO::FETCH_ASSOC);
if ($topQuiz) {
    $progressAchievements[] = ['title' => 'Top Quiz Performer', 'description' => ($topQuiz['quiz_title'] ?? 'Quiz') . ' - Score: ' . (int) $topQuiz['score'] . '%'];
}

/* Payments */
$stmt = $pdo->prepare("SELECT COALESCE(SUM(amount),0) FROM payments WHERE user_id=:uid AND status='completed'");
$stmt->execute([':uid' => $user_id]);
$totalPaid = $stmt->fetchColumn() ?: 0;

$stmt = $pdo->prepare("SELECT COALESCE(SUM(amount),0) FROM payments WHERE user_id=:uid AND status='pending'");
$stmt->execute([':uid' => $user_id]);
$pendingPayments = $stmt->fetchColumn() ?: 0;

$stmt = $pdo->prepare("
    SELECT p.*, c.title AS course_title
    FROM payments p LEFT JOIN courses c ON c.id = p.course_id
    WHERE p.user_id=:uid ORDER BY p.created_at DESC
");
$stmt->execute([':uid' => $user_id]);
$transactions_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM invoices WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid' => $user_id]);
$invoices_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("SELECT * FROM payment_methods WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid' => $user_id]);
$paymentMethods_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$invoices_count     = count($invoices_rows);
$transactions_count = count($transactions_rows);

$stmt = $pdo->prepare("
    SELECT id, title, price FROM courses
    WHERE price > 0 AND status='Active'
      AND id NOT IN (SELECT course_id FROM enrollments WHERE user_id=:uid)
    ORDER BY title ASC
");
$stmt->execute([':uid' => $user_id]);
$payableCoursesData = $stmt->fetchAll(PDO::FETCH_ASSOC);
$hasPayableCourses  = !empty($payableCoursesData);

/* Settings, tickets */
$stmt = $pdo->prepare("SELECT * FROM user_settings WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$settingsRow = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['theme' => 'light', 'email_notifications' => 1, 'sms_notifications' => 1, 'password_updated_at' => null];

$stmt = $pdo->prepare("SELECT * FROM tickets WHERE user_id=:uid ORDER BY id DESC");
$stmt->execute([':uid' => $user_id]);
$tickets_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Attendance */
$stmt = $pdo->prepare("SELECT a.*, c.title FROM attendance a JOIN courses c ON a.course_id=c.id WHERE a.user_id=:uid ORDER BY a.attendance_date DESC");
$stmt->execute([':uid' => $user_id]);
$att_history_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("
    SELECT c.id, c.title FROM courses c
    INNER JOIN enrollments e ON e.course_id = c.id
    WHERE e.user_id = :uid AND e.status NOT IN ('pending','rejected','deleted')
    ORDER BY c.title ASC
");
$stmt->execute([':uid' => $user_id]);
$att_courses_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Professional profile + resource hub */
$stmt = $pdo->prepare("SELECT license_number, qualification_level, verification_status FROM students WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$extendedProfile = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['license_number' => null, 'qualification_level' => null, 'verification_status' => 'unverified'];

$resourceCategories = $pdo->query("SELECT * FROM resource_hub_categories ORDER BY sort_order ASC, name ASC")->fetchAll(PDO::FETCH_ASSOC);
$resourceItemsByCategory = [];
foreach ($pdo->query("SELECT * FROM resource_hub_items WHERE access_level IN ('all','students') ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC) as $ri) {
    $resourceItemsByCategory[(int) $ri['category_id']][] = $ri;
}

/* Referrals */
$stmt = $pdo->prepare("SELECT * FROM referral_codes WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$myReferralCode = $stmt->fetch(PDO::FETCH_ASSOC);

$myReferrals_rows = [];
$myRewardsTotal   = 0;
$myReferralLink   = '';
if ($myReferralCode) {
    $stmt = $pdo->prepare("SELECT * FROM referrals WHERE referral_code_id=:rcid ORDER BY created_at DESC");
    $stmt->execute([':rcid' => $myReferralCode['id']]);
    $myReferrals_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("
        SELECT COALESCE(SUM(rr.amount),0) FROM referral_rewards rr
        INNER JOIN referrals r ON r.id = rr.referral_id
        WHERE r.referral_code_id = :rcid AND rr.status IN ('approved','paid')
    ");
    $stmt->execute([':rcid' => $myReferralCode['id']]);
    $myRewardsTotal = (float) ($stmt->fetchColumn() ?: 0);

    $scheme = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ? 'https://' : 'http://';
    $host   = preg_replace('/[^a-zA-Z0-9\.\-:]/', '', $_SERVER['HTTP_HOST'] ?? '');
    $base   = rtrim(str_replace('student.php', '', $_SERVER['PHP_SELF'] ?? ''), '/');
    $myReferralLink = $scheme . $host . $base . '/register.php?ref=' . urlencode($myReferralCode['code']);
}

/* CPD */
$stmt = $pdo->prepare("SELECT * FROM cpd_points WHERE user_id=:uid ORDER BY date_earned DESC");
$stmt->execute([':uid' => $user_id]);
$cpdPoints_rows   = $stmt->fetchAll(PDO::FETCH_ASSOC);
$cpdVerifiedTotal = array_sum(array_map(fn($r) => $r['verification_status'] === 'verified' ? (float) $r['points'] : 0, $cpdPoints_rows));
$cpdPendingTotal  = array_sum(array_map(fn($r) => $r['verification_status'] === 'pending'  ? (float) $r['points'] : 0, $cpdPoints_rows));

/* Logbook */
$stmt = $pdo->prepare("SELECT * FROM supervision_logbooks WHERE student_id=:uid ORDER BY session_date DESC");
$stmt->execute([':uid' => $user_id]);
$logbook_rows        = $stmt->fetchAll(PDO::FETCH_ASSOC);
$logbookSignedHours  = array_sum(array_map(fn($r) => (int) $r['supervisor_signoff'] === 1 ? (float) $r['hours'] : 0, $logbook_rows));
$logbookPendingHours = array_sum(array_map(fn($r) => (int) $r['supervisor_signoff'] === 0 ? (float) $r['hours'] : 0, $logbook_rows));

/* Jobs */
$jobPostings_rows = $pdo->query("SELECT * FROM job_postings WHERE status='open' ORDER BY created_at DESC LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);
$stmt = $pdo->prepare("
    SELECT ja.*, jp.title AS job_title, jp.organization
    FROM job_applications ja INNER JOIN job_postings jp ON jp.id = ja.job_id
    WHERE ja.user_id = :uid ORDER BY ja.applied_at DESC
");
$stmt->execute([':uid' => $user_id]);
$myJobApplications_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$appliedJobIds = array_map('intval', array_column($myJobApplications_rows, 'job_id'));

/* Forums */
$forumTopics_rows = [];
if (!empty($activeEnrolledCourseIds)) {
    $in = implode(',', array_map('intval', $activeEnrolledCourseIds));
    $forumTopics_rows = $pdo->query("
        SELECT ft.*, c.title AS course_title, u.full_name AS author_name
        FROM forum_topics ft
        INNER JOIN courses c ON c.id = ft.course_id
        LEFT JOIN users u ON u.id = ft.user_id
        WHERE ft.course_id IN ($in)
        ORDER BY ft.created_at DESC LIMIT 25
    ")->fetchAll(PDO::FETCH_ASSOC);
}
$forumRepliesByTopic = [];
if (!empty($forumTopics_rows)) {
    $topicIds = implode(',', array_map(fn($t) => (int) $t['id'], $forumTopics_rows));
    $reps = $pdo->query("
        SELECT fr.*, u.full_name AS author_name FROM forum_replies fr
        LEFT JOIN users u ON u.id = fr.user_id
        WHERE fr.topic_id IN ($topicIds) ORDER BY fr.created_at ASC
    ")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($reps as $r) { $forumRepliesByTopic[(int) $r['topic_id']][] = $r; }
}

/* Alumni & mentorship */
$stmt = $pdo->prepare("SELECT * FROM alumni WHERE user_id=:uid LIMIT 1");
$stmt->execute([':uid' => $user_id]);
$myAlumniProfile = $stmt->fetch(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("
    SELECT al.*, u.full_name, u.id AS mentor_user_id
    FROM alumni al INNER JOIN users u ON u.id = al.user_id
    WHERE al.is_mentor_available = 1 AND al.user_id <> :uid
    ORDER BY al.created_at DESC LIMIT 20
");
$stmt->execute([':uid' => $user_id]);
$availableMentors_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stmt = $pdo->prepare("
    SELECT mm.*, u.full_name AS mentor_name
    FROM mentorship_matches mm INNER JOIN users u ON u.id = mm.mentor_id
    WHERE mm.mentee_id = :uid ORDER BY mm.matched_at DESC
");
$stmt->execute([':uid' => $user_id]);
$myMentorships_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* Portfolio + promos */
$stmt = $pdo->prepare("SELECT * FROM portfolios WHERE user_id=:uid ORDER BY created_at DESC");
$stmt->execute([':uid' => $user_id]);
$portfolio_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

try {
    $promoSlots_rows = $pdo->query("
        SELECT * FROM promo_slots
        WHERE status='active' AND (starts_at IS NULL OR starts_at <= NOW()) AND (ends_at IS NULL OR ends_at >= NOW())
        ORDER BY sort_order ASC, created_at DESC LIMIT 5
    ")->fetchAll(PDO::FETCH_ASSOC);
} catch (Throwable $e) { $promoSlots_rows = []; }

/* ==== FLASH + ACTIVE SECTION ==== */
$flash = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);

$active_section_map = [
    'profile' => 'profileSection', 'payments' => 'paymentsSection', 'attendance' => 'attendanceSection',
    'browse' => 'browseCoursesSection', 'resourcehub' => 'resourceHubSection', 'referrals' => 'referralsSection',
    'cpd' => 'cpdSection', 'logbook' => 'logbookSection', 'jobs' => 'jobsSection', 'forums' => 'forumsSection',
    'alumni' => 'alumniSection', 'portfolio' => 'portfolioSection', 'certificates' => 'certificatesSection',
];
$active_section_key = $_SESSION['active_section'] ?? '';
unset($_SESSION['active_section']);
if ($active_section_key === '' && isset($_GET['search'])) { $active_section_key = 'browse'; }
$active_section_id = $active_section_map[$active_section_key] ?? '';

$JSON_SAFE  = JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP;
$app_js     = json_encode(['activeSection' => $active_section_id ?: 'dashboardContent'], $JSON_SAFE);
$csrf       = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
$flashIsErr = $flash !== '' && preg_match('/\b(invalid|failed|unable|not |please|wrong|error|incorrect|already|sorry)\b/i', $flash);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Student Dashboard - <?= htmlspecialchars(CERT_ORG_NAME) ?> <?= htmlspecialchars(CERT_PROGRAM_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="stylesheet" href="Student.css">
</head>
<body>

<div class="topbar">
    <button class="hamburger" onclick="toggleSidebar()" aria-label="Menu"><i class="fas fa-bars"></i></button>
    <h2>CBT-Kenya STP</h2>
    <span style="width:36px;"></span>
</div>
<div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

<div class="layout">
<nav class="sidebar" id="sidebar" role="navigation" aria-label="Main menu">
    <div class="sidebar-logo">
        <img src="cbt-ke.png" alt="CBT-Kenya">
        <p>Skills Transfer Program</p>
    </div>
    <ul class="nav-menu" id="navMenu">
        <?php
        $nav = [
            ['dashboardContent',     'fa-home',           'Dashboard'],
            ['coursesSection',       'fa-book-open',      'My Courses'],
            ['browseCoursesSection', 'fa-search',         'Browse Courses'],
            ['progressSection',      'fa-chart-line',     'Progress'],
            ['certificatesSection',  'fa-award',          'My Certificates'],
            ['attendanceSection',    'fa-user-check',     'Attendance'],
            ['paymentsSection',      'fa-credit-card',    'Payments'],
            ['notificationsSection', 'fa-bell',           'Notifications'],
            ['bookmarksSection',     'fa-bookmark',       'Bookmarks'],
            ['forumsSection',        'fa-comments',       'Discussion Forums'],
            ['resourceHubSection',   'fa-briefcase-medical', 'Resource Hub'],
            ['cpdSection',           'fa-graduation-cap', 'CPD / CME Points'],
            ['logbookSection',       'fa-notes-medical',  'Logbook'],
            ['jobsSection',          'fa-briefcase',      'Jobs'],
            ['alumniSection',        'fa-user-graduate',  'Alumni &amp; Mentors'],
            ['referralsSection',     'fa-user-friends',   'Referrals'],
            ['portfolioSection',     'fa-folder-open',    'Portfolio'],
            ['ticketSection',        'fa-ticket-alt',     'Support'],
            ['profileSection',       'fa-user',           'Profile'],
            ['settingsSection',      'fa-cog',            'Settings'],
        ];
        foreach ($nav as [$sid, $icon, $label]): ?>
            <li><a href="#" data-section="<?= $sid ?>" onclick="showSection('<?= $sid ?>', this); return false;"><i class="fas <?= $icon ?>"></i><?= $label ?></a></li>
        <?php endforeach; ?>
        <li class="logout"><a href="student.php?action=logout"><i class="fas fa-sign-out-alt"></i>Logout</a></li>
    </ul>
</nav>

<main class="main">

<?php if ($flash): ?>
    <div class="flash<?= $flashIsErr ? ' error' : '' ?>"><?= htmlspecialchars($flash) ?></div>
<?php endif; ?>

<!-- DASHBOARD -->
<div id="dashboardContent" class="section">
    <div class="page-header">
        <h1>Welcome back, <?= htmlspecialchars($profile['full_name'] ?? 'Student') ?></h1>
        <p>Track your learning progress and manage your courses.</p>
    </div>

    <?php if (!empty($promoSlots_rows)): ?>
    <div class="promo-strip">
        <?php foreach ($promoSlots_rows as $promo): ?>
            <div class="promo-card">
                <span class="promo-tag"><?= htmlspecialchars($promo['tag'] ?? 'CBT-Kenya') ?></span>
                <h4><?= htmlspecialchars($promo['title'] ?? '') ?></h4>
                <?php if (!empty($promo['description'])): ?><p><?= htmlspecialchars(mb_strimwidth($promo['description'], 0, 110, '…')) ?></p><?php endif; ?>
                <?php if (!empty($promo['link_url']) && preg_match('#^https?://#i', $promo['link_url'])): ?>
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
            <?php if (empty($courses_widget_rows)): ?>
                <div class="activity-item"><p>No courses yet</p><span>Browse courses to get started.</span></div>
            <?php endif; ?>
            <?php foreach ($courses_widget_rows as $row): ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($row['title']) ?></h4>
                        <p><?= (int) $row['progress'] ?>% completed</p>
                        <div class="progress-bar-wrap"><div class="progress-fill" style="width:<?= (int) $row['progress'] ?>%"></div></div>
                    </div>
                    <?php if (($row['status'] ?? '') === 'pending'): ?>
                        <span class="enroll-label pending"><i class="fas fa-hourglass-half"></i> Pending Approval</span>
                    <?php else: ?>
                        <a href="course1.php?id=<?= (int) $row['id'] ?>" class="btn small <?= ($row['status'] ?? '') === 'completed' ? 'dark' : '' ?>">
                            <?php if (($row['status'] ?? '') === 'completed'): ?><i class="fas fa-check-double"></i> Review<?php else: ?><i class="fas fa-play"></i> Continue<?php endif; ?>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="card">
            <div class="card-title"><i class="fas fa-history"></i>Recent Activities</div>
            <?php foreach ($activities_rows as $act): ?>
                <div class="activity-item"><p><?= htmlspecialchars($act['message']) ?></p><span><?= htmlspecialchars($act['created_at']) ?></span></div>
            <?php endforeach; ?>
            <?php if (empty($activities_rows)): ?><div class="activity-item"><p>No recent activity</p></div><?php endif; ?>
        </div>
    </div>
</div>

<!-- MY COURSES -->
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
                $pct = min(100, max(0, (int) ($row['progress'] ?? 0)));
                $isCompleted = ($row['status'] ?? '') === 'completed';
                $isPending   = ($row['status'] ?? '') === 'pending';
            ?>
                <div class="course-row">
                    <div class="course-info" style="flex:1;">
                        <h4><?= htmlspecialchars($row['title']) ?></h4>
                        <p style="margin-bottom:6px;">
                            <?= (int) ($row['lessons'] ?? 0) ?> lessons &nbsp;•&nbsp; <strong style="color:var(--navy);"><?= $pct ?>%</strong> completed
                            <?php if ($isCompleted): ?>&nbsp;•&nbsp;<span style="color:var(--teal);font-weight:700;">Completed</span>
                            <?php elseif ($isPending): ?>&nbsp;•&nbsp;<span style="color:var(--gold-dark);font-weight:700;">Pending Admin Approval</span><?php endif; ?>
                        </p>
                        <div class="progress-bar-wrap" style="width:100%;max-width:320px;"><div class="progress-fill" style="width:<?= $pct ?>%;"></div></div>
                    </div>
                    <?php if ($isPending): ?>
                        <span class="enroll-label pending" style="flex-shrink:0;"><i class="fas fa-hourglass-half"></i> Pending</span>
                    <?php else: ?>
                        <a href="course1.php?id=<?= (int) $row['id'] ?>" class="btn small <?= $isCompleted ? 'dark' : '' ?>" style="flex-shrink:0;">
                            <?php if ($isCompleted): ?><i class="fas fa-check-double"></i> Review<?php else: ?><i class="fas fa-play"></i> Continue<?php endif; ?>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="activity-item"><p>No courses in progress</p>
                <span><a href="#" onclick="showSection('browseCoursesSection'); return false;" style="color:var(--teal);font-weight:600;">Browse courses to get started →</a></span>
            </div>
        <?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-folder-open"></i>Course Materials</div>
        <?php if (!empty($materials_rows)): ?>
            <?php foreach ($materials_rows as $mat): ?>
                <div class="activity-item"><p><?= htmlspecialchars($mat['title'] ?? '') ?></p><span>Downloaded <?= (int) ($mat['downloads'] ?? 0) ?> times</span></div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No materials available</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-video"></i>Upcoming Live Classes</div>
        <?php if (!empty($live_classes_rows)): ?>
            <?php foreach ($live_classes_rows as $live): ?>
                <div class="activity-item"><p><?= htmlspecialchars($live['title'] ?? '') ?></p>
                    <span><?= !empty($live['schedule_time']) ? date('d F Y • h:i A', strtotime($live['schedule_time'])) : 'N/A' ?></span></div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No live classes scheduled</p></div><?php endif; ?>
    </div>
</div>

<!-- PROGRESS -->
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
                        <p><?= (int) ($cp['progress'] ?? 0) ?>% completed</p>
                        <div class="progress-bar-wrap"><div class="progress-fill" style="width:<?= (int) ($cp['progress'] ?? 0) ?>%"></div></div>
                    </div>
                    <span style="color:<?= ($cp['status'] ?? '') === 'completed' ? 'var(--teal)' : 'var(--green)' ?>;font-weight:700;"><?= htmlspecialchars(ucfirst($cp['status'] ?? 'ongoing')) ?></span>
                </div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No progress data</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-question-circle"></i>Quiz Performance</div>
        <?php if (!empty($quizPerformance_rows)): ?>
            <?php foreach ($quizPerformance_rows as $qp):
                $qDate = $qp['completed_at'] ?? $qp['created_at'] ?? null; ?>
                <div class="activity-item"><p><?= htmlspecialchars($qp['quiz_title'] ?? 'Quiz') ?></p>
                    <span>Score: <?= (int) ($qp['score'] ?? 0) ?>% • <?= htmlspecialchars(ucfirst($qp['status'] ?? '')) ?><?= $qDate ? ' • ' . date('d M Y', strtotime($qDate)) : '' ?></span></div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No quiz results yet</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-award"></i>Certificates</div>
        <p style="color:var(--gray-500);font-size:.85rem;margin-top:-12px;margin-bottom:16px;">Certificates are generated automatically once a course reaches 100% completion, or issued directly by an administrator.</p>
        <?php if (!empty($progressCertificates_rows)): ?>
            <?php foreach ($progressCertificates_rows as $cert):
                $qrSrc = null;
                if (!empty($cert['qr_code_path'])) {
                    $qrBase = basename(strip_tags(trim($cert['qr_code_path'])));
                    if (in_array(strtolower(pathinfo($qrBase, PATHINFO_EXTENSION)), ['png','jpg','jpeg','svg'], true) && is_file(__DIR__ . '/uploads/' . $qrBase)) {
                        $qrSrc = 'uploads/' . $qrBase;
                    }
                }
                $codeLink = trim($cert['certificate_code'] ?? '');
                $dlUrl = $codeLink !== '' ? 'student.php?action=certificate&code=' . urlencode($codeLink) : 'student.php?action=certificate&id=' . (int) $cert['id'];
            ?>
                <div class="activity-item" style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;">
                    <div>
                        <p><i class="fas fa-certificate" style="color:var(--gold-dark);"></i> <?= htmlspecialchars($cert['title'] ?? '') ?></p>
                        <span>Issued <?= !empty($cert['issued_at']) ? date('d F Y', strtotime($cert['issued_at'])) : '' ?>
                            <?php if ($codeLink !== ''): ?>&nbsp;•&nbsp;Cert No: <strong style="color:var(--navy);"><?= htmlspecialchars($codeLink) ?></strong><?php endif; ?></span>
                        <div class="item-actions">
                            <a class="btn small gold" href="<?= htmlspecialchars($dlUrl, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer"><i class="fas fa-download"></i> View / Download Certificate</a>
                        </div>
                    </div>
                    <?php if ($qrSrc): ?><img src="<?= htmlspecialchars($qrSrc, ENT_QUOTES, 'UTF-8') ?>" alt="Certificate verification QR code" style="width:64px;height:64px;border-radius:8px;border:1px solid var(--gray-200);"><?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No certificates yet</p><span>Finish 100% of a course to earn your certificate automatically.</span></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-chart-bar"></i>Learning Analytics</div>
        <div class="activity-item"><p>Total Study Hours</p><span><?= (int) ($analytics['study_hours'] ?? 0) ?> hrs</span></div>
        <div class="activity-item"><p>Lessons Completed</p><span><?= (int) ($analytics['lessons_completed'] ?? 0) ?></span></div>
        <div class="activity-item"><p>Assignments Submitted</p><span><?= (int) ($analytics['assignments_submitted'] ?? 0) ?></span></div>
        <div class="activity-item"><p>Avg Daily Study</p><span><?= round(($analytics['study_hours'] ?? 0) / 30, 1) ?> hrs/day</span></div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-trophy"></i>Achievements</div>
        <?php if (!empty($progressAchievements)): ?>
            <?php foreach ($progressAchievements as $a): ?>
                <div class="activity-item"><p><?= htmlspecialchars($a['title']) ?></p><span><?= htmlspecialchars($a['description']) ?></span></div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No achievements yet</p></div><?php endif; ?>
    </div>
</div>

<!-- MY CERTIFICATES -->
<div id="certificatesSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-award"></i>My Certificates</div>
        <p style="color:var(--gray-500);font-size:.88rem;margin-top:-12px;margin-bottom:16px;">Each certificate has a unique number and a scannable QR code that anyone can use to verify it - great for sharing with employers.</p>
        <div class="stats-grid" style="margin-bottom:0;">
            <div class="stat-box gold"><i class="fas fa-certificate"></i><h2><?= count($certs_rows) ?></h2><p>Certificates Earned</p></div>
            <div class="stat-box"><i class="fas fa-book"></i><h2><?= $completed_courses ?></h2><p>Courses Completed</p></div>
            <div class="stat-box green"><i class="fas fa-chart-pie"></i><h2><?= $progress ?>%</h2><p>Overall Progress</p></div>
        </div>
    </div>

    <?php if (!empty($certs_rows)): ?>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;">
        <?php foreach ($certs_rows as $cert):
            $cTitle  = strip_cert_prefix($cert['title'] ?? '');
            $cCode   = trim($cert['certificate_code'] ?? '');
            $cIssued = !empty($cert['issued_at']) ? date('d F Y', strtotime($cert['issued_at'])) : '';
            $dlUrl   = $cCode !== '' ? 'student.php?action=certificate&code=' . urlencode($cCode) : 'student.php?action=certificate&id=' . (int) $cert['id'];
            $vfUrl   = $cCode !== '' ? 'student.php?action=verify&code=' . urlencode($cCode) : '';
        ?>
            <div class="card" style="margin-bottom:0;border-top-color:var(--gold);">
                <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:14px;">
                    <div style="width:46px;height:46px;border-radius:50%;background:linear-gradient(135deg,var(--gold) 0%,var(--gold-dark) 100%);display:flex;align-items:center;justify-content:center;flex-shrink:0;"><i class="fas fa-certificate" style="color:#fff;font-size:1.2rem;"></i></div>
                    <div>
                        <h4 style="font-size:1rem;color:var(--navy);margin-bottom:4px;"><?= htmlspecialchars($cTitle) ?></h4>
                        <p style="color:var(--gray-500);font-size:.82rem;">Issued <?= htmlspecialchars($cIssued) ?></p>
                    </div>
                </div>
                <div class="activity-item" style="margin-bottom:14px;"><p>Certificate No.</p>
                    <span style="font-weight:700;color:var(--navy);"><?= $cCode !== '' ? htmlspecialchars($cCode) : 'Pending assignment' ?></span></div>
                <div class="item-actions" style="margin-top:0;">
                    <a class="btn small gold" style="flex:1;justify-content:center;" href="<?= htmlspecialchars($dlUrl, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer"><i class="fas fa-download"></i> View / Download</a>
                    <?php if ($vfUrl): ?><a class="btn small outline" href="<?= htmlspecialchars($vfUrl, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer"><i class="fas fa-shield-alt"></i> Verify</a><?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    <?php else: ?>
        <div class="card"><div class="activity-item" style="text-align:center;padding:34px 16px;">
            <p style="font-size:1.05rem;"><i class="fas fa-award" style="color:var(--gray-500);"></i> No certificates yet</p>
            <span>Finish 100% of any enrolled course and your certificate will appear here automatically.</span></div></div>
    <?php endif; ?>
</div>

<!-- BROWSE COURSES -->
<div id="browseCoursesSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-search"></i>Browse Courses</div>
        <form method="GET" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
            <div class="form-group" style="flex:1;margin:0;">
                <input type="text" name="search" value="<?= htmlspecialchars($search) ?>" placeholder="Search courses by title…" maxlength="100">
            </div>
            <button type="submit" class="btn"><i class="fas fa-search"></i> Search</button>
        </form>
        <div class="card-title" style="font-size:1rem;"><i class="fas fa-layer-group"></i>Categories</div>
        <div class="chip-wrap"><?php foreach ($categories as $cat): ?><span class="chip"><?= htmlspecialchars($cat) ?></span><?php endforeach; ?></div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-star"></i>Featured Courses</div>
        <?php if (!empty($browseCoursesData)): ?>
            <?php foreach ($browseCoursesData as $course):
                $cid = (int) $course['id'];
                $enrollStatus = $enrolledCourseMap[$cid] ?? null;
            ?>
                <div class="course-row">
                    <div class="course-info">
                        <h4><?= htmlspecialchars($course['title']) ?></h4>
                        <p><?= htmlspecialchars(mb_strimwidth($course['description'] ?? '', 0, 90, '…')) ?></p>
                        <p style="color:var(--teal);font-weight:700;margin-top:6px;"><?= (float) $course['price'] > 0 ? 'KES ' . number_format((float) $course['price']) : 'Free' ?></p>
                        <p style="font-size:.82rem;"><?= htmlspecialchars($course['instructor']) ?> • <?= (int) $course['lessons'] ?> lessons • <?= number_format((int) $course['enrolled_students']) ?> students</p>
                    </div>
                    <?php if ($enrollStatus === null): ?>
                        <a href="enroll.php?course_id=<?= $cid ?>" class="btn small"><i class="fas fa-plus"></i> Enroll</a>
                    <?php elseif ($enrollStatus === 'pending'): ?>
                        <span class="enroll-label pending" title="Awaiting admin approval"><i class="fas fa-hourglass-half"></i> Pending Approval</span>
                    <?php elseif ($enrollStatus === 'rejected'): ?>
                        <span class="enroll-label" style="background:#fee2e2;color:#991b1b;"><i class="fas fa-times-circle"></i> Rejected</span>
                    <?php elseif ($enrollStatus === 'completed'): ?>
                        <a href="course1.php?id=<?= $cid ?>" class="enroll-label completed" title="Course completed - click to review"><i class="fas fa-check-double"></i> Completed</a>
                    <?php else: ?>
                        <a href="course1.php?id=<?= $cid ?>" class="btn small green"><i class="fas fa-play"></i> Continue</a>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php else: ?><div class="activity-item"><p>No courses found</p><span>Try a different keyword</span></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-fire"></i>Trending Courses</div>
        <?php foreach ($trendingCourses_rows as $trend): ?>
            <div class="activity-item"><p><?= htmlspecialchars($trend['title']) ?></p><span><?= number_format((int) $trend['enrolled_students']) ?> students</span></div>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-chalkboard-teacher"></i>Top Instructors</div>
        <?php foreach ($topInstructors_rows as $inst): ?>
            <div class="activity-item"><p><?= htmlspecialchars($inst['full_name']) ?></p>
                <span><?= htmlspecialchars($inst['specialization'] ?? '') ?> • <?= (int) $inst['experience_years'] ?> yrs • <?= (int) $inst['courses_count'] ?> courses</span></div>
        <?php endforeach; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-gift"></i>Why Learn With Us?</div>
        <?php foreach ($courseBenefits as $b): ?>
            <div class="activity-item"><p><?= htmlspecialchars($b['title']) ?></p><span><?= htmlspecialchars($b['description']) ?></span></div>
        <?php endforeach; ?>
    </div>
</div>

<!-- ATTENDANCE -->
<div id="attendanceSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-check"></i>Sign Attendance</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="sign_attendance" value="1">
            <div class="form-group">
                <label>Select Course</label>
                <select name="course_id" required>
                    <option value="">-- Choose Course --</option>
                    <?php foreach ($att_courses_rows as $c): ?><option value="<?= (int) $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option><?php endforeach; ?>
                </select>
            </div>
            <button type="submit" class="btn"><i class="fas fa-signature"></i> Sign Attendance</button>
        </form>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-calendar-check"></i>Attendance History</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Course</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
            <?php if (!empty($att_history_rows)): foreach ($att_history_rows as $row): ?>
                <tr><td><?= htmlspecialchars($row['title']) ?></td><td><?= htmlspecialchars($row['status']) ?></td><td><?= htmlspecialchars($row['attendance_date'] ?? '') ?></td></tr>
            <?php endforeach; else: ?><tr><td colspan="3" style="color:var(--gray-500);">No attendance records</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- PAYMENTS -->
<div id="paymentsSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:18px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-credit-card"></i>Payments &amp; Billing</div>
            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <?php if ($hasPayableCourses): ?>
                    <button class="btn green" onclick="openModal('kcbStkModal')"><i class="fas fa-bolt"></i> Instant STK Push</button>
                    <button class="btn outline" onclick="openModal('bankPaymentModal')"><i class="fas fa-university"></i> Pay via Bank</button>
                    <button class="btn gold" onclick="openModal('paybillPaymentModal')"><i class="fas fa-mobile-alt"></i> Pay via Paybill</button>
                <?php else: ?>
                    <span class="btn muted"><i class="fas fa-check-circle"></i> All Courses Enrolled</span>
                <?php endif; ?>
            </div>
        </div>
        <div class="stats-grid">
            <div class="stat-box"><i class="fas fa-wallet"></i><h2>KES <?= number_format((float) $totalPaid) ?></h2><p>Total Paid</p></div>
            <div class="stat-box red"><i class="fas fa-clock"></i><h2>KES <?= number_format((float) $pendingPayments) ?></h2><p>Pending</p></div>
            <div class="stat-box"><i class="fas fa-receipt"></i><h2><?= $invoices_count ?></h2><p>Invoices</p></div>
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= $transactions_count ?></h2><p>Transactions</p></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-money-check-alt"></i>Payment Methods</div>
        <?php if (!empty($paymentMethods_rows)): foreach ($paymentMethods_rows as $m): ?>
            <div class="activity-item"><p><?= htmlspecialchars($m['method_type'] ?? '') ?></p><span><?= htmlspecialchars($m['account_number'] ?? '') ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No payment methods added</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-receipt"></i>Transactions</div>
        <?php if (!empty($transactions_rows)): ?>
            <div class="table-scroll"><table class="data-table">
                <thead><tr><th>Course</th><th>Amount</th><th>Method</th><th>Reference</th><th>Status</th><th>Date</th></tr></thead>
                <tbody>
                <?php foreach ($transactions_rows as $t):
                    $tStatus = strtolower($t['status'] ?? '');
                    $tMethod = strtolower($t['payment_method'] ?? '');

                    if ($tStatus === 'pending' && in_array($tMethod, ['bank_transfer', 'paybill'], true)) { $tBadge = '<span class="badge badge-pending">Pending Review</span>'; }
                    elseif ($tStatus === 'pending' && $tMethod === 'kcb_stk')                              { $tBadge = '<span class="badge badge-pending">Awaiting PIN</span>'; }
                    elseif ($tStatus === 'completed')                                                       { $tBadge = '<span class="badge badge-success">Completed</span>'; }
                    elseif ($tStatus === 'pending')                                                         { $tBadge = '<span class="badge badge-pending">Processing</span>'; }
                    elseif ($tStatus === 'failed')                                                          { $tBadge = '<span class="badge badge-failed">Failed</span>'; }
                    else                                                                                    { $tBadge = htmlspecialchars(ucfirst($t['status'] ?? '')); }

                    $methodLabels = ['kcb_stk' => 'KCB STK (M-Pesa)', 'bank_transfer' => 'Bank Transfer', 'paybill' => 'Paybill (M-Pesa)', 'mpesa' => 'M-Pesa', 'card' => 'Card'];
                    $methodLabel  = $methodLabels[$tMethod] ?? ucfirst($t['payment_method'] ?? 'M-Pesa');
                ?>
                    <tr>
                        <td><?= htmlspecialchars($t['course_title'] ?? ('#' . (int) $t['course_id'])) ?></td>
                        <td>KES <?= number_format((float) $t['amount']) ?></td>
                        <td><?= htmlspecialchars($methodLabel) ?></td>
                        <td><?= ($tMethod === 'kcb_stk' && $tStatus !== 'completed') ? '—' : htmlspecialchars($t['transaction_code'] ?? '') ?></td>
                        <td><?= $tBadge ?></td>
                        <td><?= date('d M Y', strtotime($t['created_at'])) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table></div>
        <?php else: ?><div class="activity-item"><p>No transactions yet</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-file-invoice"></i>Invoices</div>
        <?php if (!empty($invoices_rows)): foreach ($invoices_rows as $inv): ?>
            <div class="activity-item"><p><?= htmlspecialchars($inv['invoice_no'] ?? '') ?></p><span><?= htmlspecialchars($inv['description'] ?? '') ?> • <?= htmlspecialchars(ucfirst($inv['status'] ?? '')) ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No invoices yet</p></div><?php endif; ?>
    </div>
</div>

<!-- NOTIFICATIONS -->
<div id="notificationsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-bell"></i>Notifications &amp; Announcements</div>
        <?php if (!empty($notifications_rows)): foreach ($notifications_rows as $note): ?>
            <div class="activity-item" style="border-left:4px solid <?= $note['type'] === 'announcement' ? 'var(--gold)' : 'var(--teal)' ?>">
                <p><i class="fas <?= $note['type'] === 'announcement' ? 'fa-bullhorn' : 'fa-bell' ?>" style="color:<?= $note['type'] === 'announcement' ? 'var(--gold-dark)' : 'var(--teal)' ?>"></i> <?= htmlspecialchars($note['message']) ?></p>
                <span><?= date('F j, Y g:i A', strtotime($note['notification_date'])) ?></span>
            </div>
        <?php endforeach; else: ?><div class="activity-item"><p>No notifications</p><span>You're all caught up</span></div><?php endif; ?>
    </div>
</div>

<!-- BOOKMARKS -->
<div id="bookmarksSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-bookmark"></i>My Bookmarks</div>
        <?php if (!empty($bookmarks_rows)): foreach ($bookmarks_rows as $bm): ?>
            <div class="activity-item"><p><?= htmlspecialchars($bm['title']) ?></p><span><?= date('F j, Y H:i', strtotime($bm['created_at'])) ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No bookmarks yet</p></div><?php endif; ?>
    </div>
</div>

<!-- SUPPORT TICKETS -->
<div id="ticketSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-ticket-alt"></i>Raise a Support Ticket</div>
        <form method="POST" action="create_ticket.php">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="form-group">
                <label>Ticket Type</label>
                <select name="type" required>
                    <option value="">-- Select Type --</option>
                    <option value="academic">Academic</option><option value="technical">Technical</option>
                    <option value="attendance">Attendance</option><option value="general">General</option>
                </select>
            </div>
            <div class="form-group"><label>Subject</label><input type="text" name="subject" required placeholder="Brief subject…" maxlength="150"></div>
            <div class="form-group"><label>Message</label><textarea name="message" required placeholder="Describe your issue…" maxlength="4000"></textarea></div>
            <button type="submit" name="submit_ticket" class="btn"><i class="fas fa-paper-plane"></i> Submit Ticket</button>
        </form>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Tickets</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Type</th><th>Subject</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
            <?php if (!empty($tickets_rows)): foreach ($tickets_rows as $ticket):
                $tb = ['open' => ['badge-open', 'Open'], 'in_progress' => ['badge-progress', 'In Progress'], 'resolved' => ['badge-resolved', 'Resolved'], 'closed' => ['badge-closed', 'Closed']][$ticket['status']] ?? null; ?>
                <tr>
                    <td><?= htmlspecialchars($ticket['type']) ?></td>
                    <td><?= htmlspecialchars($ticket['subject']) ?></td>
                    <td><?= $tb ? '<span class="badge ' . $tb[0] . '">' . $tb[1] . '</span>' : htmlspecialchars($ticket['status'] ?? '') ?></td>
                    <td><?= htmlspecialchars($ticket['created_at']) ?></td>
                </tr>
            <?php endforeach; else: ?><tr><td colspan="4" style="color:var(--gray-500);">No tickets raised yet</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- PROFILE -->
<div id="profileSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user"></i>My Profile</div>
        <?php
        $src = 'https://ui-avatars.com/api/?name=' . urlencode($profile['full_name'] ?? 'S') . '&background=7CB342&color=fff&size=200';
        if (!empty($profile['profile_image'])) {
            $img = basename(strip_tags(trim($profile['profile_image'])));
            if (in_array(strtolower(pathinfo($img, PATHINFO_EXTENSION)), ['jpg','jpeg','png','webp'], true) && is_file(__DIR__ . '/uploads/' . $img)) {
                $src = 'uploads/' . $img;
            }
        }
        ?>
        <img src="<?= htmlspecialchars($src, ENT_QUOTES, 'UTF-8') ?>" alt="Profile photo" class="profile-img">
        <div class="grid-auto">
            <div class="activity-item"><p>Student No.</p><span><?= htmlspecialchars($profile['student_no'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Full Name</p><span><?= htmlspecialchars($profile['full_name']) ?></span></div>
            <div class="activity-item"><p>Email</p><span><?= htmlspecialchars($profile['email']) ?></span></div>
            <div class="activity-item"><p>Phone</p><span><?= htmlspecialchars($profile['phone'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Location</p><span><?= htmlspecialchars($profile['location'] ?? '-') ?></span></div>
            <div class="activity-item"><p>Joined</p><span><?= date('d F Y', strtotime($profile['created_at'])) ?></span></div>
            <div class="activity-item"><p>Courses</p><span><?= $total_courses ?></span></div>
        </div>
        <?php if (!empty($profile['bio'])): ?><div class="activity-item" style="margin-bottom:16px;"><p>Bio</p><span><?= nl2br(htmlspecialchars($profile['bio'])) ?></span></div><?php endif; ?>
        <div class="btn-row">
            <button class="btn" onclick="openModal('profileModal')"><i class="fas fa-user-edit"></i> Edit Profile</button>
            <button class="btn green" onclick="openModal('passwordModal')"><i class="fas fa-lock"></i> Change Password</button>
            <button class="btn dark" onclick="openModal('photoModal')"><i class="fas fa-image"></i> Upload Photo</button>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><i class="fas fa-id-card"></i>Professional Details</div>
        <?php
        $vStatus = $extendedProfile['verification_status'] ?? 'unverified';
        $verifBadge = [
            'verified' => '<span class="badge badge-success">Verified</span>',
            'pending'  => '<span class="badge badge-pending">Pending Review</span>',
            'rejected' => '<span class="badge badge-failed">Rejected - please update</span>',
        ][$vStatus] ?? '<span class="badge badge-closed">Not Submitted</span>';
        ?>
        <div class="grid-auto">
            <div class="activity-item"><p>KRA PIN</p><span><?= htmlspecialchars($profile['kra_pin'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Licence / Registration No.</p><span><?= htmlspecialchars($extendedProfile['license_number'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Qualification Level</p><span><?= htmlspecialchars($extendedProfile['qualification_level'] ?? '') ?: '-' ?></span></div>
            <div class="activity-item"><p>Verification Status</p><span><?= $verifBadge ?></span></div>
        </div>
        <div class="btn-row" style="margin-top:0;"><button class="btn outline" onclick="openModal('extendedProfileModal')"><i class="fas fa-file-signature"></i> Update Professional Details</button></div>
    </div>
</div>

<!-- SETTINGS -->
<div id="settingsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-cog"></i>Settings</div>
        <div class="activity-item"><p>Account Email</p><span><?= htmlspecialchars($profile['email'] ?? '') ?></span></div>
        <div class="activity-item"><p>Password Last Updated</p><span><?= !empty($settingsRow['password_updated_at']) ? date('d M Y', strtotime($settingsRow['password_updated_at'])) : 'Never' ?></span></div>
        <div class="activity-item"><p>Notifications</p><span>Email: <?= !empty($settingsRow['email_notifications']) ? 'On' : 'Off' ?> &nbsp;|&nbsp; SMS: <?= !empty($settingsRow['sms_notifications']) ? 'On' : 'Off' ?></span></div>
        <div class="activity-item"><p>Theme</p><span><?= htmlspecialchars(ucfirst($settingsRow['theme'] ?? 'light')) ?></span></div>
    </div>
</div>

<!-- RESOURCE HUB -->
<div id="resourceHubSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-briefcase-medical"></i>Professional Practice Support Hub</div>
        <p style="color:var(--gray-500);font-size:.9rem;">Resources to help you transition into and sustain professional practice.</p>
    </div>
    <?php if (!empty($resourceCategories)): foreach ($resourceCategories as $cat):
        $items = $resourceItemsByCategory[(int) $cat['id']] ?? []; ?>
        <div class="card">
            <div class="card-title" style="font-size:1rem;"><i class="fas fa-folder"></i><?= htmlspecialchars($cat['name']) ?></div>
            <?php if (!empty($cat['description'])): ?><p style="color:var(--gray-500);font-size:.85rem;margin-bottom:10px;"><?= htmlspecialchars($cat['description']) ?></p><?php endif; ?>
            <?php if (!empty($items)): foreach ($items as $item): ?>
                <div class="activity-item"><p><?= htmlspecialchars($item['title']) ?></p>
                    <span><?= htmlspecialchars(ucfirst($item['resource_type'] ?? 'document')) ?>
                        <?php if (!empty($item['description'])): ?> • <?= htmlspecialchars(mb_strimwidth($item['description'], 0, 100, '…')) ?><?php endif; ?>
                        <?php if (!empty($item['external_link']) && preg_match('#^https?://#i', $item['external_link'])): ?>
                            &nbsp;•&nbsp;<a href="<?= htmlspecialchars($item['external_link'], ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;">Open link</a>
                        <?php elseif (!empty($item['file_path'])): ?>
                            &nbsp;•&nbsp;<a href="uploads/<?= htmlspecialchars(basename($item['file_path']), ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;">Download</a>
                        <?php endif; ?></span></div>
            <?php endforeach; else: ?><div class="activity-item"><p>No resources published yet</p></div><?php endif; ?>
        </div>
    <?php endforeach; else: ?><div class="card"><div class="activity-item"><p>Resource hub categories have not been set up yet</p></div></div><?php endif; ?>
</div>

<!-- REFERRALS -->
<div id="referralsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-friends"></i>Referral Programme</div>
        <?php if ($myReferralCode): ?>
            <div class="stats-grid">
                <div class="stat-box"><i class="fas fa-hashtag"></i><h2 style="font-size:1.4rem;"><?= htmlspecialchars($myReferralCode['code']) ?></h2><p>Your Referral Code</p></div>
                <div class="stat-box"><i class="fas fa-users"></i><h2><?= count($myReferrals_rows) ?></h2><p>People Referred</p></div>
                <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= count(array_filter($myReferrals_rows, fn($r) => $r['status'] === 'converted')) ?></h2><p>Converted</p></div>
                <div class="stat-box gold"><i class="fas fa-coins"></i><h2>KES <?= number_format($myRewardsTotal) ?></h2><p>Rewards Earned</p></div>
            </div>
            <p style="color:var(--gray-500);font-size:.88rem;">Share your referral link - anyone who registers through it is automatically credited to you.</p>
            <div class="referral-link-box">
                <i class="fas fa-link" style="color:var(--teal);"></i>
                <input type="text" id="referralLinkInput" value="<?= htmlspecialchars($myReferralLink, ENT_QUOTES, 'UTF-8') ?>" readonly onclick="this.select();">
                <button type="button" class="btn small gold" onclick="copyReferralLink()"><i class="fas fa-copy"></i> Copy Link</button>
            </div>
            <div class="btn-row" style="margin-top:12px;">
                <a class="btn small outline" target="_blank" rel="noopener noreferrer" href="https://api.whatsapp.com/send?text=<?= urlencode('Join me on the CBT-Kenya Skills Transfer Program! Register using my referral link: ' . $myReferralLink) ?>"><i class="fab fa-whatsapp"></i> Share on WhatsApp</a>
                <a class="btn small outline" href="mailto:?subject=<?= rawurlencode('Join CBT-Kenya STP') ?>&amp;body=<?= rawurlencode('Register using my referral link: ' . $myReferralLink) ?>"><i class="fas fa-envelope"></i> Share via Email</a>
            </div>
        <?php else: ?>
            <p style="color:var(--gray-500);font-size:.9rem;margin-bottom:14px;">You don't have a referral code yet. Generate one to start referring people.</p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="hidden" name="generate_referral_code" value="1">
                <button type="submit" class="btn"><i class="fas fa-magic"></i> Generate My Referral Code</button>
            </form>
        <?php endif; ?>
    </div>

    <?php if ($myReferralCode): ?>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>Referral Activity</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Referred</th><th>Status</th><th>Date</th></tr></thead>
            <tbody>
            <?php if (!empty($myReferrals_rows)): foreach ($myReferrals_rows as $ref):
                $rb = ['converted' => ['badge-success', 'Converted'], 'enrolled' => ['badge-progress', 'Enrolled'], 'registered' => ['badge-pending', 'Registered'], 'expired' => ['badge-closed', 'Expired']][$ref['status']] ?? ['badge-pending', 'Pending']; ?>
                <tr><td><?= htmlspecialchars($ref['referred_email'] ?? 'Not yet identified') ?></td><td><span class="badge <?= $rb[0] ?>"><?= $rb[1] ?></span></td><td><?= htmlspecialchars($ref['created_at']) ?></td></tr>
            <?php endforeach; else: ?><tr><td colspan="3" style="color:var(--gray-500);">No referrals yet - share your code to get started</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
    <?php endif; ?>
</div>

<!-- CPD -->
<div id="cpdSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:18px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-graduation-cap"></i>CPD / CME Points</div>
            <button class="btn" onclick="openModal('cpdModal')"><i class="fas fa-plus"></i> Log Activity</button>
        </div>
        <div class="stats-grid">
            <div class="stat-box green"><i class="fas fa-check-circle"></i><h2><?= number_format($cpdVerifiedTotal, 1) ?></h2><p>Verified Points</p></div>
            <div class="stat-box gold"><i class="fas fa-clock"></i><h2><?= number_format($cpdPendingTotal, 1) ?></h2><p>Pending Verification</p></div>
            <div class="stat-box"><i class="fas fa-bullseye"></i><h2><?= number_format($cpdVerifiedTotal + $cpdPendingTotal, 1) ?></h2><p>Total Logged</p></div>
        </div>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>CPD Activity Log</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Activity</th><th>Type</th><th>Points</th><th>Date</th><th>Evidence</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php if (!empty($cpdPoints_rows)): foreach ($cpdPoints_rows as $cp):
                $cb = ['verified' => ['badge-success', 'Verified'], 'rejected' => ['badge-failed', 'Rejected']][$cp['verification_status']] ?? ['badge-pending', 'Pending'];
                $evLink = null;
                if (!empty($cp['evidence_path'])) {
                    $evBase = basename(strip_tags(trim($cp['evidence_path'])));
                    if (is_file(__DIR__ . '/uploads/' . $evBase)) { $evLink = 'uploads/' . $evBase; }
                } ?>
                <tr>
                    <td><?= htmlspecialchars($cp['activity_title']) ?></td>
                    <td><?= htmlspecialchars(ucfirst($cp['activity_type'])) ?></td>
                    <td><?= number_format((float) $cp['points'], 1) ?></td>
                    <td><?= htmlspecialchars($cp['date_earned']) ?></td>
                    <td><?php if ($evLink): ?><a href="<?= htmlspecialchars($evLink, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" style="color:var(--teal);font-weight:600;">View</a><?php else: ?>—<?php endif; ?></td>
                    <td><span class="badge <?= $cb[0] ?>"><?= $cb[1] ?></span></td>
                    <td><?php if (($cp['verification_status'] ?? '') === 'pending'): ?>
                        <form method="POST" class="inline-form" onsubmit="return confirm('Remove this pending CPD entry?');">
                            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="delete_cpd_point" value="1"><input type="hidden" name="cpd_id" value="<?= (int) $cp['id'] ?>">
                            <button type="submit" class="btn small danger-outline" title="Remove entry"><i class="fas fa-trash"></i></button>
                        </form><?php endif; ?></td>
                </tr>
            <?php endforeach; else: ?><tr><td colspan="7" style="color:var(--gray-500);">No CPD activity logged yet</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- LOGBOOK -->
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
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Date</th><th>Hours</th><th>Activity</th><th>Sign-off</th></tr></thead>
            <tbody>
            <?php if (!empty($logbook_rows)): foreach ($logbook_rows as $lb): ?>
                <tr><td><?= htmlspecialchars($lb['session_date']) ?></td><td><?= number_format((float) $lb['hours'], 1) ?></td>
                    <td><?= htmlspecialchars(mb_strimwidth($lb['activity_description'], 0, 80, '…')) ?></td>
                    <td><?= (int) $lb['supervisor_signoff'] === 1 ? '<span class="badge badge-success">Signed</span>' : '<span class="badge badge-pending">Pending</span>' ?></td></tr>
            <?php endforeach; else: ?><tr><td colspan="4" style="color:var(--gray-500);">No logbook entries yet</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- JOBS -->
<div id="jobsSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-briefcase"></i>Job &amp; Placement Opportunities</div>
        <?php if (!empty($jobPostings_rows)): foreach ($jobPostings_rows as $job):
            $jid = (int) $job['id']; ?>
            <div class="course-row">
                <div class="course-info">
                    <h4><?= htmlspecialchars($job['title']) ?></h4>
                    <p><?= htmlspecialchars($job['organization'] ?? '') ?> • <?= htmlspecialchars($job['location'] ?? 'Location not specified') ?> • <?= htmlspecialchars(ucwords(str_replace('_', ' ', $job['employment_type'] ?? ''))) ?></p>
                    <?php if (!empty($job['application_deadline'])): ?><p style="font-size:.82rem;">Apply by <?= date('d M Y', strtotime($job['application_deadline'])) ?></p><?php endif; ?>
                </div>
                <?php if (in_array($jid, $appliedJobIds, true)): ?>
                    <span class="enroll-label enrolled"><i class="fas fa-check"></i> Applied</span>
                <?php else: ?>
                    <button type="button" class="btn small" onclick='openJobApplyModal(<?= $jid ?>, <?= json_encode($job['title'], $JSON_SAFE) ?>)'><i class="fas fa-paper-plane"></i> Apply</button>
                <?php endif; ?>
            </div>
        <?php endforeach; else: ?><div class="activity-item"><p>No open job postings right now</p></div><?php endif; ?>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Applications</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Job</th><th>Organization</th><th>Status</th><th>Applied</th></tr></thead>
            <tbody>
            <?php if (!empty($myJobApplications_rows)): foreach ($myJobApplications_rows as $app):
                $ab = ['shortlisted' => ['badge-progress', 'Shortlisted'], 'hired' => ['badge-success', 'Hired'], 'rejected' => ['badge-failed', 'Rejected']][$app['status']] ?? ['badge-pending', 'Submitted']; ?>
                <tr><td><?= htmlspecialchars($app['job_title']) ?></td><td><?= htmlspecialchars($app['organization'] ?? '') ?></td><td><span class="badge <?= $ab[0] ?>"><?= $ab[1] ?></span></td><td><?= htmlspecialchars($app['applied_at']) ?></td></tr>
            <?php endforeach; else: ?><tr><td colspan="4" style="color:var(--gray-500);">You haven't applied to any jobs yet</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- FORUMS -->
<div id="forumsSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:10px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-comments"></i>Discussion Forums</div>
            <button class="btn" onclick="openModal('newTopicModal')"><i class="fas fa-plus"></i> New Topic</button>
        </div>
        <p style="color:var(--gray-500);font-size:.88rem;">Peer discussions for the courses you're enrolled in.</p>
    </div>
    <?php if (!empty($forumTopics_rows)): foreach ($forumTopics_rows as $topic):
        $tid = (int) $topic['id']; $replies = $forumRepliesByTopic[$tid] ?? []; ?>
        <div class="card">
            <div class="card-title" style="font-size:1rem;"><i class="fas fa-comment-dots"></i><?= htmlspecialchars($topic['title']) ?></div>
            <p style="color:var(--gray-500);font-size:.82rem;margin-bottom:10px;">
                <?= htmlspecialchars($topic['course_title']) ?> • by <?= htmlspecialchars($topic['author_name'] ?? 'Unknown') ?> • <?= htmlspecialchars($topic['created_at']) ?>
                <?php if ($topic['status'] === 'closed'): ?> • <span class="badge badge-closed">Closed</span><?php endif; ?>
            </p>
            <p style="font-size:.92rem;margin-bottom:14px;"><?= nl2br(htmlspecialchars($topic['message'])) ?></p>
            <?php foreach ($replies as $rep): ?>
                <div class="activity-item" style="margin-left:18px;"><p><?= htmlspecialchars($rep['author_name'] ?? 'Unknown') ?></p><span><?= nl2br(htmlspecialchars($rep['message'])) ?></span></div>
            <?php endforeach; ?>
            <?php if ($topic['status'] !== 'closed'): ?>
            <form method="POST" style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="post_forum_reply" value="1"><input type="hidden" name="topic_id" value="<?= $tid ?>">
                <input type="text" name="message" required maxlength="4000" placeholder="Write a reply…" style="flex:1;min-width:200px;padding:10px 12px;border:1px solid var(--gray-200);border-radius:9px;">
                <button type="submit" class="btn small"><i class="fas fa-reply"></i> Reply</button>
            </form>
            <?php endif; ?>
        </div>
    <?php endforeach; else: ?><div class="card"><div class="activity-item"><p>No discussion topics yet - start one!</p></div></div><?php endif; ?>
</div>

<!-- ALUMNI -->
<div id="alumniSection" class="section">
    <div class="card">
        <div class="card-title"><i class="fas fa-user-graduate"></i>Alumni Profile</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="update_alumni_profile" value="1">
            <div class="form-group"><label>Graduation Year</label><input type="number" name="graduation_year" min="2000" max="2100" value="<?= htmlspecialchars((string) ($myAlumniProfile['graduation_year'] ?? '')) ?>"></div>
            <div class="form-group"><label>Current Role</label><input type="text" name="current_role" maxlength="150" value="<?= htmlspecialchars($myAlumniProfile['current_role'] ?? '') ?>"></div>
            <div class="form-group"><label>Organization</label><input type="text" name="organization" maxlength="150" value="<?= htmlspecialchars($myAlumniProfile['organization'] ?? '') ?>"></div>
            <div class="form-group"><label>Testimonial</label><textarea name="testimonial" maxlength="2000"><?= htmlspecialchars($myAlumniProfile['testimonial'] ?? '') ?></textarea></div>
            <div class="form-group"><label><input type="checkbox" name="is_public" value="1" style="width:auto;margin-right:8px;" <?= !empty($myAlumniProfile['is_public']) ? 'checked' : '' ?>> Make my alumni profile public</label></div>
            <div class="form-group"><label><input type="checkbox" name="is_mentor_available" value="1" style="width:auto;margin-right:8px;" <?= !empty($myAlumniProfile['is_mentor_available']) ? 'checked' : '' ?>> I'm available to mentor others</label></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Save Alumni Profile</button>
        </form>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-user-friends"></i>Available Mentors</div>
        <?php if (!empty($availableMentors_rows)): foreach ($availableMentors_rows as $mentor): ?>
            <div class="course-row">
                <div class="course-info"><h4><?= htmlspecialchars($mentor['full_name']) ?></h4>
                    <p><?= htmlspecialchars($mentor['current_role'] ?? '') ?> <?= !empty($mentor['organization']) ? '• ' . htmlspecialchars($mentor['organization']) : '' ?></p></div>
                <button type="button" class="btn small" onclick='openMentorRequestModal(<?= (int) $mentor['mentor_user_id'] ?>, <?= json_encode($mentor['full_name'], $JSON_SAFE) ?>)'><i class="fas fa-hand-holding-heart"></i> Request</button>
            </div>
        <?php endforeach; else: ?><div class="activity-item"><p>No mentors listed yet</p></div><?php endif; ?>
    </div>
    <div class="card">
        <div class="card-title"><i class="fas fa-list-ul"></i>My Mentorship Requests</div>
        <div class="table-scroll"><table class="data-table">
            <thead><tr><th>Mentor</th><th>Focus Area</th><th>Status</th></tr></thead>
            <tbody>
            <?php if (!empty($myMentorships_rows)): foreach ($myMentorships_rows as $mm):
                $mb = ['active' => ['badge-success', 'Active'], 'completed' => ['badge-closed', 'Completed'], 'declined' => ['badge-failed', 'Declined']][$mm['status']] ?? ['badge-pending', 'Requested']; ?>
                <tr><td><?= htmlspecialchars($mm['mentor_name']) ?></td><td><?= htmlspecialchars($mm['focus_area'] ?? '-') ?></td><td><span class="badge <?= $mb[0] ?>"><?= $mb[1] ?></span></td></tr>
            <?php endforeach; else: ?><tr><td colspan="3" style="color:var(--gray-500);">No mentorship requests yet</td></tr><?php endif; ?>
            </tbody>
        </table></div>
    </div>
</div>

<!-- PORTFOLIO -->
<div id="portfolioSection" class="section">
    <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:10px;">
            <div class="card-title" style="margin:0;"><i class="fas fa-folder-open"></i>Digital Portfolio</div>
            <button class="btn" onclick="openModal('portfolioModal')"><i class="fas fa-plus"></i> Add Item</button>
        </div>
        <p style="color:var(--gray-500);font-size:.88rem;">Case studies, competency evidence, and publications you want to showcase. Items marked "Public" can be shared with employers and mentors; everything else stays private to you.</p>
        <div class="stats-grid" style="margin-top:18px;margin-bottom:0;">
            <div class="stat-box"><i class="fas fa-folder-open"></i><h2><?= count($portfolio_rows) ?></h2><p>Total Items</p></div>
            <div class="stat-box green"><i class="fas fa-globe"></i><h2><?= count(array_filter($portfolio_rows, fn($p) => !empty($p['is_public']))) ?></h2><p>Public</p></div>
            <div class="stat-box gold"><i class="fas fa-lock"></i><h2><?= count(array_filter($portfolio_rows, fn($p) => empty($p['is_public']))) ?></h2><p>Private</p></div>
        </div>
    </div>
    <?php if (!empty($portfolio_rows)): foreach ($portfolio_rows as $pf):
        $pfFileLink = null;
        if (!empty($pf['file_path'])) {
            $pfBase = basename(strip_tags(trim($pf['file_path'])));
            if (is_file(__DIR__ . '/uploads/' . $pfBase)) { $pfFileLink = 'uploads/' . $pfBase; }
        } ?>
        <div class="card">
            <div class="card-title" style="font-size:1rem;"><i class="fas fa-file-alt"></i><?= htmlspecialchars($pf['title']) ?></div>
            <p style="color:var(--gray-500);font-size:.82rem;margin-bottom:8px;">
                <?= htmlspecialchars($pf['category'] ?? 'General') ?> • <?= htmlspecialchars($pf['created_at']) ?>
                <?= !empty($pf['is_public']) ? ' • <span class="badge badge-success">Public</span>' : ' • <span class="badge badge-closed">Private</span>' ?>
            </p>
            <?php if (!empty($pf['description'])): ?><p style="font-size:.9rem;margin-bottom:8px;"><?= nl2br(htmlspecialchars($pf['description'])) ?></p><?php endif; ?>
            <div class="item-actions">
                <?php if ($pfFileLink): ?><a href="<?= htmlspecialchars($pfFileLink, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener noreferrer" class="btn small outline"><i class="fas fa-download"></i> View file</a><?php endif; ?>
                <button type="button" class="btn small" onclick='openPortfolioEdit(<?= (int) $pf["id"] ?>, <?= json_encode($pf["title"], $JSON_SAFE) ?>, <?= json_encode($pf["category"] ?? "", $JSON_SAFE) ?>, <?= json_encode($pf["description"] ?? "", $JSON_SAFE) ?>, <?= !empty($pf["is_public"]) ? 1 : 0 ?>)'><i class="fas fa-edit"></i> Edit</button>
                <form method="POST" class="inline-form" onsubmit="return confirm('Delete this portfolio item? This cannot be undone.');">
                    <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="delete_portfolio_item" value="1"><input type="hidden" name="portfolio_id" value="<?= (int) $pf['id'] ?>">
                    <button type="submit" class="btn small danger-outline"><i class="fas fa-trash"></i> Delete</button>
                </form>
            </div>
        </div>
    <?php endforeach; else: ?><div class="card"><div class="activity-item"><p>No portfolio items yet</p><span>Add case studies, sample work, or publications to build your professional showcase.</span></div></div><?php endif; ?>
</div>

</main>
</div>

<!-- ================= MODALS ================= -->

<!-- KCB STK -->
<div id="kcbStkModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('kcbStkModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-bolt"></i> Instant M-Pesa STK (KCB)</div>
        <?php if ($hasPayableCourses): ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="trigger_kcb_stk" value="1">
            <div class="form-group">
                <label>Select Course</label>
                <select name="course_id" required>
                    <option value="">-- Select Course --</option>
                    <?php foreach ($payableCoursesData as $pc): ?>
                        <option value="<?= (int) $pc['id'] ?>"><?= htmlspecialchars($pc['title']) ?> (KES <?= number_format((float) $pc['price']) ?>)</option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label>M-Pesa Phone Number</label>
                <input type="tel" name="phone_number" required maxlength="15" value="<?= htmlspecialchars($profile['phone'] ?? '') ?>" placeholder="e.g. 0712345678">
                <div class="form-hint">A prompt will appear on this phone asking for your M-Pesa PIN. You're enrolled automatically once payment is confirmed.</div>
            </div>
            <button type="submit" class="btn green" style="width:100%;justify-content:center;margin-top:14px;"><i class="fas fa-paper-plane"></i> Send STK Prompt</button>
        </form>
        <?php else: ?>
            <div class="activity-item" style="text-align:center;padding:24px 12px;"><p>You are already enrolled in all available paid courses!</p></div>
        <?php endif; ?>
    </div>
</div>

<!-- BANK -->
<div id="bankPaymentModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('bankPaymentModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-university"></i> Pay via Bank Transfer</div>
        <div class="bank-details">
            <div class="bd-row"><span class="bd-label">Bank Name</span><span class="bd-value"><?= htmlspecialchars(BANK_NAME) ?></span></div>
            <div class="bd-row"><span class="bd-label">Account Name</span><span class="bd-value"><?= htmlspecialchars(BANK_ACCOUNT_NAME) ?></span></div>
            <div class="bd-row"><span class="bd-label">Account Number</span><span class="bd-value"><?= htmlspecialchars(BANK_ACCOUNT_NUMBER) ?></span></div>
            <div class="bd-row"><span class="bd-label">Branch</span><span class="bd-value"><?= htmlspecialchars(BANK_BRANCH) ?></span></div>
            <div class="bd-row"><span class="bd-label">Swift Code</span><span class="bd-value"><?= htmlspecialchars(BANK_SWIFT_CODE) ?></span></div>
        </div>
        <?php if ($hasPayableCourses): ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="submit_bank_payment" value="1">
            <div class="form-group"><label>Course</label>
                <select name="course_id" required><option value="">-- Select Course --</option>
                    <?php foreach ($payableCoursesData as $pc): ?><option value="<?= (int) $pc['id'] ?>"><?= htmlspecialchars($pc['title']) ?> (KES <?= number_format((float) $pc['price']) ?>)</option><?php endforeach; ?>
                </select></div>
            <div class="form-group"><label>Amount Deposited (KES)</label><input type="number" name="amount" min="1" step="0.01" required placeholder="e.g. 5000"></div>
            <div class="form-group"><label>Payer Full Name</label><input type="text" name="payer_name" required maxlength="150" value="<?= htmlspecialchars($profile['full_name'] ?? '') ?>" placeholder="Name on the deposit slip"></div>
            <div class="form-group"><label>Payer Phone Number</label><input type="tel" name="payer_phone" required maxlength="30" value="<?= htmlspecialchars($profile['phone'] ?? '') ?>" placeholder="e.g. 07XXXXXXXX"></div>
            <div class="form-group"><label>Payer Email (optional)</label><input type="email" name="payer_email" maxlength="150" value="<?= htmlspecialchars($profile['email'] ?? '') ?>"></div>
            <div class="form-group"><label>Bank Transaction Code / Slip No.</label><input type="text" name="transaction_code" required maxlength="100" placeholder="e.g. FT23A1B2C3"></div>
            <div class="form-group"><label>Date of Deposit</label><input type="date" name="payment_date" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Notes (optional)</label><textarea name="notes" maxlength="2000" placeholder="Any extra info for the admin…"></textarea></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;margin-top:14px;"><i class="fas fa-paper-plane"></i> Submit for Verification</button>
        </form>
        <?php else: ?>
            <div class="activity-item" style="text-align:center;padding:30px 16px;"><p style="font-size:1.1rem;">You are enrolled in all available paid courses!</p><span>Check back later for new courses.</span></div>
        <?php endif; ?>
    </div>
</div>

<!-- PAYBILL -->
<div id="paybillPaymentModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('paybillPaymentModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-mobile-alt"></i> Pay via Paybill (M-Pesa)</div>
        <div class="bank-details paybill">
            <div class="bd-row"><span class="bd-label">Paybill Name</span><span class="bd-value"><?= htmlspecialchars(PAYBILL_NAME) ?></span></div>
            <div class="bd-row"><span class="bd-label">Paybill Number</span><span class="bd-value"><?= htmlspecialchars(PAYBILL_NUMBER) ?></span></div>
            <div class="bd-row"><span class="bd-label">Account Number</span><span class="bd-value"><?= htmlspecialchars(PAYBILL_ACCOUNT_NUMBER) ?></span></div>
        </div>
        <p class="form-hint" style="margin-bottom:16px;">Go to M-Pesa &rarr; Lipa na M-Pesa &rarr; Pay Bill, enter the details above, complete the payment, then fill in the form below and attach a screenshot of your M-Pesa confirmation message as proof.</p>
        <?php if ($hasPayableCourses): ?>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <input type="hidden" name="submit_paybill_payment" value="1">
            <div class="form-group"><label>Course</label>
                <select name="course_id" required><option value="">-- Select Course --</option>
                    <?php foreach ($payableCoursesData as $pc): ?><option value="<?= (int) $pc['id'] ?>"><?= htmlspecialchars($pc['title']) ?> (KES <?= number_format((float) $pc['price']) ?>)</option><?php endforeach; ?>
                </select></div>
            <div class="form-group"><label>Amount Paid (KES)</label><input type="number" name="amount" min="1" step="0.01" required placeholder="e.g. 5000"></div>
            <div class="form-group"><label>Payer Full Name</label><input type="text" name="payer_name" required maxlength="150" value="<?= htmlspecialchars($profile['full_name'] ?? '') ?>"></div>
            <div class="form-group"><label>Payer Phone Number (M-Pesa line)</label><input type="tel" name="payer_phone" required maxlength="30" value="<?= htmlspecialchars($profile['phone'] ?? '') ?>" placeholder="e.g. 07XXXXXXXX"></div>
            <div class="form-group"><label>Payer Email (optional)</label><input type="email" name="payer_email" maxlength="150" value="<?= htmlspecialchars($profile['email'] ?? '') ?>"></div>
            <div class="form-group"><label>M-Pesa Confirmation Code</label><input type="text" name="transaction_code" required maxlength="100" placeholder="e.g. QFT7XXXXXX"></div>
            <div class="form-group"><label>Date Paid</label><input type="date" name="payment_date" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Proof of Payment (screenshot, PDF/JPG/PNG)</label><input type="file" name="proof_file" accept="application/pdf,image/jpeg,image/png" required></div>
            <div class="form-group"><label>Notes (optional)</label><textarea name="notes" maxlength="2000" placeholder="Any extra info for the admin…"></textarea></div>
            <button type="submit" class="btn gold" style="width:100%;justify-content:center;margin-top:14px;"><i class="fas fa-paper-plane"></i> Submit for Verification</button>
        </form>
        <?php else: ?>
            <div class="activity-item" style="text-align:center;padding:30px 16px;"><p style="font-size:1.1rem;">You are enrolled in all available paid courses!</p><span>Check back later for new courses.</span></div>
        <?php endif; ?>
    </div>
</div>

<!-- PROFILE EDIT -->
<div id="profileModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('profileModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-user-edit"></i> Update Profile</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="form-group"><label>Student No.</label><input type="text" value="<?= htmlspecialchars($profile['student_no'] ?? '-') ?>" disabled></div>
            <div class="form-group"><label>Full Name</label><input type="text" value="<?= htmlspecialchars($profile['full_name'] ?? '') ?>" disabled>
                <div class="form-hint">Your registered name can't be changed here. Contact an administrator if it needs correcting.</div></div>
            <div class="form-group"><label>Email</label><input type="email" name="email" value="<?= htmlspecialchars($profile['email'] ?? '') ?>" required></div>
            <div class="form-group"><label>Phone</label><input type="tel" name="phone" value="<?= htmlspecialchars($profile['phone'] ?? '') ?>" maxlength="30"></div>
            <div class="form-group"><label>Location</label><input type="text" name="location" value="<?= htmlspecialchars($profile['location'] ?? '') ?>" maxlength="120"></div>
            <div class="form-group"><label>Bio</label><textarea name="bio" maxlength="2000"><?= htmlspecialchars($profile['bio'] ?? '') ?></textarea></div>
            <button type="submit" name="update_profile" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Save Changes</button>
        </form>
    </div>
</div>

<!-- PASSWORD -->
<div id="passwordModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('passwordModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-lock"></i> Change Password</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="form-group"><label>Current Password</label><input type="password" name="current_password" required autocomplete="current-password"></div>
            <div class="form-group"><label>New Password</label><input type="password" name="new_password" required autocomplete="new-password" minlength="8"></div>
            <div class="form-group"><label>Confirm Password</label><input type="password" name="confirm_password" required autocomplete="new-password" minlength="8"></div>
            <button type="submit" name="change_password" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-key"></i> Update Password</button>
        </form>
    </div>
</div>

<!-- PHOTO -->
<div id="photoModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('photoModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-camera"></i> Upload Profile Photo</div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
            <div class="form-group"><label>Choose Image (JPG / PNG / WEBP, max 5 MB)</label><input type="file" name="profile_photo" accept="image/jpeg,image/png,image/webp" required></div>
            <button type="submit" name="upload_photo" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-upload"></i> Upload Photo</button>
        </form>
    </div>
</div>

<!-- EXTENDED PROFILE -->
<div id="extendedProfileModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('extendedProfileModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-file-signature"></i> Update Professional Details</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="update_extended_profile" value="1">
            <div class="form-group"><label>Professional Licence / Registration No.</label><input type="text" name="license_number" maxlength="100" value="<?= htmlspecialchars($extendedProfile['license_number'] ?? '') ?>" placeholder="e.g. board registration number"></div>
            <div class="form-group"><label>Academic Qualification Level</label>
                <select name="qualification_level"><option value="">-- Select --</option>
                    <?php foreach (['Diploma', 'Degree', 'Masters', 'PhD'] as $q): ?><option value="<?= $q ?>" <?= ($extendedProfile['qualification_level'] ?? '') === $q ? 'selected' : '' ?>><?= $q ?></option><?php endforeach; ?>
                </select></div>
            <div class="form-group"><label>KRA PIN</label><input type="text" name="kra_pin" maxlength="11" value="<?= htmlspecialchars($profile['kra_pin'] ?? '') ?>" placeholder="e.g. A123456789Z"><div class="form-hint">Used for eTIMS-compliant invoicing.</div></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Submit for Verification</button>
        </form>
    </div>
</div>

<!-- CPD -->
<div id="cpdModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('cpdModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-graduation-cap"></i> Log CPD / CME Activity</div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="submit_cpd_point" value="1">
            <div class="form-group"><label>Activity Title</label><input type="text" name="activity_title" required maxlength="255" placeholder="e.g. Ethics in Clinical Practice Workshop"></div>
            <div class="form-group"><label>Activity Type</label>
                <select name="activity_type"><option value="course">Course</option><option value="workshop">Workshop</option><option value="conference">Conference</option><option value="supervision">Supervision</option><option value="publication">Publication</option><option value="other">Other</option></select></div>
            <div class="form-group"><label>Points</label><input type="number" name="points" min="0.5" step="0.5" required placeholder="e.g. 2"></div>
            <div class="form-group"><label>Date Earned</label><input type="date" name="date_earned" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Evidence (PDF/JPG/PNG, optional)</label><input type="file" name="evidence_file" accept="application/pdf,image/jpeg,image/png"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit</button>
        </form>
    </div>
</div>

<!-- LOGBOOK -->
<div id="logbookModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('logbookModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-notes-medical"></i> Log Supervision Session</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="submit_logbook_entry" value="1">
            <div class="form-group"><label>Session Date</label><input type="date" name="session_date" required max="<?= date('Y-m-d') ?>"></div>
            <div class="form-group"><label>Hours</label><input type="number" name="hours" min="0.5" step="0.5" required></div>
            <div class="form-group"><label>Activity Description</label><textarea name="activity_description" required maxlength="3000" placeholder="What did the session cover?"></textarea></div>
            <div class="form-group"><label>Competencies Covered</label><input type="text" name="competencies_covered" maxlength="1000" placeholder="e.g. Risk assessment, case formulation"></div>
            <div class="form-group"><label>Client / Case Reference (anonymised, optional)</label><input type="text" name="client_case_ref" maxlength="100" placeholder="Never use identifying client information"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit for Sign-off</button>
        </form>
    </div>
</div>

<!-- JOB APPLY -->
<div id="jobApplyModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('jobApplyModal')" aria-label="Close">✕</button>
        <div class="modal-title" id="jobApplyTitle"><i class="fas fa-paper-plane"></i> Apply for Job</div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="apply_job" value="1"><input type="hidden" name="job_id" id="jobApplyJobId" value="">
            <div class="form-group"><label>CV / Resume (PDF/JPG/PNG)</label><input type="file" name="cv_file" accept="application/pdf,image/jpeg,image/png"></div>
            <div class="form-group"><label>Cover Note (optional)</label><textarea name="cover_letter" maxlength="3000" placeholder="Briefly tell them why you're a fit…"></textarea></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Submit Application</button>
        </form>
    </div>
</div>

<!-- NEW FORUM TOPIC -->
<div id="newTopicModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('newTopicModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-comment-dots"></i> Start a Discussion Topic</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="post_forum_topic" value="1">
            <div class="form-group"><label>Course</label>
                <select name="course_id" required><option value="">-- Select one of your courses --</option>
                    <?php foreach ($att_courses_rows as $c): ?><option value="<?= (int) $c['id'] ?>"><?= htmlspecialchars($c['title']) ?></option><?php endforeach; ?>
                </select></div>
            <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="255"></div>
            <div class="form-group"><label>Message</label><textarea name="message" required maxlength="4000"></textarea></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Post Topic</button>
        </form>
    </div>
</div>

<!-- MENTOR REQUEST -->
<div id="mentorRequestModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('mentorRequestModal')" aria-label="Close">✕</button>
        <div class="modal-title" id="mentorRequestTitle"><i class="fas fa-hand-holding-heart"></i> Request Mentorship</div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="request_mentorship" value="1"><input type="hidden" name="mentor_id" id="mentorRequestMentorId" value="">
            <div class="form-group"><label>What would you like guidance on?</label><input type="text" name="focus_area" maxlength="255" placeholder="e.g. Starting a private practice"></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-paper-plane"></i> Send Request</button>
        </form>
    </div>
</div>

<!-- PORTFOLIO ADD -->
<div id="portfolioModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('portfolioModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-folder-open"></i> Add Portfolio Item</div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="add_portfolio_item" value="1">
            <div class="form-group"><label>Title</label><input type="text" name="title" required maxlength="255"></div>
            <div class="form-group"><label>Category</label><input type="text" name="category" maxlength="150" placeholder="e.g. Case Study, Publication"></div>
            <div class="form-group"><label>Description</label><textarea name="description" maxlength="2000"></textarea></div>
            <div class="form-group"><label>File (PDF/JPG/PNG, optional)</label><input type="file" name="portfolio_file" accept="application/pdf,image/jpeg,image/png"></div>
            <div class="form-group"><label><input type="checkbox" name="is_public" value="1" style="width:auto;margin-right:8px;"> Make this item public</label></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Add to Portfolio</button>
        </form>
    </div>
</div>

<!-- PORTFOLIO EDIT -->
<div id="portfolioEditModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeModal('portfolioEditModal')" aria-label="Close">✕</button>
        <div class="modal-title"><i class="fas fa-edit"></i> Edit Portfolio Item</div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="edit_portfolio_item" value="1"><input type="hidden" name="portfolio_id" id="portfolioEditId" value="">
            <div class="form-group"><label>Title</label><input type="text" name="title" id="portfolioEditTitle" required maxlength="255"></div>
            <div class="form-group"><label>Category</label><input type="text" name="category" id="portfolioEditCategory" maxlength="150"></div>
            <div class="form-group"><label>Description</label><textarea name="description" id="portfolioEditDescription" maxlength="2000"></textarea></div>
            <div class="form-group"><label>Replace File (optional, PDF/JPG/PNG)</label><input type="file" name="portfolio_file" accept="application/pdf,image/jpeg,image/png"></div>
            <div class="form-group"><label><input type="checkbox" name="is_public" id="portfolioEditPublic" value="1" style="width:auto;margin-right:8px;"> Make this item public</label></div>
            <button type="submit" class="btn" style="width:100%;justify-content:center;"><i class="fas fa-save"></i> Save Changes</button>
        </form>
    </div>
</div>

<script>window.APP = <?= $app_js ?>;</script>
<script src="Student.js"></script>
</body>
</html>