<?php

session_start();
include "db.php";
include "advance.php";

/* ========
 * CONSTANTS
 * ======== */
const ENROLLED_STATUSES = ['approved', 'ongoing', 'completed', 'active'];

/* ========
 * SECURITY HELPERS
 * ======== */
function validateCsrf(): void {
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die("Invalid CSRF token.");
    }
}

function inPlaceholders(array $ids): string {
    return implode(',', array_fill(0, count($ids), '?'));
}

/* ========
 * INLINED FROM lms_helpers.php
 * ======== */
function checkCourseAccess(PDO $pdo, int $user_id, int $course_id, bool $is_paid): bool {
    $stmt = $pdo->prepare(
        "SELECT status FROM enrollments WHERE user_id = ? AND course_id = ? LIMIT 1"
    );
    $stmt->execute([$user_id, $course_id]);
    $enrollment = $stmt->fetch();

    if (!$enrollment || !in_array(strtolower(trim((string)$enrollment['status'])), ENROLLED_STATUSES, true)) {
        return false;
    }

    if ($is_paid) {
        $pstmt = $pdo->prepare(
            "SELECT id FROM payments
             WHERE user_id = ? AND course_id = ? AND status = 'confirmed'
             LIMIT 1"
        );
        $pstmt->execute([$user_id, $course_id]);
        if (!$pstmt->fetch()) {
            return false;
        }
    }

    return true;
}

/* ========
 * QUIZ ATTEMPT FUNCTIONS
 * ======== */
function startQuizAttempt(
    PDO $pdo,
    int $user_id,
    int $quiz_id,
    int $course_id,
    int $duration_minutes
): array {
    $qstmt = $pdo->prepare(
        "SELECT duration
         FROM quizzes
         WHERE id = ?
         LIMIT 1"
    );
    $qstmt->execute([$quiz_id]);
    $quizRow = $qstmt->fetch();

    if (!$quizRow) {
        throw new RuntimeException("Quiz not found.");
    }

    $duration_minutes = (int) $quizRow['duration'];

    if ($duration_minutes <= 0) {
        throw new RuntimeException(
            "Quiz duration must be greater than 0 minutes."
        );
    }
    $existing = $pdo->prepare(
        "SELECT *,
                TIMESTAMPDIFF(SECOND, started_at, NOW()) AS elapsed_sec
         FROM quiz_attempts
         WHERE user_id = ?
           AND quiz_id = ?
           AND status = 'in_progress'
         ORDER BY started_at DESC
         LIMIT 1"
    );

    $existing->execute([
        $user_id,
        $quiz_id
    ]);

    $row = $existing->fetch();

    if ($row) {
        $elapsed_sec       = (int) $row['elapsed_sec'];
        $correct_remaining = ($duration_minutes * 60) - $elapsed_sec;

        if ($correct_remaining <= 0) {
            $expire = $pdo->prepare(
                "UPDATE quiz_attempts
                 SET status = 'completed',
                     submitted_at = NOW()
                 WHERE id = ?"
            );
            $expire->execute([
                (int) $row['id']
            ]);

            $row = null;
        } else {
            $updateExpiry = $pdo->prepare(
                "UPDATE quiz_attempts
                 SET server_expires_at = DATE_ADD(started_at, INTERVAL ? MINUTE)
                 WHERE id = ?"
            );
            $updateExpiry->execute([
                $duration_minutes,
                (int) $row['id']
            ]);

            $row['seconds_remaining'] = $correct_remaining;
            return $row;
        }
    }
    $countStmt = $pdo->prepare(
        "SELECT COUNT(*) AS n
         FROM quiz_attempts
         WHERE user_id = ?
           AND quiz_id = ?"
    );

    $countStmt->execute([
        $user_id,
        $quiz_id
    ]);

    $attempt_number = (int) $countStmt->fetch()['n'] + 1;
    $insert = $pdo->prepare(
        "INSERT INTO quiz_attempts
        (
            user_id,
            quiz_id,
            course_id,
            attempt_number,
            started_at,
            server_expires_at,
            status
        )
        VALUES
        (
            ?,
            ?,
            ?,
            ?,
            NOW(),
            DATE_ADD(NOW(), INTERVAL ? MINUTE),
            'in_progress'
        )"
    );

    $insert->execute([
        $user_id,
        $quiz_id,
        $course_id,
        $attempt_number,
        $duration_minutes
    ]);

    $attempt_id = (int) $pdo->lastInsertId();

    $get = $pdo->prepare(
        "SELECT *,
                TIMESTAMPDIFF(SECOND, NOW(), server_expires_at) AS remaining_sec
         FROM quiz_attempts
         WHERE id = ?
         LIMIT 1"
    );

    $get->execute([
        $attempt_id
    ]);

    $attempt = $get->fetch();

    if (!$attempt) {
        throw new RuntimeException("Could not retrieve quiz attempt.");
    }

    $attempt['seconds_remaining'] = max(0, (int) $attempt['remaining_sec']);
    return $attempt;
}

function closeQuizAttempt(PDO $pdo, int $user_id, int $quiz_id, int $score, string $status): array {
    $find = $pdo->prepare(
        "SELECT *,
                (server_expires_at IS NULL OR server_expires_at < NOW()) AS is_expired,
                TIMESTAMPDIFF(SECOND, started_at, NOW()) AS time_used
         FROM quiz_attempts
         WHERE user_id=? AND quiz_id=? AND status='in_progress'
         ORDER BY started_at DESC LIMIT 1"
    );
    $find->execute([$user_id, $quiz_id]);
    $attempt = $find->fetch();

    if (!$attempt) {
        return ['valid' => false, 'reason' => 'no_active_attempt'];
    }

    $expired      = (bool) $attempt['is_expired'];
    $time_used    = (int) $attempt['time_used'];
    $final_status = 'completed';

    $update = $pdo->prepare(
        "UPDATE quiz_attempts
         SET submitted_at = NOW(),
             score = ?,
             status = ?,
             time_used_sec = ?
         WHERE id = ?"
    );

    $update->execute([
        $expired ? null : $score,
        $final_status,
        $time_used,
        $attempt['id']
    ]);

    $attempt['valid']  = !$expired;
    $attempt['status'] = $final_status;

    return $attempt;
}

function awardCpdPoints(PDO $pdo, int $user_id, int $course_id, string $activity_type): void {
    $rule = $pdo->prepare(
        "SELECT points FROM cpd_rules WHERE course_id=? AND activity_type=? LIMIT 1"
    );
    $rule->execute([$course_id, $activity_type]);
    $r = $rule->fetch();
    if (!$r) return;

    $ins = $pdo->prepare(
        "INSERT INTO cpd_points_earned (user_id, course_id, activity_type, points)
         VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE points = VALUES(points), earned_at = NOW()"
    );
    $ins->execute([$user_id, $course_id, $activity_type, $r['points']]);
}

function getCpdSummary(PDO $pdo, int $user_id, int $course_id): array {
    $avail = $pdo->prepare("SELECT COALESCE(SUM(points),0) AS total FROM cpd_rules WHERE course_id=?");
    $avail->execute([$course_id]);
    $available = (float) $avail->fetch()['total'];

    $earned = $pdo->prepare("SELECT COALESCE(SUM(points),0) AS total FROM cpd_points_earned WHERE user_id=? AND course_id=?");
    $earned->execute([$user_id, $course_id]);
    $got = (float) $earned->fetch()['total'];

    $breakdown = $pdo->prepare("SELECT activity_type, points FROM cpd_points_earned WHERE user_id=? AND course_id=?");
    $breakdown->execute([$user_id, $course_id]);

    return ['available' => $available, 'earned' => $got, 'breakdown' => $breakdown->fetchAll()];
}

/* ========
 * CERTIFICATE ISSUANCE
 * ======== */
function checkAndIssueCertificate(PDO $pdo, int $user_id, int $course_id, array $progress): ?array {
    $exists = $pdo->prepare("SELECT * FROM certificates WHERE user_id=? AND course_id=? LIMIT 1");
    $exists->execute([$user_id, $course_id]);
    if ($cert = $exists->fetch()) {
        return $cert;
    }

    $rule = [
        'min_video_pct'       => 90,
        'min_notes_pct'       => 90,
        'min_assignments_pct' => 0,
        'min_quiz_pct'        => 90,
        'min_cpd_points'      => 0,
    ];

    $meets = $progress['video_pct']       >= $rule['min_video_pct']
          && $progress['notes_pct']       >= $rule['min_notes_pct']
          && $progress['quiz_pct']        >= $rule['min_quiz_pct']
          && $progress['assignments_pct'] >= $rule['min_assignments_pct']
          && $progress['cpd_points']      >= $rule['min_cpd_points'];

    if (!$meets) return null;

    $courseStmt = $pdo->prepare("SELECT title FROM courses WHERE id=?");
    $courseStmt->execute([$course_id]);
    $course_title = $courseStmt->fetch()['title'] ?? '';

    $cert_number       = 'CBTK-STP-' . date('Y') . '-' . str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $certificate_code  = bin2hex(random_bytes(8));
    $verification_hash = hash('sha256', $cert_number . '|' . $user_id . '|' . $course_id . '|' . bin2hex(random_bytes(16)));

    try {
        $ins = $pdo->prepare(
            "INSERT INTO certificates
                (user_id, course_id, title, template_id, issued_at, status, certificate_code, verification_hash, cert_number)
             VALUES (?,?,?,NULL,NOW(),'issued',?,?,?)"
        );
        $ins->execute([$user_id, $course_id, $course_title, $certificate_code, $verification_hash, $cert_number]);
    } catch (PDOException $e) {
        error_log("Certificate issuance failed (user_id={$user_id}, course_id={$course_id}): " . $e->getMessage());
        return null;
    }

    $get = $pdo->prepare("SELECT * FROM certificates WHERE id = ?");
    $get->execute([(int) $pdo->lastInsertId()]);
    return $get->fetch();
}

/* ========
 * CERTIFICATE DOWNLOAD
 * ======== */
function certificateHtml(array $cert, bool $forPdfLib): string {
    $name   = htmlspecialchars($cert['participant_name'] ?? '');
    $course = htmlspecialchars($cert['course_title'] ?? $cert['title'] ?? '');
    $number = htmlspecialchars($cert['cert_number'] ?? '');
    $date   = !empty($cert['issued_at']) ? htmlspecialchars(date('F j, Y', strtotime($cert['issued_at']))) : '';
    $token  = htmlspecialchars($cert['verification_hash'] ?? '');

    if ($forPdfLib) {
        return '
        <table width="100%" cellpadding="10">
          <tr><td align="center">
            <h1 style="color:#6b9b2e;">Certificate of Completion</h1>
            <p style="font-size:10pt;color:#6b7280;">CBT-Kenya &middot; Skills Transfer Program</p>
            <br /><br />
            <p style="font-size:11pt;">This certifies that</p>
            <h2 style="color:#2b2b3d;">' . $name . '</h2>
            <p style="font-size:11pt;">has successfully completed</p>
            <h3 style="color:#6b9b2e;">' . $course . '</h3>
            <br />
            <p style="font-size:10pt;color:#6b7280;">Completed on ' . $date . '</p>
            <p style="font-size:9pt;color:#6b7280;">Certificate No. ' . $number . '</p>
          </td></tr>
        </table>';
    }

    return '<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>Certificate ' . $number . '</title>
    <style>
      @media print { .no-print { display:none !important; } @page { size: A4 landscape; margin: 0; } }
      body{font-family:Georgia,serif;background:#f7f8f5;margin:0;padding:40px;display:flex;align-items:center;justify-content:center;min-height:100vh;}
      .cert{background:#fff;border:10px solid #6b9b2e;border-radius:6px;padding:60px 70px;max-width:900px;width:100%;text-align:center;box-shadow:0 4px 30px rgba(0,0,0,0.15);}
      .cert h1{color:#6b9b2e;font-size:32px;margin-bottom:6px;}
      .cert .sub{color:#6b7280;font-size:13px;letter-spacing:1px;text-transform:uppercase;margin-bottom:30px;}
      .cert .name{font-size:28px;color:#2b2b3d;margin:14px 0;font-weight:bold;border-bottom:2px solid #8bc53f;display:inline-block;padding-bottom:6px;}
      .cert .course{font-size:20px;color:#6b9b2e;margin:14px 0 30px;}
      .cert .meta{font-size:12px;color:#6b7280;margin-top:30px;line-height:1.8;}
      .print-btn{margin-top:26px;background:#6b9b2e;color:#fff;border:none;padding:12px 26px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;}
    </style></head><body>
    <div class="cert">
        <h1>Certificate of Completion</h1>
        <div class="sub">CBT-Kenya &middot; Skills Transfer Program</div>
        <p>This certifies that</p>
        <div class="name">' . $name . '</div>
        <p>has successfully completed</p>
        <div class="course">' . $course . '</div>
        <div class="meta">
            Completed on ' . $date . '<br>
            Certificate No. ' . $number . '<br>
            Verify at: verify_certificate.php?token=' . $token . '
        </div>
        <br>
        <button class="print-btn no-print" onclick="window.print()"> Print / Save as PDF</button>
    </div>
    <script>window.onload = () => setTimeout(() => window.print(), 400);</script>
    </body></html>';
}

/* === AUTH === */
if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit; }
$user_id = (int) $_SESSION['user_id'];

/* === CSRF === */
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

/* === COURSE ID === */
if (empty($_GET['id'])) die("Course not found");
$course_id = intval($_GET['id']);

/* ========
 * SERVE CERTIFICATE DOWNLOAD
 * ======== */
if (isset($_GET['certificate'])) {
    $cert_number = trim((string) $_GET['certificate']);
    if ($cert_number === '') { http_response_code(400); die("Missing certificate number."); }

    $cstmt = $pdo->prepare(
        "SELECT c.*, u.full_name AS participant_name, co.title AS course_title
         FROM certificates c
         LEFT JOIN users u ON u.id = c.user_id
         LEFT JOIN courses co ON co.id = c.course_id
         WHERE c.cert_number = ? AND c.user_id = ? LIMIT 1"
    );
    $cstmt->execute([$cert_number, $user_id]);
    $cert = $cstmt->fetch();
    if (!$cert) { http_response_code(404); die("Certificate not found."); }

    $safe_number = preg_replace('/[^A-Za-z0-9_-]/', '', $cert_number);

    if (class_exists('TCPDF')) {
        $pdf = new TCPDF('L', 'mm', 'A4', true, 'UTF-8', false);
        $pdf->SetCreator('CBT-Kenya STP');
        $pdf->SetAuthor('CBT-Kenya');
        $pdf->SetTitle('Certificate-' . $safe_number);
        $pdf->setPrintHeader(false);
        $pdf->setPrintFooter(false);
        $pdf->AddPage();
        $pdf->SetFont('helvetica', '', 11);
        $pdf->writeHTML(certificateHtml($cert, true), true, false, true, false, '');
        $pdf->Output('Certificate-' . $safe_number . '.pdf', 'D');
        exit;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Disposition: inline; filename="Certificate-' . $safe_number . '.html"');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo certificateHtml($cert, false);
    exit;
}

/* ========
 * SERVE NOTE 
 * ======== */
if (isset($_GET['note'])) {
    $note_id = intval($_GET['note']);

    $stmt = $pdo->prepare("SELECT n.file_path, n.content, n.title, c.course_type, c.price 
                           FROM notes n 
                           JOIN courses c ON c.id = n.course_id 
                           WHERE n.id = ? AND n.course_id = ?");
    $stmt->execute([$note_id, $course_id]);
    $note_row = $stmt->fetch();
    if (!$note_row) die("Note not found.");
    
    $is_paid = (!empty($note_row['course_type']) && $note_row['course_type'] === 'Paid')
             || (!empty($note_row['price']) && (float)$note_row['price'] > 0);
    
    if (!checkCourseAccess($pdo, $user_id, $course_id, $is_paid)) {
        http_response_code(403);
        die("You do not have access to this note.");
    }
    
    if (!empty($note_row['file_path']) && file_exists($note_row['file_path'])) {
        $file = $note_row['file_path'];

        $mime_map = [
            'pdf'  => 'application/pdf',
            'doc'  => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'ppt'  => 'application/vnd.ms-powerpoint',
            'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'xls'  => 'application/vnd.ms-excel',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'txt'  => 'text/plain',
        ];
        $ext  = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $mime = $mime_map[$ext] ?? 'application/octet-stream';

        header('Content-Type: ' . $mime);
        header('Content-Disposition: inline; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file));
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        if ($is_paid) {
            header('Content-Security-Policy: frame-ancestors \'self\'; default-src \'self\'; style-src \'self\' \'unsafe-inline\';');
        }
        readfile($file);
        exit;
    }
    
    if (!empty($note_row['content'])) {
        header('Content-Type: text/plain; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Frame-Options: SAMEORIGIN');
        if ($is_paid) {
            header('Content-Security-Policy: frame-ancestors \'self\';');
        }
        echo $note_row['content'];
        exit;
    }
    
    die("Note content not found.");
}

/* ========
 * SERVE VIDEO
 * ======== */
if (isset($_GET['video'])) {
    $video_id = intval($_GET['video']);
    if ($video_id <= 0) {
        http_response_code(400);
        die("Missing video id.");
    }

    $vstmt = $pdo->prepare(
        "SELECT cv.video_path, c.id AS v_course_id, c.course_type, c.price
         FROM course_videos cv
         JOIN courses c ON c.id = cv.course_id
         WHERE cv.id = ?"
    );
    $vstmt->execute([$video_id]);
    $vrow = $vstmt->fetch();
    if (!$vrow) {
        http_response_code(404);
        die("Video not found.");
    }

    $v_course_id = (int) $vrow['v_course_id'];
    $v_is_paid = (!empty($vrow['course_type']) && $vrow['course_type'] === 'Paid')
               || (!empty($vrow['price']) && (float) $vrow['price'] > 0);

    if (!checkCourseAccess($pdo, $user_id, $v_course_id, $v_is_paid)) {
        http_response_code(403);
        die("You do not have access to this video. Enroll and complete payment to view course content.");
    }

    $file = $vrow['video_path'];
    if (!$file || !file_exists($file)) {
        http_response_code(404);
        die("File not found on server.");
    }

    $filesize = filesize($file);
    $mime = 'video/mp4';
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $detected = $fi->file($file);
    if ($detected) $mime = $detected;

    header('Content-Type: ' . $mime);
    header('Accept-Ranges: bytes');
    header('Cache-Control: private, max-age=0, no-cache');
    header('X-Content-Type-Options: nosniff');
    
    if ($v_is_paid) {
        header('X-Frame-Options: SAMEORIGIN');
        header('Content-Security-Policy: frame-ancestors \'self\'; default-src \'self\'; media-src \'self\';');
    }

    $start = 0;
    $end   = $filesize - 1;
    if (isset($_SERVER['HTTP_RANGE'])) {
        if (preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $matches)) {
            if ($matches[1] !== '') $start = (int) $matches[1];
            if ($matches[2] !== '') $end   = (int) $matches[2];
            $end = min($end, $filesize - 1);
            if ($start > $end || $start >= $filesize) {
                header('Content-Range: bytes */' . $filesize);
                http_response_code(416);
                exit;
            }
            http_response_code(206);
            header('Content-Range: bytes ' . $start . '-' . $end . '/' . $filesize);
        }
    }

    $length = $end - $start + 1;
    header('Content-Length: ' . $length);

    $fp = fopen($file, 'rb');
    if ($fp === false) {
        http_response_code(500);
        die("Could not open file.");
    }
    fseek($fp, $start);
    $bufferSize = 8192;
    $bytesRemaining = $length;
    while ($bytesRemaining > 0 && !feof($fp)) {
        $readSize = min($bufferSize, $bytesRemaining);
        echo fread($fp, $readSize);
        $bytesRemaining -= $readSize;
        flush();
    }
    fclose($fp);
    exit;
}

/* === QUIZ SUBMISSION === */
if (isset($_POST['submit_quiz'])) {
    validateCsrf();
    $roleCheck = $pdo->prepare("SELECT role FROM users WHERE id=? LIMIT 1");
    $roleCheck->execute([$user_id]);
    $roleRow = $roleCheck->fetch();
    if (!$roleRow || $roleRow['role'] !== 'student') die("X Unauthorized.");

    $quiz_id    = (int)($_POST['quiz_id'] ?? 0);
    $student_id = $user_id;

    $stmt = $pdo->prepare("SELECT * FROM quizzes WHERE id=? AND course_id=?");
    $stmt->execute([$quiz_id, $course_id]);
    $quiz_data = $stmt->fetch();

    if ($quiz_data) {
        $stmt = $pdo->prepare("SELECT * FROM quiz_questions WHERE quiz_id=?");
        $stmt->execute([$quiz_id]);
        $questions_result = $stmt->fetchAll();
        $total = 0; $correct = 0;
        $valid_answers = ['A','B','C','D'];
        foreach ($questions_result as $question) {
            $total++;
            $qid = (int)$question['id'];
            $student_answer = $_POST['answer'][$qid] ?? '';
            if (in_array($student_answer, $valid_answers, true) && $student_answer === $question['correct_answer']) $correct++;
        }
        $score = ($total > 0) ? (int)round(($correct / $total) * 100) : 0;
        $status  = ($score >= (int)$quiz_data['passing_score']) ? 'passed' : 'failed';
        $quiz_title = $quiz_data['title'];

        $attempt = closeQuizAttempt($pdo, $student_id, $quiz_id, $score, $status);
        if (!$attempt['valid']) {
            $_SESSION['quiz_success'] = ($attempt['reason'] ?? '') === 'no_active_attempt'
                ? " Quiz session not found - please start the quiz again from the course page."
                : " Time's up - this attempt expired and was not scored. Start a new attempt.";
            header("Location: course1.php?id=" . $course_id); exit;
        }

        try {
            $pdo->beginTransaction();

            $stmt = $pdo->prepare(
                "INSERT INTO quiz_results (student_id, user_id, quiz_id, quiz_title, score, status, completed_at)
                 VALUES (?,?,?,?,?,?,NOW())
                 ON DUPLICATE KEY UPDATE
                    score=VALUES(score),
                    status=VALUES(status),
                    completed_at=NOW()"
            );
            $stmt->execute([$student_id, $student_id, $quiz_id, $quiz_title, $score, $status]);
            $histStmt = $pdo->prepare(
                "INSERT INTO quiz_history (user_id, title, score, completed_at)
                 VALUES (?,?,?,NOW())"
            );
            $histStmt->execute([$student_id, $quiz_title, $score]);

            $prog_stmt = $pdo->prepare(
                "INSERT INTO student_progress (user_id, course_id, item_type, item_id, completed, score, updated_at)
                 VALUES (?,?,'quiz',?,1,?,NOW())
                 ON DUPLICATE KEY UPDATE
                    completed=1,
                    score=VALUES(score),
                    updated_at=NOW()"
            );
            $prog_stmt->execute([$student_id, $course_id, $quiz_id, $score]);

            if ($status === 'passed') {
                awardCpdPoints($pdo, $student_id, $course_id, 'quiz');
            }

            $vp = $pdo->prepare(
                "SELECT COALESCE(AVG(watched_percentage),0) AS pct FROM video_progress vp
                 JOIN course_videos cv ON cv.id = vp.content_id
                 WHERE vp.user_id=? AND cv.course_id=?"
            );
            $vp->execute([$student_id, $course_id]);
            $video_pct_now = (float) $vp->fetch()['pct'];

            $np = $pdo->prepare(
                "SELECT COUNT(*) AS total, COALESCE(SUM(np.completed),0) AS done
                 FROM notes n LEFT JOIN note_progress np ON np.note_id = n.id AND np.user_id = ?
                 WHERE n.course_id = ?"
            );
            $np->execute([$student_id, $course_id]);
            $npr = $np->fetch();
            $notes_pct_now = $npr['total'] > 0 ? round(($npr['done'] / $npr['total']) * 100) : 100;

            $qp = $pdo->prepare(
                "SELECT COUNT(*) AS total, COALESCE(SUM(qr.status='passed'),0) AS passed
                 FROM quizzes q LEFT JOIN quiz_results qr ON qr.quiz_id = q.id AND qr.user_id = ?
                 WHERE q.course_id = ?"
            );
            $qp->execute([$student_id, $course_id]);
            $qpr = $qp->fetch();
            $quiz_pct_now = $qpr['total'] > 0 ? round(($qpr['passed'] / $qpr['total']) * 100) : 100;

            $ap = $pdo->prepare(
                "SELECT COUNT(*) AS total, COALESCE(SUM(sub.status IN ('submitted','marked','returned')),0) AS done
                 FROM assignments a LEFT JOIN assignment_submissions sub ON sub.assignment_id = a.id AND sub.user_id = ?
                 WHERE a.course_id = ?"
            );
            $ap->execute([$student_id, $course_id]);
            $apr = $ap->fetch();
            $assignments_pct_now = $apr['total'] > 0 ? round(($apr['done'] / $apr['total']) * 100) : 100;

            $cpdNow = getCpdSummary($pdo, $student_id, $course_id);

            checkAndIssueCertificate($pdo, $student_id, $course_id, [
                'video_pct'       => $video_pct_now,
                'notes_pct'       => $notes_pct_now,
                'quiz_pct'        => $quiz_pct_now,
                'assignments_pct' => $assignments_pct_now,
                'cpd_points'      => $cpdNow['earned'],
            ]);

            $pdo->commit();

            $_SESSION['quiz_success'] = "Quiz Submitted! Score: {$score}% - " . ucfirst($status) . "!";
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log("Quiz submission post-processing failed (quiz_id={$quiz_id}, user_id={$student_id}): " . $e->getMessage());
            $_SESSION['quiz_success'] = " Your quiz was scored ({$score}%) but we hit a problem saving some details. Please contact support if this keeps happening.";
        }
    }
    header("Location: course1.php?id=" . $course_id); exit;
}

/* === AJAX === */
if (isset($_POST['action'])) {

    /* Save video progress */
    if ($_POST['action'] === 'save_progress' && $user_id) {
        header('Content-Type: application/json');

        $video_id = intval($_POST['content_id'] ?? 0);
        $watched  = min(100, max(0, intval($_POST['watched'] ?? 0)));
        if (!$video_id || $watched <= 0) {
            echo json_encode(['ok' => false, 'reason' => 'invalid_input', 'video_id' => $video_id, 'watched' => $watched]);
            exit;
        }

        $vcheck = $pdo->prepare("SELECT id FROM course_videos WHERE id=? AND course_id=?");
        $vcheck->execute([$video_id, $course_id]);
        $valid_video = $vcheck->fetch();
        if (!$valid_video) {
            echo json_encode(['ok' => false, 'reason' => 'video_not_in_course', 'video_id' => $video_id, 'course_id' => $course_id]);
            exit;
        }
        $completed = ($watched >= 90) ? 1 : 0;
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO video_progress
                    (user_id, content_id, watched_percentage, completed)
                 VALUES (?,?,?,?)
                 ON DUPLICATE KEY UPDATE
                    watched_percentage = GREATEST(video_progress.watched_percentage, VALUES(watched_percentage)),
                    completed= GREATEST(video_progress.completed, VALUES(completed)),
                    updated_at= CURRENT_TIMESTAMP"
            );
            $stmt->execute([$user_id, $video_id, $watched, $completed]);

            if ($completed) {
                $up = $pdo->prepare(
                    "INSERT INTO student_progress
                        (user_id, course_id, item_type, item_id, completed, updated_at)
                     VALUES (?,?,'video',?,1,NOW())
                     ON DUPLICATE KEY UPDATE completed=1, updated_at=NOW()"
                );
                $up->execute([$user_id, $course_id, $video_id]);
            }

            echo json_encode(['ok' => true, 'video_id' => $video_id, 'watched' => $watched, 'completed' => $completed]);
        } catch (PDOException $e) {
            error_log("save_progress failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error', 'message' => $e->getMessage()]);
        }
        exit;
    }
    
    /* Save note progress */
    if ($_POST['action'] === 'save_note_progress' && $user_id) {
        header('Content-Type: application/json');
        define('NOTE_COMPLETE_PERCENT', 95);
        $note_id = intval($_POST['note_id'] ?? 0);
        $percentage = min(100, max(0, intval($_POST['percentage'] ?? $_POST['seconds'] ?? 0)));
        $force_done = isset($_POST['force_done']) && $_POST['force_done'] === '1';

        if (!$note_id) {
            echo json_encode(['ok' => false, 'reason' => 'invalid_input']);
            exit;
        }
        $check = $pdo->prepare("SELECT id FROM notes WHERE id=? AND course_id=?");
        $check->execute([$note_id, $course_id]);
        $valid_note = $check->fetch();
        if (!$valid_note) {
            echo json_encode(['ok' => false, 'reason' => 'note_not_in_course', 'note_id' => $note_id, 'course_id' => $course_id]);
            exit;
        }
        $completed = ($percentage >= NOTE_COMPLETE_PERCENT || $force_done) ? 1 : 0;
        $percentage = $force_done ? 100 : $percentage;
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO note_progress
                    (user_id, note_id, opened, seconds_viewed, completed)
                 VALUES (?,?,1,?,?)
                 ON DUPLICATE KEY UPDATE
                    opened         = 1,
                    seconds_viewed = GREATEST(note_progress.seconds_viewed, VALUES(seconds_viewed)),
                    completed      = GREATEST(note_progress.completed, VALUES(completed)),
                    updated_at     = CURRENT_TIMESTAMP"
            );
            $stmt->execute([$user_id, $note_id, $percentage, $completed]);
            if ($completed) {
                $up = $pdo->prepare(
                    "INSERT INTO student_progress
                        (user_id, course_id, item_type, item_id, completed, updated_at)
                     VALUES (?,?,'note',?,1,NOW())
                     ON DUPLICATE KEY UPDATE completed=1, updated_at=NOW()"
                );
                $up->execute([$user_id, $course_id, $note_id]);
            }
            echo json_encode(['ok' => true, 'note_id' => $note_id, 'percentage' => $percentage, 'completed' => $completed]);
        } catch (PDOException $e) {
            error_log("save_note_progress failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error', 'message' => $e->getMessage()]);
        }
        exit;
    }
    
    /* Add review */
    if ($_POST['action'] === 'add_review' && $user_id) {
        header('Content-Type: application/json');
        $review_course_id = intval($_POST['course_id'] ?? $course_id);
        $rating  = min(5, max(1, intval($_POST['rating'])));
        $comment = trim($_POST['comment'] ?? '');
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO course_reviews (user_id, course_id, rating, review)
                 VALUES (?,?,?,?)
                 ON DUPLICATE KEY UPDATE
                    rating=VALUES(rating),
                    review=VALUES(review)"
            );
            $stmt->execute([$user_id, $review_course_id, $rating, $comment]);
            $avg_stmt = $pdo->prepare("SELECT ROUND(AVG(rating),1) AS avg_rating, COUNT(*) AS total FROM course_reviews WHERE course_id=?");
            $avg_stmt->execute([$review_course_id]);
            $avg_data = $avg_stmt->fetch();
            echo json_encode(array_merge(['ok' => true], $avg_data));
        } catch (PDOException $e) {
            error_log("add_review failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error', 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ========
     * START QUIZ 
     * ======== */
    if ($_POST['action'] === 'start_quiz' && $user_id) {
        header('Content-Type: application/json');
        
        $quiz_id = intval($_POST['quiz_id'] ?? 0);
        if ($quiz_id <= 0) {
            echo json_encode(['ok' => false, 'reason' => 'invalid_quiz_id']);
            exit;
        }
        
        $qcheck = $pdo->prepare("SELECT id, duration, max_attempts FROM quizzes WHERE id=? AND course_id=?");
        $qcheck->execute([$quiz_id, $course_id]);
        $quizRow = $qcheck->fetch();
        if (!$quizRow) {
            echo json_encode(['ok' => false, 'reason' => 'quiz_not_in_course']);
            exit;
        }

        $max_attempts = (isset($quizRow['max_attempts']) && $quizRow['max_attempts'] !== null)
            ? (int) $quizRow['max_attempts'] : 0;
            
        if ($max_attempts > 0) {
            $cnt = $pdo->prepare("SELECT COUNT(*) AS n FROM quiz_attempts WHERE user_id=? AND quiz_id=?");
            $cnt->execute([$user_id, $quiz_id]);
            $attempts_used = (int) $cnt->fetch()['n'];

            $inprog = $pdo->prepare(
                "SELECT id FROM quiz_attempts
                 WHERE user_id=? AND quiz_id=? AND status='in_progress' AND server_expires_at > NOW()
                 LIMIT 1"
            );
            $inprog->execute([$user_id, $quiz_id]);

            if ($attempts_used >= $max_attempts && !$inprog->fetch()) {
                echo json_encode(['ok' => false, 'reason' => 'max_attempts_reached', 'max_attempts' => $max_attempts]);
                exit;
            }
        }

        try {
            $duration = (int) $quizRow['duration'];
            $attempt = startQuizAttempt($pdo, $user_id, $quiz_id, $course_id, $duration);
            
            if (!$attempt) {
                echo json_encode(['ok' => false, 'reason' => 'failed_to_create_attempt']);
                exit;
            }
            echo json_encode([
                'ok' => true,
                'seconds_remaining' => (int) $attempt['seconds_remaining'],
            ]);
        } catch (PDOException $e) {
            error_log("start_quiz failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error', 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* Assignment submission */
    if ($_POST['action'] === 'submit_assignment' && $user_id) {
        header('Content-Type: application/json');
        validateCsrf();
        $assignment_id = intval($_POST['assignment_id'] ?? 0);
        $text = trim((string)($_POST['submission_text'] ?? ''));

        $achk = $pdo->prepare("SELECT * FROM assignments WHERE id=? AND course_id=?");
        $achk->execute([$assignment_id, $course_id]);
        $assignment = $achk->fetch();
        if (!$assignment) {
            echo json_encode(['ok' => false, 'reason' => 'assignment_not_found']);
            exit;
        }
        if ($text === '' && empty($_FILES['submission_file']['name'])) {
            echo json_encode(['ok' => false, 'reason' => 'empty_submission']);
            exit;
        }

        $is_late = 0;
        if (!empty($assignment['due_date']) && strtotime($assignment['due_date']) < time()) {
            $is_late = 1;
        }

        $file_path = null;
        if (!empty($_FILES['submission_file']['name']) && $_FILES['submission_file']['error'] === UPLOAD_ERR_OK) {
            $allowed_ext = ['pdf','doc','docx','png','jpg','jpeg'];
            $ext = strtolower(pathinfo($_FILES['submission_file']['name'], PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed_ext, true)) {
                echo json_encode(['ok' => false, 'reason' => 'invalid_file_type']);
                exit;
            }
            $dest_dir = __DIR__ . '/uploads/assignments/';
            if (!is_dir($dest_dir)) mkdir($dest_dir, 0755, true);
            $safe_name = 'a' . $assignment_id . '_u' . $user_id . '_' . time() . '.' . $ext;
            $dest = $dest_dir . $safe_name;
            if (move_uploaded_file($_FILES['submission_file']['tmp_name'], $dest)) {
                $file_path = 'uploads/assignments/' . $safe_name;
            }
        }

        try {
            $ins = $pdo->prepare(
                "INSERT INTO assignment_submissions
                    (assignment_id, user_id, submission_text, file_path, submitted_at, is_late, status)
                 VALUES (?,?,?,?,NOW(),?, 'submitted')"
            );
            $ins->execute([$assignment_id, $user_id, $text ?: null, $file_path, $is_late]);
            awardCpdPoints($pdo, $user_id, $course_id, 'assignment');
            echo json_encode(['ok' => true, 'is_late' => (bool) $is_late]);
        } catch (PDOException $e) {
            error_log("submit_assignment failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error']);
        }
        exit;
    }

    /* Discussion / Q&A post */
    if ($_POST['action'] === 'post_discussion' && $user_id) {
        header('Content-Type: application/json');
        validateCsrf();
        $body = trim((string)($_POST['body'] ?? ''));
        $parent_id = !empty($_POST['parent_id']) ? intval($_POST['parent_id']) : null;
        if ($body === '') {
            echo json_encode(['ok' => false, 'reason' => 'empty_post']);
            exit;
        }
        $roleStmt = $pdo->prepare("SELECT role FROM users WHERE id=?");
        $roleStmt->execute([$user_id]);
        $is_trainer = (($roleStmt->fetch()['role'] ?? '') === 'trainer') ? 1 : 0;

        try {
            $ins = $pdo->prepare(
                "INSERT INTO course_discussion_posts (course_id, parent_id, user_id, body, is_trainer_reply, created_at)
                 VALUES (?,?,?,?,?,NOW())"
            );
            $ins->execute([$course_id, $parent_id, $user_id, $body, $is_trainer]);
            echo json_encode(['ok' => true, 'id' => (int) $pdo->lastInsertId()]);
        } catch (PDOException $e) {
            error_log("post_discussion failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error']);
        }
        exit;
    }

    http_response_code(200); exit;
}

/* ========== PAGE LOAD ========== */
$course_query = $pdo->prepare("SELECT c.*, u.full_name AS instructor FROM courses c LEFT JOIN teachers t ON t.id=c.teacher_id LEFT JOIN users u ON u.id=t.user_id WHERE c.id=?");
$course_query->execute([$course_id]);
$course = $course_query->fetch();
if (!$course) die("Course not found");

$is_paid = (!empty($course['course_type']) && $course['course_type'] === 'Paid')
         || (!empty($course['price']) && (float)$course['price'] > 0);

$has_access = checkCourseAccess($pdo, $user_id, $course_id, $is_paid);
if (!$has_access) {
    $enroll_stmt = $pdo->prepare("SELECT status FROM enrollments WHERE user_id=? AND course_id=?");
    $enroll_stmt->execute([$user_id, $course_id]);
    $enroll_row = $enroll_stmt->fetch();
    $enroll_status_norm = $enroll_row ? strtolower(trim((string)$enroll_row['status'])) : null;
    $is_enrolled_status  = $enroll_status_norm !== null && in_array($enroll_status_norm, ENROLLED_STATUSES, true);
    $reason = !$enroll_row ? 'not_enrolled'
            : ($is_enrolled_status ? 'payment_required' : 'enrollment_' . $enroll_status_norm);

    $messages = [
        'not_enrolled'         => ['title' => "You're not enrolled in this course yet",
                                   'body'  => "Enroll to get access to the videos, notes, quizzes and assignments."],
        'enrollment_pending'   => ['title' => "Enrollment pending approval",
                                   'body'  => "Your enrollment request is being reviewed. We'll notify you once it's confirmed."],
        'enrollment_cancelled' => ['title' => "Enrollment cancelled",
                                   'body'  => "Your enrollment in this course was cancelled. Contact support if you believe this is a mistake."],
        'enrollment_expired'   => ['title' => "Enrollment expired",
                                   'body'  => "Your access window for this course has ended. Renew to continue."],
        'payment_required'     => ['title' => "Payment required",
                                   'body'  => "This is a paid course. Complete payment to unlock the full content."],
    ];
    $m = $messages[$reason] ?? $messages['not_enrolled'];
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access required - <?= htmlspecialchars($course['title']) ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
    :root {
        --accent:#6b9b2e; --accent2:#8bc53f; --accent-lt:#eef7e3;
        --text:#2b2b3d; --muted:#6b7280; --bg:#f7f8f5; --surface:#fff;
        --border:rgba(107,155,46,0.15);
    }
    *{margin:0;padding:0;box-sizing:border-box;}
    body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
    .box{background:var(--surface);border:1px solid var(--border);border-radius:18px;max-width:460px;width:100%;padding:36px 32px;text-align:center;box-shadow:0 4px 24px rgba(107,155,46,0.08);}
    .icon{width:56px;height:56px;border-radius:50%;background:var(--accent-lt);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:22px;margin:0 auto 18px;}
    h1{font-size:19px;margin-bottom:10px;}
    p{color:var(--muted);font-size:14px;line-height:1.6;margin-bottom:22px;}
    .course-name{font-weight:700;color:var(--accent);}
    .btn{display:inline-flex;align-items:center;gap:8px;background:var(--accent);color:#fff;padding:11px 22px;border-radius:10px;font-weight:700;font-size:14px;text-decoration:none;}
    .btn:hover{background:#588424;text-decoration:none;color:#fff;}
    .secondary{display:block;margin-top:14px;font-size:13px;color:var(--muted);}
    .brand{font-size:12px;color:var(--muted);margin-top:26px;letter-spacing:0.4px;}
    </style>
    </head>
    <body>
    <div class="box">
        <div class="icon"><i class="fas fa-lock"></i></div>
        <h1><?= htmlspecialchars($m['title']) ?></h1>
        <p><span class="course-name"><?= htmlspecialchars($course['title']) ?></span><br><?= htmlspecialchars($m['body']) ?></p>
        <?php if ($reason === 'not_enrolled'): ?>
            <a class="btn" href="enroll.php?course_id=<?= (int)$course_id ?>"><i class="fas fa-arrow-right"></i> Enroll now</a>
        <?php elseif ($reason === 'payment_required'): ?>
            <a class="btn" href="checkout.php?course_id=<?= (int)$course_id ?>"><i class="fas fa-credit-card"></i> Complete payment</a>
        <?php elseif ($reason === 'enrollment_expired'): ?>
            <a class="btn" href="checkout.php?course_id=<?= (int)$course_id ?>&renew=1"><i class="fas fa-rotate"></i> Renew access</a>
        <?php endif; ?>
        <a class="secondary" href="student.php">← Back to dashboard</a>
        <div class="brand">CBT-Kenya · Skills Transfer Program</div>
    </div>
    </body>
    </html>
    <?php
    exit;
}

/* NOTES */
$notes_stmt = $pdo->prepare("SELECT * FROM notes WHERE course_id=? ORDER BY id ASC");
$notes_stmt->execute([$course_id]);
$notes_rows = $notes_stmt->fetchAll();
$note_count = count($notes_rows);

/* VIDEOS */
$videos_stmt = $pdo->prepare("SELECT * FROM course_videos WHERE course_id=? ORDER BY id ASC");
$videos_stmt->execute([$course_id]);
$videos_rows = $videos_stmt->fetchAll();
$video_count = count($videos_rows);

/* QUIZZES */
$quizzes_stmt = $pdo->prepare("SELECT * FROM quizzes WHERE course_id=? ORDER BY id DESC");
$quizzes_stmt->execute([$course_id]);
$quizzes_rows = $quizzes_stmt->fetchAll();
$quiz_count  = count($quizzes_rows);

/* VIDEO PROGRESS MAP */
$video_progress_map = [];
foreach ($videos_rows as $v) {
    $video_progress_map[(int)$v['id']] = ['pct' => 0, 'completed' => 0];
}

if ($video_count > 0) {
    $vid_ids = array_map('intval', array_keys($video_progress_map));
    $ph = inPlaceholders($vid_ids);
    $vpm_stmt = $pdo->prepare(
        "SELECT content_id,
                MAX(watched_percentage) AS watched_percentage,
                MAX(completed) AS completed
         FROM video_progress
         WHERE user_id = ? AND content_id IN ($ph)
         GROUP BY content_id"
    );
    $vpm_stmt->execute(array_merge([$user_id], $vid_ids));
    foreach ($vpm_stmt->fetchAll() as $row) {
        $cid = (int)$row['content_id'];
        if (isset($video_progress_map[$cid])) {
            $video_progress_map[$cid] = [
                'pct'       => (int)$row['watched_percentage'],
                'completed' => (int)$row['completed'],
            ];
        }
    }
}

/* NOTE PROGRESS MAP */
$note_progress_map = [];
foreach ($notes_rows as $n) {
    $note_progress_map[(int)$n['id']] = ['percentage' => 0, 'completed' => 0];
}

if ($note_count > 0) {
    $note_ids = array_map('intval', array_keys($note_progress_map));
    $ph = inPlaceholders($note_ids);
    $npres_stmt = $pdo->prepare(
        "SELECT note_id,
                MAX(seconds_viewed) AS percentage_scrolled,
                MAX(completed)      AS completed
         FROM note_progress
         WHERE user_id = ? AND note_id IN ($ph)
         GROUP BY note_id"
    );
    $npres_stmt->execute(array_merge([$user_id], $note_ids));
    foreach ($npres_stmt->fetchAll() as $row) {
        $nid = (int)$row['note_id'];
        if (isset($note_progress_map[$nid])) {
            $note_progress_map[$nid] = [
                'percentage' => min(100, (int)$row['percentage_scrolled']),
                'completed'  => (int)$row['completed'],
            ];
        }
    }
}

/* Compute aggregate percentages */
$video_progress = 0;
if ($video_count > 0) {
    $sum = array_sum(array_column($video_progress_map, 'pct'));
    $video_progress = (int)round($sum / $video_count);
}

$note_progress = 0;
$completed_notes_count = 0;
if ($note_count > 0) {
    $completed_notes_count = array_sum(array_column($note_progress_map, 'completed'));
    $note_progress = (int)round(($completed_notes_count / $note_count) * 100);
}

$quiz_progress   = 0;
$quiz_status_map = [];
if ($quiz_count > 0) {
    $quiz_ids  = array_map(fn($q) => (int)$q['id'], $quizzes_rows);
    $ph = inPlaceholders($quiz_ids);
    $qsm_stmt = $pdo->prepare(
        "SELECT quiz_id, status
         FROM quiz_results
         WHERE user_id=? AND quiz_id IN ($ph)
         ORDER BY completed_at DESC"
    );
    $qsm_stmt->execute(array_merge([$user_id], $quiz_ids));
    foreach ($qsm_stmt->fetchAll() as $row) {
        if (!isset($quiz_status_map[(int)$row['quiz_id']])) {
            $quiz_status_map[(int)$row['quiz_id']] = $row['status'];
        }
    }
    $passed_count  = count(array_filter($quiz_status_map, fn($s) => $s === 'passed'));
    $quiz_progress = (int)round(($passed_count / $quiz_count) * 100);
}

/* QUIZ ATTEMPT COUNTS */
$quiz_attempts_map = [];
if ($quiz_count > 0) {
    $quiz_ids = array_map(fn($q) => (int)$q['id'], $quizzes_rows);
    $ph = inPlaceholders($quiz_ids);
    $qam_stmt = $pdo->prepare(
        "SELECT quiz_id, COUNT(*) AS attempts
         FROM quiz_attempts
         WHERE user_id=? AND quiz_id IN ($ph)
         GROUP BY quiz_id"
    );
    $qam_stmt->execute(array_merge([$user_id], $quiz_ids));
    foreach ($qam_stmt->fetchAll() as $row) {
        $quiz_attempts_map[(int)$row['quiz_id']] = (int)$row['attempts'];
    }
}

/* Weighted overall progress */
$w_video = ($video_count > 0) ? 0.60 : 0;
$w_note  = ($note_count  > 0) ? 0.25 : 0;
$w_quiz  = ($quiz_count  > 0) ? 0.15 : 0;
$w_total = $w_video + $w_note + $w_quiz;
$progress = ($w_total > 0)
    ? (int)round(($video_progress * $w_video + $note_progress * $w_note + $quiz_progress * $w_quiz) / $w_total)
    : 0;

/* RATING */
$rating_stmt = $pdo->prepare("SELECT ROUND(AVG(rating),1) AS avg_rating, COUNT(*) AS total FROM course_reviews WHERE course_id=?");
$rating_stmt->execute([$course_id]);
$rating_data   = $rating_stmt->fetch();
$avg_rating    = $rating_data['avg_rating'] ?? 0;
$total_ratings = $rating_data['total'] ?? 0;

/* QUIZ DATA */
$all_quizzes   = $quizzes_rows;
$all_questions = [];
if (!empty($all_quizzes)) {
    $quiz_ids  = array_map(fn($q) => (int)$q['id'], $all_quizzes);
    $ph = inPlaceholders($quiz_ids);
    $qres2_stmt = $pdo->prepare("SELECT * FROM quiz_questions WHERE quiz_id IN ($ph) ORDER BY quiz_id, id");
    $qres2_stmt->execute($quiz_ids);
    $all_questions = $qres2_stmt->fetchAll();
}

/* QUIZ STATS */
$total_quizzes = 0; $passed = 0; $failed = 0; $avgScore = 0;
if (!empty($all_quizzes)) {
    $quiz_ids  = array_map(fn($q) => (int)$q['id'], $all_quizzes);
    $ph = inPlaceholders($quiz_ids);
    $statRes_stmt = $pdo->prepare(
        "SELECT COUNT(*) AS total_quizzes, COALESCE(SUM(status='passed'),0) AS passed, COALESCE(SUM(status='failed'),0) AS failed, COALESCE(AVG(score),0) AS avg_score
         FROM quiz_results WHERE user_id=? AND quiz_id IN ($ph)"
    );
    $statRes_stmt->execute(array_merge([$user_id], $quiz_ids));
    $quizStats     = $statRes_stmt->fetch();
    $total_quizzes = (int)($quizStats['total_quizzes'] ?? 0);
    $passed        = (int)($quizStats['passed']        ?? 0);
    $failed        = (int)($quizStats['failed']        ?? 0);
    $avgScore      = round((float)($quizStats['avg_score'] ?? 0), 1);
}

$results_rows = [];
if (!empty($all_quizzes)) {
    $quiz_ids  = array_map(fn($q) => (int)$q['id'], $all_quizzes);
    $ph = inPlaceholders($quiz_ids);
    $rq_stmt = $pdo->prepare(
        "SELECT * FROM quiz_results WHERE user_id=? AND quiz_id IN ($ph) ORDER BY completed_at DESC LIMIT 5"
    );
    $rq_stmt->execute(array_merge([$user_id], $quiz_ids));
    $results_rows = $rq_stmt->fetchAll();
}

$history_rows = [];
if (!empty($all_quizzes)) {
    $quiz_titles = array_map(fn($q) => $q['title'], $all_quizzes);
    $ph3 = inPlaceholders($quiz_titles);
    $hist_stmt = $pdo->prepare(
        "SELECT * FROM quiz_history WHERE user_id=? AND title IN ($ph3) ORDER BY completed_at DESC"
    );
    $hist_stmt->execute(array_merge([$user_id], $quiz_titles));
    $history_rows = $hist_stmt->fetchAll();
}

$stmt = $pdo->prepare("SELECT * FROM quiz_achievements WHERE user_id=?");
$stmt->execute([$user_id]);
$achievements_rows = $stmt->fetchAll();

$stmt = $pdo->prepare("SELECT * FROM certificates WHERE user_id=? AND course_id=? ORDER BY issued_at DESC");
$stmt->execute([$user_id, $course_id]);
$certs_rows = $stmt->fetchAll();

/* === ASSIGNMENTS === */
$assign_stmt = $pdo->prepare(
    "SELECT 
        a.*,
        s.status AS sub_status,
        s.score AS sub_score,
        s.feedback AS sub_feedback,
        s.submitted_at AS sub_submitted_at,
        s.is_late AS sub_is_late
     FROM assignments a
     LEFT JOIN assignment_submissions s 
        ON s.assignment_id = a.id 
        AND s.user_id = ?
     WHERE a.course_id = ?
     ORDER BY 
        a.due_date IS NULL,
        a.due_date ASC"
);
$assign_stmt->execute([$user_id, $course_id]);
$assignments_rows = $assign_stmt->fetchAll();
$assignment_count = count($assignments_rows);
$assignments_done = count(
    array_filter(
        $assignments_rows,
        fn($a) => !empty($a['sub_status'])
    )
);

/* === ANNOUNCEMENTS === */
$ann_stmt = $pdo->prepare(
    "SELECT ca.*, u.full_name AS poster_name
     FROM course_announcements ca
     LEFT JOIN users u ON u.id = ca.posted_by
     WHERE ca.course_id = ? ORDER BY ca.created_at DESC LIMIT 10"
);
$ann_stmt->execute([$course_id]);
$announcements_rows = $ann_stmt->fetchAll();

/* === DISCUSSION / Q&A === */
$disc_stmt = $pdo->prepare(
    "SELECT p.*, u.full_name AS author_name,
            (SELECT COUNT(*) FROM course_discussion_posts r WHERE r.parent_id = p.id) AS reply_count
     FROM course_discussion_posts p
     LEFT JOIN users u ON u.id = p.user_id
     WHERE p.course_id = ? AND p.parent_id IS NULL
     ORDER BY p.created_at DESC LIMIT 20"
);
$disc_stmt->execute([$course_id]);
$discussion_rows = $disc_stmt->fetchAll();

/* === CPD / CME POINTS === */
$cpd_summary = getCpdSummary($pdo, $user_id, $course_id);

/* === COMPETENCIES === */
$comp_stmt = $pdo->prepare(
    "SELECT c.*, sc.verified
     FROM competencies c
     LEFT JOIN student_competencies sc
       ON sc.competency_id = c.id
      AND sc.user_id = ?
     WHERE c.course_id = ?
     ORDER BY c.sort_order ASC, c.id ASC"
);
$comp_stmt->execute([$user_id, $course_id]);
$competency_rows = $comp_stmt->fetchAll();

/* === CAREER OPPORTUNITIES === */
$career_stmt = $pdo->prepare(
    "SELECT * FROM career_opportunities
     WHERE course_id = ? OR course_id IS NULL
     ORDER BY deadline IS NULL, deadline ASC LIMIT 4"
);
$career_stmt->execute([$course_id]);
$career_rows = $career_stmt->fetchAll();

$flash        = $_SESSION['flash']        ?? ''; unset($_SESSION['flash']);
$quiz_success = $_SESSION['quiz_success'] ?? ''; unset($_SESSION['quiz_success']);

$csrf_js    = json_encode($_SESSION['csrf_token'], JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP);
$is_paid_js = $is_paid ? 'true' : 'false';

/* JS INIT DATA */
$js_video_map = [];
foreach ($video_progress_map as $vid => $vdata) {
    $js_video_map[$vid] = $vdata['pct'];
}
$js_note_map = [];
$js_note_progress = [];
foreach ($note_progress_map as $nid => $ndata) {
    $js_note_map[$nid] = $ndata['completed'] ? 1 : 0;
    $js_note_progress[$nid] = $ndata['percentage'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($course['title']) ?> - CBT-Kenya STP</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
:root {
    --bg:#f7f8f5; --surface:#fff; --surface2:#f2f6ea;
    --border:rgba(107,155,46,0.14); --border-md:rgba(107,155,46,0.26);
    --text:#2b2b3d; --muted:#6b7280;
    --accent:#6b9b2e; --accent2:#8bc53f; --accent-lt:#eef7e3;
    --orange:#f5a623; --orange-lt:#fef3e0;
    --green:#16a34a; --green-lt:#dcfce7;
    --amber:#d97706; --amber-lt:#fef3c7; --red:#dc2626;
    --shadow-sm:0 1px 4px rgba(107,155,46,0.08);
    --shadow-md:0 4px 20px rgba(107,155,46,0.12);
    --radius-sm:8px; --radius-md:12px; --radius-lg:18px;
}
html { scroll-behavior:smooth; }
body { background:var(--bg); color:var(--text); font-family:-apple-system,'Segoe UI',sans-serif; font-size:15px; line-height:1.6; min-height:100vh; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
img { display:block; max-width:100%; }

/* PAID CONTENT PROTECTION */
body.protected { -webkit-user-select:none; user-select:none; -webkit-user-drag:none; }
body.protected video::-webkit-media-controls-download-button { display:none!important; }
body.protected img { pointer-events:none; }
.paid-watermark { position:fixed; inset:0; pointer-events:none; z-index:8000; display:none;
    background:repeating-linear-gradient(-45deg,transparent,transparent 120px,rgba(91,82,232,0.04) 120px,rgba(91,82,232,0.04) 122px); }
.paid-watermark::after { content:'CBT-Kenya STP - Licensed Content'; position:absolute; top:50%; left:50%;
    transform:translate(-50%,-50%) rotate(-30deg); font-size:clamp(14px,2vw,22px); font-weight:700;
    color:rgba(107,155,46,0.08); white-space:nowrap; letter-spacing:2px; pointer-events:none; }
body.protected .paid-watermark { display:block; }
.badge-paid { background:rgba(245,166,35,0.25); border-color:rgba(245,166,35,0.5); color:#fff5e6; }

/* PROTECTION TOAST */
.protection-toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:#2b2b3d; color:#fff; padding:12px 24px; border-radius:30px; font-size:13px; font-weight:600; box-shadow:0 4px 20px rgba(0,0,0,0.3); z-index:9999; opacity:0; transition:opacity 0.3s; pointer-events:none; white-space:nowrap; }
.protection-toast.show { opacity:1; }

/* PAID NOTE PROTECTION */
.note-protected-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.85); z-index:9998; align-items:center; justify-content:center; }
.note-protected-overlay.active { display:flex; }
.note-protected-overlay .msg { background:#fff; border-radius:16px; padding:40px; max-width:420px; text-align:center; }
.note-protected-overlay .msg i { font-size:48px; color:var(--accent); display:block; margin-bottom:16px; }
.note-protected-overlay .msg h3 { font-size:18px; margin-bottom:8px; }
.note-protected-overlay .msg p { color:var(--muted); font-size:14px; }

/* LAYOUT */
.page-wrap { max-width:1180px; margin:0 auto; padding:0 24px 80px; }
.site-header { background:var(--surface); border-bottom:1px solid var(--border); padding:12px 24px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; }
.site-header-inner { max-width:1180px; margin:0 auto; width:100%; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; }
.brand-lockup { display:flex; align-items:center; gap:10px; }
.brand-mark { width:34px; height:34px; border-radius:9px; background:linear-gradient(135deg,var(--accent),var(--accent2)); color:#fff; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:13px; letter-spacing:0.5px; }
.brand-text { font-weight:800; font-size:15px; color:var(--text); line-height:1.15; }
.brand-text small { display:block; font-weight:600; font-size:10.5px; color:var(--muted); letter-spacing:0.5px; text-transform:uppercase; }
.site-footer { background:var(--text); color:rgba(255,255,255,0.75); padding:26px 24px; text-align:center; font-size:12.5px; margin-top:10px; }
.site-footer strong { color:#fff; }
.hero { background:linear-gradient(130deg,#5a8524 0%,#8bc53f 60%,#a9d666 100%); padding:20px 0; margin-bottom:10px; }
.hero-inner { max-width:1180px; margin:0 auto; padding:0 24px; }
.hero-meta { display:flex; align-items:center; gap:5px; margin-bottom:10px; flex-wrap:wrap; justify-content:center; }
.badge { display:inline-flex; align-items:center; gap:5px; background:rgba(255,255,255,0.2); color:#fff;
    border:1px solid rgba(255,255,255,0.3); font-size:12px; font-weight:600; padding:4px 12px; border-radius:20px; }
.badge-green { background:rgba(22,163,74,0.2); border-color:rgba(22,163,74,0.4); }
.hero h1 { font-size:clamp(20px,4vw,40px); font-weight:700; color:#fff; margin-bottom:10px; text-align:center; }
.hero-desc { color:rgba(255,255,255,0.82); max-width:640px; margin:0 auto 15px; text-align:center; font-size:15px; }
.hero-stats { display:flex; align-items:center; justify-content:center; gap:12px; flex-wrap:wrap; font-size:13px; color:rgba(255,255,255,0.75); }
.hero-stats span { display:flex; align-items:center; gap:6px; }
.hero-stats .dot { width:3px; height:3px; background:rgba(255,255,255,0.4); border-radius:50%; }
.hero-stats strong { color:#fff; }
.stars { color:#fcd34d; font-size:15px; }

/* GRID */
.main-grid { display:grid; grid-template-columns:1fr 320px; gap:24px; align-items:start; }

/* CARD */
.card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-lg); box-shadow:var(--shadow-sm); overflow:hidden; margin-bottom:20px; }
.card-header { padding:18px 22px 14px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px; }
.card-header h2 { font-size:15px; font-weight:700; color:var(--text); display:flex; align-items:center; gap:8px; }
.card-header h2 i { color:var(--accent); }
.card-header .count { font-size:12px; color:var(--muted); background:var(--surface2); padding:2px 10px; border-radius:20px; border:1px solid var(--border); font-weight:500; }

/* FLASH */
.flash { background:var(--green-lt); color:var(--green); border:1px solid rgba(22,163,74,0.25); border-radius:var(--radius-sm); padding:13px 18px; margin:0 22px 18px; font-weight:600; }

/* PROGRESS */
.progress-wrap { padding:20px 22px; }
.progress-numbers { display:flex; align-items:baseline; gap:6px; margin-bottom:12px; }
.progress-numbers .big { font-size:34px; font-weight:700; color:var(--green); }
.progress-numbers .small { font-size:14px; color:var(--muted); }
.progress-bar-track { width:100%; height:10px; background:var(--surface2); border-radius:10px; overflow:hidden; border:1px solid var(--border); }
.progress-bar-fill { height:100%; background:linear-gradient(90deg,#16a34a,#22c55e); border-radius:10px; transition:width 0.8s ease; }
.progress-label { margin-top:10px; font-size:13px; color:var(--muted); }
.progress-breakdown { display:flex; gap:12px; flex-wrap:wrap; margin-top:12px; font-size:12px; color:var(--muted); }
.progress-breakdown span strong { color:var(--text); }

/* VIDEO */
.video-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:14px; padding:18px 22px; }
.video-card { background:var(--surface2); border-radius:var(--radius-md); overflow:hidden; border:1.5px solid var(--border); transition:transform 0.18s,box-shadow 0.18s,border-color 0.18s; cursor:pointer; }
.video-card:hover { transform:translateY(-3px); box-shadow:var(--shadow-md); border-color:var(--accent2); }
.video-card.watching { border-color:var(--accent); box-shadow:0 0 0 3px rgba(107,155,46,0.15); }
.video-card.done { border-color:var(--green); }
.video-thumb { position:relative; background:#1a1830; aspect-ratio:16/9; display:flex; align-items:center; justify-content:center; }
.play-overlay { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(26,24,48,0.35); }
.play-btn { width:46px; height:46px; background:var(--accent); border-radius:50%; display:flex; align-items:center; justify-content:center; box-shadow:0 4px 16px rgba(107,155,46,0.45); transition:transform 0.15s; }
.video-card:hover .play-btn { transform:scale(1.1); }
.play-btn svg { width:18px; height:18px; fill:#fff; margin-left:3px; }
.video-info { padding:12px 14px; }
.video-num { font-size:11px; color:var(--accent); font-weight:700; text-transform:uppercase; letter-spacing:0.7px; margin-bottom:4px; }
.video-title { font-size:13px; font-weight:600; line-height:1.4; color:var(--text); }
.video-watched { margin-top:10px; height:4px; background:var(--border); border-radius:4px; overflow:hidden; }
.video-watched-fill { height:100%; background:var(--accent); border-radius:4px; transition:width 0.3s; }
.done-badge { display:inline-flex; align-items:center; gap:3px; font-size:10px; font-weight:700; color:var(--green); background:var(--green-lt); padding:2px 8px; border-radius:10px; margin-top:4px; }
.done-badge i { font-size:9px; }

/* PLAYER */
#player-wrap { display:none; margin:0 22px 0; }
#player-wrap.active { display:block; }
#main-player { background:#0a0916; border-radius:var(--radius-md); overflow:hidden; aspect-ratio:16/9; border:1px solid var(--border-md); box-shadow:var(--shadow-md); }
#main-player video { width:100%; height:100%; display:block; }
#main-player video::-webkit-media-controls-download-button,
#main-player video::-webkit-media-controls-picture-in-picture-button { display:none!important; }
#player-title { padding:12px 4px 18px; font-size:14px; font-weight:600; color:var(--text); display:none; }
#player-title.active { display:block; }

/* NOTE VIEWERS */
#note-viewer-wrap,#text-note-wrap { display:none; margin:0 22px 18px; }
#note-viewer-wrap.active,#text-note-wrap.active { display:block; }
#note-viewer-toolbar,#text-note-toolbar { display:flex; align-items:center; justify-content:space-between; padding:10px 4px 12px; font-size:13px; color:var(--muted); flex-wrap:wrap; gap:6px; }
#note-viewer-title,#text-note-title { font-weight:700; color:var(--text); }
.read-timer { font-weight:600; color:var(--accent); }
.read-timer.done { color:var(--green); }
.read-done-pill { display:none; align-items:center; gap:4px; font-size:11px; font-weight:700; color:var(--green);
    background:var(--green-lt); border:1px solid rgba(22,163,74,0.3); border-radius:20px; padding:3px 10px; }
.read-done-pill.show { display:inline-flex; }
.read-done-pill i { font-size:10px; }
#note-viewer { width:100%; height:min(620px,70vh); border:1px solid var(--border-md); border-radius:var(--radius-md); box-shadow:var(--shadow-md); background:#fff; }
#text-note-body { max-height:min(620px,70vh); overflow-y:auto; background:var(--surface); border:1px solid var(--border-md); border-radius:var(--radius-md); box-shadow:var(--shadow-md); padding:26px 30px; font-size:14.5px; line-height:1.8; color:var(--text); white-space:pre-wrap; word-wrap:break-word; }
#text-note-body a { color:var(--accent); text-decoration:underline; word-break:break-all; }
#text-note-body table { border-collapse:collapse; margin-bottom:16px; font-size:13px; white-space:normal; }
#text-note-body table td, #text-note-body table th { border:1px solid var(--border-md); padding:4px 8px; }
#text-note-body img { max-width:100%; margin:10px 0; }
#text-note-body h1, #text-note-body h2, #text-note-body h3 { margin:14px 0 8px; color:var(--text); }
#text-note-body p { margin-bottom:10px; }
.note-close-btn { background:var(--surface2); border:1px solid var(--border-md); color:var(--muted); border-radius:20px; padding:4px 12px; font-size:12px; cursor:pointer; font-weight:600; }
.note-close-btn:hover { background:var(--red); color:#fff; border-color:var(--red); }

/* NOTE LIST */
.note-list { padding:6px 22px 18px; }
.note-item { display:flex; align-items:flex-start; justify-content:space-between; padding:14px 0; border-bottom:1px solid var(--border); gap:12px; flex-wrap:wrap; }
.note-item:last-child { border-bottom:none; }
.note-item-left { display:flex; align-items:flex-start; gap:12px; flex:1; min-width:0; }
.note-icon { width:40px; height:40px; flex-shrink:0; background:var(--accent-lt); border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center; font-size:18px; border:1px solid var(--border); }
.note-name { font-size:14px; font-weight:600; color:var(--text); display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.note-done-badge { font-size:10px; font-weight:700; color:var(--green); background:var(--green-lt); padding:1px 8px; border-radius:10px; }
.note-sub { font-size:12px; color:var(--muted); margin-top:2px; }
.note-watched-wrap { margin-top:8px; width:100%; max-width:180px; }
.note-time-label { font-size:11px; color:var(--muted); margin-top:3px; }

/* BUTTONS */
.btn-outline { display:inline-flex; align-items:center; gap:6px; padding:7px 14px; font-size:12px; font-weight:600; border:1.5px solid var(--border-md); background:var(--surface); color:var(--accent); border-radius:var(--radius-sm); cursor:pointer; transition:background 0.15s,border-color 0.15s; text-decoration:none; white-space:nowrap; flex-shrink:0; }
.btn-outline:hover { background:var(--accent-lt); border-color:var(--accent); text-decoration:none; }
.btn-outline.done-btn { border-color:var(--green); color:var(--green); }
.btn-primary { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; font-size:13px; font-weight:700; background:var(--accent); color:#fff; border:none; border-radius:var(--radius-sm); cursor:pointer; transition:background 0.15s,transform 0.1s,box-shadow 0.15s; text-decoration:none; white-space:nowrap; flex-shrink:0; box-shadow:0 2px 8px rgba(107,155,46,0.3); }
.btn-primary:hover { background:#588424; transform:translateY(-1px); box-shadow:0 4px 14px rgba(107,155,46,0.4); text-decoration:none; color:#fff; }
.btn-primary:disabled { opacity:0.5; cursor:not-allowed; transform:none; box-shadow:none; }

/* QUIZ */
.quiz-list { padding:6px 22px 18px; }
.quiz-item { display:flex; align-items:center; justify-content:space-between; padding:14px 0; border-bottom:1px solid var(--border); gap:12px; flex-wrap:wrap; }
.quiz-item:last-child { border-bottom:none; }
.quiz-item-left { display:flex; align-items:center; gap:12px; flex:1; min-width:0; }
.quiz-icon { width:40px; height:40px; flex-shrink:0; background:var(--amber-lt); border-radius:var(--radius-sm); display:flex; align-items:center; justify-content:center; font-size:18px; border:1px solid rgba(217,119,6,0.15); }
.quiz-name { font-size:14px; font-weight:600; color:var(--text); }
.quiz-meta { font-size:12px; color:var(--muted); margin-top:2px; }
.quiz-stats-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; padding:18px 22px; }
.quiz-stat-box { background:var(--surface2); border-radius:var(--radius-md); padding:14px 12px; text-align:center; border:1px solid var(--accent); }
.quiz-stat-box.green { border-color:var(--green); }
.quiz-stat-box.red { border-color:var(--red); }
.quiz-stat-box i { font-size:1.1rem; color:var(--accent); margin-bottom:6px; display:block; }
.quiz-stat-box.green i { color:var(--green); }
.quiz-stat-box.red i { color:var(--red); }
.quiz-stat-box .val { font-size:20px; font-weight:700; color:var(--text); }
.quiz-stat-box .lbl { font-size:11px; color:var(--muted); margin-top:3px; font-weight:500; }

/* MISC */
.activity-item { padding:12px 14px; border-radius:10px; border:1px solid var(--accent); background:var(--surface2); margin:0 22px 10px; transition:transform 0.2s; }
.activity-item:last-child { margin-bottom:18px; }
.activity-item:hover { transform:translateX(4px); }
.activity-item p { font-weight:600; font-size:0.9rem; color:var(--text); margin-bottom:2px; }
.activity-item span { color:var(--muted); font-size:0.8rem; }
.stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; padding:18px 22px; }
.stat-box { background:var(--surface2); border-radius:var(--radius-md); padding:14px 12px; text-align:center; border:1px solid var(--border); }
.stat-box .val { font-size:22px; font-weight:700; color:var(--accent); }
.stat-box .lbl { font-size:11px; color:var(--muted); margin-top:3px; font-weight:500; }
.rating-section { padding:14px 22px 22px; }
.rating-current { display:flex; align-items:center; gap:12px; background:var(--surface2); border-radius:var(--radius-md); padding:16px; margin-bottom:18px; border:1px solid var(--border); }
.rating-big { font-size:38px; font-weight:700; line-height:1; color:var(--text); }
.rating-sub { font-size:12px; color:var(--muted); margin-top:4px; font-weight:500; }
.star-select { display:flex; gap:4px; margin-bottom:12px; }
.star-select button { background:none; border:none; font-size:26px; cursor:pointer; opacity:0.25; transition:opacity 0.15s,transform 0.15s; padding:0; line-height:1; }
.star-select button.on { opacity:1; }
.star-select button:hover { transform:scale(1.2); opacity:1; }
.rating-textarea { width:100%; background:var(--surface2); border:1.5px solid var(--border-md); color:var(--text); border-radius:var(--radius-sm); padding:10px 12px; font-size:13px; resize:vertical; min-height:80px; font-family:inherit; }
.rating-textarea:focus { outline:none; border-color:var(--accent); }
.rating-submit { width:100%; margin-top:12px; padding:11px; font-size:14px; font-weight:700; background:var(--accent); color:#fff; border:none; border-radius:var(--radius-sm); cursor:pointer; }
.rating-submit:hover { background:#588424; }
.review-toast { display:none; margin-top:10px; padding:10px 14px; background:var(--green-lt); color:var(--green); border:1px solid rgba(22,163,74,0.25); border-radius:var(--radius-sm); font-size:13px; text-align:center; font-weight:600; }
.review-toast.show { display:block; }
.instructor-card { display:flex; align-items:center; gap:14px; padding:18px 22px; }
.avatar { width:48px; height:48px; flex-shrink:0; background:linear-gradient(135deg,var(--accent),var(--accent2)); border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:19px; font-weight:700; color:#fff; }
.instructor-name { font-weight:700; font-size:15px; color:var(--text); }
.instructor-role { font-size:12px; color:var(--muted); font-weight:500; }
.empty { padding:36px 22px; text-align:center; color:var(--muted); font-size:14px; }
.empty-icon { font-size:34px; margin-bottom:8px; opacity:0.45; }
.video-error { background:#fef2f2; color:#991b1b; border:1px solid #fecaca; border-radius:var(--radius-sm); padding:10px 14px; font-size:13px; margin:0 22px 14px; display:none; }
.video-error.show { display:block; }
.modal-overlay { display:none; position:fixed; inset:0; background:rgba(10,9,22,0.65); z-index:9000; align-items:center; justify-content:center; padding:16px; overflow-y:auto; }
.modal-overlay.active { display:flex; }
.modal-box { background:var(--surface); border-radius:var(--radius-lg); padding:30px; width:100%; max-width:860px; position:relative; animation:popIn 0.2s ease; box-shadow:var(--shadow-md); max-height:90vh; overflow-y:auto; }
@keyframes popIn { from{transform:scale(0.93);opacity:0} to{transform:scale(1);opacity:1} }
.modal-close { position:absolute; top:14px; right:16px; width:30px; height:30px; background:var(--surface2); border:none; border-radius:50%; cursor:pointer; font-size:1rem; display:flex; align-items:center; justify-content:center; }
.modal-close:hover { background:var(--red); color:#fff; }
.quiz-option { display:block; background:var(--surface2); border:2px solid var(--border); border-radius:9px; padding:12px 14px; margin-bottom:10px; cursor:pointer; font-size:0.92rem; }
.quiz-option:hover { border-color:var(--accent); background:var(--accent-lt); }
.quiz-option input { margin-right:10px; accent-color:var(--accent); }
.quiz-timer { background:var(--red); color:#fff; padding:8px 16px; border-radius:9px; font-weight:700; font-size:1rem; min-width:80px; text-align:center; flex-shrink:0; }

/* ASSIGNMENTS */
.assignment-list { padding:6px 22px 18px; }
.assignment-item { padding:16px; border:1px solid var(--border); border-radius:var(--radius-md); margin-bottom:12px; }
.assignment-item:last-child { margin-bottom:0; }
.assignment-top { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; flex-wrap:wrap; margin-bottom:6px; }
.assignment-title { font-weight:700; font-size:14px; color:var(--text); }
.assignment-due { font-size:12px; color:var(--muted); margin-top:2px; }
.assignment-due.overdue { color:var(--red); font-weight:600; }
.status-pill { font-size:10.5px; font-weight:700; padding:3px 10px; border-radius:20px; white-space:nowrap; }
.status-pill.not-submitted { background:var(--amber-lt); color:var(--amber); }
.status-pill.submitted { background:var(--accent-lt); color:var(--accent); }
.status-pill.marked, .status-pill.returned { background:var(--green-lt); color:var(--green); }
.assignment-instructions { font-size:12.5px; color:var(--muted); margin:8px 0 12px; line-height:1.6; }
.assignment-form textarea { width:100%; min-height:70px; border:1.5px solid var(--border-md); border-radius:var(--radius-sm); padding:9px 11px; font-size:13px; font-family:inherit; resize:vertical; margin-bottom:8px; }
.assignment-form-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.assignment-form input[type=file] { font-size:12px; flex:1; min-width:160px; }
.assignment-feedback { margin-top:10px; background:var(--surface2); border-radius:var(--radius-sm); padding:10px 12px; font-size:12.5px; }
.assignment-score { font-weight:700; color:var(--accent); }

/* ANNOUNCEMENTS */
.announcement-item { padding:14px 22px; border-bottom:1px solid var(--border); }
.announcement-item:last-child { border-bottom:none; }
.announcement-title { font-weight:700; font-size:13.5px; color:var(--text); display:flex; align-items:center; gap:6px; }
.announcement-body { font-size:13px; color:var(--muted); margin-top:5px; line-height:1.6; }
.announcement-meta { font-size:11px; color:var(--muted); margin-top:6px; }

/* COMPETENCIES */
.competency-list { padding:6px 22px 18px; }
.competency-item { display:flex; align-items:center; gap:10px; padding:9px 0; border-bottom:1px solid var(--border); font-size:13.5px; }
.competency-item:last-child { border-bottom:none; }
.comp-check { width:20px; height:20px; border-radius:6px; border:2px solid var(--border-md); display:flex; align-items:center; justify-content:center; flex-shrink:0; font-size:11px; }
.comp-check.verified { background:var(--green); border-color:var(--green); color:#fff; }
.comp-name.verified-text { color:var(--text); }
.comp-name.pending-text { color:var(--muted); }

/* DISCUSSION */
.discussion-list { padding:6px 22px 18px; }
.discussion-item { padding:13px 0; border-bottom:1px solid var(--border); }
.discussion-item:last-child { border-bottom:none; }
.discussion-head { display:flex; align-items:center; gap:8px; font-size:12.5px; }
.discussion-author { font-weight:700; color:var(--text); }
.trainer-tag { font-size:9.5px; font-weight:700; color:var(--accent); background:var(--accent-lt); padding:1px 7px; border-radius:10px; }
.discussion-time { color:var(--muted); font-size:11px; }
.discussion-body { font-size:13px; color:var(--text); margin-top:5px; line-height:1.6; }
.discussion-replies { font-size:11.5px; color:var(--accent); margin-top:5px; font-weight:600; }
.discussion-form { padding:12px 22px 18px; border-top:1px solid var(--border); }
.discussion-form textarea { width:100%; min-height:60px; border:1.5px solid var(--border-md); border-radius:var(--radius-sm); padding:9px 11px; font-size:13px; font-family:inherit; resize:vertical; margin-bottom:8px; }

/* CPD WIDGET */
.cpd-wrap { padding:18px 22px; }
.cpd-numbers { display:flex; align-items:baseline; gap:6px; margin-bottom:10px; }
.cpd-numbers .big { font-size:28px; font-weight:700; color:var(--accent); }
.cpd-numbers .small { font-size:13px; color:var(--muted); }
.cpd-breakdown { margin-top:12px; display:flex; flex-direction:column; gap:6px; }
.cpd-row { display:flex; justify-content:space-between; font-size:12px; color:var(--muted); }
.cpd-row strong { color:var(--text); }

/* CAREER WIDGET */
.career-item { padding:12px 22px; border-bottom:1px solid var(--border); }
.career-item:last-child { border-bottom:none; }
.career-title { font-weight:700; font-size:13px; color:var(--text); }
.career-meta { font-size:11.5px; color:var(--muted); margin-top:3px; }

/* CBT-KENYA PROMO WIDGET */
.promo-card { background:linear-gradient(135deg,#e0941a,var(--orange)); border-radius:var(--radius-lg); padding:20px; color:#fff; margin-bottom:20px; }
.promo-card h3 { font-size:14px; margin-bottom:10px; }
.promo-list { display:flex; flex-direction:column; gap:8px; font-size:12.5px; }
.promo-list a { color:#fff; opacity:0.92; display:flex; align-items:center; gap:8px; }
.promo-list a:hover { opacity:1; text-decoration:underline; }

/* CERTIFICATE */
.cert-card { display:flex; gap:12px; padding:14px 22px; border-bottom:1px solid var(--border); align-items:flex-start; }
.cert-card:last-child { border-bottom:none; }
.cert-icon { width:40px; height:40px; border-radius:var(--radius-sm); background:var(--amber-lt); color:var(--amber); display:flex; align-items:center; justify-content:center; font-size:17px; flex-shrink:0; }
.cert-number { font-size:11px; color:var(--muted); font-family:monospace; margin-top:2px; }
.cert-actions { margin-top:6px; display:flex; gap:8px; }

@media(max-width:860px){.main-grid{grid-template-columns:1fr}.right-col{display:contents}}
@media(max-width:600px){.page-wrap{padding:0 14px 60px}.video-row{grid-template-columns:1fr 1fr;gap:10px;padding:14px}.card-header{padding:14px 16px 12px}}
@media(max-width:400px){.video-row{grid-template-columns:1fr}.note-item{flex-direction:column}.quiz-item{flex-direction:column;align-items:flex-start}}
</style>
</head>
<body<?= $is_paid ? ' class="protected"' : '' ?>>

<div class="paid-watermark" aria-hidden="true"></div>
<div class="protection-toast" id="protection-toast"> This content is protected</div>

<!-- NOTE PROTECTION OVERLAY (for paid courses) -->
<?php if ($is_paid): ?>
<div class="note-protected-overlay" id="noteProtectionOverlay">
    <div class="msg">
        <i class="fas fa-shield-alt"></i>
        <h3>Content Protected</h3>
        <p>Screenshots, screen recording, and copying are disabled for this paid course content.</p>
        <button class="btn-primary" onclick="closeNoteProtection()" style="margin-top:16px;">Continue Reading</button>
    </div>
</div>
<?php endif; ?>

<!-- CBT-KENYA / STP BRANDING HEADER -->
<header class="site-header">
    <div class="site-header-inner">
        <div class="brand-lockup">
            <div class="brand-mark">CBT</div>
            <div class="brand-text">CBT-Kenya<small>Skills Transfer Program</small></div>
        </div>
        <div style="font-size:12px;color:var(--muted);">
            <a href="student.php" style="color:var(--muted);">Dashboard</a> &nbsp;·&nbsp;
            <a href="student.php#" style="color:var(--muted);">My Portfolio</a>
        </div>
    </div>
</header>

<section class="hero">
    <div class="hero-inner">
        <div class="hero-meta">
            <span class="badge">Course</span>
            <?php if ($is_paid): ?><span class="badge badge-paid"> Premium</span><?php endif; ?>
            <?php if ($progress >= 90): ?>
                <span class="badge badge-green"> Completed</span>
            <?php elseif ($progress > 0): ?>
                <span class="badge"> In Progress</span>
            <?php endif; ?>
        </div>
        <h1><?= htmlspecialchars($course['title']) ?></h1>
        <p class="hero-desc"><?= nl2br(htmlspecialchars($course['description'])) ?></p>
        <div class="hero-stats">
            <?php if ($avg_rating > 0): ?>
                <span>
                    <span class="stars"><?= str_repeat('★', round($avg_rating)) ?><?= str_repeat('☆', 5 - round($avg_rating)) ?></span>
                    <strong><?= $avg_rating ?></strong> <span>(<?= $total_ratings ?> ratings)</span>
                </span><span class="dot"></span>
            <?php endif; ?>
            <span><?= $video_count ?> videos</span>
            <span class="dot"></span>
            <span><?= $note_count ?> notes</span>
            <span class="dot"></span>
            <span><?= $quiz_count ?> quizzes</span>
        </div>
    </div>
</section>

<div class="page-wrap">
<div class="main-grid">
<div class="left-col">

    <?php if ($flash): ?><div class="flash"><?= htmlspecialchars($flash) ?></div><?php endif; ?>
    <?php if ($quiz_success): ?><div class="flash"><?= htmlspecialchars($quiz_success) ?></div><?php endif; ?>

    <!-- ANNOUNCEMENTS -->
    <?php if ($announcements_rows): ?>
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-bullhorn"></i> Announcements</h2>
            <span class="count"><?= count($announcements_rows) ?></span>
        </div>
        <?php foreach ($announcements_rows as $a): ?>
            <div class="announcement-item">
                <div class="announcement-title">📢 <?= htmlspecialchars($a['title']) ?></div>
                <div class="announcement-body"><?= nl2br(htmlspecialchars($a['body'])) ?></div>
                <div class="announcement-meta">
                    Posted by <?= htmlspecialchars($a['poster_name'] ?? 'Trainer') ?> ·
                    <?= htmlspecialchars(date('d M Y', strtotime($a['created_at']))) ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- VIDEOS -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-film"></i> Course Videos</h2>
            <span class="count"><?= $video_count ?> lessons</span>
        </div>
        <div class="video-error" id="video-error"> Video could not be loaded. Check <code>uploads/videos/</code>.</div>
        <div id="player-wrap">
            <div id="main-player">
                <video id="main-video" controls
                    <?= $is_paid ? 'controlsList="nodownload nofullscreen" disablepictureinpicture' : 'controlsList="nodownload"' ?>
                    playsinline></video>
            </div>
            <p id="player-title"></p>
        </div>

        <?php if ($video_count > 0): ?>
        <div class="video-row">
            <?php foreach ($videos_rows as $vn => $video):
                $vid_id  = (int)$video['id'];
                if (empty($video['video_path'])) continue;
                $vpstate  = $video_progress_map[$vid_id];
                $video_url = 'course1.php?id=' . $course_id . '&video=' . $vid_id;
                $card_cls  = $vpstate['completed'] ? ' done' : '';
            ?>
            <div class="video-card<?= $card_cls ?>"
                 data-src="<?= htmlspecialchars($video_url) ?>"
                 data-title="<?= htmlspecialchars($video['title']) ?>"
                 data-id="<?= $vid_id ?>"
                 onclick="playVideo(this)">
                <div class="video-thumb">
                    <div class="play-overlay">
                        <div class="play-btn">
                            <svg viewBox="0 0 24 24"><polygon points="5,3 19,12 5,21"/></svg>
                        </div>
                    </div>
                </div>
                <div class="video-info">
                    <div class="video-num">Lesson <?= $vn + 1 ?></div>
                    <div class="video-title"><?= htmlspecialchars($video['title']) ?></div>
                    <?php if ($vpstate['completed']): ?>
                        <div class="done-badge"><i class="fas fa-check-circle"></i> Watched</div>
                    <?php endif; ?>
                    <div class="video-watched">
                        <div class="video-watched-fill" style="width:<?= $vpstate['pct'] ?>%" id="vw-<?= $vid_id ?>"></div>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"><i class="fa-solid fa-video"></i> Video</div><p>No videos added yet.</p></div>
        <?php endif; ?>
    </div>

    <!-- NOTES -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-file-alt"></i> Course Notes</h2>
            <span class="count"><?= $note_count ?> files</span>
            <?php if ($is_paid): ?>
                <span style="font-size:11px;color:var(--muted);background:var(--accent-lt);padding:2px 10px;border-radius:20px;">
                    <i class="fas fa-shield-alt"></i> Protected
                </span>
            <?php endif; ?>
        </div>

        <!-- PDF viewer -->
        <div id="note-viewer-wrap">
            <div id="note-viewer-toolbar">
                <span id="note-viewer-title"></span>
                <span style="display:flex;align-items:center;gap:8px;">
                    <span class="read-done-pill" id="note-pdf-done-pill"><i class="fas fa-check-circle"></i> Done reading</span>
                    <button class="note-close-btn btn-mark-done" id="note-pdf-mark-btn" onclick="markNoteDone('pdf')"> Mark as Done</button>
                    <button class="note-close-btn" onclick="closeNote()">✕ Close</button>
                </span>
            </div>
            <iframe id="note-viewer" src="" allowfullscreen></iframe>
        </div>

        <!-- Text / rendered-document viewer -->
        <div id="text-note-wrap">
            <div id="text-note-toolbar">
                <span id="text-note-title"></span>
                <span style="display:flex;align-items:center;gap:8px;">
                    <span class="read-timer" id="text-note-timer">0% scrolled</span>
                    <span class="read-done-pill" id="note-text-done-pill"><i class="fas fa-check-circle"></i> Done reading</span>
                    <button class="note-close-btn btn-mark-done" id="note-text-mark-btn" onclick="markNoteDone('text')"> Mark as Done</button>
                    <button class="note-close-btn" onclick="closeTextNote()">✕ Close</button>
                </span>
            </div>
            <div id="text-note-body"></div>
        </div>

        <?php if ($note_count > 0): ?>
        <div class="note-list">
            <?php foreach ($notes_rows as $note):
                $nid     = (int)$note['id'];
                $npstate = $note_progress_map[$nid];
                $npct    = $npstate['percentage'];
                $has_file = !empty($note['file_path']);
                $note_ext = $has_file ? strtolower(pathinfo($note['file_path'], PATHINFO_EXTENSION)) : '';
                $has_pdf     = $has_file && $note_ext === 'pdf';
                $has_office  = $has_file && in_array($note_ext, ['doc','docx','ppt','pptx','xls','xlsx'], true);
                $has_text    = !$has_file && trim((string)($note['content'] ?? '')) !== '';
            ?>
            <div class="note-item" id="note-item-<?= $nid ?>" data-note-id="<?= $nid ?>">
                <div class="note-item-left">
                    <div class="note-icon"> <i class="fas fa-book-open"></i></div>
                    <div style="min-width:0;flex:1;">
                        <div class="note-name" id="note-name-<?= $nid ?>">
                            <?= htmlspecialchars($note['title']) ?>
                            <?php if ($npstate['completed']): ?>
                                <span class="note-done-badge" id="note-badge-<?= $nid ?>"><i class="fas fa-check-circle"></i> Read</span>
                            <?php else: ?>
                                <span class="note-done-badge" id="note-badge-<?= $nid ?>" style="display:none;"><i class="fas fa-check-circle"></i> Read</span>
                            <?php endif; ?>
                            <?php if ($is_paid): ?>
                                <span style="font-size:9px;color:var(--muted);background:var(--accent-lt);padding:1px 6px;border-radius:10px;">
                                    <i class="fas fa-shield-alt"></i>
                                </span>
                            <?php endif; ?>
                        </div>
                        <?php if (!empty($note['content'])): ?>
                            <div class="note-sub"><?= htmlspecialchars(mb_substr($note['content'], 0, 70)) ?>…</div>
                        <?php endif; ?>
                        <?php if ($has_pdf || $has_office || $has_text): ?>
                        <div class="note-watched-wrap">
                            <div class="video-watched">
                                <div class="video-watched-fill" style="width:<?= $npct ?>%" id="nw-<?= $nid ?>"></div>
                            </div>
                            <div class="note-time-label" id="ntime-<?= $nid ?>">
                                <?= $npct ?>% scrolled
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;">
                    <?php if ($has_pdf): ?>
                        <button type="button" class="btn-outline<?= $npstate['completed'] ? ' done-btn' : '' ?>" id="note-btn-<?= $nid ?>"
                                onclick="openNote(<?= $nid ?>, '?id=<?= $course_id ?>&note=<?= $nid ?>', '<?= htmlspecialchars($note['title'], ENT_QUOTES) ?>')">
                           <i class="fas fa-file-pdf"></i> <?= $npstate['completed'] ? 'Re-read PDF' : 'Open PDF' ?>
                        </button>
                    <?php elseif ($has_office): ?>
                        <button type="button" class="btn-outline<?= $npstate['completed'] ? ' done-btn' : '' ?>" id="note-btn-<?= $nid ?>"
                                onclick="openOfficeNote(<?= $nid ?>, '?id=<?= $course_id ?>&note=<?= $nid ?>', '<?= htmlspecialchars($note['title'], ENT_QUOTES) ?>', '<?= $note_ext ?>')">
                           <i class="fas fa-file-word"></i> <?= $npstate['completed'] ? 'Re-read' : 'Open Document' ?>
                        </button>
                    <?php elseif ($has_text): ?>
                        <button type="button" class="btn-outline<?= $npstate['completed'] ? ' done-btn' : '' ?>" id="note-btn-<?= $nid ?>"
                                data-note-text="<?= htmlspecialchars($note['content'], ENT_QUOTES) ?>"
                                data-note-title="<?= htmlspecialchars($note['title'], ENT_QUOTES) ?>"
                                onclick="openTextNote(<?= $nid ?>, this.dataset.noteText, this.dataset.noteTitle)">
                           <i class="fas fa-book-open"></i> <?= $npstate['completed'] ? 'Re-read' : 'Open Text' ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"> </div><p>No notes available yet.</p></div>
        <?php endif; ?>
    </div>

    <!-- QUIZZES -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-question-circle"></i> Quizzes</h2>
            <span class="count"><?= $quiz_count ?> quizzes</span>
        </div>
        <?php if ($quiz_count > 0): ?>
        <div class="quiz-list">
            <?php foreach ($quizzes_rows as $quiz):
                $qid           = (int)$quiz['id'];
                $qpassed       = $quiz_status_map[$qid] ?? '';
                $attempts_used = $quiz_attempts_map[$qid] ?? 0;
                $max_attempts  = (isset($quiz['max_attempts']) && $quiz['max_attempts'] !== null && (int)$quiz['max_attempts'] > 0)
                                 ? (int)$quiz['max_attempts'] : null;
                $limit_reached = $max_attempts !== null && $attempts_used >= $max_attempts;
            ?>
            <div class="quiz-item">
                <div class="quiz-item-left">
                    <div class="quiz-icon"><i class="fas fa-file-alt"></i></div>
                    <div>
                        <div class="quiz-name">
                            <?= htmlspecialchars($quiz['title']) ?>
                            <?php if ($qpassed === 'passed'): ?>
                                <span class="note-done-badge" style="margin-left:6px;"><i class="fas fa-check-circle"></i> Passed</span>
                            <?php elseif ($qpassed === 'failed'): ?>
                                <span class="note-done-badge" style="background:#fee2e2;color:#dc2626;margin-left:6px;">✕ Failed</span>
                            <?php endif; ?>
                        </div>
                        <div class="quiz-meta">
                            ⏱ <?= (int)$quiz['duration'] ?> min &nbsp;·&nbsp; Pass at <?= (int)$quiz['passing_score'] ?>%
                            <?php if ($max_attempts !== null): ?>
                                &nbsp;·&nbsp; Attempts: <?= $attempts_used ?>/<?= $max_attempts ?>
                            <?php else: ?>
                                &nbsp;·&nbsp; Unlimited attempts
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <?php if ($limit_reached): ?>
                    <button class="btn-primary" disabled title="You've used all your allowed attempts for this quiz.">No attempts left</button>
                <?php else: ?>
                    <button class="btn-primary" onclick="openQuiz(<?= $qid ?>)">
                        <?= $qpassed ? 'Retry →' : 'Start →' ?>
                    </button>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"></div><p>No quizzes for this course yet.</p></div>
        <?php endif; ?>
    </div>

    <!-- ASSIGNMENTS -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-file-signature"></i> Assignments</h2>
            <span class="count"><?= $assignments_done ?>/<?= $assignment_count ?> submitted</span>
        </div>
        <?php if ($assignment_count > 0): ?>
        <div class="assignment-list">
            <?php foreach ($assignments_rows as $asn):
                $asn_id     = (int)$asn['id'];
                $due_ts    = !empty($asn['due_date']) ? strtotime($asn['due_date']) : null;
                $overdue   = $due_ts && $due_ts < time() && empty($asn['sub_status']);
                $sub_status = $asn['sub_status'] ?: 'not_submitted';
                $pill_cls  = str_replace('_', '-', $sub_status);
                $pill_label = ['not_submitted'=>'Not submitted','submitted'=>'Submitted','marked'=>'Marked','returned'=>'Returned'][$sub_status] ?? 'Not submitted';
            ?>
            <div class="assignment-item">
                <div class="assignment-top">
                    <div>
                        <div class="assignment-title"><?= htmlspecialchars($asn['title']) ?></div>
                        <div class="assignment-due<?= $overdue ? ' overdue' : '' ?>">
                            <?= $due_ts ? ('Due: ' . date('d M Y, g:i A', $due_ts)) : 'No due date' ?>
                            <?= $overdue ? ' · Overdue' : '' ?>
                        </div>
                    </div>
                    <span class="status-pill <?= $pill_cls ?>"><?= $pill_label ?></span>
                </div>
                <?php if (!empty($asn['description'])): ?>
                    <div class="assignment-instructions"><?= nl2br(htmlspecialchars($asn['description'])) ?></div>
                <?php endif; ?>

                <?php if ($sub_status === 'marked' || $sub_status === 'returned'): ?>
                    <div class="assignment-feedback">
                        <span class="assignment-score">Score: <?= (int)$asn['sub_score'] ?></span>
                        <?php if (!empty($asn['sub_feedback'])): ?>
                            <div style="margin-top:6px;"><?= nl2br(htmlspecialchars($asn['sub_feedback'])) ?></div>
                        <?php endif; ?>
                    </div>
                <?php elseif ($sub_status === 'submitted'): ?>
                    <div class="assignment-feedback">Submitted <?= htmlspecialchars(date('d M Y, g:i A', strtotime($asn['sub_submitted_at']))) ?><?= $asn['sub_is_late'] ? ' (late)' : '' ?> - awaiting marking.</div>
                <?php else: ?>
                    <form class="assignment-form" onsubmit="return submitAssignment(event, <?= $asn_id ?>)" enctype="multipart/form-data">
                        <textarea name="submission_text" placeholder="Write your submission, or attach a file below…"></textarea>
                        <div class="assignment-form-row">
                            <input type="file" name="submission_file" accept=".pdf,.doc,.docx,.png,.jpg,.jpeg">
                            <button type="submit" class="btn-primary"><i class="fas fa-paper-plane"></i> Submit</button>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"><i class="fas fa-file-signature"></i></div><p>No assignments for this course yet.</p></div>
        <?php endif; ?>
    </div>

    <!-- COMPETENCIES -->
    <?php if ($competency_rows): ?>
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-clipboard-check"></i> Competencies</h2>
            <span class="count"><?= count(array_filter($competency_rows, fn($c) => (int)$c['verified'] === 1)) ?>/<?= count($competency_rows) ?> verified</span>
        </div>
        <div class="competency-list">
            <?php foreach ($competency_rows as $c): $v = (int)($c['verified'] ?? 0) === 1; ?>
                <div class="competency-item">
                    <div class="comp-check<?= $v ? ' verified' : '' ?>"><?php if ($v): ?><i class="fas fa-check"></i><?php endif; ?></div>
                    <span class="comp-name <?= $v ? 'verified-text' : 'pending-text' ?>"><?= htmlspecialchars($c['name']) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <p style="padding:0 22px 16px;font-size:11.5px;color:var(--muted);">Competencies are verified by your trainer as you demonstrate them.</p>
    </div>
    <?php endif; ?>

    <!-- DISCUSSION / Q&A -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-comments"></i> Course Discussion</h2>
            <span class="count"><?= count($discussion_rows) ?> topics</span>
        </div>
        <?php if ($discussion_rows): ?>
        <div class="discussion-list">
            <?php foreach ($discussion_rows as $d): ?>
                <div class="discussion-item">
                    <div class="discussion-head">
                        <span class="discussion-author"><?= htmlspecialchars($d['author_name'] ?? 'Student') ?></span>
                        <?php if ($d['is_trainer_reply']): ?><span class="trainer-tag">TRAINER</span><?php endif; ?>
                        <span class="discussion-time">· <?= htmlspecialchars(date('d M, g:i A', strtotime($d['created_at']))) ?></span>
                    </div>
                    <div class="discussion-body"><?= nl2br(htmlspecialchars($d['body'])) ?></div>
                    <?php if ($d['reply_count'] > 0): ?>
                        <div class="discussion-replies"><?= (int)$d['reply_count'] ?> repl<?= $d['reply_count']==1?'y':'ies' ?></div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"><i class="fas fa-comments"></i></div><p>No questions or discussion yet - be the first to post.</p></div>
        <?php endif; ?>
        <div class="discussion-form">
            <textarea id="discussion-body" placeholder="Ask a question or start a discussion…"></textarea>
            <button class="btn-primary" onclick="postDiscussion()"><i class="fas fa-paper-plane"></i> Post</button>
        </div>
    </div>

    <!-- QUIZ HISTORY -->
    <div class="card">
        <div class="card-header"><h2><i class="fas fa-history"></i> Quiz History</h2></div>
        <?php if ($history_rows): foreach ($history_rows as $h): ?>
            <div class="activity-item"><p><?= htmlspecialchars($h['title'] ?? '') ?></p><span>Score: <?= (int)($h['score'] ?? 0) ?>% · Completed <?= htmlspecialchars($h['completed_at'] ?? '') ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No history yet</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-header"><h2><i class="fas fa-trophy"></i> Top Performance</h2></div>
        <?php if ($achievements_rows): foreach ($achievements_rows as $a): ?>
            <div class="activity-item"><p><?= htmlspecialchars($a['title'] ?? '') ?></p><span><?= htmlspecialchars($a['value'] ?? '') ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No achievements yet</p></div><?php endif; ?>
    </div>

    <!-- CERTIFICATES -->
    <div class="card">
        <div class="card-header"><h2><i class="fas fa-award"></i> Certificates</h2></div>
        <?php if ($certs_rows): foreach ($certs_rows as $c): ?>
            <div class="cert-card">
                <div class="cert-icon"><i class="fas fa-certificate"></i></div>
                <div style="flex:1;">
                    <p style="font-weight:700;font-size:13.5px;"><?= htmlspecialchars($c['title'] ?? 'Certificate') ?></p>
                    <?php if (!empty($c['cert_number'])): ?>
                        <div class="cert-number">№ <?= htmlspecialchars($c['cert_number']) ?></div>
                    <?php endif; ?>
                    <span style="font-size:11.5px;color:var(--muted);">
                        <?= !empty($c['issued_at']) ? 'Issued ' . htmlspecialchars(date('d M Y', strtotime($c['issued_at']))) : htmlspecialchars($c['status'] ?? '') ?>
                    </span>
                    <?php if (!empty($c['cert_number'])): ?>
                    <div class="cert-actions">
                        <a class="btn-primary" href="course1.php?id=<?= $course_id ?>&certificate=<?= urlencode($c['cert_number']) ?>"><i class="fas fa-download"></i> Download PDF</a>
                        <a class="btn-outline" href="verify_certificate.php?token=<?= urlencode($c['verification_hash'] ?? '') ?>" target="_blank"><i class="fas fa-shield-check"></i> Verify</a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; else: ?>
            <div class="activity-item"><p>No certificates yet</p><span>Complete this course to earn your CBT-Kenya STP certificate.</span></div>
        <?php endif; ?>
    </div>

</div>

<!-- SIDEBAR -->
<div class="right-col">

    <div class="card">
        <div class="card-header"><h2>Your progress</h2></div>
        <div class="progress-wrap">
            <div class="progress-numbers">
                <span class="big" id="progress-pct"><?= $progress ?>%</span>
                <span class="small">completed</span>
            </div>
            <div class="progress-bar-track">
                <div class="progress-bar-fill" id="progress-bar" style="width:<?= $progress ?>%"></div>
            </div>
            <p class="progress-label" id="progress-label">
                <?php if ($progress===0): ?>Start watching to track your progress.
                <?php elseif ($progress<50): ?>Just getting started - keep going!
                <?php elseif ($progress<90): ?>More than halfway there. Great work!
                <?php else: ?> You've completed this course!<?php endif; ?>
            </p>
            <div class="progress-breakdown">
                <?php if ($video_count > 0): ?>
                    <span> Videos: <strong id="vp-pct"><?= $video_progress ?>%</strong></span>
                <?php endif; ?>
                <?php if ($note_count > 0): ?>
                    <span> Notes: <strong id="np-pct"><?= $note_progress ?>%</strong>
                        <span style="color:var(--muted);font-weight:400;" id="np-fraction">(<?= $completed_notes_count ?>/<?= $note_count ?>)</span>
                    </span>
                <?php endif; ?>
                <?php if ($quiz_count > 0): ?>
                    <span> Quizzes: <strong><?= $quiz_progress ?>%</strong></span>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><h2>Course overview</h2></div>
        <div class="stat-grid">
            <div class="stat-box"><div class="val"><?= $video_count ?></div><div class="lbl">Videos</div></div>
            <div class="stat-box"><div class="val"><?= $note_count ?></div><div class="lbl">Notes</div></div>
            <div class="stat-box"><div class="val"><?= $quiz_count ?></div><div class="lbl">Quizzes</div></div>
            <div class="stat-box"><div class="val"><?= $avg_rating > 0 ? $avg_rating : '-' ?></div><div class="lbl">Rating</div></div>
        </div>
    </div>

    <!-- CPD / CME POINTS -->
    <?php if ($cpd_summary['available'] > 0): ?>
    <div class="card">
        <div class="card-header"><h2><i class="fas fa-user-graduate"></i> CPD Points</h2></div>
        <div class="cpd-wrap">
            <div class="cpd-numbers">
                <span class="big"><?= rtrim(rtrim(number_format($cpd_summary['earned'], 1), '0'), '.') ?></span>
                <span class="small">/ <?= rtrim(rtrim(number_format($cpd_summary['available'], 1), '0'), '.') ?> points earned</span>
            </div>
            <div class="progress-bar-track">
                <div class="progress-bar-fill" style="width:<?= $cpd_summary['available'] > 0 ? min(100, round(($cpd_summary['earned']/$cpd_summary['available'])*100)) : 0 ?>%"></div>
            </div>
            <?php if ($cpd_summary['breakdown']): ?>
            <div class="cpd-breakdown">
                <?php foreach ($cpd_summary['breakdown'] as $b): ?>
                    <div class="cpd-row">
                        <span><?= htmlspecialchars(ucfirst(str_replace('_',' ', $b['activity_type']))) ?></span>
                        <strong>+<?= rtrim(rtrim(number_format($b['points'],1),'0'),'.') ?></strong>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="card">
        <div class="card-header"><h2><i class="fas fa-chart-line"></i> Your quiz stats</h2></div>
        <div class="quiz-stats-grid">
            <div class="quiz-stat-box"><i class="fas fa-file-alt"></i><div class="val"><?= $total_quizzes ?></div><div class="lbl">Total</div></div>
            <div class="quiz-stat-box green"><i class="fas fa-check-circle"></i><div class="val"><?= $passed ?></div><div class="lbl">Passed</div></div>
            <div class="quiz-stat-box red"><i class="fas fa-times-circle"></i><div class="val"><?= $failed ?></div><div class="lbl">Failed</div></div>
            <div class="quiz-stat-box"><i class="fas fa-chart-line"></i><div class="val"><?= $avgScore ?>%</div><div class="lbl">Avg Score</div></div>
        </div>
        <div style="padding:0 22px 18px;">
            <?php if ($results_rows): foreach ($results_rows as $r): ?>
                <div class="activity-item" style="margin:0 0 10px;">
                    <p><?= htmlspecialchars($r['quiz_title'] ?? 'Quiz') ?></p>
                    <span>Score: <?= (int)$r['score'] ?>% • <?= ucfirst($r['status']) ?></span>
                </div>
            <?php endforeach; else: ?>
                <div class="activity-item" style="margin:0;"><p>No results yet</p></div>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!empty($course['instructor'])): ?>
    <div class="card">
        <div class="card-header"><h2>Instructor</h2></div>
        <div class="instructor-card">
            <div class="avatar"><?= strtoupper(mb_substr($course['instructor'], 0, 1)) ?></div>
            <div>
                <div class="instructor-name"><?= htmlspecialchars($course['instructor']) ?></div>
                <div class="instructor-role">Course Instructor</div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- CAREER OPPORTUNITIES -->
    <?php if ($career_rows): ?>
    <div class="card">
        <div class="card-header"><h2><i class="fas fa-briefcase"></i> Career Opportunities</h2></div>
        <?php foreach ($career_rows as $job): ?>
            <div class="career-item">
                <div class="career-title"><?= htmlspecialchars($job['title']) ?></div>
                <div class="career-meta">
                    <?= htmlspecialchars($job['location'] ?? '') ?>
                    <?= !empty($job['deadline']) ? ' · Deadline: ' . htmlspecialchars(date('d M Y', strtotime($job['deadline']))) : '' ?>
                </div>
                <?php if (!empty($job['url'])): ?>
                    <a class="btn-outline" style="margin-top:8px;" href="<?= htmlspecialchars($job['url']) ?>" target="_blank">View Opportunity</a>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- CBT-KENYA PROMOTIONAL SPACE -->
    <div class="promo-card">
        <h3><i class="fas fa-star"></i> CBT-Kenya Programmes</h3>
        <div class="promo-list">
            <a href="https://www.cbtkenya.org/skills-transfer-program/" target="_blank"><i class="fas fa-graduation-cap"></i> Skills Transfer Program</a>
            <a href="https://www.cbtkenya.org/blog/" target="_blank"><i class="fas fa-newspaper"></i> Latest articles &amp; updates</a>
            <a href="https://www.cbtkenya.org/careers/" target="_blank"><i class="fas fa-user-tie"></i> Careers at CBT-Kenya</a>
            <a href="portfolio.php"><i class="fas fa-id-badge"></i> My Professional Portfolio</a>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><h2>Rate this course</h2></div>
        <div class="rating-section">
            <?php if ($avg_rating > 0): ?>
            <div class="rating-current">
                <div style="flex:1;text-align:center;">
                    <div class="rating-big"><?= $avg_rating ?></div>
                    <div class="stars" style="font-size:18px;margin-top:6px;">
                        <?= str_repeat('★', round($avg_rating)) ?><?= str_repeat('☆', 5-round($avg_rating)) ?>
                    </div>
                    <div class="rating-sub"><?= $total_ratings ?> rating<?= $total_ratings!==1?'s':'' ?></div>
                </div>
            </div>
            <?php endif; ?>
            <div class="star-select" id="star-select">
                <?php for ($i=1;$i<=5;$i++): ?>
                    <button type="button" data-val="<?= $i ?>" onclick="setRating(<?= $i ?>)">⭐</button>
                <?php endfor; ?>
            </div>
            <input type="hidden" id="rating-val" value="5">
            <textarea class="rating-textarea" id="comment" placeholder="Share your thoughts…"></textarea>
            <button class="rating-submit" onclick="sendReview()">Submit review</button>
            <div class="review-toast" id="review-toast"> Review submitted - thank you!</div>
        </div>
    </div>

</div>
</div>
</div>

<!-- FOOTER -->
<footer class="site-footer">
    <strong>CBT-Kenya</strong> · Skills Transfer Program &nbsp;|&nbsp;
    Muthangari Road 37, Lavington, Nairobi &nbsp;|&nbsp;
    <a href="mailto:info@cbtkenya.org" style="color:rgba(255,255,255,0.85);">info@cbtkenya.org</a>
    <div style="margin-top:6px;opacity:0.6;">© <?= date('Y') ?> CBT-Kenya. All rights reserved.</div>
</footer>

<div id="quizModal" class="modal-overlay" role="dialog" aria-modal="true" onmousedown="if(event.target===this) closeQuiz();">
    <div class="modal-box">
        <button class="modal-close" onclick="closeQuiz()">✕</button>
        <div id="quizContainer"></div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.6.0/mammoth.browser.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>

<script>
/* ==== DATA FROM PHP ==== */
const IS_PAID       = <?= $is_paid_js ?>;
const ALL_QUIZZES   = <?= json_encode($all_quizzes,   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP) ?>;
const ALL_QUESTIONS = <?= json_encode($all_questions, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP) ?>;
const CSRF_TOKEN    = <?= $csrf_js ?>;
const VIDEO_COUNT = <?= (int)$video_count ?>;
const NOTE_COUNT  = <?= (int)$note_count ?>;
const QUIZ_COUNT  = <?= (int)$quiz_count ?>;
const NOTE_DONE_PERCENT = 95;
const VID_DONE_PC = 90;
const W_VIDEO = VIDEO_COUNT > 0 ? 0.60 : 0;
const W_NOTE  = NOTE_COUNT  > 0 ? 0.25 : 0;
const W_QUIZ  = QUIZ_COUNT  > 0 ? 0.15 : 0;
const W_TOTAL = W_VIDEO + W_NOTE + W_QUIZ;
const videoMap = <?= json_encode($js_video_map, JSON_HEX_TAG) ?>;
const noteMap  = <?= json_encode($js_note_map,  JSON_HEX_TAG) ?>;
const noteProgressMap = <?= json_encode($js_note_progress, JSON_HEX_TAG) ?>;
let liveQuizProgress = <?= (int)$quiz_progress ?>;

/* ==== PROGRESS CALCULATOR ==== */
function calcProgress() {
    let videoSum = 0;
    Object.keys(videoMap).forEach(id => { videoSum += (videoMap[id] || 0); });
    const videoPct = VIDEO_COUNT > 0 ? Math.round(videoSum / VIDEO_COUNT) : 0;
    const doneNotes = Object.values(noteMap).filter(v => v === 1).length;
    const notePct   = NOTE_COUNT > 0 ? Math.round((doneNotes / NOTE_COUNT) * 100) : 0;
    const overall = W_TOTAL > 0
        ? Math.round((videoPct * W_VIDEO + notePct * W_NOTE + liveQuizProgress * W_QUIZ) / W_TOTAL)
        : 0;
    return { videoPct, notePct, doneNotes, overall };
}

function updateProgressUI() {
    const { videoPct, notePct, doneNotes, overall } = calcProgress();
    const elPct = document.getElementById('progress-pct');
    const elBar = document.getElementById('progress-bar');
    const elLbl = document.getElementById('progress-label');
    const elVP  = document.getElementById('vp-pct');
    const elNP  = document.getElementById('np-pct');
    const elNF  = document.getElementById('np-fraction');
    if (elPct) elPct.textContent = overall + '%';
    if (elBar) elBar.style.width = overall + '%';
    if (elVP)  elVP.textContent  = videoPct + '%';
    if (elNP)  elNP.textContent  = notePct  + '%';
    if (elNF)  elNF.textContent  = '(' + doneNotes + '/' + NOTE_COUNT + ')';
    if (elLbl) {
        if (overall === 0)      elLbl.textContent = 'Start watching to track your progress.';
        else if (overall < 50)  elLbl.textContent = 'Just getting started - keep going!';
        else if (overall < 90)  elLbl.textContent = 'More than halfway there. Great work!';
        else                    elLbl.textContent = '🎉 You\'ve completed this course!';
    }
}

/* ==== PAID PROTECTION ==== */
if (IS_PAID) {
    document.addEventListener('contextmenu', e => { e.preventDefault(); showToast(); });
    document.addEventListener('keydown', e => {
        const b = e.key==='PrintScreen'||e.key==='F12'
            ||(e.ctrlKey&&['s','p','c','a','u','S','P','C','A','U'].includes(e.key))
            ||(e.metaKey&&['s','p','c','a','S','P','C','A'].includes(e.key));
        if (b) { e.preventDefault(); e.stopImmediatePropagation(); showToast(); return false; }
    }, true);
    if (navigator.mediaDevices?.getDisplayMedia) {
        navigator.mediaDevices.getDisplayMedia = () => {
            showToast();
            return Promise.reject(new DOMException('Disabled','NotAllowedError'));
        };
    }
    document.addEventListener('dragstart', e => {
        if (['VIDEO','IMG','IFRAME'].includes(e.target.tagName)) { e.preventDefault(); showToast(); }
    });
}
function showToast() {
    const t = document.getElementById('protection-toast');
    if (!t) return;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
}

/* ==== NOTE PROTECTION FOR PAID COURSES ==== */
<?php if ($is_paid): ?>
let noteProtectionActive = false;
let noteProtectionTimer = null;

function showNoteProtection() {
    if (noteProtectionActive) return;
    noteProtectionActive = true;
    const overlay = document.getElementById('noteProtectionOverlay');
    if (overlay) overlay.classList.add('active');
    
    if (mainVideo && !mainVideo.paused) {
        mainVideo.pause();
    }
    
    if (noteProtectionTimer) clearTimeout(noteProtectionTimer);
    noteProtectionTimer = setTimeout(() => {
        noteProtectionActive = false;
    }, 500);
}

function closeNoteProtection() {
    const overlay = document.getElementById('noteProtectionOverlay');
    if (overlay) overlay.classList.remove('active');
    noteProtectionActive = false;
}

document.addEventListener('visibilitychange', () => {
    if (document.hidden && (document.getElementById('note-viewer-wrap').classList.contains('active') || 
        document.getElementById('text-note-wrap').classList.contains('active'))) {
        showNoteProtection();
    }
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'PrintScreen' || e.key === 'F12') {
        e.preventDefault();
        showNoteProtection();
        return false;
    }
    if (e.ctrlKey && (e.key === 'p' || e.key === 'P')) {
        if (document.getElementById('note-viewer-wrap').classList.contains('active') || 
            document.getElementById('text-note-wrap').classList.contains('active')) {
            e.preventDefault();
            showNoteProtection();
            return false;
        }
    }
}, true);

document.addEventListener('dragstart', function(e) {
    if (e.target.closest('#note-viewer') || e.target.closest('#text-note-body')) {
        e.preventDefault();
        showNoteProtection();
    }
});

document.addEventListener('copy', function(e) {
    if (e.target.closest('#note-viewer') || e.target.closest('#text-note-body')) {
        e.preventDefault();
        showNoteProtection();
        return false;
    }
}, true);

document.addEventListener('contextmenu', function(e) {
    if (e.target.closest('#note-viewer') || e.target.closest('#text-note-body')) {
        e.preventDefault();
        showNoteProtection();
        return false;
    }
}, true);
<?php endif; ?>

/* ==== VIDEO PLAYER ==== */
const mainVideo   = document.getElementById('main-video');
const playerWrap  = document.getElementById('player-wrap');
const playerTitle = document.getElementById('player-title');
const videoError  = document.getElementById('video-error');
let   currentCard = null;

function playVideo(card) {
    document.querySelectorAll('.video-card').forEach(c => c.classList.remove('watching'));
    card.classList.add('watching');
    currentCard = card;
    const src   = card.dataset.src;
    const title = card.dataset.title;
    const cid   = parseInt(card.dataset.id, 10);
    videoError.classList.remove('show');
    playerWrap.classList.add('active');
    playerTitle.textContent = '▶  ' + title;
    playerTitle.classList.add('active');
    mainVideo.src = src;
    mainVideo.load();
    mainVideo.play().catch(() => {});
    mainVideo.onerror = () => videoError.classList.add('show');
    playerWrap.scrollIntoView({ behavior:'smooth', block:'start' });
    const savedPct = videoMap[cid] || 0;
    if (savedPct > 0 && savedPct < VID_DONE_PC) {
        mainVideo.addEventListener('loadedmetadata', function restorePos() {
            mainVideo.removeEventListener('loadedmetadata', restorePos);
            mainVideo.currentTime = (savedPct / 100) * mainVideo.duration;
        });
    }

    mainVideo.ontimeupdate = null;
    mainVideo.ontimeupdate = function () {
        if (!mainVideo.duration) return;
        const pct = Math.floor((mainVideo.currentTime / mainVideo.duration) * 100);
        const fill = document.getElementById('vw-' + cid);
        if (fill) fill.style.width = pct + '%';
        if (pct > (videoMap[cid] || 0)) {
            videoMap[cid] = pct;
            updateProgressUI();
            saveVideoProgress(cid, pct);
        }
        if (pct >= VID_DONE_PC) {
            card.classList.remove('watching');
            card.classList.add('done');
            if (!card.querySelector('.done-badge')) {
                const info = card.querySelector('.video-info');
                if (info) {
                    const b = document.createElement('div');
                    b.className = 'done-badge';
                    b.innerHTML = '<i class="fas fa-check-circle"></i> Watched';
                    info.insertBefore(b, info.querySelector('.video-watched'));
                }
            }
        }
    };
}

const lastSentVideo = {};
function saveVideoProgress(cid, pct) {
    if (pct === 0) return;
    if (lastSentVideo[cid] === pct) return;
    lastSentVideo[cid] = pct;
    fetch(location.href, {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'action=save_progress&content_id='+cid+'&watched='+pct+'&csrf_token='+encodeURIComponent(CSRF_TOKEN),
        keepalive:true
    })
    .then(r => r.json())
    .then(data => {
        if (!data.ok) {
            console.warn('Video progress NOT saved:', data);
            delete lastSentVideo[cid];
        }
    })
    .catch(err => {
        console.error('Video progress save request failed:', err);
        delete lastSentVideo[cid];
    });
}

/* ==== NOTE VIEWER - SCROLL TRACKING ENGINE ==== */
const noteWrap    = document.getElementById('note-viewer-wrap');
const noteFrame   = document.getElementById('note-viewer');
const noteTitleEl = document.getElementById('note-viewer-title');
const notePdfDone = document.getElementById('note-pdf-done-pill');
let curNoteId = null;

const textWrap    = document.getElementById('text-note-wrap');
const textBody    = document.getElementById('text-note-body');
const textTitleEl = document.getElementById('text-note-title');
const textTimer   = document.getElementById('text-note-timer');
const textDone    = document.getElementById('note-text-done-pill');
let curTextNoteId = null;
let curNoteScrollMax = 0;

function updateNoteUI(noteId, pct) {
    const fill = document.getElementById('nw-' + noteId);
    const lbl  = document.getElementById('ntime-' + noteId);
    if (fill) fill.style.width = pct + '%';
    if (lbl)  lbl.textContent  = pct + '% scrolled';
}

function setupNoteScrollTracking(noteId) {
    const container = document.getElementById('text-note-body');
    if (!container) return;

    curNoteScrollMax = noteProgressMap[noteId] || 0;
    container.scrollTop = 0;

    container.onscroll = function () {
        const scrollable = container.scrollHeight - container.clientHeight;
        let pct = 0;

        if (scrollable <= 5) {
            pct = 100;
        } else {
            pct = Math.round((container.scrollTop / scrollable) * 100);
        }

        pct = Math.min(100, Math.max(0, pct));

        if (pct > curNoteScrollMax) {
            curNoteScrollMax = pct;
            noteProgressMap[noteId] = curNoteScrollMax;
            textTimer.textContent = curNoteScrollMax + '% scrolled';
            updateNoteUI(noteId, curNoteScrollMax);

            if (curNoteScrollMax >= NOTE_DONE_PERCENT) {
                textTimer.classList.add('done');
                textDone.classList.add('show');
                onNoteCompleted(noteId);
                saveNoteProgress(noteId, curNoteScrollMax, true);
            } else if (curNoteScrollMax % 5 === 0) {
                saveNoteProgress(noteId, curNoteScrollMax, false);
            }
        }
    };
}

/* ==== NOTE VIEWER - PDF ==== */
function openNote(noteId, url, title) {
    if (curTextNoteId !== null) closeTextNote();
    curNoteId = noteId;
    noteFrame.src = url;
    noteTitleEl.textContent = ' ' + title;
    notePdfDone.classList.remove('show');
    const alreadyDone = noteMap[noteId] === 1;
    toggleMarkBtn('pdf', alreadyDone);
    if (alreadyDone) {
        notePdfDone.classList.add('show');
    }
    noteWrap.classList.add('active');
    noteWrap.scrollIntoView({behavior:'smooth', block:'start'});

    <?php if ($is_paid): ?>
    noteFrame.addEventListener('load', function() {
        showNoteProtection();
    });
    <?php endif; ?>
}

function closeNote() {
    noteWrap.classList.remove('active');
    noteFrame.src = '';
    curNoteId = null;
}

/* ==== NOTE VIEWER - PLAIN TEXT ==== */
function openTextNote(noteId, content, title) {
    closeNote();
    if (curTextNoteId !== null) closeTextNote();
    curTextNoteId = noteId;
    textBody.style.whiteSpace = 'pre-wrap';
    textBody.innerHTML = linkify(content);
    textTitleEl.textContent = ' ' + title;
    
    const savedPct = noteProgressMap[noteId] || 0;
    textTimer.textContent = savedPct + '% scrolled';
    textTimer.classList.remove('done');
    textDone.classList.remove('show');

    const alreadyDone = noteMap[noteId] === 1;
    toggleMarkBtn('text', alreadyDone);

    if (alreadyDone) {
        textTimer.textContent = '100% scrolled';
        textTimer.classList.add('done');
        textDone.classList.add('show');
        updateNoteUI(noteId, 100);
    }

    textWrap.classList.add('active');
    textWrap.scrollIntoView({behavior:'smooth', block:'start'});

    <?php if ($is_paid): ?>
    showNoteProtection();
    <?php endif; ?>

    if (!alreadyDone) {
        setTimeout(() => setupNoteScrollTracking(noteId), 100);
    }
}

/* ==== NOTE VIEWER - OFFICE DOCS ==== */
function openOfficeNote(noteId, url, title, ext) {
    closeNote();
    if (curTextNoteId !== null) closeTextNote();
    curTextNoteId = noteId;
    textBody.style.whiteSpace = 'normal';
    textTitleEl.textContent = ' ' + title;

    const savedPct = noteProgressMap[noteId] || 0;
    textTimer.textContent = savedPct + '% scrolled';
    textTimer.classList.remove('done');
    textDone.classList.remove('show');

    const alreadyDone = noteMap[noteId] === 1;
    toggleMarkBtn('text', alreadyDone);
    textBody.innerHTML = '<p style="color:var(--muted);"><i class="fas fa-spinner fa-spin"></i> Loading document…</p>';
    textWrap.classList.add('active');
    textWrap.scrollIntoView({behavior:'smooth', block:'start'});

    <?php if ($is_paid): ?>
    showNoteProtection();
    <?php endif; ?>

    if (ext === 'docx' && window.mammoth) {
        fetch(url).then(r => r.arrayBuffer())
            .then(buf => mammoth.convertToHtml({ arrayBuffer: buf }))
            .then(result => {
                textBody.innerHTML = result.value || '<p style="color:var(--muted);">This document has no readable content.</p>';
                if (!alreadyDone) setTimeout(() => setupNoteScrollTracking(noteId), 100);
            })
            .catch(() => { textBody.innerHTML = officeFallbackMessage(); });
    } else if ((ext === 'xlsx' || ext === 'xls') && window.XLSX) {
        fetch(url).then(r => r.arrayBuffer())
            .then(buf => {
                const wb = XLSX.read(new Uint8Array(buf), { type: 'array' });
                let html = '';
                wb.SheetNames.forEach(name => {
                    html += '<h4>' + escHtml(name) + '</h4>';
                    html += XLSX.utils.sheet_to_html(wb.Sheets[name], { editable: false });
                });
                textBody.innerHTML = html || '<p style="color:var(--muted);">This spreadsheet is empty.</p>';
                if (!alreadyDone) setTimeout(() => setupNoteScrollTracking(noteId), 100);
            })
            .catch(() => { textBody.innerHTML = officeFallbackMessage(); });
    } else {
        textBody.innerHTML = officeFallbackMessage();
    }
}

function officeFallbackMessage() {
    return '<div style="text-align:center;color:var(--muted);padding:30px 10px;">' +
           '<i class="fas fa-file-circle-exclamation" style="font-size:34px;display:block;margin-bottom:10px;opacity:0.5;"></i>' +
           '<p>An in-browser preview isn\'t available for this file type yet.</p>' +
           '</div>';
}

function closeTextNote() {
    const container = document.getElementById('text-note-body');
    if (container) container.onscroll = null;
    if (curTextNoteId !== null) {
        saveNoteProgress(curTextNoteId, curNoteScrollMax, false);
    }
    textWrap.classList.remove('active');
    textBody.innerHTML = '';
    curTextNoteId = null;
    curNoteScrollMax = 0;
}

function linkify(text) {
    const escaped = escHtml(text);
    const urlPattern = /(\bhttps?:\/\/[^\s<]+|\bwww\.[^\s<]+)/gi;
    return escaped.replace(urlPattern, (match) => {
        const href = match.startsWith('http') ? match : 'https://' + match;
        return '<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + match + '</a>';
    }).replace(/\n/g, '<br>');
}

function toggleMarkBtn(type, isDone) {
    const btn = document.getElementById(type === 'pdf' ? 'note-pdf-mark-btn' : 'note-text-mark-btn');
    if (!btn) return;
    btn.style.display = isDone ? 'none' : '';
}

function markNoteDone(type) {
    let noteId;
    if (type === 'pdf') {
        if (curNoteId === null) return;
        noteId = curNoteId;
        notePdfDone.classList.add('show');
    } else {
        if (curTextNoteId === null) return;
        noteId = curTextNoteId;
        textTimer.textContent = '100% scrolled';
        textTimer.classList.add('done');
        textDone.classList.add('show');
    }
    updateNoteUI(noteId, 100);
    saveNoteProgress(noteId, 100, true);
    onNoteCompleted(noteId);
    toggleMarkBtn(type, true);
}

const completedNotesSet = new Set(
    Object.entries(noteMap).filter(([,v]) => v === 1).map(([k]) => parseInt(k))
);

function onNoteCompleted(noteId) {
    if (completedNotesSet.has(noteId)) return;
    completedNotesSet.add(noteId);
    noteMap[noteId] = 1;
    noteProgressMap[noteId] = 100;
    const badge = document.getElementById('note-badge-' + noteId);
    if (badge) badge.style.display = '';
    const btn = document.getElementById('note-btn-' + noteId);
    if (btn) {
        btn.classList.add('done-btn');
        btn.innerHTML = btn.innerHTML
            .replace('Open PDF',      'Re-read PDF')
            .replace('Open Document', 'Re-read')
            .replace('Open Text',     'Re-read');
    }
    updateProgressUI();
}

function saveNoteProgress(noteId, percentage, forceDone) {
    let body = 'action=save_note_progress&note_id=' + noteId + '&percentage=' + percentage + '&csrf_token=' + encodeURIComponent(CSRF_TOKEN);
    if (forceDone) body += '&force_done=1';
    fetch(location.href, {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body: body,
        keepalive:true
    })
    .then(r => r.json())
    .then(data => {
        if (!data.ok) console.warn('Note progress NOT saved:', data);
    })
    .catch(err => console.error('Note progress save request failed:', err));
}

window.addEventListener('beforeunload', () => {
    if (curTextNoteId !== null) {
        saveNoteProgress(curTextNoteId, curNoteScrollMax, false);
    }
});

/* ==== STAR RATING ==== */
let selectedRating = 5;
function setRating(val) {
    selectedRating = val;
    document.getElementById('rating-val').value = val;
    document.querySelectorAll('#star-select button').forEach(b =>
        b.classList.toggle('on', parseInt(b.dataset.val) <= val));
}
setRating(5);

function sendReview() {
    const comment = document.getElementById('comment').value.trim();
    fetch(location.href, {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'action=add_review&course_id=<?= $course_id ?>&rating='+encodeURIComponent(selectedRating)+'&comment='+encodeURIComponent(comment)+'&csrf_token='+encodeURIComponent(CSRF_TOKEN)
    }).finally(() => {
        const t = document.getElementById('review-toast');
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 4000);
    });
}

/* ========
 * QUIZ MODAL
 * ======== */
let countdown;
let quizIsOpen = false;     
let quizAutoSubmitting = false; 
document.addEventListener('keydown', e => { if (e.key==='Escape') closeQuiz(); });

function openQuiz(id) {
    const quiz = ALL_QUIZZES.find(q => parseInt(q.id) === parseInt(id));
    if (!quiz) {
        alert("Quiz not found.");
        return;
    }

    const formData = new URLSearchParams();
    formData.append("action", "start_quiz");
    formData.append("quiz_id", id);
    formData.append("csrf_token", CSRF_TOKEN);

    fetch(window.location.href, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json"
        },
        body: formData.toString()
    })
    .then(async response => {
        const text = await response.text();
        let data;
        try {
            data = JSON.parse(text);
        } catch (error) {
            throw new Error("Invalid server response.\n\n" + text.substring(0, 1000));
        }
        if (!response.ok) {
            throw new Error(data.message || data.reason || ("HTTP error " + response.status));
        }
        return data;
    })
    .then(data => {
        if (!data.ok) {
            if (data.reason === "max_attempts_reached") {
                alert("You have used all " + data.max_attempts + " attempt(s) allowed for this quiz.");
                return;
            }
            alert("Could not start quiz.\n\n" + (data.reason || "Unknown error"));
            return;
        }

        if (typeof data.seconds_remaining === "undefined") {
            alert("Quiz started, but the server did not return the timer.");
            return;
        }

        renderQuiz(quiz, parseInt(id), parseInt(data.seconds_remaining));
    })
    .catch(error => {
        alert("Quiz could not be started.\n\n" + error.message);
    });
}

function renderQuiz(quiz, id, secondsRemaining) {
    const qs = ALL_QUESTIONS.filter(q => parseInt(q.quiz_id) === id);

    let html = `<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
        <div>
            <h2 style="font-size:1.2rem;color:var(--text);">${escHtml(quiz.title)}</h2>
            <p style="color:var(--muted);font-size:0.87rem;margin-top:4px;">
                ${parseInt(quiz.questions)} questions &bull; ${parseInt(quiz.duration)} min &bull; Pass: ${parseInt(quiz.passing_score)}%
            </p>
        </div>
        <div class="quiz-timer" id="quizTimer">--:--</div>
    </div>
    <form method="POST" action="course1.php?id=<?= $course_id ?>">
        <input type="hidden" name="csrf_token" value="${escHtml(CSRF_TOKEN)}">
        <input type="hidden" name="quiz_id" value="${parseInt(quiz.id)}">`;

    if (qs.length === 0) {
        html += '<p style="color:var(--muted);">No questions available.</p>';
    } else {
        qs.forEach((q, i) => {
            const qid = parseInt(q.id);
            html += `<div style="padding:16px;border:1px solid var(--border);border-radius:10px;margin-bottom:14px;">
                <p style="font-weight:700;margin-bottom:12px;font-size:0.95rem;">Q${i+1}: ${escHtml(q.question)}</p>
                ${['A','B','C','D'].map(opt => `
                    <label class="quiz-option">
                        <input type="radio" name="answer[${qid}]" value="${opt}" required>
                        <strong>${opt}.</strong> ${escHtml(q['option_'+opt.toLowerCase()] ?? '')}
                    </label>`).join('')}
            </div>`;
        });
    }
    html += `<button type="submit" name="submit_quiz" class="btn-primary" style="width:100%;justify-content:center;margin-top:8px;padding:12px;">
        <i class="fas fa-paper-plane"></i> Submit Quiz
    </button></form>`;

    document.getElementById('quizContainer').innerHTML = html;
    document.getElementById('quizModal').classList.add('active');
    document.body.style.overflow = 'hidden';
    quizIsOpen = true;
    quizAutoSubmitting = false;
    startTimer(secondsRemaining);
}

function startTimer(secondsRemaining) {
    clearInterval(countdown);
    let remaining = Math.max(0, secondsRemaining);
    const update = () => {
        const timer = document.getElementById('quizTimer');
        if (!timer) { clearInterval(countdown); return; }
        const m = Math.floor(remaining / 60), s = remaining % 60;
        timer.textContent = String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
        if (m < 2) timer.style.background = m < 1 ? '#dc2626' : '#f97316';
        if (remaining <= 0) {
            clearInterval(countdown);
            autoSubmitQuiz();
            return;
        }
        remaining--;
    };
    update();
    countdown = setInterval(update, 1000);
}

function autoSubmitQuiz() {
    if (quizAutoSubmitting) return;
    quizAutoSubmitting = true;
    clearInterval(countdown);
    quizIsOpen = false;
    const form = document.querySelector('#quizContainer form');
    if (form) {
        form.submit();
    } else {
        closeQuiz();
    }
}

function closeQuiz() {
    if (quizIsOpen) {
        autoSubmitQuiz();
        return;
    }
    clearInterval(countdown);
    document.getElementById('quizModal')?.classList.remove('active');
    document.body.style.overflow = '';
}

function escHtml(str) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(str ?? '')));
    return d.innerHTML;
}

/* ==== ASSIGNMENTS ==== */
function submitAssignment(evt, assignmentId) {
    evt.preventDefault();
    const form = evt.target;
    const fd = new FormData(form);
    fd.append('action', 'submit_assignment');
    fd.append('assignment_id', assignmentId);
    fd.append('csrf_token', CSRF_TOKEN);

    const btn = form.querySelector('button[type=submit]');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Submitting…';

    fetch(location.href, { method:'POST', body: fd })
        .then(r => r.json())
        .then(data => {
            if (data.ok) {
                location.reload();
            } else {
                alert('Submission failed: ' + (data.reason || 'unknown error'));
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-paper-plane"></i> Submit';
            }
        })
        .catch(() => {
            alert('Submission failed - check your connection and try again.');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-paper-plane"></i> Submit';
        });
    return false;
}

/* ==== DISCUSSION ==== */
function postDiscussion() {
    const el = document.getElementById('discussion-body');
    const body = el.value.trim();
    if (!body) return;
    fetch(location.href, {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'action=post_discussion&body='+encodeURIComponent(body)+'&csrf_token='+encodeURIComponent(CSRF_TOKEN)
    })
    .then(r => r.json())
    .then(data => {
        if (data.ok) { location.reload(); }
        else { alert('Could not post: ' + (data.reason || 'unknown error')); }
    })
    .catch(() => alert('Could not post - check your connection and try again.'));
}

updateProgressUI();

<?php if ($is_paid): ?>
document.addEventListener('DOMContentLoaded', function() {
    document.addEventListener('keydown', function(e) {
        const active = document.activeElement;
        if (active && active.tagName === 'IFRAME') {
            if (e.ctrlKey && ['c', 'v', 'p', 'C', 'V', 'P'].includes(e.key)) {
                e.preventDefault();
                showNoteProtection();
                return false;
            }
            if (e.key === 'PrintScreen' || e.key === 'F12') {
                e.preventDefault();
                showNoteProtection();
                return false;
            }
        }
    }, true);
});
<?php endif; ?>
</script>
</body>
</html>