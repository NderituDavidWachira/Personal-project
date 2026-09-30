<?php
/**
 * course1.php  (combined build)
 *
 * This single file now contains everything that used to be split
 * across four files:
 *   - lms_helpers.php        -> inlined as plain functions below
 *   - secure_video.php       -> inlined as a `?video=<id>` handler
 *                                (was a separate public endpoint,
 *                                now just another branch of this
 *                                script, same as the existing
 *                                `?note=<id>` PDF handler)
 *   - course_access_denied.php -> inlined as the $deny_html block
 *                                used when checkCourseAccess() fails
 *
 * Nothing about the *security model* changed in this merge: the same
 * checks that used to live in lms_helpers.php / secure_video.php are
 * still run, just from inside this file instead of via `include`.
 */

session_start();
include "db.php";
include "advance.php";

/* =====================================================================
 * INLINED FROM lms_helpers.php
 * Shared, testable logic used by both the page-render path and the
 * secure video-streaming path below, so the security rules can't
 * drift out of sync between the two.
 * ===================================================================== */

/* ---------------------------------------------------------------------
 * 1. ENROLLMENT + PAYMENT GATE  (audit gap #9)
 * ---------------------------------------------------------------------
 * A student may access a course only if:
 *   - they have a row in `enrollments` for that course whose status
 *     counts as "currently enrolled", AND
 *   - if the course is paid, they also have a 'confirmed' row in
 *     `payments` for that course.
 * Admin/teacher roles bypass the paid check (but still need to exist
 * as users) — extend here if you add an admin preview mode.
 *
 * NOTE: this schema's `enrollments.status` never uses the value
 * 'active' — it uses 'approved', 'ongoing', and 'completed' (verified
 * against the live enrollments table). ENROLLED_STATUSES below is the
 * single source of truth for which statuses grant access; add to it
 * here if enroll.php ever introduces another "has access" status.
 * Comparison is trim()+strtolower()'d so stray casing/whitespace in
 * the DB can't cause a false denial either.
 * ------------------------------------------------------------------- */
const ENROLLED_STATUSES = ['approved', 'ongoing', 'completed', 'active'];

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

/* ---------------------------------------------------------------------
 * 2. SERVER-AUTHORITATIVE QUIZ TIMER  (audit gap #11)
 * ---------------------------------------------------------------------
 * The JS timer is now cosmetic only. The server records when a quiz
 * attempt started and its hard expiry; submissions after expiry are
 * rejected regardless of what the client claims.
 * ------------------------------------------------------------------- */
function startQuizAttempt(PDO $pdo, int $user_id, int $quiz_id, int $course_id, int $duration_minutes): array {
    // Re-use an unexpired in-progress attempt if one exists (e.g. page reload)
    $existing = $pdo->prepare(
        "SELECT * FROM quiz_attempts
         WHERE user_id=? AND quiz_id=? AND status='in_progress' AND server_expires_at > NOW()
         ORDER BY started_at DESC LIMIT 1"
    );
    $existing->execute([$user_id, $quiz_id]);
    if ($row = $existing->fetch()) {
        return $row;
    }

    $countStmt = $pdo->prepare("SELECT COUNT(*) AS n FROM quiz_attempts WHERE user_id=? AND quiz_id=?");
    $countStmt->execute([$user_id, $quiz_id]);
    $attempt_number = (int) $countStmt->fetch()['n'] + 1;

    $insert = $pdo->prepare(
        "INSERT INTO quiz_attempts
            (user_id, quiz_id, course_id, attempt_number, started_at, server_expires_at, status)
         VALUES (?,?,?,?, NOW(), DATE_ADD(NOW(), INTERVAL ? MINUTE), 'in_progress')"
    );
    $insert->execute([$user_id, $quiz_id, $course_id, $attempt_number, $duration_minutes]);
    $attempt_id = (int) $pdo->lastInsertId();

    $get = $pdo->prepare("SELECT * FROM quiz_attempts WHERE id=?");
    $get->execute([$attempt_id]);
    return $get->fetch();
}

/**
 * Validates that a submission is happening within the server-recorded
 * window and closes out the attempt. Returns the attempt row (with a
 * 'valid' key added) so the caller can decide whether to grade it.
 */
function closeQuizAttempt(PDO $pdo, int $user_id, int $quiz_id, int $score, string $status): array {
    $find = $pdo->prepare(
        "SELECT * FROM quiz_attempts
         WHERE user_id=? AND quiz_id=? AND status='in_progress'
         ORDER BY started_at DESC LIMIT 1"
    );
    $find->execute([$user_id, $quiz_id]);
    $attempt = $find->fetch();

    if (!$attempt) {
        // No attempt was ever started server-side — reject the submission.
        return ['valid' => false, 'reason' => 'no_active_attempt'];
    }

    $expired = strtotime($attempt['server_expires_at']) < time();
    $final_status = $expired ? 'expired' : $status;
    $time_used = time() - strtotime($attempt['started_at']);

    $update = $pdo->prepare(
        "UPDATE quiz_attempts
         SET submitted_at = NOW(), score = ?, status = ?, time_used_sec = ?
         WHERE id = ?"
    );
    $update->execute([$expired ? null : $score, $final_status, $time_used, $attempt['id']]);

    $attempt['valid']  = !$expired;
    $attempt['status'] = $final_status;
    return $attempt;
}

/* ---------------------------------------------------------------------
 * 3. CPD / CME POINTS  (audit gap #3)
 * ------------------------------------------------------------------- */
function awardCpdPoints(PDO $pdo, int $user_id, int $course_id, string $activity_type): void {
    $rule = $pdo->prepare(
        "SELECT points FROM cpd_rules WHERE course_id=? AND activity_type=? LIMIT 1"
    );
    $rule->execute([$course_id, $activity_type]);
    $r = $rule->fetch();
    if (!$r) return; // no CPD configured for this course/activity

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

/* ---------------------------------------------------------------------
 * 4. CERTIFICATE ISSUANCE  (audit gap #8)
 * ---------------------------------------------------------------------
 * Call this after any completion-relevant event (quiz pass, note read,
 * video watched, assignment marked). It checks the course's
 * completion rule and — if met and no certificate exists yet — issues
 * one. This is what actually populates the `certificates` table,
 * instead of course1.php only ever reading from it.
 * ------------------------------------------------------------------- */
function checkAndIssueCertificate(PDO $pdo, int $user_id, int $course_id, array $progress): ?array {
    // Already issued?
    $exists = $pdo->prepare("SELECT * FROM certificates WHERE user_id=? AND course_id=? LIMIT 1");
    $exists->execute([$user_id, $course_id]);
    if ($cert = $exists->fetch()) {
        return $cert;
    }

    $ruleStmt = $pdo->prepare("SELECT * FROM course_completion_rules WHERE course_id=?");
    $ruleStmt->execute([$course_id]);
    $rule = $ruleStmt->fetch();
    if (!$rule) {
        // No configured rule — fall back to the simple 90% overall rule
        // rather than silently never issuing anything.
        $rule = [
            'min_video_pct' => 90, 'min_notes_pct' => 90, 'min_assignments_pct' => 0,
            'min_quiz_pct' => 90, 'require_final_pass' => 0, 'min_cpd_points' => 0,
        ];
    }

    $meets = $progress['video_pct']  >= $rule['min_video_pct']
          && $progress['notes_pct']  >= $rule['min_notes_pct']
          && $progress['quiz_pct']   >= $rule['min_quiz_pct']
          && $progress['assignments_pct'] >= $rule['min_assignments_pct']
          && $progress['cpd_points'] >= $rule['min_cpd_points'];

    if (!$meets) return null;

    $userStmt = $pdo->prepare("SELECT full_name FROM users WHERE id=?");
    $userStmt->execute([$user_id]);
    $participant_name = $userStmt->fetch()['full_name'] ?? '';

    $courseStmt = $pdo->prepare("SELECT title FROM courses WHERE id=?");
    $courseStmt->execute([$course_id]);
    $course_title = $courseStmt->fetch()['title'] ?? '';

    $cert_number = 'CBTK-STP-' . date('Y') . '-' . str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $verification_token = bin2hex(random_bytes(16));

    $ins = $pdo->prepare(
        "INSERT INTO certificates
            (user_id, course_id, certificate_number, participant_name, course_title,
             completion_date, verification_token, status, issued_at)
         VALUES (?,?,?,?,?, CURDATE(), ?, 'issued', NOW())"
    );
    $ins->execute([$user_id, $course_id, $cert_number, $participant_name, $course_title, $verification_token]);

    $get = $pdo->prepare("SELECT * FROM certificates WHERE id = ?");
    $get->execute([(int) $pdo->lastInsertId()]);
    return $get->fetch();
}

/* =====================================================================
 * END INLINED lms_helpers.php
 * ===================================================================== */

/* === AUTH === */
if (!isset($_SESSION['user_id'])) { header("Location: index.php"); exit; }
$user_id = (int) $_SESSION['user_id'];

/* === CSRF === */
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
function validateCsrf(): void {
    if (empty($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403); die("Invalid CSRF token.");
    }
}

function inPlaceholders(array $ids): string {
    return implode(',', array_fill(0, count($ids), '?'));
}

/* === COURSE ID === */
if (empty($_GET['id'])) die("Course not found");
$course_id = intval($_GET['id']);

/* =====================================================================
 * SELF-ONLY DEBUG VIEW  (temporary diagnostic aid)
 * ---------------------------------------------------------------------
 * Visit  course1.php?id=<course_id>&debug=1  while logged in as the
 * affected student. This ONLY ever prints the requesting session's
 * own user_id/course_id and their own enrollment row(s) — it cannot
 * be used to look up any other student's data, so it's safe to leave
 * in temporarily. Remove this block once the enrollment mismatch is
 * root-caused.
 * ===================================================================== */
if (isset($_GET['debug'])) {
    header('Content-Type: text/plain');
    echo "session user_id: "; var_export($user_id); echo "\n";
    echo "URL course_id:   "; var_export($course_id); echo "\n\n";

    $dbg = $pdo->prepare("SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?");
    $dbg->execute([$user_id, $course_id]);
    echo "enrollments row(s) for this exact (user_id, course_id) pair:\n";
    print_r($dbg->fetchAll());

    $dbgAll = $pdo->prepare("SELECT id, course_id, status FROM enrollments WHERE user_id = ?");
    $dbgAll->execute([$user_id]);
    echo "\nALL enrollment rows for this user_id (to spot a course_id mismatch):\n";
    print_r($dbgAll->fetchAll());

    $dbgCourses = $pdo->prepare("SELECT id, title FROM courses WHERE title = (SELECT title FROM courses WHERE id = ?)");
    $dbgCourses->execute([$course_id]);
    echo "\nAny OTHER course rows sharing this course's title (possible duplicate course_id):\n";
    print_r($dbgCourses->fetchAll());
    exit;
}

/* === SERVE NOTE PDF === */
if (isset($_GET['note'])) {
    $note_id = intval($_GET['note']);
    $stmt = $pdo->prepare("SELECT file_path FROM notes WHERE id = ? AND course_id = ?");
    $stmt->execute([$note_id, $course_id]);
    $note_row = $stmt->fetch();
    if (!$note_row) die("Note not found.");
    $file = $note_row['file_path'];
    if (!file_exists($file)) die("File not found on server.");
    header('Content-Type: application/pdf');
    header('Content-Disposition: inline; filename="' . basename($file) . '"');
    header('Content-Length: ' . filesize($file));
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    readfile($file);
    exit;
}

/* =====================================================================
 * SERVE VIDEO  (inlined from secure_video.php, fixes audit gap #10)
 * ---------------------------------------------------------------------
 * Videos are never served from a guessable public path
 * (uploads/videos/<filename>). Instead the front-end requests
 * course1.php?id=<course_id>&video=<video_id>, and this branch
 * re-checks, exactly as the old standalone secure_video.php did:
 *   1. Is the student logged in?               (session check above)
 *   2. Does the video belong to a real course?
 *   3. Is the student enrolled (active) in that course?
 *   4. If the course is paid, has payment been confirmed?
 * Only then does it stream the file, with HTTP Range support so
 * seeking/scrubbing still works. Folding this into course1.php (rather
 * than keeping it a separate file) means there is only one script that
 * needs `checkCourseAccess()` wired in correctly for video delivery.
 * ===================================================================== */
if (isset($_GET['video'])) {
    $video_id = intval($_GET['video']);
    if ($video_id <= 0) {
        http_response_code(400);
        die("Missing video id.");
    }

    /* Look up the video and its course in one go */
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

    /* Same shared gate used for the page itself further down. */
    if (!checkCourseAccess($pdo, $user_id, $v_course_id, $v_is_paid)) {
        http_response_code(403);
        die("You do not have access to this video. Enroll and complete payment to view course content.");
    }

    $file = $vrow['video_path'];
    if (!$file || !file_exists($file)) {
        http_response_code(404);
        die("File not found on server.");
    }

    /* === STREAM WITH RANGE SUPPORT === */
    $filesize = filesize($file);
    $mime = 'video/mp4';
    $fi = new finfo(FILEINFO_MIME_TYPE);
    $detected = $fi->file($file);
    if ($detected) $mime = $detected;

    header('Content-Type: ' . $mime);
    header('Accept-Ranges: bytes');
    header('Cache-Control: private, max-age=0, no-cache');
    header('X-Content-Type-Options: nosniff');

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
/* =====================================================================
 * END INLINED secure_video.php
 * ===================================================================== */

/* === QUIZ SUBMISSION === */
if (isset($_POST['submit_quiz'])) {
    validateCsrf();
    $roleCheck = $pdo->prepare("SELECT role FROM users WHERE id=? LIMIT 1");
    $roleCheck->execute([$user_id]);
    $roleRow = $roleCheck->fetch();
    if (!$roleRow || $roleRow['role'] !== 'student') die("❌ Unauthorized.");

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

        /* === SERVER-AUTHORITATIVE TIMER CHECK (fixes gap #11) ===
           The client-side countdown is cosmetic only. closeQuizAttempt()
           looks up the attempt that startQuizAttempt() recorded when the
           quiz modal was opened and rejects the submission if the
           server-side expiry has already passed, no matter what the
           browser sent. */
        $attempt = closeQuizAttempt($pdo, $student_id, $quiz_id, $score, $status);
        if (!$attempt['valid']) {
            $_SESSION['quiz_success'] = ($attempt['reason'] ?? '') === 'no_active_attempt'
                ? "⚠️ Quiz session not found — please start the quiz again from the course page."
                : "⏱ Time's up — this attempt expired and was not scored. Start a new attempt.";
            header("Location: course1.php?id=" . $course_id); exit;
        }

        /* Snapshot table (kept for backwards compatibility with existing reads) */
        $stmt = $pdo->prepare(
            "INSERT INTO quiz_results (student_id, user_id, quiz_id, quiz_title, score, status, completed_at)
             VALUES (?,?,?,?,?,?,NOW())
             ON DUPLICATE KEY UPDATE
                score=VALUES(score),
                status=VALUES(status),
                completed_at=NOW()"
        );
        $stmt->execute([$student_id, $student_id, $quiz_id, $quiz_title, $score, $status]);

        /* === FULL ATTEMPT HISTORY (fixes gap #12) ===
           quiz_attempts (written by closeQuizAttempt above) already keeps
           every attempt instead of overwriting. Mirror this attempt into
           quiz_history too, since course1.php reads from quiz_history for
           the "Quiz History" card and previously nothing ever wrote there. */
        $histStmt = $pdo->prepare(
            "INSERT INTO quiz_history (user_id, title, score, status, completed_at)
             VALUES (?,?,?,?,NOW())"
        );
        $histStmt->execute([$student_id, $quiz_title, $score, $status]);

        $prog_stmt = $pdo->prepare(
            "INSERT INTO student_progress (user_id, course_id, item_type, item_id, completed, score, updated_at)
             VALUES (?,?,'quiz',?,1,?,NOW())
             ON DUPLICATE KEY UPDATE
                completed=1,
                score=VALUES(score),
                updated_at=NOW()"
        );
        $prog_stmt->execute([$student_id, $course_id, $quiz_id, $score]);

        /* === CPD POINTS (fixes gap #3) === */
        if ($status === 'passed') {
            awardCpdPoints($pdo, $student_id, $course_id, 'quiz');
        }

        /* === CERTIFICATE CHECK (fixes gap #8) ===
           Recompute the same progress percentages the page itself shows,
           then let checkAndIssueCertificate() decide whether this event
           was the one that pushed the student over the completion rule. */
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

        $_SESSION['quiz_success'] = "Quiz Submitted! Score: {$score}% — " . ucfirst($status) . "!";
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
        define('NOTE_COMPLETE_SECONDS', 30);
        $note_id = intval($_POST['note_id'] ?? 0);
        $seconds = max(0, intval($_POST['seconds'] ?? 0));
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
        $completed = ($seconds >= NOTE_COMPLETE_SECONDS || $force_done) ? 1 : 0;
        $seconds   = $force_done ? max($seconds, NOTE_COMPLETE_SECONDS) : $seconds;
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
            $stmt->execute([$user_id, $note_id, $seconds, $completed]);
            if ($completed) {
                $up = $pdo->prepare(
                    "INSERT INTO student_progress
                        (user_id, course_id, item_type, item_id, completed, updated_at)
                     VALUES (?,?,'note',?,1,NOW())
                     ON DUPLICATE KEY UPDATE completed=1, updated_at=NOW()"
                );
                $up->execute([$user_id, $course_id, $note_id]);
            }
            echo json_encode(['ok' => true, 'note_id' => $note_id, 'seconds' => $seconds, 'completed' => $completed]);
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

    /* Start a quiz attempt — records server-side start time + expiry
       BEFORE the modal opens, so the timer shown to the student is a
       reflection of server truth, not something the client controls. */
    if ($_POST['action'] === 'start_quiz' && $user_id) {
        header('Content-Type: application/json');
        $quiz_id = intval($_POST['quiz_id'] ?? 0);
        $qcheck = $pdo->prepare("SELECT duration FROM quizzes WHERE id=? AND course_id=?");
        $qcheck->execute([$quiz_id, $course_id]);
        $quizRow = $qcheck->fetch();
        if (!$quizRow) {
            echo json_encode(['ok' => false, 'reason' => 'quiz_not_in_course']);
            exit;
        }
        try {
            $attempt = startQuizAttempt($pdo, $user_id, $quiz_id, $course_id, (int) $quizRow['duration']);
            echo json_encode([
                'ok' => true,
                'server_now'        => date('c'),
                'server_expires_at' => date('c', strtotime($attempt['server_expires_at'])),
                'seconds_remaining' => max(0, strtotime($attempt['server_expires_at']) - time()),
            ]);
        } catch (PDOException $e) {
            error_log("start_quiz failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['ok' => false, 'reason' => 'db_error']);
        }
        exit;
    }

    /* Assignment submission (fixes gap #1) */
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
        if (!empty($assignment['due_at']) && strtotime($assignment['due_at']) < time()) {
            if (!$assignment['allow_late']) {
                echo json_encode(['ok' => false, 'reason' => 'past_due']);
                exit;
            }
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

    /* Discussion / Q&A post (fixes gap #2) */
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
/* ==========
   PAGE LOAD
   ========== */
$course_query = $pdo->prepare("SELECT c.*, u.full_name AS instructor FROM courses c LEFT JOIN teachers t ON t.id=c.teacher_id LEFT JOIN users u ON u.id=t.user_id WHERE c.id=?");
$course_query->execute([$course_id]);
$course = $course_query->fetch();
if (!$course) die("Course not found");

$is_paid = (!empty($course['course_type']) && $course['course_type'] === 'Paid')
         || (!empty($course['price']) && (float)$course['price'] > 0);

/* === ENROLLMENT / PAYMENT GATE (fixes: authentication alone was enough
   to reach course content) ===
   A logged-in user is not automatically entitled to a course. They
   must have an active enrollment, and — for paid courses — a
   confirmed payment. Both are checked server-side in
   checkCourseAccess() (inlined above), the same function the video
   handler above uses, so this can't drift out of sync. */
$has_access = checkCourseAccess($pdo, $user_id, $course_id, $is_paid);
if (!$has_access) {
    $enroll_stmt = $pdo->prepare("SELECT status FROM enrollments WHERE user_id=? AND course_id=?");
    $enroll_stmt->execute([$user_id, $course_id]);
    $enroll_row = $enroll_stmt->fetch();
    $enroll_status_norm = $enroll_row ? strtolower(trim((string)$enroll_row['status'])) : null;
    $is_enrolled_status  = $enroll_status_norm !== null && in_array($enroll_status_norm, ENROLLED_STATUSES, true);
    $reason = !$enroll_row ? 'not_enrolled'
            : ($is_enrolled_status ? 'payment_required' : 'enrollment_' . $enroll_status_norm);

    /* =================================================================
     * INLINED FROM course_access_denied.php
     * Expects $course, $course_id, $is_paid, $reason to already be set
     * (all set above), same as when it was a separate included file.
     * ================================================================= */
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
    <title>Access required — <?= htmlspecialchars($course['title']) ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
    :root {
        --accent:#0f766e; --accent2:#14b8a6; --accent-lt:#ecfdf9;
        --text:#132a29; --muted:#5b7370; --bg:#f2f8f7; --surface:#fff;
        --border:rgba(15,118,110,0.15);
    }
    *{margin:0;padding:0;box-sizing:border-box;}
    body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
    .box{background:var(--surface);border:1px solid var(--border);border-radius:18px;max-width:460px;width:100%;padding:36px 32px;text-align:center;box-shadow:0 4px 24px rgba(15,118,110,0.08);}
    .icon{width:56px;height:56px;border-radius:50%;background:var(--accent-lt);color:var(--accent);display:flex;align-items:center;justify-content:center;font-size:22px;margin:0 auto 18px;}
    h1{font-size:19px;margin-bottom:10px;}
    p{color:var(--muted);font-size:14px;line-height:1.6;margin-bottom:22px;}
    .course-name{font-weight:700;color:var(--accent);}
    .btn{display:inline-flex;align-items:center;gap:8px;background:var(--accent);color:#fff;padding:11px 22px;border-radius:10px;font-weight:700;font-size:14px;text-decoration:none;}
    .btn:hover{background:#0d5f58;text-decoration:none;color:#fff;}
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
    /* ================= END INLINED course_access_denied.php ================= */
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

/*
   VIDEO PROGRESS MAP
 */
$video_progress_map = [];
foreach ($videos_rows as $v) {
    $video_progress_map[(int)$v['id']] = ['pct' => 0, 'completed' => 0];
}

if ($video_count > 0) {
    $vid_ids = array_map('intval', array_keys($video_progress_map));
    $ph = inPlaceholders($vid_ids);
    $vpm_stmt = $pdo->prepare(
        "SELECT content_id,
                MAX(watched_percentage)
                AS watched_percentage,
                MAX(completed)
                AS completed
         FROM video_progress
         WHERE user_id = ?
           AND content_id IN ($ph)
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

/*
   NOTE PROGRESS MAP
    */
$note_progress_map = [];
foreach ($notes_rows as $n) {
    $note_progress_map[(int)$n['id']] = ['seconds' => 0, 'completed' => 0];
}

if ($note_count > 0) {
    $note_ids = array_map('intval', array_keys($note_progress_map));
    $ph = inPlaceholders($note_ids);

    $npres_stmt = $pdo->prepare(
        "SELECT note_id,
                MAX(seconds_viewed) AS seconds_viewed,
                MAX(completed)      AS completed
         FROM note_progress
         WHERE user_id = ?
           AND note_id IN ($ph)
         GROUP BY note_id"
    );
    $npres_stmt->execute(array_merge([$user_id], $note_ids));
    foreach ($npres_stmt->fetchAll() as $row) {
        $nid = (int)$row['note_id'];
        if (isset($note_progress_map[$nid])) {
            $note_progress_map[$nid] = [
                'seconds'   => (int)$row['seconds_viewed'],
                'completed' => (int)$row['completed'],
            ];
        }
    }
}

/*Compute aggregate percentages*/
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

/* BASE URL */
$base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']==='on' ? 'https' : 'http')
    . '://' . $_SERVER['HTTP_HOST']
    . rtrim(dirname($_SERVER['PHP_SELF']), '/\\') . '/';

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

$stmt = $pdo->prepare("SELECT * FROM quiz_history WHERE user_id=? ORDER BY completed_at DESC");
$stmt->execute([$user_id]);
$history_rows = $stmt->fetchAll();

$stmt = $pdo->prepare("SELECT * FROM quiz_achievements WHERE user_id=?");
$stmt->execute([$user_id]);
$achievements_rows = $stmt->fetchAll();

$stmt = $pdo->prepare("SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC");
$stmt->execute([$user_id]);
$certs_rows = $stmt->fetchAll();

/* === ASSIGNMENTS (fixes gap #1) === */
$assign_stmt = $pdo->prepare(
    "SELECT a.*, s.status AS sub_status, s.score AS sub_score, s.feedback AS sub_feedback,
            s.submitted_at AS sub_submitted_at, s.is_late AS sub_is_late
     FROM assignments a
     LEFT JOIN assignment_submissions s ON s.assignment_id = a.id AND s.user_id = ?
     WHERE a.course_id = ?
     ORDER BY a.due_at IS NULL, a.due_at ASC"
);
$assign_stmt->execute([$user_id, $course_id]);
$assignments_rows = $assign_stmt->fetchAll();
$assignment_count  = count($assignments_rows);
$assignments_done  = count(array_filter($assignments_rows, fn($a) => !empty($a['sub_status'])));

/* === ANNOUNCEMENTS (fixes gap #22) === */
$ann_stmt = $pdo->prepare(
    "SELECT ca.*, u.full_name AS poster_name
     FROM course_announcements ca
     LEFT JOIN users u ON u.id = ca.posted_by
     WHERE ca.course_id = ? ORDER BY ca.created_at DESC LIMIT 10"
);
$ann_stmt->execute([$course_id]);
$announcements_rows = $ann_stmt->fetchAll();

/* === DISCUSSION / Q&A (fixes gap #2) — top-level posts + reply counts === */
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

/* === CPD / CME POINTS (fixes gap #3) === */
$cpd_summary = getCpdSummary($pdo, $user_id, $course_id);

/* === COMPETENCIES (fixes gap #4) === */
$comp_stmt = $pdo->prepare(
    "SELECT c.*, sc.verified
     FROM competencies c
     LEFT JOIN student_competencies sc ON sc.competency_id = c.id AND sc.user_id = ?
     WHERE c.course_id = ? ORDER BY c.sort_order ASC, c.id ASC"
);
$comp_stmt->execute([$user_id, $course_id]);
$competency_rows = $comp_stmt->fetchAll();

/* === CAREER OPPORTUNITIES (fixes gap #19) — course-linked + platform-wide === */
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

/* JS INIT DATA — built directly from the DB-fetched maps */
$js_video_map = [];
foreach ($video_progress_map as $vid => $vdata) {
    $js_video_map[$vid] = $vdata['pct'];
}
$js_note_map = [];
foreach ($note_progress_map as $nid => $ndata) {
    $js_note_map[$nid] = $ndata['completed'] ? 1 : 0;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($course['title']) ?> — CBT-Kenya STP</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
/* =====================================================================
   CBT-KENYA / STP BRAND TOKENS (fixes gap #17)
   Palette approximates the calm clinical teal used across
   cbtkenya.org (counselling-service branding). Swap the hex values
   below for the exact brand-kit values once CBT-Kenya shares their
   logo file and style guide — everything downstream references
   these variables, so a rebrand is a one-place edit.
   ===================================================================== */
:root {
    --bg:#f2f8f7; --surface:#fff; --surface2:#eaf5f3;
    --border:rgba(15,118,110,0.14); --border-md:rgba(15,118,110,0.26);
    --text:#132a29; --muted:#5b7370;
    --accent:#0f766e; --accent2:#14b8a6; --accent-lt:#e3f6f3;
    --green:#16a34a; --green-lt:#dcfce7;
    --amber:#d97706; --amber-lt:#fef3c7; --red:#dc2626;
    --shadow-sm:0 1px 4px rgba(15,118,110,0.08);
    --shadow-md:0 4px 20px rgba(15,118,110,0.12);
    --radius-sm:8px; --radius-md:12px; --radius-lg:18px;
}
html { scroll-behavior:smooth; }
body { background:var(--bg); color:var(--text); font-family:-apple-system,'Segoe UI',sans-serif; font-size:15px; line-height:1.6; min-height:100vh; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
img { display:block; max-width:100%; }

/* PAID */
body.protected { -webkit-user-select:none; user-select:none; -webkit-user-drag:none; }
body.protected video::-webkit-media-controls-download-button { display:none!important; }
body.protected img { pointer-events:none; }
.paid-watermark { position:fixed; inset:0; pointer-events:none; z-index:8000; display:none;
    background:repeating-linear-gradient(-45deg,transparent,transparent 120px,rgba(91,82,232,0.04) 120px,rgba(91,82,232,0.04) 122px); }
.paid-watermark::after { content:'CBT-Kenya STP — Licensed Content'; position:absolute; top:50%; left:50%;
    transform:translate(-50%,-50%) rotate(-30deg); font-size:clamp(14px,2vw,22px); font-weight:700;
    color:rgba(15,118,110,0.08); white-space:nowrap; letter-spacing:2px; pointer-events:none; }
body.protected .paid-watermark { display:block; }
.badge-paid { background:rgba(217,119,6,0.2); border-color:rgba(217,119,6,0.4); color:#fef3c7; }

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
.hero { background:linear-gradient(130deg,#0f766e 0%,#14b8a6 55%,#5eead4 100%); padding:20px 0; margin-bottom:10px; }
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
.video-card.watching { border-color:var(--accent); box-shadow:0 0 0 3px rgba(15,118,110,0.15); }
.video-card.done { border-color:var(--green); }
.video-thumb { position:relative; background:#1a1830; aspect-ratio:16/9; display:flex; align-items:center; justify-content:center; }
.play-overlay { position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(26,24,48,0.35); }
.play-btn { width:46px; height:46px; background:var(--accent); border-radius:50%; display:flex; align-items:center; justify-content:center; box-shadow:0 4px 16px rgba(15,118,110,0.45); transition:transform 0.15s; }
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
.btn-primary { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; font-size:13px; font-weight:700; background:var(--accent); color:#fff; border:none; border-radius:var(--radius-sm); cursor:pointer; transition:background 0.15s,transform 0.1s,box-shadow 0.15s; text-decoration:none; white-space:nowrap; flex-shrink:0; box-shadow:0 2px 8px rgba(15,118,110,0.3); }
.btn-primary:hover { background:#0d5f58; transform:translateY(-1px); box-shadow:0 4px 14px rgba(15,118,110,0.4); text-decoration:none; color:#fff; }
.btn-mark-done { background:var(--accent-lt)!important; color:var(--accent)!important; border-color:var(--accent)!important; }
.btn-mark-done:hover { background:var(--accent)!important; color:#fff!important; }

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
.rating-submit:hover { background:#0d5f58; }
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
.protection-toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:#132a29; color:#fff; padding:12px 24px; border-radius:30px; font-size:13px; font-weight:600; box-shadow:0 4px 20px rgba(0,0,0,0.3); z-index:9999; opacity:0; transition:opacity 0.3s; pointer-events:none; white-space:nowrap; }
.protection-toast.show { opacity:1; }

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
.promo-card { background:linear-gradient(135deg,var(--accent),var(--accent2)); border-radius:var(--radius-lg); padding:20px; color:#fff; margin-bottom:20px; }
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

<!-- CBT-KENYA / STP BRANDING HEADER (fixes gap #17) -->
<header class="site-header">
    <div class="site-header-inner">
        <div class="brand-lockup">
            <div class="brand-mark">CBT</div>
            <div class="brand-text">CBT-Kenya<small>Skills Transfer Program</small></div>
        </div>
        <div style="font-size:12px;color:var(--muted);">
            <a href="student.php" style="color:var(--muted);">Dashboard</a> &nbsp;·&nbsp;
            <a href="portfolio.php" style="color:var(--muted);">My Portfolio</a>
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
                <span class="badge">▶ In Progress</span>
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

    <!--  ANNOUNCEMENTS (fixes gap #22)  -->
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

    <!--  VIDEOS  -->
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
                /* Fixes gap #10: no longer expose uploads/videos/<file> directly.
                   The browser only ever sees an opaque video id; the ?video=
                   branch at the top of this file re-checks session +
                   enrollment + payment before streaming bytes. */
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

    <!--  NOTES  -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-file-alt"></i> Course Notes</h2>
            <span class="count"><?= $note_count ?> files</span>
        </div>

        <!-- PDF viewer -->
        <div id="note-viewer-wrap">
            <div id="note-viewer-toolbar">
                <span id="note-viewer-title"></span>
                <span style="display:flex;align-items:center;gap:8px;">
                    <span class="read-timer" id="note-viewer-timer">00:00</span>
                    <span class="read-done-pill" id="note-pdf-done-pill"><i class="fas fa-check-circle"></i> Done reading</span>
                    <button class="note-close-btn btn-mark-done" id="note-pdf-mark-btn" onclick="markNoteDone('pdf')"> % Mark as Done</button>
                    <button class="note-close-btn" onclick="closeNote()">✕ Close</button>
                </span>
            </div>
            <iframe id="note-viewer" src="" allowfullscreen></iframe>
        </div>

        <!-- Text viewer -->
        <div id="text-note-wrap">
            <div id="text-note-toolbar">
                <span id="text-note-title"></span>
                <span style="display:flex;align-items:center;gap:8px;">
                    <span class="read-timer" id="text-note-timer">00:00</span>
                    <span class="read-done-pill" id="note-text-done-pill"><i class="fas fa-check-circle"></i> Done reading</span>
                    <button class="note-close-btn btn-mark-done" id="note-text-mark-btn" onclick="markNoteDone('text')">% Mark as Done</button>
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
                $npct    = min(100, (int)round(($npstate['seconds'] / 30) * 100));
                $has_pdf  = !empty($note['file_path']);
                $has_text = !$has_pdf && trim((string)($note['content'] ?? '')) !== '';
            ?>
            <div class="note-item" id="note-item-<?= $nid ?>" data-note-id="<?= $nid ?>">
                <div class="note-item-left">
                    <div class="note-icon"> <i class="fas fa-book-open"></i>
                              <?= $has_pdf ? '' : '' ?></div>
                    <div style="min-width:0;flex:1;">
                        <div class="note-name" id="note-name-<?= $nid ?>">
                            <?= htmlspecialchars($note['title']) ?>
                            <?php if ($npstate['completed']): ?>
                                <span class="note-done-badge" id="note-badge-<?= $nid ?>"><i class="fas fa-check-circle"></i> Read</span>
                            <?php else: ?>
                                <span class="note-done-badge" id="note-badge-<?= $nid ?>" style="display:none;"><i class="fas fa-check-circle"></i> Read</span>
                            <?php endif; ?>
                        </div>
                        <?php if (!empty($note['content'])): ?>
                            <div class="note-sub"><?= htmlspecialchars(mb_substr($note['content'], 0, 70)) ?>…</div>
                        <?php endif; ?>
                        <?php if ($has_pdf || $has_text): ?>
                        <div class="note-watched-wrap">
                            <div class="video-watched">
                                <div class="video-watched-fill" style="width:<?= $npct ?>%" id="nw-<?= $nid ?>"></div>
                            </div>
                            <div class="note-time-label" id="ntime-<?= $nid ?>">
                                <?= $npstate['seconds'] ?>s read · <?= $npct ?>% complete
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

    <!--  QUIZZES  -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-question-circle"></i> Quizzes</h2>
            <span class="count"><?= $quiz_count ?> quizzes</span>
        </div>
        <?php if ($quiz_count > 0): ?>
        <div class="quiz-list">
            <?php foreach ($quizzes_rows as $quiz):
                $qpassed = $quiz_status_map[(int)$quiz['id']] ?? '';
            ?>
            <div class="quiz-item">
                <div class="quiz-item-left">
                    <div class="quiz-icon"><i class="fas fa-file-alt"></i>
                    </div>
                    <div>
                        <div class="quiz-name">
                            <?= htmlspecialchars($quiz['title']) ?>
                            <?php if ($qpassed === 'passed'): ?>
                                <span class="note-done-badge" style="margin-left:6px;"><i class="fas fa-check-circle"></i> Passed</span>
                            <?php elseif ($qpassed === 'failed'): ?>
                                <span class="note-done-badge" style="background:#fee2e2;color:#dc2626;margin-left:6px;">✕ Failed</span>
                            <?php endif; ?>
                        </div>
                        <div class="quiz-meta">⏱ <?= (int)$quiz['duration'] ?> min &nbsp;·&nbsp; Pass at <?= (int)$quiz['passing_score'] ?>%</div>
                    </div>
                </div>
                <button class="btn-primary" onclick="openQuiz(<?= (int)$quiz['id'] ?>)">
                    <?= $qpassed ? 'Retry →' : 'Start →' ?>
                </button>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"></div><p>No quizzes for this course yet.</p></div>
        <?php endif; ?>
    </div>

    <!--  ASSIGNMENTS (fixes gap #1)  -->
    <div class="card">
        <div class="card-header">
            <h2><i class="fas fa-file-signature"></i> Assignments</h2>
            <span class="count"><?= $assignments_done ?>/<?= $assignment_count ?> submitted</span>
        </div>
        <?php if ($assignment_count > 0): ?>
        <div class="assignment-list">
            <?php foreach ($assignments_rows as $asn):
                $asn_id    = (int)$asn['id'];
                $due_ts    = $asn['due_at'] ? strtotime($asn['due_at']) : null;
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
                <?php if (!empty($asn['instructions'])): ?>
                    <div class="assignment-instructions"><?= nl2br(htmlspecialchars($asn['instructions'])) ?></div>
                <?php endif; ?>

                <?php if ($sub_status === 'marked' || $sub_status === 'returned'): ?>
                    <div class="assignment-feedback">
                        <span class="assignment-score">Score: <?= (int)$asn['sub_score'] ?>/<?= (int)$asn['max_score'] ?></span>
                        <?php if (!empty($asn['sub_feedback'])): ?>
                            <div style="margin-top:6px;"><?= nl2br(htmlspecialchars($asn['sub_feedback'])) ?></div>
                        <?php endif; ?>
                    </div>
                <?php elseif ($sub_status === 'submitted'): ?>
                    <div class="assignment-feedback">Submitted <?= htmlspecialchars(date('d M Y, g:i A', strtotime($asn['sub_submitted_at']))) ?><?= $asn['sub_is_late'] ? ' (late)' : '' ?> — awaiting marking.</div>
                <?php elseif (!$overdue || $asn['allow_late']): ?>
                    <form class="assignment-form" onsubmit="return submitAssignment(event, <?= $asn_id ?>)" enctype="multipart/form-data">
                        <textarea name="submission_text" placeholder="Write your submission, or attach a file below…"></textarea>
                        <div class="assignment-form-row">
                            <input type="file" name="submission_file" accept=".pdf,.doc,.docx,.png,.jpg,.jpeg">
                            <button type="submit" class="btn-primary"><i class="fas fa-paper-plane"></i> Submit</button>
                        </div>
                    </form>
                <?php else: ?>
                    <div class="assignment-feedback" style="color:var(--red);">Submission window closed.</div>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
            <div class="empty"><div class="empty-icon"><i class="fas fa-file-signature"></i></div><p>No assignments for this course yet.</p></div>
        <?php endif; ?>
    </div>

    <!--  COMPETENCIES (fixes gap #4)  -->
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

    <!--  DISCUSSION / Q&A (fixes gap #2)  -->
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
            <div class="empty"><div class="empty-icon"><i class="fas fa-comments"></i></div><p>No questions or discussion yet — be the first to post.</p></div>
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
            <div class="activity-item"><p><?= htmlspecialchars($h['title'] ?? '') ?></p><span>Completed <?= htmlspecialchars($h['completed_at'] ?? '') ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No history yet</p></div><?php endif; ?>
    </div>

    <div class="card">
        <div class="card-header"><h2><i class="fas fa-trophy"></i> Top Performance</h2></div>
        <?php if ($achievements_rows): foreach ($achievements_rows as $a): ?>
            <div class="activity-item"><p><?= htmlspecialchars($a['title'] ?? '') ?></p><span><?= htmlspecialchars($a['value'] ?? '') ?></span></div>
        <?php endforeach; else: ?><div class="activity-item"><p>No achievements yet</p></div><?php endif; ?>
    </div>

    <!-- CERTIFICATES (fixes gap #8 — generation is now real, not display-only) -->
    <div class="card">
        <div class="card-header"><h2><i class="fas fa-award"></i> Certificates</h2></div>
        <?php if ($certs_rows): foreach ($certs_rows as $c): ?>
            <div class="cert-card">
                <div class="cert-icon"><i class="fas fa-certificate"></i></div>
                <div style="flex:1;">
                    <p style="font-weight:700;font-size:13.5px;"><?= htmlspecialchars($c['course_title'] ?? $c['title'] ?? 'Certificate') ?></p>
                    <?php if (!empty($c['certificate_number'])): ?>
                        <div class="cert-number">№ <?= htmlspecialchars($c['certificate_number']) ?></div>
                    <?php endif; ?>
                    <span style="font-size:11.5px;color:var(--muted);">
                        <?= !empty($c['completion_date']) ? 'Issued ' . htmlspecialchars(date('d M Y', strtotime($c['completion_date']))) : htmlspecialchars($c['status'] ?? '') ?>
                    </span>
                    <?php if (!empty($c['certificate_number'])): ?>
                    <div class="cert-actions">
                        <a class="btn-outline" href="certificate_download.php?number=<?= urlencode($c['certificate_number']) ?>"><i class="fas fa-download"></i> Download</a>
                        <a class="btn-outline" href="verify_certificate.php?token=<?= urlencode($c['verification_token'] ?? '') ?>" target="_blank"><i class="fas fa-shield-check"></i> Verify</a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; else: ?>
            <div class="activity-item"><p>No certificates yet</p><span>Complete this course to earn your CBT-Kenya STP certificate.</span></div>
        <?php endif; ?>
    </div>

</div>

<!--  SIDEBAR  -->
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
                <?php elseif ($progress<50): ?>Just getting started — keep going!
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
            <div class="stat-box"><div class="val"><?= $avg_rating > 0 ? $avg_rating : '—' ?></div><div class="lbl">Rating</div></div>
        </div>
    </div>

    <!-- CPD / CME POINTS (fixes gap #3) -->
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

    <!-- CAREER OPPORTUNITIES (fixes gap #19) -->
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

    <!-- CBT-KENYA PROMOTIONAL SPACE (fixes gap #18) -->
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
            <div class="review-toast" id="review-toast"> Review submitted — thank you!</div>
        </div>
    </div>

</div>
</div>
</div>

<!-- CBT-KENYA / STP BRANDING FOOTER (fixes gap #17) -->
<footer class="site-footer">
    <strong>CBT-Kenya</strong> · Skills Transfer Program &nbsp;|&nbsp;
    Muthangari Road 37, Lavington, Nairobi &nbsp;|&nbsp;
    <a href="mailto:info@cbtkenya.org" style="color:rgba(255,255,255,0.85);">info@cbtkenya.org</a>
    <div style="margin-top:6px;opacity:0.6;">© <?= date('Y') ?> CBT-Kenya. All rights reserved.</div>
</footer>

<div id="quizModal" class="modal-overlay" role="dialog" aria-modal="true">
    <div class="modal-box">
        <button class="modal-close" onclick="closeQuiz()">✕</button>
        <div id="quizContainer"></div>
    </div>
</div>

<script>
/* ====
   DB on every page load
   ==== */
const IS_PAID       = <?= $is_paid_js ?>;
const ALL_QUIZZES   = <?= json_encode($all_quizzes,   JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP) ?>;
const ALL_QUESTIONS = <?= json_encode($all_questions, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP) ?>;
const CSRF_TOKEN    = <?= $csrf_js ?>;

const VIDEO_COUNT = <?= (int)$video_count ?>;
const NOTE_COUNT  = <?= (int)$note_count ?>;
const QUIZ_COUNT  = <?= (int)$quiz_count ?>;
const NOTE_DONE_S = 30;
const VID_DONE_PC = 90;

const W_VIDEO = VIDEO_COUNT > 0 ? 0.60 : 0;
const W_NOTE  = NOTE_COUNT  > 0 ? 0.25 : 0;
const W_QUIZ  = QUIZ_COUNT  > 0 ? 0.15 : 0;
const W_TOTAL = W_VIDEO + W_NOTE + W_QUIZ;
const videoMap = <?= json_encode($js_video_map, JSON_HEX_TAG) ?>;
const noteMap  = <?= json_encode($js_note_map,  JSON_HEX_TAG) ?>;

// Quiz progress comes from DB too — used in the weighted calc below
let liveQuizProgress = <?= (int)$quiz_progress ?>;

/* ====
   PROGRESS CALCULATOR
   ==== */
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
        else if (overall < 50)  elLbl.textContent = 'Just getting started — keep going!';
        else if (overall < 90)  elLbl.textContent = 'More than halfway there. Great work!';
        else                    elLbl.textContent  = '🎉 You\'ve completed this course!';
    }
}

/* ====
   PAID PROTECTION
   ==== */
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

/* ====
   VIDEO PLAYER
   ==== */
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

/* ====
   NOTE VIEWER  PDF
   ==== */
const noteWrap    = document.getElementById('note-viewer-wrap');
const noteFrame   = document.getElementById('note-viewer');
const noteTitleEl = document.getElementById('note-viewer-title');
const noteTimer   = document.getElementById('note-viewer-timer');
const notePdfDone = document.getElementById('note-pdf-done-pill');
let noteHandle=null, noteSec=0, curNoteId=null;

function openNote(noteId, url, title) {
    stopNoteTimer();
    if (curTextNoteId !== null) closeTextNote();
    curNoteId = noteId;
    noteFrame.src = url;
    noteTitleEl.textContent = ' ' + title;
    noteTimer.textContent = '00:00';
    noteTimer.classList.remove('done');
    notePdfDone.classList.remove('show');
    const alreadyDone = noteMap[noteId] === 1;
    toggleMarkBtn('pdf', alreadyDone);
    if (alreadyDone) {
        noteTimer.textContent = '00:30';
        noteTimer.classList.add('done');
        notePdfDone.classList.add('show');
    }
    noteWrap.classList.add('active');
    noteWrap.scrollIntoView({behavior:'smooth', block:'start'});
    saveNoteProgress(noteId, 0);

    if (!alreadyDone) {
        noteHandle = setInterval(() => {
            noteSec++;
            noteTimer.textContent = fmtTime(noteSec);
            updateNoteBar(noteId, noteSec);
            if (noteSec === NOTE_DONE_S) {
                noteTimer.classList.add('done');
                notePdfDone.classList.add('show');
                onNoteCompleted(noteId);
            }
            if (noteSec % 5 === 0) saveNoteProgress(noteId, noteSec);
        }, 1000);
    }
}

function closeNote() {
    if (curNoteId !== null) saveNoteProgress(curNoteId, noteSec);
    stopNoteTimer();
    noteWrap.classList.remove('active');
    noteFrame.src = '';
    curNoteId = null;
}
function stopNoteTimer() { clearInterval(noteHandle); noteHandle = null; }

/* ====
   NOTE VIEWER
   ==== */
const textWrap    = document.getElementById('text-note-wrap');
const textBody    = document.getElementById('text-note-body');
const textTitleEl = document.getElementById('text-note-title');
const textTimer   = document.getElementById('text-note-timer');
const textDone    = document.getElementById('note-text-done-pill');
let textHandle=null, textSec=0, curTextNoteId=null;

function openTextNote(noteId, content, title) {
    closeNote(); stopTextTimer();
    curTextNoteId = noteId;
    textSec = 0;
    textBody.innerHTML = linkify(content);
    textTitleEl.textContent = '📝 ' + title;
    textTimer.textContent = '00:00';
    textTimer.classList.remove('done');
    textDone.classList.remove('show');
    const alreadyDone = noteMap[noteId] === 1;
    toggleMarkBtn('text', alreadyDone);
    if (alreadyDone) {
        textTimer.textContent = '00:30';
        textTimer.classList.add('done');
        textDone.classList.add('show');
    }
    textWrap.classList.add('active');
    textWrap.scrollIntoView({behavior:'smooth', block:'start'});
    saveNoteProgress(noteId, 0);

    if (!alreadyDone) {
        textHandle = setInterval(() => {
            textSec++;
            textTimer.textContent = fmtTime(textSec);
            updateNoteBar(noteId, textSec);
            if (textSec === NOTE_DONE_S) {
                textTimer.classList.add('done');
                textDone.classList.add('show');
                onNoteCompleted(noteId);
            }
            if (textSec % 5 === 0) saveNoteProgress(noteId, textSec);
        }, 1000);
    }
}

function closeTextNote() {
    if (curTextNoteId !== null) saveNoteProgress(curTextNoteId, textSec);
    stopTextTimer();
    textWrap.classList.remove('active');
    textBody.innerHTML = '';
    curTextNoteId = null;
}
function stopTextTimer() { clearInterval(textHandle); textHandle = null; }

function linkify(text) {
    const escaped = escHtml(text);
    const urlPattern = /(\bhttps?:\/\/[^\s<]+|\bwww\.[^\s<]+)/gi;
    return escaped.replace(urlPattern, (match) => {
        const href = match.startsWith('http') ? match : 'https://' + match;
        return '<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + match + '</a>';
    }).replace(/\n/g, '<br>');
}

function updateNoteBar(noteId, sec) {
    const fill = document.getElementById('nw-' + noteId);
    const lbl  = document.getElementById('ntime-' + noteId);
    const pct  = Math.min(100, Math.round((sec / NOTE_DONE_S) * 100));
    if (fill) fill.style.width = pct + '%';
    if (lbl)  lbl.textContent  = sec + 's read · ' + pct + '% complete';
}

function toggleMarkBtn(type, isDone) {
    const btn = document.getElementById(type === 'pdf' ? 'note-pdf-mark-btn' : 'note-text-mark-btn');
    if (!btn) return;
    btn.style.display = isDone ? 'none' : '';
}

function markNoteDone(type) {
    let noteId, sec;
    if (type === 'pdf') {
        if (curNoteId === null) return;
        noteId = curNoteId;
        noteSec = Math.max(noteSec, NOTE_DONE_S);
        sec = noteSec;
        stopNoteTimer();
        noteTimer.textContent = fmtTime(sec);
        noteTimer.classList.add('done');
        notePdfDone.classList.add('show');
    } else {
        if (curTextNoteId === null) return;
        noteId = curTextNoteId;
        textSec = Math.max(textSec, NOTE_DONE_S);
        sec = textSec;
        stopTextTimer();
        textTimer.textContent = fmtTime(sec);
        textTimer.classList.add('done');
        textDone.classList.add('show');
    }
    updateNoteBar(noteId, sec);
    saveNoteProgress(noteId, sec, true);
    onNoteCompleted(noteId);
    toggleMarkBtn(type, true);
}

// Track already-completed notes to avoid double-firing
const completedNotesSet = new Set(
    Object.entries(noteMap).filter(([,v]) => v === 1).map(([k]) => parseInt(k))
);

function onNoteCompleted(noteId) {
    if (completedNotesSet.has(noteId)) return;
    completedNotesSet.add(noteId);
    noteMap[noteId] = 1;

    const badge = document.getElementById('note-badge-' + noteId);
    if (badge) badge.style.display = '';

    const btn = document.getElementById('note-btn-' + noteId);
    if (btn) {
        btn.classList.add('done-btn');
        btn.innerHTML = btn.innerHTML
            .replace('Open PDF',  'Re-read PDF')
            .replace('Open Text', 'Re-read');
    }

    updateProgressUI();
}

function saveNoteProgress(noteId, seconds, forceDone) {
    let body = 'action=save_note_progress&note_id=' + noteId + '&seconds=' + seconds + '&csrf_token=' + encodeURIComponent(CSRF_TOKEN);
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

function fmtTime(s) {
    return String(Math.floor(s / 60)).padStart(2,'0') + ':' + String(s % 60).padStart(2,'0');
}

window.addEventListener('beforeunload', () => {
    if (curNoteId     !== null) saveNoteProgress(curNoteId,     noteSec);
    if (curTextNoteId !== null) saveNoteProgress(curTextNoteId, textSec);
});

/* ====
   STAR RATING
   ==== */
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

/* ====
   QUIZ MODAL
   ==== */
let countdown;
document.addEventListener('keydown', e => { if (e.key==='Escape') closeQuiz(); });

function openQuiz(id) {
    const quiz = ALL_QUIZZES.find(q => parseInt(q.id) === id);
    if (!quiz) { alert('Quiz not found.'); return; }

    /* === SERVER-AUTHORITATIVE TIMER (fixes gap #11) ===
       Ask the server to record (or resume) this attempt's start time
       and hard expiry BEFORE showing the modal. The countdown below is
       just a display of that server value — the actual enforcement
       happens again when the form is submitted (closeQuizAttempt in
       course1.php), so manipulating this client timer cannot extend
       the real deadline. */
    fetch(location.href, {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'action=start_quiz&quiz_id='+id+'&csrf_token='+encodeURIComponent(CSRF_TOKEN)
    })
    .then(r => r.json())
    .then(data => {
        if (!data.ok) { alert('Could not start quiz. Please try again.'); return; }
        renderQuiz(quiz, id, data.seconds_remaining);
    })
    .catch(() => alert('Could not reach the server to start the quiz. Check your connection.'));
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
            // Server will reject/expire this anyway, but auto-submit for a clean UX.
            document.querySelector('#quizContainer form')?.submit();
            return;
        }
        remaining--;
    };
    update();
    countdown = setInterval(update, 1000);
}

function closeQuiz() {
    clearInterval(countdown);
    document.getElementById('quizModal')?.classList.remove('active');
    document.body.style.overflow = '';
}

function escHtml(str) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(String(str ?? '')));
    return d.innerHTML;
}

/* ====
   ASSIGNMENTS (fixes gap #1)
   ==== */
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
            alert('Submission failed — check your connection and try again.');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-paper-plane"></i> Submit';
        });
    return false;
}

/* ====
   DISCUSSION (fixes gap #2)
   ==== */
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
    .catch(() => alert('Could not post — check your connection and try again.'));
}

</script>
</body>
</html>