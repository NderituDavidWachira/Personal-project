<?php
/** Weighted live progress: videos 60%, notes 25%, quizzes 15% (only parts the course has). */
function computeCourseProgress(PDO $pdo, int $user_id, int $course_id): int
{
    $stmt = $pdo->prepare("
        SELECT cv.id, COALESCE(MAX(vp.watched_percentage), 0) AS pct
        FROM course_videos cv
        LEFT JOIN video_progress vp ON vp.content_id = cv.id AND vp.user_id = :uid
        WHERE cv.course_id = :cid GROUP BY cv.id
    ");
    $stmt->execute([':uid' => $user_id, ':cid' => $course_id]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $video_count    = count($rows);
    $video_progress = $video_count > 0 ? (int) round(array_sum(array_column($rows, 'pct')) / $video_count) : 0;

    $stmt = $pdo->prepare("
        SELECT n.id, COALESCE(MAX(np.completed), 0) AS completed
        FROM notes n
        LEFT JOIN note_progress np ON np.note_id = n.id AND np.user_id = :uid
        WHERE n.course_id = :cid GROUP BY n.id
    ");
    $stmt->execute([':uid' => $user_id, ':cid' => $course_id]);
    $noteRows      = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $note_count    = count($noteRows);
    $doneNotes     = count(array_filter($noteRows, fn($r) => (int) $r['completed'] === 1));
    $note_progress = $note_count > 0 ? (int) round(($doneNotes / $note_count) * 100) : 0;

    $stmt = $pdo->prepare("SELECT id FROM quizzes WHERE course_id = :cid");
    $stmt->execute([':cid' => $course_id]);
    $quizIds       = array_map('intval', array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id'));
    $quiz_count    = count($quizIds);
    $quiz_progress = 0;

    if ($quiz_count > 0) {
        $in   = implode(',', $quizIds);
        $stmt = $pdo->prepare("
            SELECT quiz_id, status FROM quiz_results
            WHERE user_id = :uid AND quiz_id IN ($in) ORDER BY completed_at DESC
        ");
        $stmt->execute([':uid' => $user_id]);
        $statusMap = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $qid = (int) $row['quiz_id'];
            if (!isset($statusMap[$qid])) { $statusMap[$qid] = $row['status']; }
        }
        $passed        = count(array_filter($statusMap, fn($s) => $s === 'passed'));
        $quiz_progress = (int) round(($passed / $quiz_count) * 100);
    }

    $w_video = $video_count > 0 ? 0.60 : 0;
    $w_note  = $note_count  > 0 ? 0.25 : 0;
    $w_quiz  = $quiz_count  > 0 ? 0.15 : 0;
    $w_total = $w_video + $w_note + $w_quiz;
    if ($w_total <= 0) { return 0; }

    return (int) round(($video_progress * $w_video + $note_progress * $w_note + $quiz_progress * $w_quiz) / $w_total);
}