<?php
/**
 * secure_video.php
 * ---------------------------------------------------------------------
 * Streams a course video ONLY to a logged-in, enrolled, payment-approved
 * student — replacing the old approach of exposing the raw
 * uploads/videos/<file>.mp4 URL directly in the page markup.
 *
 * Usage from course1.php:
 *   <video src="secure_video.php?id=123">
 *
 * Supports HTTP Range requests so the browser's seek bar / scrubbing
 * keeps working (without Range support, some browsers can't seek or
 * will re-download the whole file on every seek).
 *
 * IMPORTANT FOLLOW-UP (not done in this file, needs host-level config):
 * For real protection, uploads/videos/ should either be:
 *   (a) moved outside the public webroot entirely, or
 *   (b) blocked from direct HTTP access via a .htaccess "Deny from all"
 *       in that folder (works on InfinityFree/Apache).
 * Otherwise a student could still find the direct file URL some other
 * way (e.g. via server logs) and bypass this endpoint. This file makes
 * the *normal* access path secure; the direct-URL leak path should be
 * closed at the web-server level too.
 */

session_start();
include "db.php";
include "access_control.php";

/* === AUTH === */
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit('Not authenticated.');
}
$user_id = (int) $_SESSION['user_id'];

/* === VIDEO LOOKUP === */
$video_id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
if (!$video_id) {
    http_response_code(400);
    exit('Missing video id.');
}

$stmt = $pdo->prepare("SELECT * FROM course_videos WHERE id = ?");
$stmt->execute([$video_id]);
$video = $stmt->fetch();
if (!$video) {
    http_response_code(404);
    exit('Video not found.');
}

$course_id = (int) $video['course_id'];

/* === ACCESS CONTROL (enrolled + payment-approved) === */
$access = stp_course_access($pdo, $user_id, $course_id);
if (!$access['allowed']) {
    http_response_code(403);
    exit(stp_access_denied_message($access['reason']));
}

/* === RESOLVE FILE PATH SAFELY (no path traversal via a crafted row) === */
$relative_path = $video['video_path'] ?: $video['local_path'];
if (!$relative_path) {
    http_response_code(404);
    exit('Video file not set for this lesson.');
}

$videos_dir = realpath(__DIR__ . '/uploads/videos');
$candidate  = $videos_dir ? realpath($videos_dir . '/' . basename($relative_path)) : false;

if (!$videos_dir || !$candidate || strpos($candidate, $videos_dir) !== 0 || !file_exists($candidate)) {
    http_response_code(404);
    exit('Video file not found on server.');
}

/* === STREAM WITH RANGE SUPPORT === */
$size   = filesize($candidate);
$mime   = $video['mime_type'] ?: 'video/mp4';
$start  = 0;
$end    = $size - 1;
$length = $size;

header('Content-Type: ' . $mime);
header('Accept-Ranges: bytes');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Content-Disposition: inline; filename="' . basename($candidate) . '"');

if (isset($_SERVER['HTTP_RANGE'])) {
    if (preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
        $start = $m[1] !== '' ? (int)$m[1] : 0;
        $end   = $m[2] !== '' ? (int)$m[2] : $size - 1;
        $end   = min($end, $size - 1);

        if ($start > $end || $start >= $size) {
            http_response_code(416);
            header("Content-Range: bytes */$size");
            exit;
        }

        $length = $end - $start + 1;
        http_response_code(206);
        header("Content-Range: bytes $start-$end/$size");
    }
}

header('Content-Length: ' . $length);

$fp = fopen($candidate, 'rb');
if (!$fp) {
    http_response_code(500);
    exit('Could not open video file.');
}
fseek($fp, $start);

$buffer_size      = 8192;
$bytes_remaining  = $length;

while (!feof($fp) && $bytes_remaining > 0 && connection_status() === CONNECTION_NORMAL) {
    $read_size = ($bytes_remaining < $buffer_size) ? $bytes_remaining : $buffer_size;
    echo fread($fp, $read_size);
    flush();
    $bytes_remaining -= $read_size;
}

fclose($fp);
exit;