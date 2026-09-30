<?php

if (!function_exists('stp_get_enrollment')) {
    function stp_get_enrollment(PDO $pdo, int $user_id, int $course_id): ?array {
        $stmt = $pdo->prepare(
            "SELECT * FROM enrollments WHERE user_id = ? AND course_id = ? ORDER BY id DESC LIMIT 1"
        );
        $stmt->execute([$user_id, $course_id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }
}

if (!function_exists('stp_course_access')) {
   
    function stp_course_access(PDO $pdo, int $user_id, int $course_id, ?array $course = null): array {
        if ($course === null) {
            $stmt = $pdo->prepare("SELECT * FROM courses WHERE id = ?");
            $stmt->execute([$course_id]);
            $course = $stmt->fetch() ?: null;
        }

        if (!$course) {
            return ['allowed' => false, 'reason' => 'course_not_found', 'enrollment' => null, 'course' => null];
        }

        $enrollment = stp_get_enrollment($pdo, $user_id, $course_id);

        if (!$enrollment) {
            return ['allowed' => false, 'reason' => 'not_enrolled', 'enrollment' => null, 'course' => $course];
        }

        if ($enrollment['status'] === 'rejected') {
            return ['allowed' => false, 'reason' => 'enrollment_rejected', 'enrollment' => $enrollment, 'course' => $course];
        }

        if ($enrollment['status'] === 'pending') {
            return ['allowed' => false, 'reason' => 'payment_pending', 'enrollment' => $enrollment, 'course' => $course];
        }

        if (!in_array($enrollment['status'], ['ongoing', 'completed', 'approved'], true)) {
            return ['allowed' => false, 'reason' => 'invalid_status', 'enrollment' => $enrollment, 'course' => $course];
        }

        return ['allowed' => true, 'reason' => 'ok', 'enrollment' => $enrollment, 'course' => $course];
    }
}

if (!function_exists('stp_access_denied_message')) {
    function stp_access_denied_message(string $reason): string {
        $messages = [
            'course_not_found'    => 'That course could not be found.',
            'not_enrolled'        => 'You are not enrolled in this course yet.',
            'payment_pending'     => 'Your payment is still pending verification. Access will be granted once an administrator approves it.',
            'enrollment_rejected' => 'Your enrollment for this course was not approved.',
            'invalid_status'      => 'Your access to this course is currently unavailable. Please contact support.',
        ];
        return $messages[$reason] ?? 'You do not have access to this course.';
    }
}