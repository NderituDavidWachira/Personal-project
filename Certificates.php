<?php
/** Certificate helpers */

function strip_cert_prefix(string $title): string
{
    $t = trim(preg_replace('/^Certificate of Completion:\s*/i', '', $title));
    return $t !== '' ? $t : 'Certificate of Completion';
}

function generateCertificateNumber(PDO $pdo): string
{
    do {
        $code = 'CBT-STP-' . date('Y') . '-' . strtoupper(bin2hex(random_bytes(4)));
        $chk  = $pdo->prepare("SELECT id FROM certificates WHERE certificate_code = :code LIMIT 1");
        $chk->execute([':code' => $code]);
        $exists = (bool) $chk->fetch();
    } while ($exists);
    return $code;
}

function issueCertificateIfMissing(PDO $pdo, int $userId, int $courseId, string $courseTitle): void
{
    $certTitle = "Certificate of Completion: {$courseTitle}";
    try {
        $chk = $pdo->prepare("SELECT id FROM certificates WHERE user_id = :uid AND course_id = :cid LIMIT 1");
        $chk->execute([':uid' => $userId, ':cid' => $courseId]);
        if ($chk->fetch()) { return; }
        $hasCourseCol = true;
    } catch (Throwable $e) {                       // certificates table has no course_id column
        $chk = $pdo->prepare("SELECT id FROM certificates WHERE user_id = :uid AND title = :title LIMIT 1");
        $chk->execute([':uid' => $userId, ':title' => $certTitle]);
        if ($chk->fetch()) { return; }
        $hasCourseCol = false;
    }

    $code = generateCertificateNumber($pdo);
    try {
        if ($hasCourseCol) {
            $pdo->prepare("INSERT INTO certificates (user_id, course_id, title, certificate_code, issued_at, qr_code_path)
                           VALUES (:uid, :cid, :title, :code, NOW(), NULL)")
                ->execute([':uid' => $userId, ':cid' => $courseId, ':title' => $certTitle, ':code' => $code]);
        } else {
            $pdo->prepare("INSERT INTO certificates (user_id, title, certificate_code, issued_at, qr_code_path)
                           VALUES (:uid, :title, :code, NOW(), NULL)")
                ->execute([':uid' => $userId, ':title' => $certTitle, ':code' => $code]);
        }
    } catch (Throwable $e) {
        error_log('Certificate insert failed: ' . $e->getMessage());
        return;
    }

    try {
        $pdo->prepare("INSERT INTO activities (user_id, message, created_at) VALUES (:uid, :msg, NOW())")
            ->execute([':uid' => $userId, ':msg' => "Certificate issued for: {$courseTitle} (No. {$code})"]);
    } catch (Throwable $e) { /* non-critical */ }
}

function fetchAllStudentCertificates(PDO $pdo, int $user_id): array
{
    $stmt = $pdo->prepare("
        SELECT c.id, c.certificate_code, c.title, c.issued_at, c.qr_code_path, 'certificates' AS source
        FROM certificates c WHERE c.user_id = :uid1
        UNION ALL
        SELECT sc.id, sc.cert_number, CONCAT('Certificate of Completion: ', co.title),
               sc.issued_at, NULL, 'stp_certificates'
        FROM stp_certificates sc JOIN courses co ON co.id = sc.course_id
        WHERE sc.user_id = :uid2 AND sc.status = 'active'
        ORDER BY issued_at DESC
    ");
    $stmt->execute([':uid1' => $user_id, ':uid2' => $user_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/** Public verification lookup (by certificate number only). */
function find_certificate_by_code(PDO $pdo, string $code): ?array
{
    $stmt = $pdo->prepare("
        SELECT c.certificate_code, c.title, c.issued_at, u.full_name
        FROM certificates c LEFT JOIN users u ON u.id = c.user_id
        WHERE c.certificate_code = :code LIMIT 1
    ");
    $stmt->execute([':code' => $code]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) { return $row; }

    $stmt = $pdo->prepare("
        SELECT sc.cert_number AS certificate_code, CONCAT('Certificate of Completion: ', co.title) AS title,
               sc.issued_at, u.full_name
        FROM stp_certificates sc JOIN courses co ON co.id = sc.course_id
        LEFT JOIN users u ON u.id = sc.user_id
        WHERE sc.cert_number = :code AND sc.status = 'active' LIMIT 1
    ");
    $stmt->execute([':code' => $code]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

/** Full certificate for its OWNER only (by code or id). */
function find_owned_certificate(PDO $pdo, int $userId, string $code, int $id): ?array
{
    $where = $code !== '' ? 'c.certificate_code = :k' : 'c.id = :k';
    $stmt = $pdo->prepare("
        SELECT c.*, u.full_name, 'certificates' AS source
        FROM certificates c LEFT JOIN users u ON u.id = c.user_id
        WHERE $where AND c.user_id = :uid LIMIT 1
    ");
    $stmt->execute([':k' => $code !== '' ? $code : $id, ':uid' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) { return $row; }

    $where = $code !== '' ? 'sc.cert_number = :k' : 'sc.id = :k';
    $stmt = $pdo->prepare("
        SELECT sc.id, sc.user_id, sc.course_id, sc.cert_number AS certificate_code,
               CONCAT('Certificate of Completion: ', co.title) AS title,
               sc.issued_at, sc.qr_code_path, u.full_name, 'stp_certificates' AS source
        FROM stp_certificates sc JOIN courses co ON co.id = sc.course_id
        LEFT JOIN users u ON u.id = sc.user_id
        WHERE $where AND sc.user_id = :uid AND sc.status = 'active' LIMIT 1
    ");
    $stmt->execute([':k' => $code !== '' ? $code : $id, ':uid' => $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}