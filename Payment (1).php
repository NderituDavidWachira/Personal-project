<?php
/**
 * payment.php - all student payment logic (STK push, bank, paybill).
 * Usage in student.php / enroll.php:
 *     require_once __DIR__ . '/payment.php';
 *     payments_handle_post($pdo, $user_id);   // after session + CSRF token exist
 */
require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Helpers.php';
require_once __DIR__ . '/Kcbbuni.php';

/** Paid + active course the student isn't already enrolled in, or null. */
function payments_find_payable_course(PDO $pdo, int $userId, int $courseId): ?array
{
    $s = $pdo->prepare("
        SELECT id, title, price FROM courses
        WHERE id = :cid AND course_type = 'Paid' AND status = 'Active'
          AND id NOT IN (SELECT course_id FROM enrollments WHERE user_id = :uid)
        LIMIT 1
    ");
    $s->execute([':cid' => $courseId, ':uid' => $userId]);
    return $s->fetch(PDO::FETCH_ASSOC) ?: null;
}

function payments_log_activity(PDO $pdo, int $userId, string $msg): void
{
    try {
        $pdo->prepare("INSERT INTO activities (user_id, message, created_at) VALUES (:u, :m, NOW())")
            ->execute([':u' => $userId, ':m' => $msg]);
    } catch (Throwable $e) { /* non-critical */ }
}

/** Starts an STK push. Returns [bool success, string message]. Usable from enroll.php too. */
function payments_start_stk(PDO $pdo, int $userId, int $courseId, string $phone): array
{
    $course = payments_find_payable_course($pdo, $userId, $courseId);
    if (!$course) {
        return [false, 'That course is not available for payment.'];
    }
    $msisdn = KcbBuni::normalizePhone($phone);
    if (!$msisdn) {
        return [false, 'Enter a valid Safaricom number, e.g. 0712345678.'];
    }

    // Stop double-taps from firing multiple prompts
    $recent = $pdo->prepare("
        SELECT id FROM payments
        WHERE user_id=:u AND course_id=:c AND payment_method='kcb_stk' AND status='pending'
          AND created_at > (NOW() - INTERVAL 2 MINUTE) LIMIT 1
    ");
    $recent->execute([':u' => $userId, ':c' => $courseId]);
    if ($recent->fetch()) {
        return [false, 'A payment prompt was just sent. Please complete it on your phone or wait 2 minutes.'];
    }

    $ref = 'CRS' . $courseId . 'U' . $userId . 'T' . time();
    $res = KcbBuni::stkPush($msisdn, (float) $course['price'], $ref, $course['title']);
    if (!$res['ok']) {
        error_log('KCB STK failed: ' . $res['message'] . ' | ' . $res['raw']);
        return [false, 'STK push failed: ' . $res['message']];
    }

    $name = $pdo->prepare("SELECT full_name FROM users WHERE id=:id");
    $name->execute([':id' => $userId]);

    // CheckoutRequestID is stored as transaction_code so the callback can find this row;
    // it is replaced by the M-Pesa receipt number once the payment succeeds.
    $pdo->prepare("
        INSERT INTO payments
            (user_id, course_id, payer_name, payer_phone, amount, payment_method,
             transaction_code, status, verification_status, notes, payment_date, created_at)
        VALUES (:uid, :cid, :name, :ph, :amt, 'kcb_stk', :code, 'pending', 'pending', :notes, CURDATE(), NOW())
    ")->execute([
        ':uid' => $userId, ':cid' => $courseId,
        ':name' => $name->fetchColumn() ?: 'Student',
        ':ph' => $msisdn, ':amt' => $course['price'],
        ':code' => $res['checkoutRequestId'],
        ':notes' => 'KCB STK requested. Ref: ' . $ref,
    ]);

    return [true, 'STK push sent to ' . $msisdn . '. Enter your M-Pesa PIN on your phone; your enrollment activates automatically once payment is confirmed.'];
}

/** Shared validation for bank + paybill manual submissions. */
function payments_read_manual_form(): array
{
    $g = fn(string $k, int $max) => mb_substr(trim(strip_tags($_POST[$k] ?? '')), 0, $max);
    return [
        'course_id' => (int) ($_POST['course_id'] ?? 0),
        'amount'    => (float) ($_POST['amount'] ?? 0),
        'name'      => $g('payer_name', 150),
        'phone'     => $g('payer_phone', 30),
        'email'     => $g('payer_email', 150),
        'code'      => $g('transaction_code', 100),
        'date'      => trim($_POST['payment_date'] ?? ''),
        'notes'     => $g('notes', 2000),
    ];
}

function payments_submit_manual(PDO $pdo, int $userId, string $method, ?string $proofFile): array
{
    $label = $method === 'paybill' ? 'Paybill' : 'bank';
    $f = payments_read_manual_form();

    if ($f['course_id'] <= 0 || $f['amount'] <= 0 || $f['code'] === '' || $f['name'] === ''
        || $f['phone'] === '' || !DateTime::createFromFormat('Y-m-d', $f['date'])) {
        return [false, "Please fill in all required $label payment details correctly."];
    }
    if ($f['email'] !== '' && !filter_var($f['email'], FILTER_VALIDATE_EMAIL)) {
        return [false, 'Please enter a valid payer email, or leave it blank.'];
    }
    if (!payments_find_payable_course($pdo, $userId, $f['course_id'])) {
        return [false, 'That course is not available for payment.'];
    }

    // Transaction codes must be unique across ALL users, not just this one
    $dup = $pdo->prepare("SELECT id FROM payments WHERE transaction_code = :c LIMIT 1");
    $dup->execute([':c' => $f['code']]);
    if ($dup->fetch()) {
        return [false, 'This transaction code has already been submitted.'];
    }

    $params = [
        ':uid' => $userId, ':cid' => $f['course_id'], ':pn' => $f['name'], ':pp' => $f['phone'],
        ':pe' => $f['email'] !== '' ? $f['email'] : null, ':amt' => $f['amount'], ':method' => $method,
        ':code' => $f['code'], ':notes' => $f['notes'] !== '' ? $f['notes'] : null, ':pdate' => $f['date'],
    ];

    try {
        try {
            $pdo->prepare("
                INSERT INTO payments (user_id, course_id, payer_name, payer_phone, payer_email, amount, payment_method,
                    transaction_code, status, verification_status, notes, proof_path, payment_date, created_at)
                VALUES (:uid,:cid,:pn,:pp,:pe,:amt,:method,:code,'pending','pending',:notes,:proof,:pdate,NOW())
            ")->execute($params + [':proof' => $proofFile]);
        } catch (Throwable $noProofCol) {
            $params[':notes'] = trim(($f['notes'] !== '' ? $f['notes'] . ' | ' : '') . ($proofFile ? 'Proof file: ' . $proofFile : ''));
            $pdo->prepare("
                INSERT INTO payments (user_id, course_id, payer_name, payer_phone, payer_email, amount, payment_method,
                    transaction_code, status, verification_status, notes, payment_date, created_at)
                VALUES (:uid,:cid,:pn,:pp,:pe,:amt,:method,:code,'pending','pending',:notes,:pdate,NOW())
            ")->execute($params);
        }
    } catch (Throwable $e) {
        error_log('Manual payment insert failed: ' . $e->getMessage());
        return [false, 'Something went wrong submitting your payment. Please try again or contact support.'];
    }

    payments_log_activity($pdo, $userId, "Submitted $label payment (Code: {$f['code']}) for verification");
    return [true, ucfirst($label) . ' payment submitted. An admin will verify it and approve your enrollment shortly.'];
}

/** Router: call once from student.php. Redirects and exits when it handled a payment POST. */
function payments_handle_post(PDO $pdo, int $userId): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { return; }

    if (isset($_POST['trigger_kcb_stk'])) {
        validateCsrf();
        [$ok, $msg] = payments_start_stk($pdo, $userId, (int) ($_POST['course_id'] ?? 0), trim($_POST['phone_number'] ?? ''));
        flash_redirect($msg, 'payments');
    }

    if (isset($_POST['submit_bank_payment'])) {
        validateCsrf();
        [$ok, $msg] = payments_submit_manual($pdo, $userId, 'bank_transfer', null);
        flash_redirect($msg, 'payments');
    }

    if (isset($_POST['submit_paybill_payment'])) {
        validateCsrf();
        $up = secureFileUpload('proof_file', $userId, 'paybillproof', DOC_MIMES);
        if (!$up['ok'])            { flash_redirect($up['error'], 'payments'); }
        if (empty($up['filename'])) { flash_redirect('Please attach a screenshot or PDF of your M-Pesa confirmation as proof of payment.', 'payments'); }
        [$ok, $msg] = payments_submit_manual($pdo, $userId, 'paybill', $up['filename']);
        flash_redirect($msg, 'payments');
    }
}