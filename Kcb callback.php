<?php
/**
 * kcb_callback.php - receives the async STK result from KCB Buni.
 * No session here: this is a server-to-server call.
 */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/KcbBuni.php';

header('Content-Type: application/json');
$ack = fn() => print(json_encode(['ResultCode' => 0, 'ResultDesc' => 'Accepted']));

$token = (string) ($_GET['token'] ?? '');
if (KCB_CALLBACK_TOKEN === '' || !hash_equals(KCB_CALLBACK_TOKEN, $token)) {
    http_response_code(403);
    exit;
}

$raw = file_get_contents('php://input');
error_log('KCB callback: ' . $raw);
$result = KcbBuni::parseCallback(json_decode($raw, true) ?: []);
if (!$result) { $ack(); exit; }

try {
    $pdo->beginTransaction();

    $s = $pdo->prepare("SELECT * FROM payments WHERE transaction_code=:c AND payment_method='kcb_stk' FOR UPDATE");
    $s->execute([':c' => $result['checkoutRequestId']]);
    $pay = $s->fetch(PDO::FETCH_ASSOC);

    // Unknown or already processed -> just acknowledge (idempotent)
    if (!$pay || $pay['status'] !== 'pending') { $pdo->commit(); $ack(); exit; }

    if ($result['resultCode'] === 0
        && ($result['amount'] === null || abs($result['amount'] - (float) $pay['amount']) < 0.01)) {

        $pdo->prepare("UPDATE payments SET status='completed', verification_status='verified',
                       transaction_code=:r, notes=CONCAT(IFNULL(notes,''),' | Paid via KCB') WHERE id=:id")
            ->execute([':r' => $result['receipt'] ?: $result['checkoutRequestId'], ':id' => $pay['id']]);

        $e = $pdo->prepare("SELECT id FROM enrollments WHERE user_id=:u AND course_id=:c");
        $e->execute([':u' => $pay['user_id'], ':c' => $pay['course_id']]);
        if (!$e->fetch()) {
            // Use whatever status your enroll.php gives approved enrollments
            $pdo->prepare("INSERT INTO enrollments (user_id, course_id, status) VALUES (:u,:c,'active')")
                ->execute([':u' => $pay['user_id'], ':c' => $pay['course_id']]);
        }
        $pdo->prepare("INSERT INTO activities (user_id, message, created_at) VALUES (:u,:m,NOW())")
            ->execute([':u' => $pay['user_id'], ':m' => 'Payment received (' . ($result['receipt'] ?? 'KCB') . '). Enrollment activated.']);
    } else {
        $pdo->prepare("UPDATE payments SET status='failed', notes=CONCAT(IFNULL(notes,''),' | ',:d) WHERE id=:id")
            ->execute([':d' => substr($result['resultDesc'], 0, 200), ':id' => $pay['id']]);
    }

    $pdo->commit();
} catch (Throwable $e) {
    if ($pdo->inTransaction()) { $pdo->rollBack(); }
    error_log('KCB callback error: ' . $e->getMessage());
}
$ack();