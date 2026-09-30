<?php
include "db.php";

$raw = file_get_contents("php://input");
error_log("MPESA CALLBACK RAW: " . $raw);
file_put_contents(
    __DIR__ . "/callback.log",
    date('Y-m-d H:i:s') . "\n" . $raw . "\n\n",
    FILE_APPEND
);

/* ===
   CALLBACK SECRET
=== */
$callbackSecret = "REPLACE_WITH_A_LONG_RANDOM_SECRET"; 

$providedToken = $_GET['token'] ?? '';
if (!hash_equals($callbackSecret, $providedToken)) {
    error_log("MPESA CALLBACK: rejected — bad or missing token");
    http_response_code(403);
    echo json_encode(["ResultCode" => 1, "ResultDesc" => "Forbidden"]);
    exit;
}

$data = json_decode($raw, true);
$callback = $data['Body']['stkCallback'] ?? null;

if (!$callback) {
    http_response_code(400);
    echo json_encode(["ResultCode" => 1, "ResultDesc" => "Invalid payload"]);
    exit;
}

$checkoutRequestId = $callback['CheckoutRequestID'] ?? null;
$resultDesc        = $callback['ResultDesc'] ?? '';

$resultCodePresent = array_key_exists('ResultCode', $callback);
$resultCode         = $callback['ResultCode'] ?? null;
$isSuccess          = $resultCodePresent && (int)$resultCode === 0;

if (!$checkoutRequestId) {
    http_response_code(400);
    echo json_encode(["ResultCode" => 1, "ResultDesc" => "Missing CheckoutRequestID"]);
    exit;
}
$stmt = $pdo->prepare("
    UPDATE payments
    SET status = 'processing'
    WHERE checkout_request_id = ? AND status = 'pending'
");
$stmt->execute([$checkoutRequestId]);

if ($stmt->rowCount() === 0) {
    $stmt = $pdo->prepare("
        SELECT id FROM payments WHERE checkout_request_id = ? LIMIT 1
    ");
    $stmt->execute([$checkoutRequestId]);
    if (!$stmt->fetch()) {
        error_log("MPESA CALLBACK: no matching payment for " . $checkoutRequestId);
    } else {
        error_log("MPESA CALLBACK: payment already processed/in progress for " . $checkoutRequestId);
    }
    http_response_code(200); 
    echo json_encode(["ResultCode" => 0, "ResultDesc" => "Accepted"]);
    exit;
}

/* Now that we own this row, fetch its details. */
$stmt = $pdo->prepare("
    SELECT id, user_id, course_id
    FROM payments
    WHERE checkout_request_id = ?
    LIMIT 1
");
$stmt->execute([$checkoutRequestId]);
$payment = $stmt->fetch();

if (!$payment) {
    http_response_code(200);
    echo json_encode(["ResultCode" => 0, "ResultDesc" => "Accepted"]);
    exit;
}

/* ===
   PAYMENT FAILED
=== */
if (!$isSuccess) {
    try {
        $stmt = $pdo->prepare("
            UPDATE payments
            SET status = 'failed', result_desc = ?
            WHERE id = ?
        ");
        $stmt->execute([$resultDesc ?: 'No result code received', $payment['id']]);
    } catch (PDOException $e) {
        error_log("MPESA CALLBACK failed-status update error: " . $e->getMessage());
    }
    http_response_code(200);
    echo json_encode(["ResultCode" => 0, "ResultDesc" => "Accepted"]);
    exit;
}

/* ===
   PAYMENT SUCCEEDED 
=== */
$mpesaReceipt   = null;
$mpesaAmount    = null;
$mpesaPhone     = null;
$transactionRaw = null;

$items = $callback['CallbackMetadata']['Item'] ?? [];
foreach ($items as $item) {
    $name  = $item['Name']  ?? '';
    $value = $item['Value'] ?? null;

    switch ($name) {
        case 'MpesaReceiptNumber':
            $mpesaReceipt = $value;
            break;
        case 'Amount':
            $mpesaAmount = $value;
            break;
        case 'PhoneNumber':
            $mpesaPhone = $value;
            break;
        case 'TransactionDate':
            $transactionRaw = $value;
            break;
    }
}

$transactionDate = null;
if ($transactionRaw) {
    $parsed = DateTime::createFromFormat('YmdHis', (string)$transactionRaw);
    if ($parsed) {
        $transactionDate = $parsed->format('Y-m-d H:i:s');
    }
}

$user_id   = (int)$payment['user_id'];
$course_id = (int)$payment['course_id'];

$pdo->beginTransaction();
try {
    $stmt = $pdo->prepare("
        UPDATE payments
        SET status = 'completed',
            mpesa_receipt = ?,
            mpesa_amount = ?,
            mpesa_phone = ?,
            result_desc = ?,
            payment_date = COALESCE(?, NOW())
        WHERE id = ?
    ");
    $stmt->execute([
        $mpesaReceipt,
        $mpesaAmount,
        $mpesaPhone,
        $resultDesc,
        $transactionDate,
        $payment['id'],
    ]);
    $check = $pdo->prepare("
        SELECT id FROM enrollments
        WHERE user_id = ? AND course_id = ?
        LIMIT 1
    ");
    $check->execute([$user_id, $course_id]);

    if (!$check->fetch()) {
        $stmt = $pdo->prepare("
            INSERT INTO enrollments
            (user_id, course_id, progress, status, enrolled_at)
            VALUES (?, ?, 0, 'ongoing', NOW())
        ");
        $stmt->execute([$user_id, $course_id]);
        $stmt = $pdo->prepare("
            UPDATE courses
            SET enrolled_students = COALESCE(enrolled_students, 0) + 1
            WHERE id = ?
        ");
        $stmt->execute([$course_id]);
    }

    $pdo->commit();
} catch (Exception $e) {
    $pdo->rollBack();
    error_log("MPESA CALLBACK enrollment error: " . $e->getMessage());

    try {
        $stmt = $pdo->prepare("UPDATE payments SET status = 'processing', result_desc = ? WHERE id = ?");
        $stmt->execute(['Enrollment failed, needs manual review: ' . $e->getMessage(), $payment['id']]);
    } catch (PDOException $e2) {
        error_log("MPESA CALLBACK: failed to flag row for manual review: " . $e2->getMessage());
    }
    http_response_code(500);
    echo json_encode(["ResultCode" => 1, "ResultDesc" => "Server error"]);
    exit;
}
http_response_code(200);
echo json_encode(["ResultCode" => 0, "ResultDesc" => "Accepted"]);