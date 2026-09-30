<?php
date_default_timezone_set("Africa/Nairobi");

/* ====
   SECURE SESSION SETTINGS
==== */
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']),
    'samesite' => 'Strict'
]);

session_start();
include "db.php";

/* ====
   SECURITY HEADERS
==== */
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: camera=(), microphone=()");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline';");

/* ====
   CSRF TOKEN
==== */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ====
   VALIDATE EMAIL
==== */
$email = filter_input(INPUT_GET, 'email', FILTER_VALIDATE_EMAIL);

if (!$email) {
    die("Invalid request.");
}

$msg = "";
$success = false;

/* ====
   VERIFY OTP
==== */
if (isset($_POST['verify'])) {

    /* CSRF CHECK */
    if (
        !isset($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        die("Invalid request.");
    }
    $otp = trim($_POST['otp'] ?? '');
    $otp = preg_replace('/\s+/', '', $otp);

    if (!preg_match('/^[0-9]{6}$/', $otp)) {
        $msg = "OTP must be 6 digits only.";
    } else {

        /* ====
           GET PENDING ACCOUNT
        ==== */
        $stmt = $pdo->prepare("
            SELECT *
            FROM pending_students
            WHERE email = ?
            LIMIT 1
        ");
        $stmt->execute([$email]);
        $row = $stmt->fetch();

        if (!$row) {
            $msg = "Verification failed.";
        } else {

            /* ====
               CHECK LOCK STATUS
            ==== */
            if (
                !empty($row['otp_locked_until']) &&
                strtotime($row['otp_locked_until']) > time()
            ) {
                $msg = "Too many attempts. Try again later.";
            }

            elseif ($row['otp_verified'] == 1) {
                $msg = "Account already verified.";
            }

            elseif (strtotime($row['otp_expires']) < time()) {
                $msg = "OTP expired.";
            }

            else {

                $otpValid = false;

                if (!empty($row['otp_hash'])) {
                    $otpValid = password_verify($otp, $row['otp_hash']);
                } elseif (!empty($row['otp'])) {
                    // Legacy fallback for rows created before otp_hash existed.
                    $otpValid = hash_equals((string)$row['otp'], $otp);
                }

                if (!$otpValid) {

                    /* INCREMENT ATTEMPTS */
                    $attempts = (int)($row['otp_attempts'] ?? 0) + 1;

                    $lockUntil = null;
                    if ($attempts >= 5) {
                        $lockUntil = date("Y-m-d H:i:s", strtotime("+15 minutes"));
                    }

                    try {
                        $update = $pdo->prepare("
                            UPDATE pending_students
                            SET otp_attempts = ?,
                                otp_locked_until = ?
                            WHERE email = ?
                        ");
                        $update->execute([$attempts, $lockUntil, $email]);
                    } catch (PDOException $e) {
                        error_log("OTP attempt-tracking update failed: " . $e->getMessage());
                    }

                    $msg = "Invalid OTP.";
                }
                else {
                    $pdo->beginTransaction();
                    try {

                        /* CHECK IF USER EXISTS */
                        $check = $pdo->prepare("
                            SELECT id FROM users WHERE email = ? LIMIT 1
                        ");
                        $check->execute([$email]);

                        if ($check->fetch()) {
                            throw new Exception("Account already exists.");
                        }

                        /* ====
                           FIX (admin-approval gate): new student accounts
                           must NOT go straight to 'active'. They land in
                           'pending' here and only become usable once an
                           administrator approves them from the "New
                           Registrations Awaiting Approval" queue on
                           Admin.php. student.php independently re-checks
                           status='active' on every page load, so a
                           'pending' account is blocked from the dashboard
                           even if a session were somehow created for it.
                           Any other role inserted via this table (should
                           not normally happen - pending_students is the
                           student registration flow) is left 'active' so
                           this fix never silently locks out a non-student
                           account type that might reuse this table.
                        ==== */
                        $initialStatus = ($row['role'] === 'student') ? 'pending' : 'active';

                        /* ====
                           INSERT USER
                        ==== */
                        $insert = $pdo->prepare("
                            INSERT INTO users
                            (full_name, email, phone, national_id, kra_pin, password, role, is_verified, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                        ");

                        $insert->execute([
                            $row['full_name'],
                            $row['email'],
                            $row['phone'],
                            $row['national_id'] ?? null,
                            $row['kra_pin'] ?? null,
                            $row['password'],
                            $row['role'],
                            $initialStatus,
                        ]);

                        $newUserId = (int)$pdo->lastInsertId();

                        /* ====
                           INSERT STUDENT PROFILE
                        ==== */
                        if ($row['role'] === 'student') {

                            if (empty($row['student_no'])) {
                                throw new Exception("Missing student number for pending record id " . $row['id']);
                            }
                            $dupCheck = $pdo->prepare("
                                SELECT id FROM students WHERE student_no = ? OR user_id = ? LIMIT 1
                            ");
                            $dupCheck->execute([$row['student_no'], $newUserId]);

                            if ($dupCheck->fetch()) {
                                throw new Exception("Student profile already exists for student_no " . $row['student_no']);
                            }

                            $isProfessional = !empty($row['is_professional']);
                            $licenseNumber  = $isProfessional ? ($row['professional_reg_no'] ?? null) : null;
                            $verifStatus    = $isProfessional ? 'pending' : 'unverified';

                            $insertStudent = $pdo->prepare("
                                INSERT INTO students
                                (student_no, user_id, full_name, email, phone,
                                 license_number, qualification_level, verification_status, is_verified)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                            ");
                            $insertStudent->execute([
                                $row['student_no'],
                                $newUserId,
                                $row['full_name'],
                                $row['email'],
                                $row['phone'],
                                $licenseNumber,
                                $row['qualification_level'] ?? null,
                                $verifStatus,
                            ]);
                        }

                        /* ====
                           PENDING RECORD
                        ==== */
                        $clean = $pdo->prepare("
                            UPDATE pending_students
                            SET otp_verified = 1,
                                otp = NULL,
                                otp_hash = NULL,
                                otp_expires = NULL,
                                otp_attempts = 0,
                                otp_locked_until = NULL
                            WHERE id = ?
                        ");
                        $clean->execute([$row['id']]);

                        $pdo->commit();

                        /* ====
                           FIX (admin-approval gate): do NOT auto-login the
                           student anymore. Their account is 'pending' until
                           an admin approves it, and student.php would just
                           immediately destroy this session and bounce them
                           straight back out again - so creating it here
                           only produces a confusing dead-end redirect.
                           Instead, send them to the login page with a
                           clear "awaiting approval" message; index.php's
                           own status check already explains this if they
                           try to sign in early.
                        ==== */
                        $success = true;
                        $awaitingApproval = ($initialStatus === 'pending');

                        header("refresh:5;url=index.php");

                    } catch (Exception $e) {
                        $pdo->rollBack();
                        error_log("Student verification failed: " . $e->getMessage());
                        $msg = "Verification failed.";
                    }
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>OTP Verification</title>

<style>
body{
    margin:0;
    font-family:Arial;
    height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    background:#0f172a;
}

.box{
    width:350px;
    background:#fff;
    padding:25px;
    border-radius:10px;
    text-align:center;
}

input{
    width:100%;
    padding:12px;
    margin-top:10px;
}

button{
    width:100%;
    padding:12px;
    margin-top:10px;
    background:green;
    color:#fff;
    border:none;
    cursor:pointer;
}

.error{color:red;}
.success{color:green;}
.notice{color:#92400e;background:#fef3c7;padding:10px;border-radius:6px;font-size:13px;margin-top:10px;}
</style>
</head>

<body>

<div class="box">

<h2>OTP Verification</h2>

<?php if($success): ?>

<p class="success">
 Email verified successfully.
</p>

<?php if (!empty($awaitingApproval)): ?>
<p class="notice">
 Your registration has been submitted for admin approval. You'll be able
 to sign in once an administrator has reviewed and approved your account.
 Redirecting to the sign-in page...
</p>
<?php else: ?>
<p class="success">Redirecting to sign in...</p>
<?php endif; ?>

<?php else: ?>

<?php if(!empty($msg)): ?>
<p class="error"><?= htmlspecialchars($msg) ?></p>
<?php endif; ?>

<form method="POST">

<input type="hidden" name="csrf_token"
value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

<input type="text" name="otp"
maxlength="6"
placeholder="Enter 6-digit OTP"
required>

<button type="submit" name="verify">
Verify
</button>

</form>

<?php endif; ?>

</div>

</body>
</html>