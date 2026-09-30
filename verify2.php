<?php
include "db.php"; 
date_default_timezone_set("Africa/Nairobi");

/* =
   SESSION SECURITY
= */
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
ini_set('session.use_strict_mode', 1);

session_start();

/* =
   CSRF SETUP
= */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function validateCsrf()
{
    if (
        !isset($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        die("Invalid CSRF token.");
    }
}

/* =
   INPUT EMAIL
= */
$email = trim($_GET['email'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Invalid request.");
}

$msg = "";
$success = false;

/* =
   OTP ATTEMPT LIMIT
= */
if (!isset($_SESSION['otp_attempts'])) {
    $_SESSION['otp_attempts'] = 0;
}

/* =
   VERIFY OTP
= */
if (isset($_POST['verify'])) {

    validateCsrf();

    if ($_SESSION['otp_attempts'] >= 5) {
        die("Too many failed attempts. Try again later.");
    }

    $otp = trim($_POST['otp'] ?? '');

    if (!preg_match('/^[0-9]{6}$/', $otp)) {
        $msg = "Invalid OTP format.";

    } else {

        try {

            /* =
               CHECK OTP
            = */
            $stmt = $pdo->prepare("
                SELECT *
                FROM pending_teachers
                WHERE email = :email
                AND otp = :otp
                AND otp_verified = 0
                AND otp_expires > NOW()
                LIMIT 1
            ");

            $stmt->execute([
                ':email' => $email,
                ':otp'   => $otp,
            ]);

            $row = $stmt->fetch();

            if ($row) {

                $pdo->beginTransaction();

                /* =
                   CHECK USER EXISTS
                = */
                $check = $pdo->prepare("
                    SELECT id FROM users WHERE email = :email LIMIT 1
                ");
                $check->execute([':email' => $row['email']]);

                if ($check->fetch()) {
                    throw new Exception("Account already exists.");
                }

                /* =
                   CREATE USER (FIXED ROLE)
                   FIX: removed `is_verified` - that column does not exist
                   on the `users` table anywhere in this schema (see
                   admin.php's ensureSchema()/ensureGovernanceSchema()/
                   ensureAdvancedSchema() and every other query against
                   `users`). Inserting it threw a PDOException
                   ("Unknown column 'is_verified'") that was silently
                   caught and shown to the admin as "An unexpected error
                   occurred." with no indication of the real cause.
                   Also now carrying over phone/license_no/kra_pin from
                   the pending_teachers row so that data isn't lost on
                   activation (previously it was captured at signup but
                   dropped here).
                = */
                $role = "teacher";

                $user = $pdo->prepare("
                    INSERT INTO users
                    (full_name, email, password, role, status, phone, license_no, kra_pin)
                    VALUES (:full_name, :email, :password, :role, 'active', :phone, :license_no, :kra_pin)
                ");

                $user->execute([
                    ':full_name'  => $row['full_name'],
                    ':email'      => $row['email'],
                    ':password'   => $row['password'],
                    ':role'       => $role,
                    ':phone'      => $row['phone'] ?? null,
                    ':license_no' => $row['license_no'] ?? null,
                    ':kra_pin'    => $row['kra_pin'] ?? null,
                ]);

                $user_id = $pdo->lastInsertId();

                /* =
                   CREATE TEACHER PROFILE
                   FIX: also carry over license_no now that it's collected
                   at signup (previously dropped here too).
                = */
                $teacher = $pdo->prepare("
                    INSERT INTO teachers
                    (user_id, employee_no, license_number, specialization, qualification, experience_years)
                    VALUES (:user_id, :employee_no, :license_number, :specialization, :qualification, :experience_years)
                ");

                /* =
                   FIX: teachers.employee_no has a UNIQUE constraint
                   (uq_teachers_employee_no). A unique key allows many
                   NULLs but only ONE occurrence of any real value -
                   including an empty string. Trainers who leave
                   "Employee Number" blank at signup get '' stored in
                   pending_teachers.employee_no, so the second (and every
                   subsequent) blank-employee-no trainer collided with
                   the first one on activation:
                     SQLSTATE[23000]: Duplicate entry '' for key
                     'uq_teachers_employee_no'
                   Coalescing blank/whitespace-only values to NULL here
                   lets the unique constraint do its job (no two REAL
                   employee numbers collide) without blocking multiple
                   trainers who simply don't have one yet.
                = */
                $employeeNo = trim((string)($row['employee_no'] ?? ''));

                $teacher->execute([
                    ':user_id'          => $user_id,
                    ':employee_no'      => $employeeNo !== '' ? $employeeNo : null,
                    ':license_number'   => $row['license_no'] ?? null,
                    ':specialization'   => $row['specialization'],
                    ':qualification'    => $row['qualification'],
                    ':experience_years' => $row['experience_years'],
                ]);

                /* =
                   UPDATE OTP STATUS (FIXED)
                = */
                $update = $pdo->prepare("
                    UPDATE pending_teachers
                    SET otp_verified = 1,
                        status = 'active'
                    WHERE id = :id
                ");

                $update->execute([':id' => $row['id']]);

                $pdo->commit();

                session_regenerate_id(true);
                $_SESSION['otp_attempts'] = 0;

                $success = true;

                header("refresh:3;url=index.php");
               
            } else {
                $_SESSION['otp_attempts']++;
                $msg = "Invalid or expired OTP";
            }

        } catch (PDOException $e) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log($e->getMessage());

            $msg = "An unexpected error occurred. Please try again.";

        } catch (Exception $e) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log($e->getMessage());

            $msg = "An unexpected error occurred. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
<title>Verify Email</title>

<style>
body{
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
    font-family:Arial;
    background:#f4f4f4;
}

.box{
    background:#fff;
    padding:30px;
    width:350px;
    border-radius:10px;
    text-align:center;
}

input,button{
    width:100%;
    padding:12px;
    margin-top:10px;
}

button{
    background:green;
    color:#fff;
    border:none;
}

.error{ color:red; }
.success{ color:green; }
</style>
</head>

<body>

<div class="box">

<h2>Verify OTP</h2>

<?php if ($success): ?>

    <p class="success"> Account activated successfully</p>
    <p>Redirecting to login...</p>

<?php else: ?>

    <?php if ($msg): ?>
        <p class="error"><?= htmlspecialchars($msg) ?></p>
    <?php endif; ?>

    <form method="POST">

        <input type="hidden" name="csrf_token"
               value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

        <input type="text" name="otp"
               placeholder="Enter OTP"
               maxlength="6"
               required>

        <button type="submit" name="verify">Verify</button>
    </form>

<?php endif; ?>

</div>

</body>
</html>