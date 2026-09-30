<?php
session_start();

include "db.php";
include "sendmail.php";

$error = "";
$reset_msg = "";
$otp_error = "";

$show_otp_modal = false;
$show_reset_modal = false;




if (isset($_POST['login'])) {

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {

        $error = "Please enter your email and password.";

    } else {

        $stmt = $pdo->prepare("
            SELECT *
            FROM users
            WHERE email = :email
            LIMIT 1
        ");

        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {

            $error = "Invalid email or password.";

        } elseif (strtolower($row['status']) !== "active") {

    $error = "Your account is not active or verified.";

        } elseif (password_verify($password, $row['password'])) {

            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['user_name'] = $row['full_name'];
            $_SESSION['user_email'] = $row['email'];
            $_SESSION['user_role'] = strtolower($row['role']);

            switch (strtolower($row['role'])) {

                case 'super_admin':
                case 'super administrator':
                    header("Location: SuperAdmin.php");
                    exit;

                case 'admin':
                case 'administrator':
                    header("Location: Admin.php");
                    exit;

                case 'trainer':
                case 'teacher':
                    header("Location: Teacher.php");
                    exit;

                case 'student':
                case 'trainee':
                    header("Location: student.php");
                    exit;

                default:

                    session_destroy();

                    $error = "Invalid account role. Please contact the administrator.";
                    break;
            }

        } else {

            $error = "Invalid email or password.";
        }
    }
}


/* =======
   SEND OTP
======= */

if (isset($_POST['send_otp'])) {

    $email = trim($_POST['email'] ?? '');

    if (empty($email)) {

        $reset_msg = "Please enter your email address.";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $reset_msg = "Please enter a valid email address.";

    } else {

        $check = $pdo->prepare("
            SELECT
                id,
                full_name,
                is_verified,
                status
            FROM users
            WHERE email = :email
            LIMIT 1
        ");

        $check->bindValue(':email', $email, PDO::PARAM_STR);
        $check->execute();

        $user = $check->fetch(PDO::FETCH_ASSOC);

        if (!$user) {

            $reset_msg = "No account was found with that email address.";

        } elseif ((int)$user['is_verified'] !== 1) {

            $reset_msg = "Your account has not been verified.";

        } elseif (strtolower($user['status']) !== "active") {

            $reset_msg = "Your account is not active.";

        } else {

            $otp = str_pad(
                (string) random_int(0, 999999),
                6,
                "0",
                STR_PAD_LEFT
            );

            $saveOtp = $pdo->prepare("
                UPDATE users
                SET
                    otp = :otp,
                    otp_created = NOW(),
                    otp_expires = DATE_ADD(NOW(), INTERVAL 10 MINUTE)
                WHERE id = :id
            ");

            $saveOtp->bindValue(':otp', $otp, PDO::PARAM_STR);
            $saveOtp->bindValue(':id', $user['id'], PDO::PARAM_INT);

            $saveOtp->execute();
            try {

                $log = $pdo->prepare("
                    INSERT INTO otp_logs
                    (
                        user_id,
                        otp_code,
                        otp_type,
                        status
                    )
                    VALUES
                    (
                        :user_id,
                        :otp_code,
                        'password_reset',
                        'pending'
                    )
                ");

                $log->bindValue(
                    ':user_id',
                    $user['id'],
                    PDO::PARAM_INT
                );

                $log->bindValue(
                    ':otp_code',
                    $otp,
                    PDO::PARAM_STR
                );

                $log->execute();

            } catch (PDOException $e) {

            }

            $_SESSION['otp_email'] = $email;
            $_SESSION['otp_verified'] = false;
            $mailSent = sendOTP(
                $email,
                $user['full_name'],
                $otp
            );

            if ($mailSent) {

                $reset_msg = "A 6-digit verification code has been sent to your email.";

                $show_otp_modal = true;

            } else {

                $reset_msg = "Could not send the verification email. Please try again.";
            }
        }
    }
}


/* =======
   VERIFY OTP
======= */

if (isset($_POST['verify_otp'])) {

    $otp_input = trim($_POST['otp_input'] ?? '');

    if (empty($_SESSION['otp_email'])) {

        $otp_error = "No OTP request was found. Please start again.";

    } elseif (!preg_match('/^\d{6}$/', $otp_input)) {

        $otp_error = "Please enter a valid 6-digit OTP.";
        $show_otp_modal = true;

    } else {

        $email = $_SESSION['otp_email'];

        $lookup = $pdo->prepare("
            SELECT
                id,
                otp,
                otp_expires
            FROM users
            WHERE email = :email
            LIMIT 1
        ");

        $lookup->bindValue(
            ':email',
            $email,
            PDO::PARAM_STR
        );

        $lookup->execute();

        $user = $lookup->fetch(PDO::FETCH_ASSOC);

        if (
            !user ||
            empty($user['otp']) ||
            empty($user['otp_expires'])
        ) {

            $otp_error = "No valid OTP request was found. Please request a new code.";

        } elseif (
            strtotime($user['otp_expires']) < time()
        ) {

            $otp_error = "This OTP has expired. Please request a new one.";

            $clear = $pdo->prepare("
                UPDATE users
                SET
                    otp = NULL,
                    otp_created = NULL,
                    otp_expires = NULL
                WHERE id = :id
            ");

            $clear->bindValue(
                ':id',
                $user['id'],
                PDO::PARAM_INT
            );

            $clear->execute();

        } elseif (
            !hash_equals(
                (string)$user['otp'],
                (string)$otp_input
            )
        ) {

            $otp_error = "Incorrect verification code. Please try again.";

            $show_otp_modal = true;

        } else {
            $_SESSION['otp_verified'] = true;

            $consume = $pdo->prepare("
                UPDATE users
                SET
                    otp = NULL,
                    otp_created = NULL,
                    otp_expires = NULL
                WHERE id = :id
            ");

            $consume->bindValue(
                ':id',
                $user['id'],
                PDO::PARAM_INT
            );

            $consume->execute();

            try {

                $updateLog = $pdo->prepare("
                    UPDATE otp_logs
                    SET status = 'verified'
                    WHERE user_id = :id
                      AND otp_type = 'password_reset'
                    ORDER BY id DESC
                    LIMIT 1
                ");

                $updateLog->bindValue(
                    ':id',
                    $user['id'],
                    PDO::PARAM_INT
                );

                $updateLog->execute();

            } catch (PDOException $e) {
            }

            $show_reset_modal = true;
        }
    }
}


/* =======
   RESET PASSWORD
======= */

if (isset($_POST['reset_password'])) {

    $new_password = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (
        empty($_SESSION['otp_verified']) ||
        $_SESSION['otp_verified'] !== true ||
        empty($_SESSION['otp_email'])
    ) {

        $reset_msg = "Please verify your email with the OTP first.";

        $show_otp_modal = true;

    } elseif (strlen($new_password) < 8) {

        $reset_msg = "Password must contain at least 8 characters.";

        $show_reset_modal = true;

    } elseif ($new_password !== $confirm_password) {

        $reset_msg = "Passwords do not match.";

        $show_reset_modal = true;

    } else {

        $email = $_SESSION['otp_email'];
        $hashed = password_hash(
            $new_password,
            PASSWORD_DEFAULT
        );

        $update = $pdo->prepare("
            UPDATE users
            SET password = :password
            WHERE email = :email
        ");

        $update->bindValue(
            ':password',
            $hashed,
            PDO::PARAM_STR
        );

        $update->bindValue(
            ':email',
            $email,
            PDO::PARAM_STR
        );

        if ($update->execute()) {

            $reset_msg = "Password reset successful. You can now sign in.";
            unset(
                $_SESSION['otp_email'],
                $_SESSION['otp_verified']
            );

        } else {

            $reset_msg = "Password reset failed. Please try again.";

            $show_reset_modal = true;
        }
    }
}


/* =======
   PROMOTIONAL 
======= */

$promotions = [
    [
        'tag'   => 'Programme',
        'title' => 'Skills Transfer Programme — New Cohort Open',
        'body'  => 'Structured mentorship from training to professional practice. Applications for the next intake are open now.',
        'link'  => 'https://www.cbtkenya.org/skills-transfer-program/',
        'cta'   => 'Learn More',
    ],
    [
        'tag'   => 'Event',
        'title' => 'Counselling Outreach Programmes',
        'body'  => 'Bringing psychological support closer to communities across Kenya through regular outreach clinics.',
        'link'  => 'https://www.cbtkenya.org/counselling-outreach-programs/',
        'cta'   => 'See Schedule',
    ],
    [
        'tag'   => 'Course',
        'title' => 'Employee Assistance Programme',
        'body'  => 'Workplace counselling delivered by qualified CBT-Kenya practitioners for partner organisations.',
        'link'  => 'https://www.cbtkenya.org/employee-assistance-program/',
        'cta'   => 'Explore Programme',
    ],
    [
        'tag'   => 'Insight',
        'title' => 'From the CBT-Kenya Blog',
        'body'  => 'Fresh perspectives from our practitioners on therapy, mentorship and professional growth.',
        'link'  => 'https://www.cbtkenya.org/blog/',
        'cta'   => 'Read the Blog',
    ],
];

?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CBT-Kenya | Student Transfer Program</title>
<link rel="icon" type="image/png" href="https://www.cbtkenya.org/wp-content/uploads/2018/11/favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/icons/cbt-ke.png">
<link rel="icon" type="image/png" href="/icons/cbt-ke.png">

<style>

/* =======
   GLOBAL
======= */

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

:root {
    --primary: #86AC13;          
    --primary-dark: #6C8C10;     
    --secondary: #94CA5F;        
    --secondary-light: #EEF7E6;
    --accent: #E8A126;          
    --accent-dark: #CE8F21;

    --text: #333333;
    --muted: #6b7280;

    --background: #f3f6f7;
    --white: #ffffff;

    --danger: #c0392b;
    --success: #18864b;

    --border: #dfe5e8;

    --font-heading: "Poppins", "Segoe UI", Arial, sans-serif;
    --font-body: "Inter", "Segoe UI", Arial, sans-serif;
}

body {
    min-height: 100vh;
    font-family: var(--font-body);
    background: linear-gradient(135deg, #eef4f5, #f8fafb);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 25px;
    color: var(--text);
}

/* =======
   MAIN LOGIN CONTAINER
======= */

.login-container {
    width: 1220px;
    max-width: 100%;
    min-height: 700px;
    display: flex;
    background: var(--white);
    border-radius: 22px;
    overflow: hidden;
    box-shadow: 0 25px 70px rgba(0,0,0,0.15);
}

/* =======
   IMAGE / BRAND SIDE
======= */

.image-box {
    flex: 0.58;
    position: relative;
    overflow: hidden;
    min-height: 700px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    background:
        radial-gradient(circle at 15% 10%, #9DC93A 0%, transparent 45%),
        radial-gradient(circle at 90% 85%, #55700B 0%, transparent 55%),
        linear-gradient(160deg, var(--primary) 0%, var(--primary-dark) 100%);
}

.image-box .pattern {
    position: absolute;
    inset: 0;
    opacity: 0.10;
    background-image: radial-gradient(circle, rgba(255,255,255,0.9) 1.4px, transparent 1.4px);
    background-size: 26px 26px;
    pointer-events: none;
}

/* =======
   HERO ILLUSTRATION 
======= */

.hero-illustration {
    position: relative;
    z-index: 2;
    padding: 42px 50px 0;
}

.hero-illustration svg {
    width: 100%;
    height: auto;
    max-height: 300px;
    display: block;
}

/* =======
   IMAGE TEXT
======= */

.image-overlay {
    position: relative;
    z-index: 2;
    padding: 10px 50px 40px;
    color: white;
}

.brand-badge {
    display: inline-flex;
    align-items: center;
    padding: 9px 16px;
    border-radius: 30px;
    background: rgba(255,255,255,0.14);
    border: 1px solid rgba(255,255,255,0.35);
    backdrop-filter: blur(5px);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1.3px;
    margin-bottom: 20px;
}

.image-overlay h1 {
    font-family: var(--font-heading);
    font-size: 38px;
    line-height: 1.15;
    font-weight: 800;
    margin-bottom: 12px;
    max-width: 550px;
}

.image-overlay .tagline {
    font-size: 17px;
    line-height: 1.5;
    color: rgba(255,255,255,0.90);
    margin-bottom: 22px;
    max-width: 520px;
}

/* =======
   STP FEATURES
======= */

.stp-features {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 26px;
}

.stp-features span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 9px 13px;
    border-radius: 8px;
    background: rgba(255,255,255,0.14);
    border: 1px solid rgba(255,255,255,0.18);
    font-size: 13px;
    backdrop-filter: blur(4px);
}

/* =======
   PROMO 
======= */

.promo-panel {
    position: relative;
    z-index: 2;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.22);
    border-radius: 16px;
    padding: 18px 20px;
    backdrop-filter: blur(6px);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 14px;
}

.promo-panel .promo-copy {
    min-width: 0;
}

.promo-eyebrow {
    display: inline-block;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--accent);
    background: rgba(215,168,62,0.15);
    border: 1px solid rgba(215,168,62,0.4);
    padding: 3px 9px;
    border-radius: 20px;
    margin-bottom: 9px;
}

.promo-panel h4 {
    font-family: var(--font-heading);
    font-size: 15.5px;
    color: white;
    margin-bottom: 5px;
    line-height: 1.3;
}

.promo-panel p {
    font-size: 12.5px;
    color: rgba(255,255,255,0.78);
    line-height: 1.5;
    max-width: 360px;
}

.promo-cta {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    align-self: center;
    background: var(--accent);
    color: var(--primary-dark);
    font-size: 12.5px;
    font-weight: 700;
    padding: 10px 15px;
    border-radius: 9px;
    text-decoration: none;
    white-space: nowrap;
    transition: 0.2s;
}

.promo-cta:hover {
    background: var(--accent-dark);
}

.promo-dots {
    position: absolute;
    top: 12px;
    right: 16px;
    display: flex;
    gap: 5px;
}

.promo-dots span {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: rgba(255,255,255,0.3);
    cursor: pointer;
    transition: 0.2s;
}

.promo-dots span.active {
    background: var(--accent);
    width: 16px;
    border-radius: 4px;
}

/* =======
   LOGIN SIDE
======= */

.login-panel {
    flex: 0.42;
    padding: 50px 48px 30px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-width: 0;
}

/* =======
   BRAND
======= */

.brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    margin-bottom: 20px;
}

.brand-logo {
    width: 15rem;
    height: 5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--white);
    border: none;
    overflow: hidden;
    padding: 4px;
}

.brand-logo img {
    width: 100%;
    height: 100%;
    object-fit: contain;
}

.brand-logo .logo-fallback {
    display: none;
    width: 100%;
    height: 100%;
    align-items: center;
    justify-content: center;
    background: var(--primary);
    color: white;
    font-family: var(--font-heading);
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 1px;
    border-radius: 8px;
}

.brand-name strong {
    display: block;
    font-family: var(--font-heading);
    font-size: 17px;
    color: var(--primary);
    letter-spacing: 0.3px;
}

.brand-name small {
    display: block;
    margin-top: 2px;
    color: var(--muted);
    font-size: 20px;
}

/* =======
   INSTALL APP BUTTON & TOOLTIP (FOOTER PLACEMENT)
======= */

.install-app-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    height: 28px;
    padding: 0 12px;
    border: 1px solid var(--primary);
    background: var(--secondary-light);
    color: var(--primary-dark);
    border-radius: 20px;
    font-size: 11.5px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s ease;
    font-family: var(--font-body);
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}

.install-app-btn svg {
    width: 13px;
    height: 13px;
    fill: currentColor;
    transition: transform 0.2s ease;
}

.install-app-btn:hover {
    background: var(--primary);
    color: var(--white);
    border-color: var(--primary-dark);
    box-shadow: 0 3px 8px rgba(134,172,19,0.3);
    transform: translateY(-1px);
}

.install-app-btn:hover svg {
    transform: translateY(1px);
}

.ios-install-tip {
    display: none;
    width: 100%;
    background: var(--secondary-light);
    color: #1c5f5b;
    border: 1px solid #bfe3e0;
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 11.5px;
    line-height: 1.4;
    margin-top: 8px;
    text-align: center;
}

/* =======
   LOGIN HEADING
======= */

.login-heading {
    margin-bottom: 22px;
}

.login-heading h2 {
    font-family: var(--font-heading);
    font-size: 28px;
    line-height: 1.2;
    margin-bottom: 8px;
    color: var(--text);
}

.login-heading p {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
}

/* =======
   LOGIN FORM
======= */

.login-form {
    display: flex;
    flex-direction: column;
    gap: 18px;
    width: 100%;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 7px;
}

.form-group label {
    font-size: 13px;
    font-weight: 700;
    color: #374151;
}

.input-wrapper {
    position: relative;
}

.input-wrapper input {
    width: 100%;
    height: 50px;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0 45px 0 14px;
    font-size: 14px;
    outline: none;
    transition: 0.2s;
    font-family: var(--font-body);
}

.input-wrapper input:focus {
    border-color: var(--secondary);
    box-shadow: 0 0 0 3px rgba(148,202,95,0.18);
}

/* =======
   PASSWORD TOGGLE
======= */

.password-toggle {
    position: absolute;
    right: 13px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: #777;
    cursor: pointer;
    font-size: 13px;
}

/* =======
   LOGIN BUTTON
======= */

.login-button {
    width: 100%;
    height: 50px;
    border: none;
    border-radius: 10px;
    background: var(--primary);
    color: white;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    transition: 0.2s;
    font-family: var(--font-body);
}

.login-button:hover {
    background: var(--primary-dark);
    transform: translateY(-1px);
    box-shadow: 0 7px 20px rgba(134,172,19,0.25);
}

/* =======
   FORGOT PASSWORD
======= */

.forgot-button {
    width: 100%;
    height: 45px;
    border: 1px solid var(--border);
    background: white;
    color: black;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: 0.2s;
}

.forgot-button:hover {
    background: var(--secondary-light);
    border-color: var(--secondary);
}

/* =======
   REGISTER
======= */

.register-link {
    text-align: center;
    margin-top: 8px;
    font-size: 13px;
    color: var(--muted);
}

.register-link a {
    color: black;
    text-decoration: none;
    font-weight: 700;
    margin-left: 4px;
}

.register-link a:hover {
    text-decoration: underline;
}

/* =======
   ALERTS
======= */

.alert {
    padding: 12px 14px;
    border-radius: 9px;
    font-size: 13px;
    line-height: 1.5;
    margin-bottom: 15px;
}

.alert-error {
    background: #fff1f0;
    color: var(--danger);
    border: 1px solid #ffd6d2;
}

.alert-success {
    background: #edf9f2;
    color: var(--success);
    border: 1px solid #c8ecd5;
}

.alert-info {
    background: var(--secondary-light);
    color: #1c5f5b;
    border: 1px solid #bfe3e0;
}

/* =======
   FOOTER STRIP
======= */

.login-footer-strip {
    margin-top: 26px;
    padding-top: 18px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
    font-size: 11.5px;
    color: var(--muted);
}

.login-footer-strip a {
    color: black;
    text-decoration: none;
    font-weight: 600;
}

.login-footer-strip a:hover {
    text-decoration: underline;
}

.footer-socials {
    display: flex;
    gap: 12px;
}

/* =======
   MODALS
======= */

.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    inset: 0;
    background: rgba(8, 25, 32, 0.72);
    align-items: center;
    justify-content: center;
    padding: 20px;
    backdrop-filter: blur(5px);
}

.modal-content {
    width: 420px;
    max-width: 100%;
    background: white;
    border-radius: 18px;
    padding: 32px;
    position: relative;
    box-shadow: 0 25px 80px rgba(0,0,0,0.25);
    animation: modalIn 0.2s ease;
}

@keyframes modalIn {
    from {
        opacity: 0;
        transform: translateY(10px) scale(0.98);
    }
    to {
        opacity: 1;
        transform: translateY(0) scale(1);
    }
}

.close {
    position: absolute;
    top: 13px;
    right: 17px;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    color: #777;
    cursor: pointer;
    font-size: 23px;
    transition: 0.2s;
}

.close:hover {
    background: #f1f1f1;
    color: #222;
}

.modal-content h3 {
    font-family: var(--font-heading);
    font-size: 22px;
    margin-bottom: 8px;
    color: var(--text);
}

.modal-description {
    color: var(--muted);
    font-size: 13px;
    line-height: 1.6;
    margin-bottom: 20px;
}

.modal-form {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

.modal-form input {
    width: 100%;
    height: 48px;
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 0 13px;
    outline: none;
    font-size: 14px;
    font-family: var(--font-body);
}

.modal-form input:focus {
    border-color: var(--secondary);
    box-shadow: 0 0 0 3px rgba(148,202,95,0.16);
}

.modal-button {
    height: 48px;
    border: none;
    border-radius: 9px;
    background: var(--primary);
    color: white;
    font-weight: 700;
    cursor: pointer;
    font-family: var(--font-body);
}

.modal-button:hover {
    background: var(--primary-dark);
}

/* =======
   OTP INPUT
======= */

.otp-input {
    text-align: center;
    letter-spacing: 8px;
    font-size: 24px !important;
    font-weight: 700;
}

.modal-footer {
    text-align: center;
    margin-top: 15px;
    color: #888;
    font-size: 12px;
}

/* =======
   RESPONSIVE DESIGN
======= */

@media (max-width: 1040px) {
    .login-container {
        width: 940px;
    }
    .image-overlay,
    .hero-illustration {
        padding-left: 35px;
        padding-right: 35px;
    }
    .image-overlay h1 {
        font-size: 32px;
    }
    .login-panel {
        padding: 40px 32px;
    }
    .promo-panel {
        flex-direction: column;
        align-items: flex-start;
    }
}

@media (max-width: 768px) {
    body {
        padding: 12px;
        align-items: flex-start;
    }
    .login-container {
        width: 100%;
        min-height: auto;
        flex-direction: column;
        border-radius: 16px;
        margin: 10px 0;
    }
    .image-box {
        flex: none;
        min-height: auto;
        order: 1;
        padding-bottom: 10px;
    }
    .hero-illustration {
        padding: 30px 25px 0;
    }
    .hero-illustration svg {
        max-height: 190px;
    }
    .login-panel {
        order: 2;
        flex: none;
        padding: 32px 25px;
    }
    .image-overlay {
        padding: 10px 25px 28px;
    }
    .image-overlay h1 {
        font-size: 27px;
    }
    .image-overlay .tagline {
        font-size: 14.5px;
    }
    .brand {
        margin-bottom: 22px;
    }
    .promo-panel {
        flex-direction: column;
        align-items: flex-start;
    }
    .promo-cta {
        align-self: stretch;
        justify-content: center;
    }
    .login-footer-strip {
        flex-direction: column;
        gap: 12px;
        align-items: center;
    }
}

@media (max-width: 480px) {
    body {
        padding: 0;
    }
    .login-container {
        margin: 0;
        border-radius: 0;
        min-height: 100vh;
    }
    .hero-illustration svg {
        max-height: 150px;
    }
    .image-overlay h1 {
        font-size: 23px;
    }
    .image-overlay .tagline {
        font-size: 13.5px;
        margin-bottom: 14px;
    }
    .stp-features span {
        padding: 6px 8px;
        font-size: 11px;
    }
    .login-panel {
        padding: 28px 20px;
    }
    .login-heading h2 {
        font-size: 24px;
    }
    .modal-content {
        padding: 25px 20px;
    }
}

@media (max-width: 320px) {
    .hero-illustration svg {
        max-height: 120px;
    }
    .image-overlay h1 {
        font-size: 20px;
    }
    .stp-features {
        display: none;
    }
}
</style>
</head>

<body>

<!-- ===
     MAIN LOGIN CONTAINER
=== -->
<div class="login-container">
    <div class="image-box">
        <div class="pattern"></div>
        <div class="hero-illustration">
            <svg viewBox="0 0 560 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Illustration of the STP mentorship journey">
                <defs>
                    <linearGradient id="figGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stop-color="#d7a83e"/>
                        <stop offset="100%" stop-color="#b98a26"/>
                    </linearGradient>
                </defs>
                <path d="M40 230 C 150 150, 230 260, 320 170 S 480 90, 530 60" stroke="rgba(255,255,255,0.35)" stroke-width="3" stroke-dasharray="2 10" fill="none" stroke-linecap="round"/>
                <g transform="translate(20,190)">
                    <circle cx="30" cy="30" r="30" fill="rgba(255,255,255,0.10)" stroke="rgba(255,255,255,0.35)"/>
                    <path d="M14 22 h16 v20 h-16 z M30 22 h16 v20 h-16 z" fill="none" stroke="#eaf3f4" stroke-width="2" stroke-linejoin="round"/>
                    <line x1="30" y1="22" x2="30" y2="42" stroke="#eaf3f4" stroke-width="2"/>
                </g>
                <text x="12" y="252" font-family="Inter, sans-serif" font-size="11" fill="rgba(255,255,255,0.75)" font-weight="600">LEARNING</text>
                <g transform="translate(150,120)">
                    <circle cx="45" cy="45" r="42" fill="rgba(255,255,255,0.10)" stroke="rgba(255,255,255,0.35)"/>
                    <circle cx="34" cy="35" r="9" fill="#eaf3f4"/>
                    <path d="M18 62 c0 -14 9 -20 16 -20 s16 6 16 20" fill="#eaf3f4" opacity="0.9"/>
                    <circle cx="58" cy="32" r="7" fill="url(#figGrad)"/>
                    <path d="M46 58 c0 -11 7 -16 12 -16 s12 5 12 16" fill="url(#figGrad)" opacity="0.95"/>
                </g>
                <text x="150" y="200" font-family="Inter, sans-serif" font-size="11" fill="rgba(255,255,255,0.75)" font-weight="600">MENTORSHIP</text>

                <!-- Stage 3: Supervision (clipboard/checklist) -->
                <g transform="translate(300,70)">
                    <circle cx="40" cy="40" r="38" fill="rgba(255,255,255,0.10)" stroke="rgba(255,255,255,0.35)"/>
                    <rect x="24" y="20" width="32" height="40" rx="4" fill="none" stroke="#eaf3f4" stroke-width="2"/>
                    <rect x="32" y="16" width="16" height="8" rx="2" fill="#eaf3f4"/>
                    <path d="M30 34 l5 5 l10 -10" stroke="url(#figGrad)" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
                    <line x1="30" y1="48" x2="50" y2="48" stroke="#eaf3f4" stroke-width="2" opacity="0.7"/>
                </g>
                <text x="292" y="150" font-family="Inter, sans-serif" font-size="11" fill="rgba(255,255,255,0.75)" font-weight="600">SUPERVISION</text>

                <!-- Stage 4: Professional practice (badge/star) -->
                <g transform="translate(450,20)">
                    <circle cx="42" cy="42" r="40" fill="rgba(215,168,62,0.18)" stroke="#d7a83e" stroke-width="1.5"/>
                    <path d="M42 20 l6.5 13.5 14.8 2.2 -10.7 10.5 2.5 14.8 -13.1 -7 -13.1 7 2.5 -14.8 -10.7 -10.5 14.8 -2.2 z" fill="url(#figGrad)"/>
                </g>
                <text x="400" y="105" font-family="Inter, sans-serif" font-size="11" fill="rgba(255,255,255,0.85)" font-weight="500">PROFESSIONAL PRACTICE</text>
            </svg>
        </div>

        <div class="image-overlay">
            <div class="brand-badge">
                CBT-KENYA • STP
            </div>

            <h1>
                Skills Transfer Program
            </h1>

            <p class="tagline">
                From Training to Professional Practice
            </p>

            <div class="stp-features">
                <span>&#10003; Learning</span>
                <span>&#10003; Mentorship</span>
                <span>&#10003; Supervision</span>
                <span>&#10003; Professional Growth</span>
            </div>

            <div class="promo-panel" id="promoPanel">
                <div class="promo-dots" id="promoDots"></div>
                <div class="promo-copy" id="promoCopy"></div>
                <a href="#" id="promoCta" class="promo-cta" target="_blank" rel="noopener">
                    Learn More &rarr;
                </a>
            </div>
        </div>
    </div>

    <div class="login-panel">
        <!-- BRAND -->
        <div class="brand">
            <div class="brand-logo">
                <img
                    src="cbt-ke.png"
                    alt="CBT-Kenya logo"
                    onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';"
                >
                <div class="logo-fallback">CBT</div>
            </div>
            <div class="brand-name">
                <small>Skills Transfer Program</small>
            </div>
        </div>

        <!-- LOGIN HEADING -->
        <div class="login-heading">
            <h2>Welcome Back</h2>
            <p>Sign in to continue your professional learning journey.</p>
        </div>

        <!-- ERROR MESSAGE -->
        <?php if (!empty($error)): ?>
            <div class="alert alert-error">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <!-- SUCCESS MESSAGE -->
        <?php
        if (
            !empty($reset_msg) &&
            !$show_otp_modal &&
            !$show_reset_modal &&
            isset($_POST['reset_password'])
        ):
        ?>
            <div class="alert alert-success">
                <?= htmlspecialchars($reset_msg) ?>
            </div>
        <?php endif; ?>

        <!-- LOGIN FORM -->
        <form
            method="POST"
            class="login-form"
            autocomplete="on"
        >
            <!-- EMAIL -->
            <div class="form-group">
                <label for="login-email">Email Address</label>
                <div class="input-wrapper">
                    <input
                        type="email"
                        id="login-email"
                        name="email"
                        placeholder="Enter your email"
                        autocomplete="email"
                        required
                    >
                </div>
            </div>

            <!-- PASSWORD -->
            <div class="form-group">
                <label for="login-password">Password</label>
                <div class="input-wrapper">
                    <input
                        type="password"
                        id="login-password"
                        name="password"
                        placeholder="Enter your password"
                        autocomplete="current-password"
                        required
                    >
                    <button
                        type="button"
                        class="password-toggle"
                        onclick="togglePassword()"
                        id="passwordToggle"
                    >
                        Show
                    </button>
                </div>
            </div>

            <!-- LOGIN BUTTON -->
            <button
                type="submit"
                name="login"
                class="login-button"
            >
                Sign In
            </button>

            <!-- FORGOT PASSWORD -->
            <button
                type="button"
                class="forgot-button"
                onclick="openModal('forgotModal')"
            >
                Forgot Password?
            </button>

            <!-- REGISTER -->
            <div class="register-link">
                Don't have an account?
                <a href="register.php">Create Account</a>
            </div>
        </form>

        <!-- FOOTER STRIP -->
        <div class="login-footer-strip">
            <span>
                &copy; <?= date('Y') ?> CBT-Kenya &middot;
                <a href="https://www.cbtkenya.org/contact-us/" target="_blank" rel="noopener">Contact</a>
            </span>

            <!-- INSTALL APP BUTTON (Centered in Marked Footer Area) -->
            <button
                type="button"
                id="installAppBtn"
                class="install-app-btn"
                title="Install CBT-Kenya STP Application"
            >
                <svg viewBox="0 0 24 24">
                    <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM17 13l-5 5-5-5h3V9h4v4h3z"/>
                </svg>
                Install App
            </button>

            <div class="footer-socials">
                <a href="https://www.facebook.com/CBT-Kenya-170115403471661/" target="_blank" rel="noopener" aria-label="CBT-Kenya on Facebook">Facebook</a>
                <a href="https://twitter.com/CbtKenya" target="_blank" rel="noopener" aria-label="CBT-Kenya on Twitter">Twitter</a>
                <a href="https://www.linkedin.com/in/cbt-kenya-6241a0223/" target="_blank" rel="noopener" aria-label="CBT-Kenya on LinkedIn">LinkedIn</a>
            </div>

            <!-- iOS MANUAL INSTALL TIP -->
            <div id="iosInstallTip" class="ios-install-tip">
                To install this app on iPhone/iPad: tap the Share icon <strong>(&#9633;&#8593;)</strong> in Safari, then select <strong>"Add to Home Screen"</strong>.
            </div>
        </div>
    </div>
</div>

<!-- ===
     STEP 1 — FORGOT PASSWORD MODAL
=== -->
<div id="forgotModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('forgotModal')">&times;</span>
        <h3>Reset Password</h3>
        <p class="modal-description">
            Enter your registered email address. We'll send you a 6-digit verification code.
        </p>

        <?php if (!empty($reset_msg) && !$show_otp_modal && !$show_reset_modal): ?>
            <div class="alert alert-error">
                <?= htmlspecialchars($reset_msg) ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="modal-form">
            <input
                type="email"
                name="email"
                placeholder="Enter your email address"
                autocomplete="email"
                required
            >
            <button
                type="submit"
                name="send_otp"
                class="modal-button"
            >
                Send Verification Code
            </button>
        </form>

        <div class="modal-footer">
            Verification code expires after <strong>10 minutes</strong>.
        </div>
    </div>
</div>

<!-- ===
     STEP 2 — OTP MODAL
=== -->
<div id="otpModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('otpModal')">&times;</span>
        <h3>Verify Your Email</h3>
        <p class="modal-description">
            We sent a 6-digit verification code to your registered email address.
        </p>

        <?php if (!empty($reset_msg) && $show_otp_modal): ?>
            <div class="alert alert-info">
                <?= htmlspecialchars($reset_msg) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($otp_error)): ?>
            <div class="alert alert-error">
                <?= htmlspecialchars($otp_error) ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="modal-form">
            <input
                class="otp-input"
                type="text"
                name="otp_input"
                maxlength="6"
                minlength="6"
                pattern="[0-9]{6}"
                inputmode="numeric"
                autocomplete="one-time-code"
                placeholder="000000"
                required
            >
            <button
                type="submit"
                name="verify_otp"
                class="modal-button"
            >
                Verify Code
            </button>
        </form>

        <div class="modal-footer">
            Your verification code expires after <strong>10 minutes</strong>.
        </div>
    </div>
</div>

<!-- ===
     STEP 3 — RESET PASSWORD MODAL
=== -->
<div id="resetModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('resetModal')">&times;</span>
        <h3>Create New Password</h3>
        <p class="modal-description">
            Your email has been successfully verified. Create a new password for your account.
        </p>

        <?php if (!empty($reset_msg) && $show_reset_modal): ?>
            <div class="alert alert-error">
                <?= htmlspecialchars($reset_msg) ?>
            </div>
        <?php endif; ?>

        <form method="POST" class="modal-form">
            <input
                type="password"
                name="new_password"
                placeholder="New password"
                minlength="8"
                autocomplete="new-password"
                required
            >
            <input
                type="password"
                name="confirm_password"
                placeholder="Confirm new password"
                minlength="8"
                autocomplete="new-password"
                required
            >
            <button
                type="submit"
                name="reset_password"
                class="modal-button"
            >
                Reset Password
            </button>
        </form>

        <div class="modal-footer">
            Password must contain at least <strong>8 characters</strong>.
        </div>
    </div>
</div>

<script>
/* =======
   MODAL FUNCTIONS
======= */
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.style.display = "flex";
    }
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) {
        modal.style.display = "none";
    }
}

/* =======
   PASSWORD VISIBILITY
======= */
function togglePassword() {
    const password = document.getElementById("login-password");
    const button = document.getElementById("passwordToggle");

    if (password.type === "password") {
        password.type = "text";
        button.textContent = "Hide";
    } else {
        password.type = "password";
        button.textContent = "Show";
    }
}

/* =======
   AUTOMATIC MODALS AFTER PHP RESPONSE
======= */
window.addEventListener("DOMContentLoaded", function () {
    <?php if ($show_otp_modal): ?>
        openModal("otpModal");
    <?php endif; ?>

    <?php if ($show_reset_modal): ?>
        openModal("resetModal");
    <?php endif; ?>

    <?php
    if (
        isset($_POST['reset_password']) &&
        !empty($reset_msg) &&
        !$show_reset_modal
    ):
    ?>
        setTimeout(function () {
            alert(<?= json_encode($reset_msg) ?>);
        }, 100);
    <?php endif; ?>
});

/* =======
   CLOSE MODAL WHEN CLICKING OUTSIDE
======= */
window.addEventListener("click", function (event) {
    const modals = ["forgotModal", "otpModal", "resetModal"];
    modals.forEach(function (id) {
        const modal = document.getElementById(id);
        if (event.target === modal) {
            modal.style.display = "none";
        }
    });
});

/* =======
   ESCAPE KEY CLOSES MODAL
======= */
document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
        ["forgotModal", "otpModal", "resetModal"].forEach(function (id) {
            closeModal(id);
        });
    }
});

/* =======
   OTP — ONLY NUMBERS
======= */
const otpInput = document.querySelector(".otp-input");
if (otpInput) {
    otpInput.addEventListener("input", function () {
        this.value = this.value.replace(/\D/g, "");
    });
}

/* =======
   PWA INSTALL PROMPT
======= */
let deferredPrompt = null;
const installBtn = document.getElementById('installAppBtn');
const iosTip = document.getElementById('iosInstallTip');

// Keep button visible by default on desktop/mobile
if (installBtn) {
    installBtn.style.display = 'inline-flex';
}

window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    deferredPrompt = e;
    if (installBtn) {
        installBtn.style.display = 'inline-flex';
    }
});

if (installBtn) {
    installBtn.addEventListener('click', async function () {
        if (deferredPrompt) {
            // Trigger native prompt (Android / Chrome mobile / supported desktop)
            deferredPrompt.prompt();
            const choice = await deferredPrompt.userChoice;
            deferredPrompt = null;

            if (choice.outcome === 'accepted') {
                installBtn.style.display = 'none';
            }
        } else {
            // Desktop fallback: Direct user to the address bar icon visible in Chromium
            const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
            if (isIOS) {
                if (iosTip) iosTip.style.display = 'block';
            } else {
                installBtn.title = "Click the install icon in your browser address bar";
                // Temporary button feedback without a blocking alert
                const originalText = installBtn.innerHTML;
                installBtn.innerHTML = "Check Address Bar &uarr;";
                setTimeout(() => {
                    installBtn.innerHTML = originalText;
                }, 3000);
            }
        }
    });
}

// Hide when the application is confirmed installed
window.addEventListener('appinstalled', function () {
    if (installBtn) {
        installBtn.style.display = 'none';
    }
    deferredPrompt = null;
});

// Hide completely if already running in installed standalone mode
if (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true) {
    if (installBtn) installBtn.style.display = 'none';
    if (iosTip) iosTip.style.display = 'none';
}
/* =======
   iOS INSTRUCTIONS
======= */
(function showIosTipIfNeeded() {
    const isIOS = /iphone|ipad|ipod/i.test(navigator.userAgent);
    const isInStandaloneMode =
        window.navigator.standalone === true ||
        window.matchMedia('(display-mode: standalone)').matches;

    if (isIOS && !isInStandaloneMode && iosTip) {
        iosTip.style.display = 'block';
    }
})();

/* =======
   PROMOTIONAL BANNER CAROUSEL
======= */
const promotions = <?= json_encode($promotions, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

(function initPromoCarousel() {
    if (!promotions || !promotions.length) return;

    const copyEl = document.getElementById('promoCopy');
    const ctaEl = document.getElementById('promoCta');
    const dotsEl = document.getElementById('promoDots');
    const panelEl = document.getElementById('promoPanel');

    let index = 0;
    let timer = null;

    function render(i) {
        const p = promotions[i];
        copyEl.innerHTML =
            '<span class="promo-eyebrow">' + p.tag + '</span>' +
            '<h4>' + p.title + '</h4>' +
            '<p>' + p.body + '</p>';

        ctaEl.textContent = p.cta + ' \u2192';
        ctaEl.href = p.link;

        Array.from(dotsEl.children).forEach(function (dot, di) {
            dot.classList.toggle('active', di === i);
        });
    }

    function buildDots() {
        dotsEl.innerHTML = '';
        promotions.forEach(function (_, i) {
            const dot = document.createElement('span');
            dot.addEventListener('click', function () {
                index = i;
                render(index);
                resetTimer();
            });
            dotsEl.appendChild(dot);
        });
    }

    function next() {
        index = (index + 1) % promotions.length;
        render(index);
    }

    function resetTimer() {
        clearInterval(timer);
        timer = setInterval(next, 6000);
    }

    buildDots();
    render(index);
    resetTimer();

    panelEl.addEventListener('mouseenter', function () {
        clearInterval(timer);
    });

    panelEl.addEventListener('mouseleave', resetTimer);
})();

/* =======
   REGISTER SERVICE WORKER
======= */
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function () {
        navigator.serviceWorker.register('/sw.js')
            .then(function (registration) {
                console.log('Service worker registered:', registration.scope);
            })
            .catch(function (error) {
                console.error('Service worker registration failed:', error);
            });
    });
}
</script>

</body>
</html>