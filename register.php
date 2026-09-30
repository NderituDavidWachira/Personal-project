<?php
declare(strict_types=1);

/* =
   STRICT SESSION SECURITY
= */
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');

/* =
   ENABLE SECURE COOKIE ONLY IF HTTPS
= */
$isHttps =
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || ($_SERVER['SERVER_PORT'] ?? 80) == 443;

ini_set('session.cookie_secure', $isHttps ? '1' : '0');

session_start();

date_default_timezone_set("Africa/Nairobi");

include "db.php";
include "sendmail.php";

/* =
   FIX: make sure PDO throws exceptions instead of silently failing.
   db.php may already set this, but setting it again here is harmless
   and guarantees the try/catch blocks below actually catch something.
= */
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

/* =
   SECURITY HEADERS
= */
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");

$error = "";
$formData = []; // repopulate form on validation error (never repopulate password)

/* =
   PREFILL REFERRAL CODE FROM URL (?ref=...)
   Only applies on the initial GET load - once the form is POSTed,
   $formData gets fully repopulated from $_POST instead (see the
   PROCESS FORM section below), so this won't clobber a resubmission
   or override whatever the user actually typed/edited in the field.
= */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $refFromUrl = strtoupper(trim($_GET['ref'] ?? ''));
    $refFromUrl = preg_replace('/[^A-Z0-9]/', '', $refFromUrl); // strip anything not alphanumeric
    // NOTE: intentionally NOT gated behind referralCodeLooksValid() here -
    // that check is for the 6-12 char referral-code format, but test links
    // are currently using student-number-style values (e.g. ST20260715001BE8C,
    // 18 chars). We still want those to prefill the field so the field is
    // pre-populated as requested; the existing submit-time validation further
    // down (referralCodeLooksValid() + referralCodeExists()) still applies
    // and will reject it at submit if it doesn't fit the real code format.
    if ($refFromUrl !== '' && strlen($refFromUrl) <= 20) {
        $formData['referral_code'] = $refFromUrl;
    }
}

/* =
   CSRF TOKEN
= */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* =
   RATE LIMIT (registration attempts)
= */
if (!isset($_SESSION['last_register'])) {
    $_SESSION['last_register'] = 0;
}
if (!isset($_SESSION['register_attempts'])) {
    $_SESSION['register_attempts'] = 0;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (time() - $_SESSION['last_register'] < 5) {
        $error = "Too many requests. Please wait a few seconds.";
    } elseif ($_SESSION['register_attempts'] >= 20) {
        // resets naturally once the session expires / after a successful registration
        $error = "Too many attempts from this session. Please try again later.";
    }
}

/* =
   STATIC REFERENCE DATA
= */
$KENYA_COUNTIES = [
    "Baringo","Bomet","Bungoma","Busia","Elgeyo-Marakwet","Embu","Garissa","Homa Bay",
    "Isiolo","Kajiado","Kakamega","Kericho","Kiambu","Kilifi","Kirinyaga","Kisii","Kisumu",
    "Kitui","Kwale","Laikipia","Lamu","Machakos","Makueni","Mandera","Marsabit","Meru",
    "Migori","Mombasa","Murang'a","Nairobi","Nakuru","Nandi","Narok","Nyamira","Nyandarua",
    "Nyeri","Samburu","Siaya","Taita-Taveta","Tana River","Tharaka-Nithi","Trans Nzoia",
    "Turkana","Uasin Gishu","Vihiga","Wajir","West Pokot","Outside Kenya"
];

$QUALIFICATION_LEVELS = [
    "Certificate", "Diploma", "Higher Diploma", "Bachelor's Degree",
    "Master's Degree", "PhD / Doctorate", "Other"
];

$GENDERS = ["Female", "Male", "Prefer not to say"];

/* =
   HELPERS
= */
function clean_string(string $data): string {
    return trim(htmlspecialchars(strip_tags($data), ENT_QUOTES, 'UTF-8'));
}

/**
 * FIX: clean_string() HTML-entity-encodes apostrophes (ENT_QUOTES), which
 * turns "Bachelor's Degree" into "Bachelor&#039;s Degree" and "Murang'a"
 * into "Murang&#039;a". That's fine for free-text fields, but for fields
 * validated with a strict in_array() against a fixed whitelist (gender,
 * county, qualification level) it meant a correctly-selected dropdown
 * option would fail validation just because it contained an apostrophe.
 *
 * These values only ever come from a <select>, are checked against a
 * known-safe whitelist, and are already re-escaped with htmlspecialchars()
 * wherever they're echoed back into HTML - so no entity-encoding is
 * needed (or safe to apply) at input time here.
 */
function clean_choice(string $data): string {
    return trim(strip_tags($data));
}

function generateStudentNo(PDO $pdo): string {
    $prefix  = "ST" . date("Ymd");
    $pattern = $prefix . '%';

    $stmt = $pdo->prepare("
        SELECT MAX(CAST(SUBSTRING(student_no, 11) AS UNSIGNED)) AS max_seq
        FROM (
            SELECT student_no FROM pending_students WHERE student_no LIKE ?
            UNION ALL
            SELECT student_no FROM students WHERE student_no LIKE ?
        ) AS combined
    ");
    $stmt->execute([$pattern, $pattern]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $nextSeq = ((int)($row['max_seq'] ?? 0)) + 1;

    return $prefix . str_pad((string)$nextSeq, 3, '0', STR_PAD_LEFT);
}

/**
 * Validates a Kenyan KRA PIN format: one letter, 9 digits, one letter (e.g. A123456789Z).
 * KRA PIN is optional at registration, but if supplied it must be well-formed.
 */
function isValidKraPin(string $pin): bool {
    return (bool) preg_match('/^[A-Za-z]\d{9}[A-Za-z]$/', $pin);
}

/**
 * Referral codes are alphanumeric, 6-12 chars. Existence against the referrals
 * table is checked only if that table is present, so this file keeps working
 * even before the referral system (enhancement #8) is fully built out.
 */
function referralCodeLooksValid(string $code): bool {
    return (bool) preg_match('/^[A-Za-z0-9]{6,12}$/', $code);
}

function referralCodeExists(PDO $pdo, string $code): bool {
    try {
        $stmt = $pdo->prepare("SELECT 1 FROM referral_codes WHERE code = ? LIMIT 1");
        $stmt->execute([$code]);
        return (bool) $stmt->fetch();
    } catch (PDOException $e) {
        // referral_codes table not yet created - don't block registration on it.
        return true;
    }
}

function calculateAge(string $dob): int {
    $birth = DateTime::createFromFormat('Y-m-d', $dob);
    if (!$birth) {
        return 0;
    }
    $today = new DateTime('today');
    return (int) $birth->diff($today)->y;
}

function clientIp(): string {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * FIX: the previous version only ever deleted a stale pending_students row
 * that matched the *email* being submitted. But pending_students also has
 * UNIQUE keys on phone and national_id (uniq_pending_phone /
 * uniq_pending_national_id). So a resubmission (or a second person) using
 * the same phone or National ID under a *different* email used to blow up
 * the INSERT with a raw 23000 integrity-constraint error that the retry
 * loop could never resolve - the user just saw "Database error occurred"
 * with no way to know why.
 *
 * This helper looks up any pending row matching email OR phone OR
 * national_id. If it is still inside its OTP window, registration is
 * blocked with a clear, actionable message. If it has expired, it is
 * safe to discard and registration proceeds normally.
 *
 * @return string|null  A human-readable error message, or null if clear to proceed.
 */
function blockingPendingDuplicate(PDO $pdo, string $email, string $phone, string $nationalId): ?string {
    $stmt = $pdo->prepare("
        SELECT email, phone, national_id, otp_expires
        FROM pending_students
        WHERE email = ? OR phone = ? OR national_id = ?
        ORDER BY otp_expires DESC
        LIMIT 1
    ");
    $stmt->execute([$email, $phone, $nationalId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return null; // nothing pending at all
    }

    $stillOpen = $row['otp_expires'] !== null
        && strtotime($row['otp_expires']) > time();

    if (!$stillOpen) {
        return null; // stale/expired pending row - safe to overwrite below
    }

    if ($row['email'] === $email) {
        return "A verification code was already sent to this email. "
             . "Please check your inbox, or wait a few minutes and try again.";
    }
    if ($row['phone'] === $phone) {
        return "This phone number is already tied to a pending registration. "
             . "Please finish verifying that registration first, or wait for it to expire.";
    }
    return "This National ID/Passport number is already tied to a pending registration. "
         . "Please finish verifying that registration first, or wait for it to expire.";
}

/*  =
   PROCESS FORM
= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register']) && empty($error)) {

    /* =
       CSRF CHECK
    = */
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        die("Invalid CSRF token.");
    }

    $_SESSION['last_register'] = time();
    $_SESSION['register_attempts']++;

    /* =
       SAFE INPUT HANDLING - Personal
    = */
    $firstName  = clean_string($_POST['first_name'] ?? '');
    $lastName   = clean_string($_POST['last_name'] ?? '');
    $gender     = clean_choice($_POST['gender'] ?? '');      // whitelist dropdown - see clean_choice() note
    $dob        = clean_string($_POST['dob'] ?? '');
    $nationalId = clean_string($_POST['national_id'] ?? '');
    $county     = clean_choice($_POST['county'] ?? '');       // whitelist dropdown - handles "Murang'a" correctly

    /* =
       SAFE INPUT HANDLING - Contact & account
    = */
    $email           = strtolower(trim($_POST['email'] ?? ''));
    $phone           = preg_replace('/[^0-9+]/', '', $_POST['phone'] ?? '');
    $passwordRaw     = $_POST['password'] ?? '';
    $passwordConfirm = $_POST['confirm_password'] ?? '';

    /* =
       SAFE INPUT HANDLING - Academic / professional
    = */
    $qualificationLevel = clean_choice($_POST['qualification_level'] ?? '');  // whitelist dropdown - handles apostrophes correctly
    $isProfessional     = isset($_POST['is_professional']) && $_POST['is_professional'] === '1';
    $profession         = clean_string($_POST['profession'] ?? '');
    $professionalRegNo  = clean_string($_POST['professional_reg_no'] ?? '');

    /* =
       SAFE INPUT HANDLING - Finance / referral
    = */
    $kraPin       = strtoupper(clean_string($_POST['kra_pin'] ?? ''));
    // FIX: trim() (inside clean_string) only strips ASCII whitespace, not a
    // non-breaking space (\xA0) - which commonly rides along when a KRA PIN
    // is copy-pasted from a PDF, Word doc, or a chat app. That invisible
    // extra character made an otherwise-correct 11-char PIN fail the regex
    // below with no visible clue why. Strip ALL whitespace (not just at the
    // ends) before validating.
    $kraPin       = preg_replace('/[\s\x{00A0}]+/u', '', $kraPin);
    $referralCode = strtoupper(clean_string($_POST['referral_code'] ?? ''));

    /* =
       CONSENT
    = */
    $termsAccepted        = isset($_POST['terms_accepted']) && $_POST['terms_accepted'] === '1';
    $privacyAccepted      = isset($_POST['privacy_accepted']) && $_POST['privacy_accepted'] === '1';
    $dataConsent          = isset($_POST['data_consent']) && $_POST['data_consent'] === '1';
    $consentPolicyVersion = "STP-2026-v1"; // bump when Terms/Privacy copy changes

    // keep non-sensitive fields so the form can be re-populated on error
    $formData = [
        'first_name' => $firstName, 'last_name' => $lastName, 'gender' => $gender,
        'dob' => $dob, 'national_id' => $nationalId, 'county' => $county,
        'email' => $email, 'phone' => $phone, 'qualification_level' => $qualificationLevel,
        'is_professional' => $isProfessional, 'profession' => $profession,
        'professional_reg_no' => $professionalRegNo, 'kra_pin' => $kraPin,
        'referral_code' => $referralCode,
    ];

    /* =
       EMAIL / HEADER INJECTION PROTECTION
    = */
    if (preg_match("/[\r\n]/", $email)) {
        die("Invalid input detected.");
    }

    /* =
       VALIDATION - required core fields
    = */
    if (!$firstName || !$lastName || !$gender || !$dob || !$nationalId || !$county
        || !$email || !$phone || !$qualificationLevel || !$passwordRaw) {
        $error = "Please complete all required fields.";
    }
    elseif (strlen($firstName) < 2 || strlen($lastName) < 2) {
        $error = "First and last name must be at least 2 characters.";
    }
    elseif (!in_array($gender, $GENDERS, true)) {
        $error = "Please select a valid gender option.";
    }
    elseif (!DateTime::createFromFormat('Y-m-d', $dob)) {
        $error = "Please provide a valid date of birth.";
    }
    elseif (calculateAge($dob) < 18) {
        $error = "You must be at least 18 years old to register for the STP.";
    }
    elseif (strlen($nationalId) < 5 || strlen($nationalId) > 20) {
        $error = "Please provide a valid National ID or Passport number.";
    }
    elseif (!in_array($county, $KENYA_COUNTIES, true)) {
        $error = "Please select a valid county.";
    }
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address.";
    }
    elseif (strlen($phone) < 8) {
        $error = "Invalid phone number.";
    }
    elseif (!in_array($qualificationLevel, $QUALIFICATION_LEVELS, true)) {
        $error = "Please select a valid academic qualification level.";
    }
    elseif ($isProfessional && (!$profession || !$professionalRegNo)) {
        $error = "Please provide your profession and registration/licence number, or uncheck 'practising professional'.";
    }
    elseif ($kraPin !== '' && !isValidKraPin($kraPin)) {
        $error = "KRA PIN format looks invalid (expected e.g. A123456789Z).";
    }
    elseif ($referralCode !== '' && !referralCodeLooksValid($referralCode)) {
        $error = "Referral code format looks invalid.";
    }
    elseif ($referralCode !== '' && !referralCodeExists($pdo, $referralCode)) {
        $error = "That referral code was not recognised.";
    }
    elseif (!$termsAccepted || !$privacyAccepted || !$dataConsent) {
        $error = "You must accept the Terms, Privacy Policy, and Data Processing Consent to continue.";
    }
    elseif (
        strlen($passwordRaw) < 8 ||
        !preg_match('/[A-Z]/', $passwordRaw) ||
        !preg_match('/[0-9]/', $passwordRaw) ||
        !preg_match('/[\W]/', $passwordRaw)
    ) {
        $error = "Password must be 8+ chars, include uppercase, number, and symbol.";
    }
    elseif ($passwordRaw !== $passwordConfirm) {
        // FIX: hash_equals() is for comparing a known secret against
        // untrusted input to avoid timing attacks; here both sides are
        // user-supplied, so a plain comparison is equivalent and clearer.
        $error = "Passwords do not match.";
    }
    else {

        /* =
           CHECK USER EXISTS (email, phone, or national ID) - already-approved accounts
        = */
        $stmt = $pdo->prepare("
            SELECT email, phone FROM users WHERE email=? OR phone=? OR national_id=? LIMIT 1
        ");
        $stmt->execute([$email, $phone, $nationalId]);

        if ($stmt->fetch()) {
            $error = "An account already exists with this email, phone, or National ID.";
        } else {

            /* =
               FIX: check for a *still-valid* pending registration on email,
               phone, OR national_id (not just email) before we touch the
               table, so we can give a clear message instead of letting a
               UNIQUE constraint throw a raw DB error later.
            = */
            $blockMsg = blockingPendingDuplicate($pdo, $email, $phone, $nationalId);

            if ($blockMsg !== null) {
                $error = $blockMsg;
            } else {

                /* =
                   DELETE OLD/EXPIRED PENDING RECORDS FOR THIS EMAIL, PHONE, OR
                   NATIONAL ID (FIX: previously only matched email, which left
                   stale rows with the same phone/national_id behind to collide
                   with the INSERT below).
                = */
                $del = $pdo->prepare("
                    DELETE FROM pending_students
                    WHERE email = ? OR phone = ? OR national_id = ?
                ");
                $del->execute([$email, $phone, $nationalId]);

                /* =
                   PASSWORD HASH (SECURE)
                = */
                $passwordHash = password_hash(
                    $passwordRaw,
                    defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT
                );

                /* =
                   OTP - stored as a hash, never in plain text
                = */
                $otp     = (string) random_int(100000, 999999);
                $otpHash = password_hash($otp, PASSWORD_DEFAULT);
                $created = date("Y-m-d H:i:s");
                $expires = date("Y-m-d H:i:s", strtotime("+10 minutes"));

                /* =
                   INSERT WITH STUDENT NUMBER (retries on duplicate-key race)
                = */
                $inserted  = false;
                $attempts  = 0;
                $studentNo = "";

                while (!$inserted && $attempts < 5) {
                    $attempts++;
                    $studentNo = generateStudentNo($pdo);

                    try {
                        $pdo->beginTransaction();

                        $insert = $pdo->prepare("
                            INSERT INTO pending_students
                            (student_no, first_name, last_name, full_name, gender, dob,
                             national_id, county, email, phone,
                             qualification_level, is_professional, profession, professional_reg_no,
                             kra_pin, referral_code_used,
                             password, otp_hash, otp_attempts, otp_created, otp_expires,
                             terms_accepted_at, privacy_accepted_at, data_consent_at, consent_policy_version,
                             registration_ip)
                            VALUES (?, ?, ?, ?, ?, ?,
                                    ?, ?, ?, ?,
                                    ?, ?, ?, ?,
                                    ?, ?,
                                    ?, ?, 0, ?, ?,
                                    ?, ?, ?, ?,
                                    ?)
                        ");
                        $insert->execute([
                            $studentNo,
                            $firstName,
                            $lastName,
                            $firstName . ' ' . $lastName,
                            $gender,
                            $dob,
                            $nationalId,
                            $county,
                            $email,
                            $phone,
                            $qualificationLevel,
                            $isProfessional ? 1 : 0,
                            $isProfessional ? $profession : null,
                            $isProfessional ? $professionalRegNo : null,
                            $kraPin !== '' ? $kraPin : null,
                            $referralCode !== '' ? $referralCode : null,
                            $passwordHash,
                            $otpHash,
                            $created,
                            $expires,
                            $created, $created, $created, $consentPolicyVersion,
                            clientIp(),
                        ]);

                        $pdo->commit();
                        $inserted = true;

                    } catch (PDOException $e) {
                        if ($pdo->inTransaction()) {
                            $pdo->rollBack();
                        }

                        // Only retry on a student_no collision (a genuine race
                        // condition); any other integrity violation (email/
                        // phone/national_id) will never resolve by retrying
                        // with a new student number, so fail fast with a
                        // useful message instead of burning all 5 attempts.
                        $msg = $e->getMessage();
                        if ($e->getCode() === '23000') {
                            if (stripos($msg, 'student_no') !== false && $attempts < 5) {
                                continue;
                            }
                            if (stripos($msg, 'uniq_pending_email') !== false) {
                                $error = "This email is already tied to a pending registration.";
                            } elseif (stripos($msg, 'uniq_pending_phone') !== false) {
                                $error = "This phone number is already tied to a pending registration.";
                            } elseif (stripos($msg, 'uniq_pending_national_id') !== false) {
                                $error = "This National ID/Passport number is already tied to a pending registration.";
                            } else {
                                $error = "This information is already tied to a pending registration.";
                            }
                            break;
                        }

                        error_log("Registration insert failed: " . $msg);
                        $error = "Database error occurred. Please try again.";
                        break;
                    }
                }

                if ($inserted) {
                    if (sendOTP($email, $firstName, $otp)) {
                        // rotate CSRF token and session id after a state-changing success
                        session_regenerate_id(true);
                        $_SESSION['csrf_token']       = bin2hex(random_bytes(32));
                        $_SESSION['register_attempts'] = 0;
                        header("Location: verify.php?email=" . urlencode($email));
                        exit;
                    } else {
                        $error = "Unable to send OTP email. Please try again.";
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register - CBT-Kenya STP</title>
<style>
/* =====================================================================
   CBT-KENYA BRAND VARIABLES
   NOTE: exact brand hex codes could not be scraped from cbtkenya.org
   (no public style-guide / CSS variables were retrievable). The palette
   below is a placeholder calm, clinical teal/navy scheme appropriate for
   a counselling & mental-health brand. Swap the values below for the
   organisation's official hex codes (and drop the real logo file into
   /assets/logo.png) to make this pixel-accurate to brand guidelines.
===================================================================== */
:root{
    --brand-primary:      #0f6e63;   /* teal - primary CTA / links   */
    --brand-primary-dark: #0b524a;
    --brand-secondary:    #123a5c;   /* deep navy - headers/footers  */
    --brand-accent:       #d6a419;   /* warm gold - highlights       */
    --brand-bg-1:         #0b3d3a;
    --brand-bg-2:         #123a5c;
    --brand-surface:      #ffffff;
    --brand-muted:        #6b7280;
    --brand-error:        #b91c1c;
    --brand-error-bg:     #fee2e2;
    --brand-border:       #e2e8ec;
}

*{box-sizing:border-box;}

body{
    margin:0;
    font-family:'Segoe UI', Arial, sans-serif;
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:30px 15px;
    background: linear-gradient(-45deg, var(--brand-bg-1), var(--brand-secondary), #1c2f4a, var(--brand-primary));
    background-size: 400% 400%;
    animation: bg 14s ease infinite;
}
@keyframes bg{
    0%{background-position:0% 50%;}
    50%{background-position:100% 50%;}
    100%{background-position:0% 50%;}
}

.box{
    width:560px;
    max-width:100%;
    background: rgba(255,255,255,0.97);
    padding:35px;
    border-radius:16px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.35);
    backdrop-filter: blur(10px);
}

.brand-header{
    display:flex;
    flex-direction:column;
    align-items:center;
    margin-bottom:18px;
}
.brand-header img{
    height:52px;
    margin-bottom:10px;
}
.brand-header h2{
    margin:0;
    color:var(--brand-secondary);
    font-weight:700;
    letter-spacing:0.3px;
}
.brand-header p{
    margin:4px 0 0;
    color:var(--brand-muted);
    font-size:13px;
    text-align:center;
}

/* promo / announcement strip - enhancement #1: designated ad space */
.promo-strip{
    background: linear-gradient(135deg, var(--brand-accent), #f0c34a);
    color:#3a2c00;
    font-size:12.5px;
    text-align:center;
    padding:8px 12px;
    border-radius:8px;
    margin-bottom:18px;
    font-weight:600;
}

fieldset{
    border:1px solid var(--brand-border);
    border-radius:10px;
    margin:0 0 16px;
    padding:14px 16px 16px;
}
legend{
    padding:0 8px;
    font-size:13px;
    font-weight:700;
    color:var(--brand-primary-dark);
    text-transform:uppercase;
    letter-spacing:0.4px;
}

label{
    display:block;
    font-size:13px;
    color:#374151;
    margin:8px 0 4px;
    font-weight:600;
}
.hint{
    font-weight:400;
    color:var(--brand-muted);
    font-size:12px;
}

/* required-field marker - shown next to the label of any mandatory field */
.required-mark{
    color:var(--brand-error);
    margin-left:3px;
    font-weight:700;
}

input[type=text], input[type=email], input[type=password], input[type=date], select{
    width:100%;
    padding:11px;
    border:1px solid #ddd;
    border-radius:8px;
    outline:none;
    transition:0.2s;
    font-size:14px;
    background:#f9fafb;
}
input:focus, select:focus{
    border-color: var(--brand-primary);
    box-shadow:0 0 0 3px rgba(15,110,99,0.18);
    background:#fff;
}

.row2{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:12px;
}
@media (max-width:520px){
    .row2{grid-template-columns:1fr;}
}

.checkbox-row{
    display:flex;
    align-items:flex-start;
    gap:8px;
    margin:8px 0;
    font-size:13px;
    color:#374151;
}
.checkbox-row input{width:auto;margin-top:2px;}
.checkbox-row a{color:var(--brand-primary-dark);}

.conditional{
    display:none;
    border-left:3px solid var(--brand-accent);
    padding-left:12px;
    margin-top:6px;
}
.conditional.show{display:block;}

button{
    width:100%;
    padding:13px;
    margin-top:14px;
    background: linear-gradient(135deg, var(--brand-primary), var(--brand-primary-dark));
    color:#fff;
    border:none;
    border-radius:10px;
    cursor:pointer;
    font-weight:bold;
    font-size:15px;
    transition:0.3s;
    box-shadow: 0 10px 20px rgba(0,0,0,0.15);
}
button:hover{transform: scale(1.01);}
button:active{transform: scale(0.99);}

.error{
    color:var(--brand-error);
    text-align:center;
    margin-bottom:14px;
    font-weight:bold;
    background:var(--brand-error-bg);
    padding:10px;
    border-radius:8px;
    border:1px solid #fecaca;
}

.footnote{
    text-align:center;
    font-size:12px;
    color:var(--brand-muted);
    margin-top:14px;
}
.footnote a{color:var(--brand-primary-dark);text-decoration:none;font-weight:600;}
</style>
</head>

<body>

<div class="box">

<div class="brand-header">
    <img src="cbt-ke.png" alt="CBT-Kenya logo">
    <h2>Skills Transfer Program - Registration</h2>
    <p>Training &amp; mentorship for psychology and mental-health professionals</p>
</div>
<?php if($error): ?>
<div class="error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<form method="POST" id="registerForm" novalidate>

    <input type="hidden" name="csrf_token"
        value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

    <fieldset>
        <legend>Personal information</legend>

        <div class="row2">
            <div>
                <label>First Name<span class="required-mark">*</span></label>
                <input type="text" name="first_name" required
                       value="<?= htmlspecialchars($formData['first_name'] ?? '') ?>">
            </div>
            <div>
                <label>Last Name<span class="required-mark">*</span></label>
                <input type="text" name="last_name" required
                       value="<?= htmlspecialchars($formData['last_name'] ?? '') ?>">
            </div>
        </div>

        <div class="row2">
            <div>
                <label>Gender<span class="required-mark">*</span></label>
                <select name="gender" required>
                    <option value="">Select…</option>
                    <?php foreach ($GENDERS as $g): ?>
                        <option value="<?= htmlspecialchars($g) ?>"
                            <?= (($formData['gender'] ?? '') === $g) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($g) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label>Date of Birth<span class="required-mark">*</span></label>
                <input type="date" name="dob" required
                       value="<?= htmlspecialchars($formData['dob'] ?? '') ?>">
            </div>
        </div>

        <label>National ID / Passport Number<span class="required-mark">*</span></label>
        <input type="text" name="national_id" required
               value="<?= htmlspecialchars($formData['national_id'] ?? '') ?>">

        <label>County <span class="hint">(select "Outside Kenya" if applicable)</span><span class="required-mark">*</span></label>
        <select name="county" required>
            <option value="">Select…</option>
            <?php foreach ($KENYA_COUNTIES as $c): ?>
                <option value="<?= htmlspecialchars($c) ?>"
                    <?= (($formData['county'] ?? '') === $c) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($c) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </fieldset>

    <fieldset>
        <legend>Contact &amp; account</legend>

        <label>Email<span class="required-mark">*</span></label>
        <input type="email" name="email" required
               value="<?= htmlspecialchars($formData['email'] ?? '') ?>">

        <label>Phone<span class="required-mark">*</span></label>
        <input type="text" name="phone" required placeholder="+2547XXXXXXXX"
               value="<?= htmlspecialchars($formData['phone'] ?? '') ?>">

        <div class="row2">
            <div>
                <label>Password <span class="hint">(8+ chars, upper, number, symbol)</span><span class="required-mark">*</span></label>
                <input type="password" name="password" required>
            </div>
            <div>
                <label>Confirm Password<span class="required-mark">*</span></label>
                <input type="password" name="confirm_password" required>
            </div>
        </div>
    </fieldset>

    <fieldset>
        <legend>Academic &amp; professional</legend>

        <label>Highest Academic Qualification<span class="required-mark">*</span></label>
        <select name="qualification_level" required>
            <option value="">Select…</option>
            <?php foreach ($QUALIFICATION_LEVELS as $q): ?>
                <option value="<?= htmlspecialchars($q) ?>"
                    <?= (($formData['qualification_level'] ?? '') === $q) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($q) ?>
                </option>
            <?php endforeach; ?>
        </select>

        <div class="checkbox-row">
            <input type="checkbox" id="is_professional" name="is_professional" value="1"
                <?= !empty($formData['is_professional']) ? 'checked' : '' ?>>
            <label for="is_professional" style="margin:0;font-weight:600;">
                I am already a practising, licensed professional
            </label>
        </div>

        <div class="conditional" id="professionalFields">
            <label>Profession<span class="required-mark">*</span></label>
            <input type="text" name="profession" placeholder="e.g. Clinical Psychologist"
                   value="<?= htmlspecialchars($formData['profession'] ?? '') ?>">
            <label>Professional Registration / Licence Number<span class="required-mark">*</span></label>
            <input type="text" name="professional_reg_no"
                   value="<?= htmlspecialchars($formData['professional_reg_no'] ?? '') ?>">
        </div>
    </fieldset>

    <fieldset>
        <legend>Billing &amp; referral <span class="hint">(optional)</span></legend>

        <label>KRA PIN <span class="hint"></span></label>
        <input type="text" name="kra_pin" placeholder="A123456789Z" maxlength="11"
               value="<?= htmlspecialchars($formData['kra_pin'] ?? '') ?>">

        <label>Referral Code <span class="hint"></span></label>
        <input type="text" name="referral_code" placeholder="e.g. ALUM2026"
               value="<?= htmlspecialchars($formData['referral_code'] ?? '') ?>">
    </fieldset>

    <fieldset>
        <legend>Consent<span class="required-mark">*</span></legend>

        <div class="checkbox-row">
            <input type="checkbox" id="terms_accepted" name="terms_accepted" value="1" required
                <?= !empty($formData['terms_accepted']) ? 'checked' : '' ?>>
            <label for="terms_accepted" style="margin:0;font-weight:400;">
                I agree to the <a href="/terms.php" target="_blank">Terms and Conditions</a><span class="required-mark">*</span>
            </label>
        </div>
        <div class="checkbox-row">
            <input type="checkbox" id="privacy_accepted" name="privacy_accepted" value="1" required
                <?= !empty($formData['privacy_accepted']) ? 'checked' : '' ?>>
            <label for="privacy_accepted" style="margin:0;font-weight:400;">
                I acknowledge the <a href="/privacy.php" target="_blank">Privacy Policy</a><span class="required-mark">*</span>
            </label>
        </div>
        <div class="checkbox-row">
            <input type="checkbox" id="data_consent" name="data_consent" value="1" required
                <?= !empty($formData['data_consent']) ? 'checked' : '' ?>>
            <label for="data_consent" style="margin:0;font-weight:400;">
                I consent to the processing of my personal information for STP training,
                mentorship, certification, and compliance purposes<span class="required-mark">*</span>
            </label>
        </div>
    </fieldset>

    <button type="submit" name="register">Create Account</button>

    <p class="hint" style="text-align:center;margin-top:10px;">
        <span class="required-mark">*</span> Required field
    </p>
</form>

<p class="footnote">Already have an account? <a href="index.php">Sign in</a></p>

</div>

<script>
// Reveal professional-registration fields only when relevant - keeps the
// form lean for trainees who aren't yet licensed practitioners.
const proCheckbox = document.getElementById('is_professional');
const proFields = document.getElementById('professionalFields');
function syncProFields(){
    proFields.classList.toggle('show', proCheckbox.checked);
}
proCheckbox.addEventListener('change', syncProFields);
syncProFields();

// Client-side password confirmation nudge (server still re-validates).
document.getElementById('registerForm').addEventListener('submit', function(e){
    const pw = document.querySelector('input[name=password]').value;
    const cpw = document.querySelector('input[name=confirm_password]').value;
    if (pw !== cpw) {
        e.preventDefault();
        alert('Passwords do not match.');
    }
});
</script>

</body>
</html>