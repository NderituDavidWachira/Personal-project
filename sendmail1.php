<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

require __DIR__ . '/PHPMailer/PHPMailer-master/src/Exception.php';
require __DIR__ . '/PHPMailer/PHPMailer-master/src/PHPMailer.php';
require __DIR__ . '/PHPMailer/PHPMailer-master/src/SMTP.php';


function sendOTP($email, $name, $otp)
{
    $mail = new PHPMailer(true);

    try {

        /* =
           SMTP CONNECTION - cPanel mailbox on this domain's own server
        = */
        $mail->isSMTP();
        $mail->Host       = 'mail.cbtkenya.org';   // <-- confirm via cPanel "Connect Devices"
        $mail->SMTPAuth   = true;
        $mail->Username   = 'info@cbtkenya.org';   // <-- full mailbox address
        $mail->Password   = 'David0001*'; // <-- cPanel mailbox password, NOT a Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // SSL wrapper
        $mail->Port       = 465;                    // cPanel default for SMTPS
       
        $mail->SMTPDebug   = SMTP::DEBUG_SERVER;
        $mail->Debugoutput = function ($str, $level) {
            error_log("PHPMailer SMTP debug: " . trim($str));
        };

        /* =
           MESSAGE
        = */
        $mail->setFrom('info@cbtkenya.org', 'Skills Transfer Program');
        $mail->addAddress($email, $name);
        $mail->addReplyTo('info@cbtkenya.org', 'CBT-Kenya STP');

        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';
        $mail->Subject = "Your OTP Verification Code";

        $safeName = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        $safeOtp  = htmlspecialchars($otp, ENT_QUOTES, 'UTF-8');

        $mail->Body = "
        <div style='font-family:Arial,sans-serif'>
            <h2>Skills Transfer Program</h2>

            <p>Hello <b>{$safeName}</b>,</p>

            <p>Your OTP code is:</p>

            <h1 style='color:#28a745'>{$safeOtp}</h1>

            <p>This code expires in 10 minutes.</p>

            <p><b>Do not share this OTP with anyone.</b></p>
        </div>
        ";

        $mail->AltBody =
            "Hello {$name}, Your OTP code is {$otp}. This code expires in 10 minutes.";

        return $mail->send();

    } catch (Exception $e) {

        // $mail->ErrorInfo holds PHPMailer's own message; the debug output
        // above (if enabled) will additionally show the raw SMTP transcript.
        error_log("sendOTP failed: " . $mail->ErrorInfo);
        return false;
    }
}