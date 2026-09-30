<?php
/* Expects: $participant, $courseTitle, $issuedDate, $certificateNoDisplay, $verifyUrl */
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Certificate - <?= htmlspecialchars($participant) ?> - <?= htmlspecialchars(CERT_ORG_NAME) ?></title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800&family=Inter:wght@400;500;600;700&family=Playfair+Display:wght@700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
:root{--teal:#7CB342;--teal-dark:#558B2F;--navy:#33691E;--gold:#F2A93C;--gold-dark:#D98A1F;--gray-100:#f4f7f6;--gray-500:#64807d;--gray-900:#12211f;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--gray-100);font-family:'Inter',Arial,sans-serif;color:var(--gray-900);display:flex;flex-direction:column;align-items:center;padding:32px 16px;}
.toolbar{display:flex;gap:12px;margin-bottom:22px;flex-wrap:wrap;justify-content:center;}
.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 20px;border-radius:10px;border:none;cursor:pointer;font-size:.92rem;font-weight:600;text-decoration:none;background:var(--teal);color:#fff;}
.btn.gold{background:var(--gold);color:var(--navy);}
.btn:hover{opacity:.92;}
.certificate{width:100%;max-width:940px;aspect-ratio:1.414/1;background:#fff;position:relative;border:14px solid var(--navy);outline:3px solid var(--gold);outline-offset:-24px;padding:56px 60px;display:flex;flex-direction:column;align-items:center;text-align:center;box-shadow:0 10px 40px rgba(51,105,30,.18);}
.cert-org{font-family:'Poppins',sans-serif;font-weight:800;letter-spacing:1px;color:var(--teal);font-size:1.05rem;text-transform:uppercase;}
.cert-program{color:var(--gray-500);font-size:.82rem;letter-spacing:2px;text-transform:uppercase;margin-bottom:22px;}
.cert-heading{font-family:'Playfair Display',serif;font-weight:800;font-size:2.5rem;color:var(--navy);margin-bottom:6px;}
.cert-sub{color:var(--gray-500);font-size:.95rem;margin-bottom:26px;}
.cert-name{font-family:'Playfair Display',serif;font-weight:800;font-size:2.1rem;color:var(--gold-dark);border-bottom:2px solid var(--gold);padding-bottom:10px;margin-bottom:22px;max-width:80%;}
.cert-body{font-size:1rem;max-width:640px;line-height:1.6;margin-bottom:26px;}
.cert-course{font-weight:700;color:var(--teal-dark);}
.cert-footer{margin-top:auto;width:100%;display:flex;justify-content:space-between;align-items:flex-end;gap:20px;}
.cert-footer-block{text-align:center;}
.cert-footer-label{font-size:.76rem;color:var(--gray-500);text-transform:uppercase;letter-spacing:1px;}
.cert-footer-value{font-weight:700;color:var(--navy);font-size:.9rem;margin-top:4px;}
#qrcode{display:inline-block;margin-top:6px;}
#qrcode img{display:block;}
.print-hint{color:var(--gray-500);font-size:.82rem;margin-top:18px;text-align:center;max-width:520px;word-break:break-all;}
@page{size:A4 landscape;margin:0;}
@media print{body{padding:0;background:#fff;}.toolbar,.print-hint{display:none!important;}.certificate{box-shadow:none;max-width:none;height:100vh;margin:0;}}
@media (max-width:700px){.certificate{padding:32px 22px;aspect-ratio:auto;}.cert-heading{font-size:1.7rem;}.cert-name{font-size:1.4rem;}.cert-footer{flex-direction:column;align-items:center;gap:16px;}}
</style>
</head>
<body>
<div class="toolbar">
    <button class="btn gold" onclick="window.print()">&#128190; Download / Print as PDF</button>
    <a class="btn" href="student.php">&#8592; Back to Dashboard</a>
</div>

<div class="certificate">
    <div class="cert-org"><?= htmlspecialchars(CERT_ORG_NAME) ?></div>
    <div class="cert-program"><?= htmlspecialchars(CERT_PROGRAM_NAME) ?></div>
    <div class="cert-heading">Certificate of Completion</div>
    <div class="cert-sub">This certificate is proudly presented to</div>
    <div class="cert-name"><?= htmlspecialchars($participant) ?></div>
    <div class="cert-body">
        for successfully completing all requirements of the course
        <br><span class="cert-course"><?= htmlspecialchars($courseTitle) ?></span>
        <br>under the <?= htmlspecialchars(CERT_ORG_NAME) ?> <?= htmlspecialchars(CERT_PROGRAM_NAME) ?>.
    </div>
    <div class="cert-footer">
        <div class="cert-footer-block">
            <div class="cert-footer-label">Date Issued</div>
            <div class="cert-footer-value"><?= htmlspecialchars($issuedDate) ?></div>
        </div>
        <div class="cert-footer-block">
            <div id="qrcode"></div>
            <div class="cert-footer-label" style="margin-top:6px;">Scan to Verify</div>
        </div>
        <div class="cert-footer-block">
            <div class="cert-footer-label">Certificate No.</div>
            <div class="cert-footer-value"><?= htmlspecialchars($certificateNoDisplay) ?></div>
        </div>
    </div>
</div>

<p class="print-hint">Verify this certificate any time with the certificate number above, or by scanning the QR code, at <?= htmlspecialchars($verifyUrl) ?></p>

<script>
new QRCode(document.getElementById("qrcode"), {
    text: <?= json_encode($verifyUrl, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>,
    width: 84, height: 84, colorDark: "#33691E", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M
});
</script>
</body>
</html>