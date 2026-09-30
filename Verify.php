<?php
/* Expects: $verifyCodeParam, $vSearched, $vCert, $vCourseTitle */
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify Certificate - <?= htmlspecialchars(CERT_ORG_NAME) ?></title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--teal:#7CB342;--navy:#33691E;--gray-100:#f4f7f6;--gray-500:#64807d;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--gray-100);font-family:'Inter',Arial,sans-serif;color:#12211f;display:flex;justify-content:center;padding:48px 16px;}
.wrap{width:100%;max-width:520px;}
.card{background:#fff;border-radius:16px;padding:32px;box-shadow:0 4px 20px rgba(51,105,30,.1);}
h1{font-family:'Poppins',sans-serif;font-size:1.3rem;color:var(--navy);margin-bottom:6px;}
p.sub{color:var(--gray-500);font-size:.9rem;margin-bottom:22px;}
.form-group{display:flex;gap:10px;}
input[type=text]{flex:1;padding:12px 14px;border:1px solid #e3ebe9;border-radius:9px;font-size:.95rem;}
button{padding:12px 18px;border:none;border-radius:9px;background:var(--teal);color:#fff;font-weight:700;cursor:pointer;}
.result{margin-top:24px;padding:18px;border-radius:12px;}
.result.valid{background:#d1fae5;border:1px solid #6ee7b7;}
.result.invalid{background:#fee2e2;border:1px solid #fca5a5;}
.result h3{font-size:1rem;margin-bottom:10px;}
.result .row{display:flex;justify-content:space-between;gap:12px;font-size:.88rem;padding:4px 0;}
.result .row span:first-child{color:var(--gray-500);}
.result .row span:last-child{font-weight:700;color:var(--navy);text-align:right;}
</style>
</head>
<body>
<div class="wrap"><div class="card">
    <h1>Certificate Verification</h1>
    <p class="sub"><?= htmlspecialchars(CERT_ORG_NAME) ?> <?= htmlspecialchars(CERT_PROGRAM_NAME) ?> - confirm the authenticity of a certificate.</p>

    <form method="GET" class="form-group">
        <input type="hidden" name="action" value="verify">
        <input type="text" name="code" placeholder="e.g. CBT-STP-2026-AB12CD34" value="<?= htmlspecialchars($verifyCodeParam) ?>" required>
        <button type="submit">Verify</button>
    </form>

    <?php if ($vSearched): ?>
        <?php if ($vCert): ?>
            <div class="result valid">
                <h3>&#9989; Valid Certificate</h3>
                <div class="row"><span>Participant</span><span><?= htmlspecialchars($vCert['full_name'] ?? '') ?></span></div>
                <div class="row"><span>Course</span><span><?= htmlspecialchars($vCourseTitle) ?></span></div>
                <div class="row"><span>Issued</span><span><?= !empty($vCert['issued_at']) ? date('d F Y', strtotime($vCert['issued_at'])) : '' ?></span></div>
                <div class="row"><span>Certificate No.</span><span><?= htmlspecialchars($vCert['certificate_code']) ?></span></div>
            </div>
        <?php else: ?>
            <div class="result invalid">
                <h3>&#10060; Not Found</h3>
                <p style="font-size:.88rem;color:#991b1b;">No certificate matches that number. Please double-check and try again.</p>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div></div>
</body>
</html>