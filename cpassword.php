<?php
session_start();
include "db.php";

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    die("Access denied. Please log in.");
}

$me = $pdo->prepare("SELECT role FROM users WHERE id = ?");
$me->execute([$_SESSION['user_id']]);
$me_row = $me->fetch();

if (!$me_row || $me_row['role'] !== 'admin') {
    http_response_code(403);
    die("Access denied. Admins only.");
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* -
   HANDLE FORM SUBMISSIONS
- */
$message      = '';
$message_type = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
        $message      = 'Invalid request token. Please try again.';
        $message_type = 'error';
        goto render;
    }

    // --- ASSIGN TRAINER ---
    if (isset($_POST['assign_teacher'])) {
        $course_id  = (int)($_POST['course_id']  ?? 0);
        $teacher_id = (int)($_POST['teacher_id'] ?? 0);

        if (!$course_id || !$teacher_id) {
            $message      = 'Please select both a course and a trainer.';
            $message_type = 'error';
            goto render;
        }

        /* Validate course */
        $cs = $pdo->prepare("SELECT id, title FROM courses WHERE id = ?");
        $cs->execute([$course_id]);
        $course = $cs->fetch();

        if (!$course) {
            $message      = 'Course not found.';
            $message_type = 'error';
            goto render;
        }

        /* Validate teacher */
        $ts = $pdo->prepare("SELECT id, full_name FROM users WHERE id = ? AND role = 'teacher'");
        $ts->execute([$teacher_id]);
        $teacher = $ts->fetch();

        if (!$teacher) {
            $message      = 'Invalid trainer selected.';
            $message_type = 'error';
            goto render;
        }

        /* Check if this specific pair already exists */
        $ck = $pdo->prepare("SELECT id FROM course_teachers WHERE course_id = ? AND teacher_id = ?");
        $ck->execute([$course_id, $teacher_id]);
        $existing = $ck->fetch();

        $cname = htmlspecialchars($course['title']);
        $tname = htmlspecialchars($teacher['full_name']);

        if ($existing) {
            $message      = "$tname is already assigned to <strong>$cname</strong>.";
            $message_type = 'error';
        } else {
            $ins = $pdo->prepare("INSERT INTO course_teachers (course_id, teacher_id) VALUES (?, ?)");
            $ins->execute([$course_id, $teacher_id]);

            $message = "$tname successfully assigned to <strong>$cname</strong>.";
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $csrf = $_SESSION['csrf_token'];
        }
    }

    // --- REMOVE ASSIGNMENT ---
    if (isset($_POST['remove_assignment'])) {
        $assignment_id = (int)($_POST['assignment_id'] ?? 0);

        $del = $pdo->prepare("DELETE FROM course_teachers WHERE id = ?");
        $del->execute([$assignment_id]);

        $message = 'Trainer unassigned successfully.';
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $csrf = $_SESSION['csrf_token'];
    }
}

render:
/* -
   LOAD DROPDOWNS & LIST
- */
$courses  = $pdo->query("SELECT id, title FROM courses ORDER BY title ASC")->fetchAll();
$teachers = $pdo->query("SELECT id, full_name FROM users WHERE role = 'teacher' ORDER BY full_name ASC")->fetchAll();

/* Current assignments */
$assignments = $pdo->query("
    SELECT ct.id AS assignment_id, c.title AS course_title, u.full_name AS teacher_name, ct.assigned_at
    FROM course_teachers ct
    JOIN courses c ON c.id = ct.course_id
    JOIN users u   ON u.id = ct.teacher_id
    ORDER BY ct.assigned_at DESC, c.title ASC
")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Assign Trainer Admin</title>
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --bg:      #f7f8f5;
    --surface: #ffffff;
    --surf2:   #f2f6ea;
    --border:  rgba(43,43,61,0.10);
    --text:    #2b2b3d;
    --muted:   #6b7280;
    --accent:  #8bc53f;
    --acc2:    #7cb342;
    --orange:  #f5a623;
    --green:   #8bc53f;
    --red:     #dc2626;
    --r-sm:    8px;
    --r-md:    14px;
    --r-lg:    20px;
}
body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, 'Segoe UI', sans-serif;
    font-size: 15px;
    line-height: 1.6;
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 48px 20px 80px;
}
.wrap { width: 100%; max-width: 680px; }

.page-header { margin-bottom: 32px; }
.eyebrow {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 11px; font-weight: 600; letter-spacing: 0.8px;
    text-transform: uppercase; color: var(--acc2);
    margin-bottom: 10px;
}
.eyebrow::before {
    content: '';
    display: block;
    width: 6px; height: 6px;
    background: var(--orange); border-radius: 2px;
}
.page-header h1 { font-size: 26px; font-weight: 700; line-height: 1.2; color: var(--text); }
.page-header p  { color: var(--muted); font-size: 14px; margin-top: 6px; }

.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    overflow: hidden;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(43,43,61,0.06);
}
.card-body { padding: 28px; }

.alert {
    display: flex; align-items: flex-start; gap: 12px;
    padding: 14px 16px; border-radius: var(--r-sm);
    font-size: 13px; line-height: 1.5;
    margin-bottom: 24px;
}
.alert-success {
    background: rgba(34,197,94,0.1);
    border: 1px solid rgba(34,197,94,0.25);
    color: #15803d;
}
.alert-error {
    background: rgba(220,38,38,0.08);
    border: 1px solid rgba(220,38,38,0.25);
    color: #b91c1c;
}
.alert-icon { font-size: 16px; flex-shrink: 0; margin-top: 1px; }

.field { margin-bottom: 20px; }
.field label {
    display: block; font-size: 12px; font-weight: 600;
    color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.5px; margin-bottom: 8px;
}
.field select {
    width: 100%;
    background: var(--surf2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    padding: 11px 14px;
    font-size: 14px;
    font-family: inherit;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%236b7280' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 12px center;
    padding-right: 36px;
    cursor: pointer;
    transition: border-color 0.15s;
}
.field select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(139,197,63,0.25);
}
.field select option { background: #ffffff; }

.divider {
    height: 1px; background: var(--border);
    margin: 24px 0;
}

.btn-submit {
    width: 100%;
    padding: 13px;
    background: var(--orange);
    color: #fff;
    border: none;
    border-radius: var(--r-sm);
    font-size: 14px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: background 0.15s, transform 0.1s;
    display: flex; align-items: center; justify-content: center; gap: 8px;
}
.btn-submit:hover  { background: #dd9114; }
.btn-submit:active { transform: scale(0.98); }

.section-label {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.6px; color: var(--muted);
    padding: 18px 24px 12px;
    border-bottom: 1px solid var(--border);
}
.assign-table { width: 100%; border-collapse: collapse; }
.assign-table th {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--muted);
    padding: 10px 20px; text-align: left;
    border-bottom: 1px solid var(--border);
}
.assign-table td {
    padding: 12px 20px;
    font-size: 13px;
    border-bottom: 1px solid rgba(43,43,61,0.06);
    vertical-align: middle;
}
.assign-table tr:last-child td { border-bottom: none; }
.assign-table tr:hover td { background: var(--surf2); }
.pill {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px; font-weight: 600;
    background: rgba(139,197,63,0.15);
    color: #5a8a1f;
    border: 1px solid rgba(139,197,63,0.35);
}
.assign-date { color: var(--muted); font-size: 12px; }
.btn-remove {
    background: none; border: none; color: var(--red);
    cursor: pointer; font-size: 12px; padding: 4px 8px;
    border-radius: var(--r-sm);
}
.btn-remove:hover { background: rgba(220,38,38,0.1); }
.no-data { padding: 24px; text-align: center; color: var(--muted); font-size: 13px; }

.back-link {
    display: inline-flex; align-items: center; gap: 6px;
    color: var(--muted); font-size: 13px;
    margin-top: 20px; text-decoration: none;
    transition: color 0.15s;
}
.back-link:hover { color: var(--acc2); }
</style>
</head>
<body>
<div class="wrap">

    <!-- Header -->
    <div class="page-header">
        <div class="eyebrow">Admin Panel</div>
        <h1>Assign Trainer</h1>
        <p>Assign multiple trainers to courses and multiple courses to trainers.</p>
    </div>

    <!-- Form card -->
    <div class="card">
        <div class="card-body">

            <!-- Alert message -->
            <?php if (!empty($message)): ?>
            <div class="alert alert-<?= $message_type ?>">
                <span class="alert-icon"><?= $message_type === 'success' ? '✓' : '⚠' ?></span>
                <span><?= $message ?></span>
            </div>
            <?php endif; ?>

            <form method="POST" action="" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">

                <!-- Course -->
                <div class="field">
                    <label for="course_id">Course</label>
                    <select name="course_id" id="course_id" required>
                        <option value="">Select a course…</option>
                        <?php foreach ($courses as $c): ?>
                            <option value="<?= (int)$c['id'] ?>"
                                <?= ((int)($_POST['course_id'] ?? 0) === (int)$c['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($c['title']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <!-- Trainer -->
                <div class="field">
                    <label for="teacher_id">Trainer</label>
                    <select name="teacher_id" id="teacher_id" required>
                        <option value="">Select a trainer…</option>
                        <?php foreach ($teachers as $t): ?>
                            <option value="<?= (int)$t['id'] ?>"
                                <?= ((int)($_POST['teacher_id'] ?? 0) === (int)$t['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($t['full_name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="divider"></div>

                <button type="submit" name="assign_teacher" class="btn-submit">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                    Assign Trainer to Course
                </button>
            </form>

        </div>
    </div>

    <!-- Assignments list -->
    <div class="card">
        <div class="section-label">Current Assignments</div>
        <?php if (count($assignments) > 0): ?>
        <table class="assign-table">
            <thead>
                <tr>
                    <th>Course</th>
                    <th>Trainer</th>
                    <th>Assigned</th>
                    <th style="text-align: right;">Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($assignments as $row): ?>
                <tr>
                    <td><?= htmlspecialchars($row['course_title']) ?></td>
                    <td><span class="pill"><?= htmlspecialchars($row['teacher_name']) ?></span></td>
                    <td class="assign-date">
                        <?= !empty($row['assigned_at']) ? date('M j, Y', strtotime($row['assigned_at'])) : '—' ?>
                    </td>
                    <td style="text-align: right;">
                        <form method="POST" action="" onsubmit="return confirm('Remove this trainer from the course?');" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                            <input type="hidden" name="assignment_id" value="<?= (int)$row['assignment_id'] ?>">
                            <button type="submit" name="remove_assignment" class="btn-remove" title="Remove assignment">Remove</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
            <div class="no-data">No assignments yet.</div>
        <?php endif; ?>
    </div>

    <a href="Admin.php" class="back-link">
        ← Back to dashboard
    </a>

</div>
</body>
</html>