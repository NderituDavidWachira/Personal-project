<?php
session_start();
include "db.php";

if (isset($_POST['submit_ticket'])) {
    /* ====
       GET LOGGED IN USER
    ==== */
    $user_id = $_SESSION['user_id'] ?? null;
    if (!$user_id) {
        header("Location: index.php");
        exit();
    }
    $user_id = (int) $user_id;
    if (
        empty($_POST['csrf_token']) ||
        empty($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        http_response_code(403);
        die("Invalid CSRF token. Request blocked.");
    }
    $type  = trim(strip_tags($_POST['type']    ?? ''));
    $subject = trim(strip_tags($_POST['subject'] ?? ''));
    $message = trim(strip_tags($_POST['message'] ?? ''));
    $valid_types = ['academic', 'technical', 'attendance', 'general'];
    /* ====
       VALIDATION
    ==== */
    if ($type === '' || $subject === '' || $message === '' || !in_array($type, $valid_types, true)) {
        $_SESSION['flash'] = "Please fill in all fields with a valid ticket type.";
        $_SESSION['active_section'] = 'ticket';
        header("Location: student.php");
        exit();
    }

    /* ====
       CHECK IF USER EXISTS
    ==== */
    $check = $pdo->prepare("SELECT id FROM users WHERE id = ? LIMIT 1");
    $check->execute([$user_id]);
    $userExists = (bool) $check->fetch();

    if (!$userExists) {
        session_unset();
        session_destroy();
        header("Location: index.php");
        exit();
    }

    /* ====
       INSERT TICKET 
    ==== */
    try {
        $stmt = $pdo->prepare("
            INSERT INTO tickets (user_id, type, subject, message, status)
            VALUES (?, ?, ?, ?, 'open')
        ");
        $stmt->execute([$user_id, $type, $subject, $message]);

        $_SESSION['flash'] = "Ticket submitted successfully. Our team will respond shortly.";
        $_SESSION['active_section'] = 'ticket';
        header("Location: student.php");
        exit();
    } catch (PDOException $e) {
        error_log("Ticket insert failed: " . $e->getMessage());
        $_SESSION['flash'] = "Something went wrong while submitting your ticket. Please try again.";
        $_SESSION['active_section'] = 'ticket';
        header("Location: student.php");
        exit();
    }
}
header("Location: student.php");
exit();