<?php
/**
 * config.php - central configuration (payments, branding).
 * Secrets come from environment variables or config.local.php (never commit that file).
 */
function cfg(string $key, $default = '')
{
    static $local = null;
    if ($local === null) {
        $file  = __DIR__ . '/config.local.php';
        $local = is_file($file) ? (require $file) : [];
    }
    $env = getenv($key);
    return $env !== false ? $env : ($local[$key] ?? $default);
}

/* ---- Branding ---- */
define('CERT_ORG_NAME', 'CBT-Kenya');
define('CERT_PROGRAM_NAME', 'Skills Transfer Program');

/* ---- Bank transfer ---- */
define('BANK_NAME',           cfg('BANK_NAME', 'Your Bank Name Ltd.'));
define('BANK_ACCOUNT_NAME',   cfg('BANK_ACCOUNT_NAME', 'Account name'));
define('BANK_ACCOUNT_NUMBER', cfg('BANK_ACCOUNT_NUMBER', '0000000000'));
define('BANK_BRANCH',         cfg('BANK_BRANCH', 'Main Branch'));
define('BANK_SWIFT_CODE',     cfg('BANK_SWIFT_CODE', 'XXXXXXXX'));

/* ---- Manual Paybill ---- */
define('PAYBILL_NAME',           cfg('PAYBILL_NAME', 'LMS Paybill'));
define('PAYBILL_NUMBER',         cfg('PAYBILL_NUMBER', '522533'));
define('PAYBILL_ACCOUNT_NUMBER', cfg('PAYBILL_ACCOUNT_NUMBER', '7669627'));




/* ---- KCB Buni Sandbox ---- */
define('KCB_ENV', 'sandbox');

define('KCB_CONSUMER_KEY',    'DsEV7sC_OwfPLFYiLYlzIBmFZr0a');
define('KCB_CONSUMER_SECRET', 'hn0uDJxeAnmyfFMcpwZYjPKFRVx9pe9IIGqkAYkAvfQa');
define('KCB_ORG_SHORT_CODE',  '522522');

// 1. Official token endpoint
define('KCB_AUTH_URL', 'https://accounts.buni.kcbgroup.com/oauth2/token');

// 2. Exact STK endpoint from your Try Out console
define('KCB_STK_URL',  'https://uat.buni.kcbgroup.com/mm/api/request/1.0.0/stkpush');

// Callback URL
define('KCB_CALLBACK_TOKEN', 'cbt_ke_sec_token_98234');
define('KCB_CALLBACK_URL',   'https://app.cbtkenya.org/kcb_callback.php?token=' . urlencode(KCB_CALLBACK_TOKEN));
define('KCB_SSL_VERIFY',     false);
