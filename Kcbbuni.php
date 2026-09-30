<?php
/**
 * Kcbbuni.php - Thin client for the KCB Buni M-Pesa Express (STK) API.
 */
final class KcbBuni
{
    private static ?string $token = null;
    private static int $tokenExpires = 0;

    /**
     * Normalizes phone numbers:
     * 07XXXXXXXX / +2547XXXXXXXX / 7XXXXXXXX (also 01XXXXXXXX) -> 254XXXXXXXX
     * Returns null if invalid.
     */
    public static function normalizePhone(string $phone): ?string
    {
        $d = preg_replace('/\D/', '', $phone);
        if (preg_match('/^(?:254|0)?([17]\d{8})$/', $d, $m)) {
            return '254' . $m[1];
        }
        return null;
    }

    /**
     * Internal cURL wrapper
     */
    private static function request(string $url, array $headers, $payload = null, bool $isJson = true): array
    {
        $sslVerify = defined('KCB_SSL_VERIFY') ? (bool) KCB_SSL_VERIFY : false;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_SSL_VERIFYPEER => $sslVerify,
            CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
        ]);

        if ($payload !== null) {
            $postFields = $isJson ? json_encode($payload) : $payload;
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        }

        $body = curl_exec($ch);
        $err  = curl_error($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ['body' => $body, 'error' => $err, 'http' => $code];
    }

    /**
     * Fetches or reuses OAuth Bearer Token from KCB Buni
     */
    public static function accessToken(): ?string
    {
        if (self::$token && time() < self::$tokenExpires) {
            return self::$token;
        }

        if (!defined('KCB_CONSUMER_KEY') || !defined('KCB_CONSUMER_SECRET') || !defined('KCB_AUTH_URL')) {
            error_log('KCB Config Error: KCB_CONSUMER_KEY, KCB_CONSUMER_SECRET, or KCB_AUTH_URL is undefined.');
            return null;
        }

        $headers = [
            'Authorization: Basic ' . base64_encode(KCB_CONSUMER_KEY . ':' . KCB_CONSUMER_SECRET),
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json',
        ];

        // WSO2/KCB requires the grant_type in the POST payload
        $r = self::request(KCB_AUTH_URL, $headers, 'grant_type=client_credentials', false);

        if ($r['error'] || $r['http'] < 200 || $r['http'] >= 300) {
            error_log('KCB token failure: http=' . $r['http'] . ' err=' . $r['error'] . ' raw=' . substr((string) $r['body'], 0, 300));
            return null;
        }

        $data = json_decode((string) $r['body'], true);
        if (empty($data['access_token'])) {
            error_log('KCB token parse error: access_token missing in ' . substr((string) $r['body'], 0, 300));
            return null;
        }

        self::$token        = $data['access_token'];
        self::$tokenExpires = time() + max(60, (int) ($data['expires_in'] ?? 3600) - 60);

        return self::$token;
    }

    /**
     * Initiates STK Push
     *
     * @return array{ok:bool,message:string,checkoutRequestId:?string,raw:string}
     */
    public static function stkPush(string $msisdn, float $amount, string $reference, string $description): array
    {
        $fail = fn(string $m, string $raw = '') => [
            'ok'                => false,
            'message'           => $m,
            'checkoutRequestId' => null,
            'raw'               => $raw,
        ];

        $token = self::accessToken();
        if (!$token) {
            return $fail('Unable to authenticate with the KCB gateway.');
        }

        if (!defined('KCB_STK_URL') || !defined('KCB_CALLBACK_URL')) {
            return $fail('KCB configuration settings are incomplete in Config.php.');
        }

        $isSandbox = !defined('KCB_ENV') || strtolower(KCB_ENV) === 'sandbox';
        $shortCode = defined('KCB_ORG_SHORT_CODE') ? (string) KCB_ORG_SHORT_CODE : '';
        $passKey   = defined('KCB_ORG_PASSKEY') ? (string) KCB_ORG_PASSKEY : '';

        // Schema expected by /mm/api/request/1.0.0/stkpush
        // In Sandbox with sharedShortCode: true, orgShortCode and orgPassKey MUST be empty strings.
        $payload = [
            'phoneNumber'            => (string) $msisdn,
            'amount'                 => (string) ((int) round($amount)),
            'invoiceNumber'          => substr($reference, 0, 30),
            'sharedShortCode'        => $isSandbox ? true : false,
            'orgShortCode'           => $isSandbox ? '' : $shortCode,
            'orgPassKey'             => $isSandbox ? '' : $passKey,
            'callbackUrl'            => (string) KCB_CALLBACK_URL,
            'transactionDescription' => substr($description, 0, 50),
        ];

        $r = self::request(KCB_STK_URL, [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json',
            'Accept: application/json',
        ], $payload, true);

        if (!empty($r['error'])) {
            return $fail('Gateway connection error: ' . $r['error'], (string) $r['body']);
        }

        $data = json_decode((string) $r['body'], true) ?: [];

        // Check status code and descriptions
        $statusCode = (string) ($data['header']['statusCode'] ?? $data['response']['statusCode'] ?? '');
        $statusDesc = strtolower((string) ($data['header']['statusDescription'] ?? $data['response']['statusDescription'] ?? ''));

        // Identify checkout request ID from standard or wrapped structures
        $checkoutId = $data['response']['CheckoutRequestID']
            ?? $data['response']['checkoutRequestId']
            ?? $data['CheckoutRequestID']
            ?? $data['checkoutRequestId']
            ?? null;

        // In KCB Buni, 0 or 100 or 'success' indicates the STK prompt was handed off to the telco
        $isSuccessful = in_array($statusCode, ['0', '100'], true) 
                     || strpos($statusDesc, 'success') !== false
                     || !empty($checkoutId);

        if ($r['http'] >= 200 && $r['http'] < 300 && $isSuccessful) {
            return [
                'ok'                => true,
                'message'           => 'STK push sent successfully.',
                'checkoutRequestId' => (string) ($checkoutId ?: ('KCB_' . time())),
                'raw'               => (string) $r['body'],
            ];
        }

        $reason = $data['header']['statusDescription']
            ?? $data['response']['statusDescription']
            ?? $data['errorMessage']
            ?? $data['message']
            ?? 'The gateway rejected the request.';

        return $fail((string) $reason, (string) $r['body']);
    }

    /**
     * Extracts a normalized result from an incoming webhook/callback body
     */
    public static function parseCallback(array $body): ?array
    {
        $cb = $body['Body']['stkCallback']
            ?? $body['stkCallback']
            ?? $body['responsePayload']
            ?? null;

        if (!$cb) {
            return null;
        }

        $checkoutId = $cb['CheckoutRequestID'] ?? $cb['checkoutRequestID'] ?? null;
        if (!$checkoutId) {
            return null;
        }

        $meta = [];
        $items = $cb['CallbackMetadata']['Item'] ?? $cb['callbackMetadata']['item'] ?? [];
        foreach ($items as $item) {
            if (isset($item['Name'])) {
                $meta[$item['Name']] = $item['Value'] ?? null;
            }
        }

        return [
            'checkoutRequestId' => (string) $checkoutId,
            'resultCode'        => (int) ($cb['ResultCode'] ?? $cb['resultCode'] ?? -1),
            'resultDesc'        => (string) ($cb['ResultDesc'] ?? $cb['resultDesc'] ?? ''),
            'receipt'           => $meta['MpesaReceiptNumber'] ?? $cb['MpesaReceiptNumber'] ?? null,
            'amount'            => isset($meta['Amount']) ? (float) $meta['Amount'] : null,
        ];
    }
}