<?php
declare(strict_types=1);

namespace FormShield;

/**
 * FormShield: protezione anti-bot per PHP puro (form e AJAX).
 *
 * Feature:
 * - CSRF (session-based, token per action)
 * - Honeypot (campo trappola)
 * - Time-gate (min/max secondi tra render e submit)
 * - Rate limiter (file-based con lock)
 *
 * Compatibilità: PHP >= 7.2
 */
final class FormShield
{
    /** @var array<string,mixed> */
    private static $cfg = [
        'store' => 'file',
        'store_path' => null, // default: sys_get_temp_dir().'/formshield'
        'actions' => [],
        'default' => [
            'csrf' => true,
            'honeypot' => true,
            'honeypot_field' => 'company_website',
            'timegate_min' => 3,      // sec
            'timegate_max' => 3600,   // sec
            'ratelimit' => [
                'enabled' => true,
                'max' => 10,
                'window' => 600, // 10 min
                'key' => 'ip_action',
            ],
            'error_mode' => 'friendly', // friendly|generic
        ],
    ];

    /**
     * Inizializza configurazione e sessione.
     *
     * @param array<string,mixed> $config
     */
    public static function init(array $config = []): void
    {
        self::$cfg = self::arrayMergeDeep(self::$cfg, $config);

        if (\session_status() !== \PHP_SESSION_ACTIVE) {
            \session_start();
        }

        if (!self::$cfg['store_path']) {
            $tmp = \sys_get_temp_dir();
            $sep = \DIRECTORY_SEPARATOR;
            self::$cfg['store_path'] = \rtrim($tmp, '/\\') . $sep . 'formshield';
        }
        if (!\is_dir((string) self::$cfg['store_path'])) {
            @\mkdir((string) self::$cfg['store_path'], 0777, true);
        }
    }

    /**
     * Rende i campi hidden da inserire in un form HTML.
     *
     * @param array<string,mixed> $overrides
     */
    public static function render(string $action, array $overrides = []): string
    {
        $c = self::configFor($action, $overrides);

        $formId = self::newFormId($action);
        $ts = \time();

        $_SESSION['fs'][$formId] = [
            'action' => $action,
            'ts' => $ts,
        ];

        $html = '';
        $html .= '<input type="hidden" name="_fs_action" value="' . self::e($action) . '">' . "\n";
        $html .= '<input type="hidden" name="_fs_id" value="' . self::e($formId) . '">' . "\n";
        $html .= '<input type="hidden" name="_fs_ts" value="' . (int) $ts . '">' . "\n";

        if (!empty($c['csrf'])) {
            $token = self::csrfToken($action);
            $html .= '<input type="hidden" name="_fs_csrf" value="' . self::e($token) . '">' . "\n";
        }

        if (!empty($c['honeypot'])) {
            $hp = (string) ($c['honeypot_field'] ?? 'company_website');
            $html .= '<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden;" aria-hidden="true">' . "\n";
            $html .= '  <label>Leave this field empty</label>' . "\n";
            $html .= '  <input type="text" name="' . self::e($hp) . '" tabindex="-1" autocomplete="off">' . "\n";
            $html .= "</div>\n";
        }

        return $html;
    }

    /**
     * Restituisce payload da passare al client JS (AJAX).
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    public static function clientPayload(string $action, array $overrides = []): array
    {
        $c = self::configFor($action, $overrides);

        $formId = self::newFormId($action);
        $ts = \time();

        $_SESSION['fs'][$formId] = [
            'action' => $action,
            'ts' => $ts,
        ];

        return [
            'action' => $action,
            'form_id' => $formId,
            'ts' => $ts,
            'csrf' => !empty($c['csrf']) ? self::csrfToken($action) : null,
            'honeypot_field' => !empty($c['honeypot']) ? ($c['honeypot_field'] ?? 'company_website') : null,
        ];
    }

    /**
     * Applica i controlli (FORM o AJAX). Se fallisce, interrompe la richiesta.
     *
     * @param array<string,mixed> $input
     * @param array<string,mixed> $overrides
     */
    public static function enforce(string $action, array $input, bool $isAjax = false, array $overrides = []): void
    {
        $c = self::configFor($action, $overrides);

        // Rate limit
        if (!empty($c['ratelimit']['enabled'])) {
            $key = self::rateKey($action, (string) ($c['ratelimit']['key'] ?? 'ip_action'));
            self::rateCheck($key, (int) $c['ratelimit']['max'], (int) $c['ratelimit']['window'], $isAjax, $c);
        }

        // Honeypot
        if (!empty($c['honeypot'])) {
            $hp = (string) ($c['honeypot_field'] ?? 'company_website');
            $val = \trim((string) ($input[$hp] ?? ''));
            if ($val !== '') {
                self::fail('blocked', $isAjax, $c, 400);
            }
        }

        // Time gate
        $min = (int) ($c['timegate_min'] ?? 0);
        $max = (int) ($c['timegate_max'] ?? 0);

        $formId = (string) ($input['_fs_id'] ?? '');
        $tsClient = (int) ($input['_fs_ts'] ?? 0);

        $tsServer = 0;
        if ($formId && isset($_SESSION['fs'][$formId]['ts'])) {
            $tsServer = (int) $_SESSION['fs'][$formId]['ts'];
        }
        $base = $tsServer ?: $tsClient;

        if ($base > 0) {
            $delta = \time() - $base;
            if ($min > 0 && $delta < $min) {
                self::fail('too_fast', $isAjax, $c, 429);
            }
            if ($max > 0 && $delta > $max) {
                self::fail('expired', $isAjax, $c, 400);
            }
        } else {
            self::fail('blocked', $isAjax, $c, 400);
        }

        // CSRF
        if (!empty($c['csrf'])) {
            $token = (string) ($input['_fs_csrf'] ?? '');
            if (!$token || !self::csrfVerify($action, $token)) {
                self::fail('csrf', $isAjax, $c, 400);
            }
        }

        // One-time form id (anti replay light)
        if ($formId && isset($_SESSION['fs'][$formId])) {
            unset($_SESSION['fs'][$formId]);
        }
    }

    // ---------------- internals ----------------

    /** @param array<string,mixed> $overrides @return array<string,mixed> */
    private static function configFor(string $action, array $overrides): array
    {
        $base = (array) self::$cfg['default'];
        $perAction = (array) (self::$cfg['actions'][$action] ?? []);
        return self::arrayMergeDeep(self::arrayMergeDeep($base, $perAction), $overrides);
    }

    private static function csrfToken(string $action): string
    {
        if (empty($_SESSION['fs_csrf'][$action])) {
            $_SESSION['fs_csrf'][$action] = \bin2hex(\random_bytes(32));
        }
        return (string) $_SESSION['fs_csrf'][$action];
    }

    private static function csrfVerify(string $action, string $token): bool
    {
        $real = (string) ($_SESSION['fs_csrf'][$action] ?? '');
        return $real !== '' && \hash_equals($real, $token);
    }

    private static function newFormId(string $action): string
    {
        return $action . '_' . \bin2hex(\random_bytes(16));
    }

    private static function rateKey(string $action, string $mode): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($mode === 'ip') {
            return "ip:$ip";
        }
        if ($mode === 'ip_action_ua') {
            return "ip:$ip|a:$action|ua:" . \substr(\hash('sha256', $ua), 0, 12);
        }
        return "ip:$ip|a:$action";
    }

    /** @param array<string,mixed> $c */
    private static function rateCheck(string $key, int $max, int $window, bool $isAjax, array $c): void
    {
        $dir = (string) self::$cfg['store_path'];
        $file = $dir . \DIRECTORY_SEPARATOR . \hash('sha256', $key) . '.json';
        $now = \time();

        $data = ['reset' => $now + $window, 'count' => 0];

        $fp = @\fopen($file, 'c+');
        if ($fp) {
            \flock($fp, \LOCK_EX);

            $raw = \stream_get_contents($fp);
            if ($raw) {
                $tmp = \json_decode($raw, true);
                if (\is_array($tmp)) {
                    $data = $tmp + $data;
                }
            }

            if ($now > (int) $data['reset']) {
                $data = ['reset' => $now + $window, 'count' => 0];
            }

            $data['count'] = (int) $data['count'] + 1;

            \ftruncate($fp, 0);
            \rewind($fp);
            \fwrite($fp, \json_encode($data));
            \fflush($fp);

            \flock($fp, \LOCK_UN);
            \fclose($fp);
        } else {
            // Se non puoi scrivere (hosting limitato), degrada in "soft": non bloccare tutto.
            return;
        }

        if ((int) $data['count'] > $max) {
            self::fail('rate_limited', $isAjax, $c, 429);
        }
    }

    /** @param array<string,mixed> $c */
    private static function fail(string $reason, bool $isAjax, array $c, int $http): void
    {
        \http_response_code($http);

        $mode = (string) ($c['error_mode'] ?? 'generic');

        // messaggio base (generico)
        $msg = 'Non è stato possibile completare la richiesta. Riprova.';

        if ($mode === 'friendly') {
            if ($reason === 'too_fast') {
                $msg = 'Invio troppo rapido. Attendi qualche secondo e riprova.';
            } elseif ($reason === 'rate_limited') {
                $msg = 'Troppi tentativi. Riprova più tardi.';
            } elseif ($reason === 'expired') {
                $msg = 'Sessione scaduta. Ricarica la pagina e riprova.';
            }
        }

        if ($isAjax) {
            \header('Content-Type: application/json; charset=utf-8');
            echo \json_encode([
                'ok' => false,
                'code' => $reason,
                'message' => $msg,
            ]);
        } else {
            // Fallback minimale: in un progetto reale fai redirect + flash message.
            echo $msg;
        }
        exit;
    }

    private static function e(string $s): string
    {
        return \htmlspecialchars($s, \ENT_QUOTES, 'UTF-8');
    }

    /**
     * Merge ricorsivo.
     *
     * @param array<string,mixed> $a
     * @param array<string,mixed> $b
     * @return array<string,mixed>
     */
    private static function arrayMergeDeep(array $a, array $b): array
    {
        foreach ($b as $k => $v) {
            if (\is_array($v) && isset($a[$k]) && \is_array($a[$k])) {
                $a[$k] = self::arrayMergeDeep($a[$k], $v);
            } else {
                $a[$k] = $v;
            }
        }
        return $a;
    }
}
