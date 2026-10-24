<?php

namespace App\Kbiz;

use DOMDocument;
use DOMXPath;

/**
 * Parses and validates the KBIZ_* environment. Every bank-specific string
 * (host, paths, header names and values, body keys, response keys, status
 * words, HTML selectors) lives in env; code only knows the logical names
 * declared here.
 */
final readonly class KbizConfig
{
    /**
     * KBIZ_API_<n>_* → logical step.
     *   fields:    logical names that must appear in KBIZ_API_<n>_FIELDS (real key names)
     *   values:    logical names that must appear in KBIZ_API_<n>_VALUES (real fixed values)
     *   constants: logical names sent on every request as field(name) => value(name)
     */
    public const array STEPS = [
        1 => ['name' => 'login_page', 'fields' => [], 'values' => [], 'constants' => []],
        2 => [
            'name' => 'login_submit',
            'fields' => ['login_name', 'login_secret', 'login_token', 'command', 'ui_locale', 'customer_type', 'touch_points', 'app_mode'],
            'values' => ['command', 'ui_locale', 'customer_type', 'touch_points', 'app_mode'],
            'constants' => ['command', 'ui_locale', 'customer_type', 'touch_points', 'app_mode'],
        ],
        3 => [
            'name' => 'approval_status',
            'fields' => ['approval_state'],
            'values' => ['state_approved', 'state_rejected'],
            'constants' => [],
        ],
        4 => [
            'name' => 'qr_confirm',
            'fields' => ['qr_timestamp', 'error_text', 'ui_locale', 'command'],
            'values' => ['error_text', 'ui_locale', 'command'],
            'constants' => ['error_text', 'ui_locale', 'command'],
        ],
        5 => ['name' => 'bank_redirect', 'fields' => [], 'values' => [], 'constants' => []],
        6 => [
            'name' => 'validate_session',
            'fields' => ['handoff_token', 'session_token_header', 'profile', 'user_ref', 'org_id', 'customer_type'],
            'values' => [],
            'constants' => [],
        ],
        7 => [
            'name' => 'list_accounts',
            'fields' => [
                'customer_type', 'owner_id', 'user_ref_header', 'session_user_ref_header', 'session_auth_header',
                'account_list', 'account_number', 'account_kind',
                'account_filter', 'balance_flag', 'response_language', 'nickname_kind', 'owner_kind',
            ],
            'values' => ['account_filter', 'balance_flag', 'response_language', 'nickname_kind', 'owner_kind'],
            'constants' => ['account_filter', 'balance_flag', 'response_language', 'nickname_kind', 'owner_kind'],
        ],
    ];

    /**
     * KBIZ_SELECTOR_<n> → logical selector and its kind.
     */
    public const array SELECTORS = [
        1 => ['name' => 'login_token', 'kind' => 'xpath'],
        2 => ['name' => 'qr_image', 'kind' => 'xpath'],
        3 => ['name' => 'qr_deadline', 'kind' => 'xpath'],
        4 => ['name' => 'qr_confirmed', 'kind' => 'regex'],
        5 => ['name' => 'handoff_token', 'kind' => 'regex'],
    ];

    private const int MAX_PATH_LENGTH = 2048;

    private const int DEFAULT_TIMEOUT_SECONDS = 20;

    /**
     * Keeps the slowest possible bank login (every connect retried, every
     * request running to its timeout) inside the register code's attempt
     * reservation (AttemptReservation::TTL_SECONDS), so a reservation never
     * expires while its credentials may still reach the bank.
     */
    public const int MAX_TIMEOUT_SECONDS = 45;

    /** Selectors whose capture group 1 carries the value. */
    private const array CAPTURING_SELECTORS = [5];

    /**
     * @param  array<string, KbizStep>  $steps
     * @param  array<string, string>  $selectors
     */
    private function __construct(
        public string $baseUrl,
        public string $host,
        public int $timeoutSeconds,
        private array $steps,
        private array $selectors,
    ) {}

    /**
     * @param  array{base_url?: mixed, timeout_seconds?: mixed, apis?: mixed, selectors?: mixed}  $raw
     */
    public static function fromArray(array $raw): self
    {
        [$baseUrl, $host] = self::parseBaseUrl($raw['base_url'] ?? null);

        $timeout = self::parseTimeout($raw['timeout_seconds'] ?? null);

        $apis = is_array($raw['apis'] ?? null) ? $raw['apis'] : [];
        $steps = [];
        foreach (self::STEPS as $n => $definition) {
            $steps[$definition['name']] = self::parseStep($n, $definition, $apis[$n] ?? []);
        }

        $rawSelectors = is_array($raw['selectors'] ?? null) ? $raw['selectors'] : [];
        $selectors = [];
        foreach (self::SELECTORS as $n => $definition) {
            $selectors[$definition['name']] = self::parseSelector($n, $definition['kind'], $rawSelectors[$n] ?? null);
        }

        self::checkApprovalStates($steps['approval_status']);

        return new self($baseUrl, $host, $timeout, $steps, $selectors);
    }

    public function step(string $name): KbizStep
    {
        return $this->steps[$name]
            ?? throw new KbizConfigException("Unknown KBiz step \"{$name}\".");
    }

    public function selector(string $name): string
    {
        return $this->selectors[$name]
            ?? throw new KbizConfigException("Unknown KBiz selector \"{$name}\".");
    }

    public function url(KbizStep $step): string
    {
        return $this->baseUrl.$step->path;
    }

    private static function stepNumber(string $name): int
    {
        foreach (self::STEPS as $n => $definition) {
            if ($definition['name'] === $name) {
                return $n;
            }
        }

        throw new KbizConfigException("Unknown KBiz step \"{$name}\".");
    }

    private static function parseTimeout(mixed $value): int
    {
        if ($value === null || $value === '') {
            return self::DEFAULT_TIMEOUT_SECONDS;
        }
        $text = is_int($value) ? (string) $value : (is_string($value) ? trim($value) : '');
        if (preg_match('/^[1-9][0-9]{0,2}$/D', $text) !== 1 || (int) $text > self::MAX_TIMEOUT_SECONDS) {
            throw new KbizConfigException('KBIZ_TIMEOUT_SECONDS must be a whole number of seconds between 1 and '.self::MAX_TIMEOUT_SECONDS.'.');
        }

        return (int) $text;
    }

    /**
     * An empty or shared status word would make every poll look approved
     * (or rejected).
     */
    private static function checkApprovalStates(KbizStep $step): void
    {
        $approved = $step->value('state_approved');
        $rejected = $step->value('state_rejected');
        if ($approved === '' || $rejected === '' || $approved === $rejected) {
            $n = self::stepNumber($step->name);

            throw new KbizConfigException("KBIZ_API_{$n}_VALUES state_approved and state_rejected must be non-empty and different.");
        }
    }

    /**
     * @return array{0: string, 1: string}
     */
    private static function parseBaseUrl(mixed $value): array
    {
        $value = self::requireString('KBIZ_BASE_URL', $value);

        if (preg_match('#^https://([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::443)?/?$#D', $value, $matches) !== 1) {
            throw new KbizConfigException('KBIZ_BASE_URL must be an https origin such as https://host (port 443 only; no path, query or credentials).');
        }

        return ['https://'.$matches[1], strtolower($matches[1])];
    }

    /**
     * @param  array{name: string, fields: list<string>, values: list<string>, constants: list<string>}  $definition
     */
    private static function parseStep(int $n, array $definition, mixed $raw): KbizStep
    {
        $raw = is_array($raw) ? $raw : [];

        $path = $raw['path'] ?? null;
        if (! is_string($path) || $path === '') {
            throw new KbizConfigException("KBIZ_API_{$n}_PATH is not set.");
        }
        $problem = self::pathProblem($path);
        if ($problem !== null) {
            throw new KbizConfigException("KBIZ_API_{$n}_PATH {$problem}.");
        }

        $headers = self::parseJsonObject("KBIZ_API_{$n}_HEADERS", $raw['headers'] ?? null);
        foreach ($headers as $name => $value) {
            if (preg_match('/^[A-Za-z0-9!#$%&\'*+.^_`|~-]+$/D', (string) $name) !== 1
                || ! is_string($value) || preg_match('/[\r\n\0]/', $value) === 1
            ) {
                throw new KbizConfigException("KBIZ_API_{$n}_HEADERS must map valid header names to single-line string values.");
            }
        }

        $fields = self::parseJsonObject("KBIZ_API_{$n}_FIELDS", $raw['fields'] ?? null);
        foreach ($fields as $logical => $real) {
            if (! in_array($logical, $definition['fields'], true)) {
                throw new KbizConfigException("KBIZ_API_{$n}_FIELDS has unknown logical field \"{$logical}\".");
            }
            if (! is_string($real) || $real === '') {
                throw new KbizConfigException("KBIZ_API_{$n}_FIELDS value for \"{$logical}\" must be a non-empty string.");
            }
        }
        foreach ($definition['fields'] as $required) {
            if (! array_key_exists($required, $fields)) {
                throw new KbizConfigException("KBIZ_API_{$n}_FIELDS is missing logical field \"{$required}\".");
            }
        }

        $values = self::parseJsonObject("KBIZ_API_{$n}_VALUES", $raw['values'] ?? null);
        foreach ($values as $logical => $value) {
            if (! in_array($logical, $definition['values'], true)) {
                throw new KbizConfigException("KBIZ_API_{$n}_VALUES has unknown logical value \"{$logical}\".");
            }
            if (! is_string($value) && ! is_int($value)) {
                throw new KbizConfigException("KBIZ_API_{$n}_VALUES value for \"{$logical}\" must be a string or integer.");
            }
        }
        foreach ($definition['values'] as $required) {
            if (! array_key_exists($required, $values)) {
                throw new KbizConfigException("KBIZ_API_{$n}_VALUES is missing logical value \"{$required}\".");
            }
        }

        /** @var array<string, string> $headers */
        /** @var array<string, string> $fields */
        /** @var array<string, string|int> $values */
        return new KbizStep($definition['name'], $path, $headers, $fields, $values, $definition['constants']);
    }

    /**
     * Same rules as the worker's bankenv loader, so one env is valid for both.
     * A query string is allowed; it is validated as part of the URL. The
     * value is never trimmed: surrounding whitespace is an error, as in Go.
     */
    private static function pathProblem(string $path): ?string
    {
        $pathPart = explode('?', $path, 2)[0];

        return match (true) {
            ! str_starts_with($path, '/') => 'must start with /',
            strlen($path) > self::MAX_PATH_LENGTH => 'must be at most '.self::MAX_PATH_LENGTH.' bytes',
            str_contains($path, '//') => 'must not contain // or a scheme',
            str_contains($path, '#') || str_contains($path, '\\') => 'must not contain # or backslash',
            in_array('.', explode('/', $pathPart), true) || in_array('..', explode('/', $pathPart), true) => 'must not contain . or .. segments',
            preg_match('/[\x00-\x20\x7F]/', $path) === 1 => 'must not contain whitespace or control characters',
            preg_match('/%(?![0-9A-Fa-f]{2})/', $pathPart) === 1 => 'has an invalid percent escape',
            default => null,
        };
    }

    private static function parseSelector(int $n, string $kind, mixed $value): string
    {
        $variable = "KBIZ_SELECTOR_{$n}";
        $value = self::requireString($variable, $value);

        if ($kind === 'regex') {
            if (@preg_match($value, '') === false) {
                throw new KbizConfigException("{$variable} must be a valid PCRE pattern including delimiters.");
            }
            if (in_array($n, self::CAPTURING_SELECTORS, true) && self::captureGroupCount($value) < 1) {
                throw new KbizConfigException("{$variable} must contain a capture group; group 1 is the extracted value.");
            }

            return $value;
        }

        $xpath = new DOMXPath(new DOMDocument);
        if (@$xpath->evaluate($value) === false) {
            throw new KbizConfigException("{$variable} must be a valid XPath expression.");
        }

        return $value;
    }

    /**
     * Re-wraps the pattern body as "(?:body\n)|" so the empty alternative
     * matches "", which makes PCRE report every group as unmatched.
     */
    private static function captureGroupCount(string $pattern): int
    {
        $closing = ['(' => ')', '{' => '}', '[' => ']', '<' => '>'][$pattern[0]] ?? $pattern[0];
        $end = strrpos($pattern, $closing);
        if ($end === false || $end === 0) {
            return 0;
        }

        $probe = $pattern[0].'(?:'.substr($pattern, 1, $end - 1)."\n)|".substr($pattern, $end);
        if (@preg_match($probe, '', $groups, PREG_UNMATCHED_AS_NULL) !== 1) {
            return 0;
        }

        return count($groups) - 1;
    }

    /**
     * Optional JSON object; an unset variable means "{}".
     *
     * @return array<string, mixed>
     */
    private static function parseJsonObject(string $variable, mixed $value): array
    {
        if ($value === null || $value === '') {
            return [];
        }
        if (! is_string($value)) {
            throw new KbizConfigException("{$variable} must be a JSON object.");
        }

        $decoded = json_decode($value, true, 8);
        if (! is_array($decoded) || ($decoded !== [] && array_is_list($decoded)) || ! str_starts_with(ltrim($value), '{')) {
            throw new KbizConfigException("{$variable} must be a JSON object.");
        }

        return $decoded;
    }

    private static function requireString(string $variable, mixed $value): string
    {
        if (! is_string($value) || trim($value) === '') {
            throw new KbizConfigException("{$variable} is not set.");
        }

        return trim($value);
    }
}
